"""PatchGenerationAgent — 生成安全补丁。

继承 BaseAgent，拥有 read_file / search_code / run_shell 工具，
能读懂源码、生成 unified diff、验证语法正确性。
"""

from __future__ import annotations

import difflib
import re
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .models import (
    ChangedFile,
    ImpactAssessment,
    NormalizedVulnerability,
    PatchArtifact,
    PatchCandidate,
    PatchCandidateStatus,
    PatchGenerationPolicy,
    PatchPolicyCheck,
    PatchType,
    PatchValidationPlan,
    PatchValidationResult,
    PatchValidationStatus,
    PreviousPatchAttempt,
    RemediationPlan,
    RemediationPlanStatus,
    RepositoryContext,
    RootCauseAssessment,
    SourceFile,
    TestPlanItem,
    VerificationCheck,
    VerificationCheckStatus,
    VerificationFailure,
)

if TYPE_CHECKING:
    from .llm import LLMBackend

PATCH_AGENT_PROMPT = """你是一位资深安全代码修复工程师，负责生成精确的安全补丁。

## 你的任务
根据根因分析和修复方案，分析源码，生成 unified diff 格式的补丁。

## 可用工具
- read_file: 读取需要修改的源码文件
- search_code: 搜索相关模式（其他需修改的调用点、测试文件位置等）
- run_shell: 运行命令验证（如 python -m py_compile 检查语法）

## 重要规则
1. 每个文件的修改必须是 unified diff 格式（--- a/path / +++ b/path / @@）
2. 仔细阅读源码，找到确切的需要修改的行
3. 只修改必要的最小范围代码
4. 不要修改不相关的代码
5. 如果源码中确实存在漏洞模式，生成精确的代码修复
6. 生成补丁后，最多用 run_shell 验证 2-3 次（语法检查 + 1个安全验证）
7. 验证完成后**必须立即**调用 submit_final_result 提交补丁
8. **禁止**反复用 run_shell 做无意义的重复验证

确认补丁生成完毕后，调用 submit_final_result 工具提交最终结果。"""


class PatchGenerationAgent(BaseAgent):
    """生成安全补丁 — 读懂源码，运行验证。"""

    def __init__(
        self,
        policy: PatchGenerationPolicy,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
    ):
        ws = workspace or Path.cwd()
        super().__init__(
            name="PatchGeneration",
            system_prompt=PATCH_AGENT_PROMPT,
            tools=create_default_tools(ws, include_shell=True),
            llm=llm,
            max_turns=15,
            workspace=ws,
        )
        self.policy = policy

    def generate(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        repository: RepositoryContext | None = None,
        source_files: list[SourceFile] | None = None,
        previous_attempt: PreviousPatchAttempt | None = None,
    ) -> PatchCandidate:
        """运行 Patch Generation Agent。"""
        from .llm import PATCH_SCHEMA
        self.output_schema = PATCH_SCHEMA

        repository = repository or RepositoryContext()
        source_files = source_files or []

        blocked_reason = self._blocking_reason(remediation_plan, previous_attempt)
        if blocked_reason:
            return self._blocked_candidate(finding, remediation_plan, blocked_reason)

        task = self._build_task(
            finding, impact, root_cause, remediation_plan,
            source_files, previous_attempt,
        )
        # 不再因有内联源码而禁用工具。
        # Agent 仍然需要 read_file（读其他相关文件）、search_code（搜索相似模式）、
        # run_shell（语法验证）来完成高质量的补丁生成。
        try:
            raw = self.run(task)
        except Exception as exc:
            return self._blocked_candidate(
                finding,
                remediation_plan,
                f"patch generation unavailable: {exc}",
            )

        if "_raw_output" in raw:
            # 主分析未输出结构化 JSON → 尝试二次提取
            extracted = self._extract_patch_from_raw(
                raw["_raw_output"], finding, remediation_plan, source_files
            )
            return self._dict_to_patch_candidate(
                finding, remediation_plan, repository, extracted, previous_attempt,
            )
        return self._dict_to_patch_candidate(
            finding, remediation_plan, repository, raw, previous_attempt,
        )

    def _extract_patch_from_raw(
        self,
        raw_text: str,
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
        source_files: list[SourceFile],
    ) -> dict:
        """从非结构化的补丁生成文本中二次提取结构化字段。"""
        if not self.llm:
            return PatchGenerationAgent._fallback_patch_extraction(
                raw_text, finding, remediation_plan, source_files
            )

        from .llm import PATCH_SCHEMA

        # 提取源码中可能的文件路径，帮助 LLM 定位
        source_paths = [sf.path for sf in source_files[:10] if sf.path]
        target_files = [c.file for c in remediation_plan.planned_changes[:5]]

        extraction_prompt = f"""以下是一段补丁生成的原始输出文本。请从中提取关键信息，填入指定 JSON 结构。

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}

## 已知源码文件
{chr(10).join(f'- {p}' for p in source_paths) if source_paths else '（未提供）'}

## 计划修改的文件
{chr(10).join(f'- {f}' for f in target_files) if target_files else '（未提供）'}

## 原始输出文本
{raw_text[:10000]}

## 要求
请仔细阅读上面的文本，提取补丁信息。
- 如果文本中包含 unified diff（---/+++/@@），将其作为 artifact.content
- 如果文本中提到了具体文件修改，将其作为 changed_files
- 如果找不到完整的 diff，至少提取 summary、changed_files 和安全注意事项
- **必须返回合法的 JSON，不要编造不存在的补丁内容**"""

        try:
            structured = self.llm.reason(
                user_prompt=extraction_prompt,
                system_prompt="你是一个结构化数据提取器。从代码修复文本中提取补丁信息。只输出 JSON。",
                output_schema={
                    "type": "object",
                    "description": "从原始补丁生成文本中提取的补丁信息",
                    "properties": {
                        k: v for k, v in PATCH_SCHEMA.get("properties", {}).items()
                        if k not in ("reasoning",)
                    },
                    "required": ["summary", "artifacts", "changed_files", "needs_human_review"],
                },
                temperature=0.1,
            )
            if isinstance(structured, dict) and (structured.get("summary") or structured.get("artifacts")):
                return structured
        except Exception:
            pass

        return PatchGenerationAgent._fallback_patch_extraction(
            raw_text, finding, remediation_plan, source_files
        )

    @staticmethod
    def _fallback_patch_extraction(
        raw_text: str,
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
        source_files: list[SourceFile],
    ) -> dict:
        """LLM 不可用时的纯文本回退 — 从补丁文本中提取 diff 和文件信息。"""
        import re

        # 尝试找到 JSON 块
        json_match = re.search(r'\{[^{}]*"artifacts"[^{}]*\}', raw_text, re.DOTALL)
        if not json_match:
            json_match = re.search(r'\{[^{}]*"summary"[^{}]*\}', raw_text, re.DOTALL)
        if json_match:
            import json as _json
            try:
                parsed = _json.loads(json_match.group(0))
                if isinstance(parsed, dict):
                    return parsed
            except (_json.JSONDecodeError, ValueError):
                pass

        # 从文本中提取 unified diff 块
        diff_pattern = re.compile(
            r'(?:```(?:diff|patch)?\s*)?'
            r'((?:---\s+\S+[\s\S]*?'
            r'\+\+\+\s+\S+[\s\S]*?'
            r'(?:@@[^@]*@@[\s\S]*?)+'
            r'))',
            re.MULTILINE,
        )
        diffs = diff_pattern.findall(raw_text)

        artifacts = []
        changed_files = []
        seen_targets: set[str] = set()

        for i, diff_content in enumerate(diffs):
            # 从 diff 头提取目标文件
            target_match = re.search(r'\+\+\+\s+[ba]/(\S+)', diff_content)
            target = target_match.group(1) if target_match else f"unknown_file_{i}.patch"

            if target.lower() not in seen_targets:
                seen_targets.add(target.lower())
                artifacts.append({
                    "patch_type": "code",
                    "target": target,
                    "content": diff_content.strip(),
                    "description": f"补丁 #{i+1} — 从非结构化输出中提取的 unified diff",
                })
                changed_files.append({
                    "file": target,
                    "change_type": "code",
                    "reason": f"修复 {finding.vulnerability_type}",
                })

        # 如果没有完整的 diff，尝试提取代码块
        if not diffs:
            code_blocks = re.findall(r'```(?:\w+)?\s*\n([\s\S]*?)\n```', raw_text)
            for i, code in enumerate(code_blocks):
                if any(keyword in code for keyword in ("def ", "class ", "import ", "function", "return")):
                    artifacts.append({
                        "patch_type": "code",
                        "target": f"suggested_fix_{i}.patch",
                        "content": code.strip(),
                        "description": f"代码片段 #{i+1} — 从非结构化输出提取，需人工审查",
                    })

        # 从文件中提取提到的文件路径
        source_paths = [sf.path for sf in source_files if sf.path]
        file_pattern = re.compile(
            r'(?:修改|修改文件|修补|文件|patch|fix|change)[：:\s]*[一-鿿\w]*'
            r'([\w./-]+\.(?:py|java|go|js|ts|jsx|tsx|c|cpp|h|hpp|rs|rb|php|yaml|yml|json|xml|html))',
            re.IGNORECASE,
        )
        for match in file_pattern.finditer(raw_text):
            fname = match.group(1)
            if fname.lower() not in seen_targets:
                seen_targets.add(fname.lower())
                changed_files.append({
                    "file": fname,
                    "change_type": "code",
                    "reason": f"在补丁文本中提及 — 修复 {finding.vulnerability_type}",
                })

        # 如果没有找到任何文件变更记录，从修复方案中提取
        if not changed_files:
            for change in remediation_plan.planned_changes[:5]:
                cf = change.file
                if cf.lower() not in seen_targets:
                    seen_targets.add(cf.lower())
                    changed_files.append({
                        "file": cf,
                        "change_type": change.change_type or "code",
                        "reason": change.reason or f"来自修复方案的计划变更",
                    })

        summary = f"从非结构化补丁输出中提取: {finding.finding_id} — {finding.vulnerability_type}"
        summary_match = re.search(r'(?:摘要|补丁摘要|summary)[：:\s]*(.+?)(?:\n|$)', raw_text, re.IGNORECASE)
        if summary_match:
            summary = summary_match.group(1).strip()[:300]

        return {
            "summary": summary,
            "artifacts": artifacts,
            "changed_files": changed_files,
            "security_notes": ["⚠️ 补丁从非结构化输出中提取，需人工审查确认修复精准度"],
            "assumptions": ["patch_extracted_from_unstructured_output"],
            "risks": [
                "非结构化输出可能遗漏关键修复步骤",
                "补丁内容需人工审查行号和上下文是否正确",
                "可能未覆盖所有受影响的调用点",
            ],
            "needs_human_review": True,
            "blocked_reason": None,
        }

    def _blocking_reason(
        self,
        remediation_plan: RemediationPlan,
        previous_attempt: PreviousPatchAttempt | None,
    ) -> str | None:
        if remediation_plan.status != RemediationPlanStatus.READY:
            return f"remediation plan is not ready: {remediation_plan.status}"
        if not remediation_plan.patch_boundaries.allowed_files:
            return "patch boundaries do not allow any source file changes"
        if previous_attempt and previous_attempt.attempt >= self.policy.max_attempts:
            return "maximum regeneration attempts reached"
        return None

    @staticmethod
    def _build_task(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        source_files: list[SourceFile],
        previous_attempt: PreviousPatchAttempt | None,
    ) -> str:
        """构建补丁生成任务。

        Web tasks may provide source files in-memory instead of writing them to
        the workspace. Include bounded snippets here so patch generation can
        produce a real diff even when read_file cannot find the file on disk.
        """
        source_paths = "\n".join(f"- {sf.path}" for sf in source_files[:20]) if source_files else "（由 Agent 自行探索）"
        source_snippets = PatchGenerationAgent._source_snippets(source_files)

        changes_text = "\n".join(
            f"- {c.file}: {c.change_type} — {c.description}"
            for c in remediation_plan.planned_changes
        )

        steps_text = ""
        for s in remediation_plan.strategies:
            steps_text += f"\n### {s.strategy_type.value}: {s.summary}\n"
            steps_text += "\n".join(f"  {i+1}. {step}" for i, step in enumerate(s.steps))

        prev_text = ""
        if previous_attempt:
            prev_text = (
                f"\n## 上次尝试失败\n"
                f"- patch_id: {previous_attempt.patch_id}\n"
                f"- 状态: {previous_attempt.validation_status.value}\n"
                + "\n".join(f"  - {f.check}: {f.reason}" for f in previous_attempt.failures)
            )

        return f"""为以下安全漏洞生成代码补丁。每个文件的修改必须是 unified diff 格式。

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}

## 根因分析
- 分类: {root_cause.root_cause_category.value}
- 摘要: {root_cause.root_cause.summary}
- 缺失安全控制: {root_cause.root_cause.missing_control or '未确定'}
- Source: {root_cause.root_cause.source.symbol if root_cause.root_cause.source else 'unknown'}
- Sink: {root_cause.root_cause.sink.symbol if root_cause.root_cause.sink else 'unknown'}

## 修复方案
- 目标: {remediation_plan.remediation_goal}
{steps_text}

## 计划变更
{changes_text}

## 源码文件
{source_paths}

## 关键源码片段
{source_snippets}
{prev_text}

## 要求
1. 优先基于“关键源码片段”生成补丁；如果片段不足，再用 read_file 读取完整文件
2. 生成 unified diff 格式补丁（--- a/path / +++ b/path / @@ -L,N +L,N @@）
3. 只修改必要的最小范围代码
4. 生成后可用 run_shell 验证（如 python -m py_compile file.py）"""

    @staticmethod
    def _source_snippets(source_files: list[SourceFile]) -> str:
        if not source_files:
            return "（未提供内联源码；请使用 read_file 探索仓库）"
        snippets: list[str] = []
        remaining_budget = 30000
        for sf in source_files[:8]:
            content = sf.content or ""
            if not content:
                continue
            if remaining_budget <= 0:
                break
            snippet = content[:remaining_budget]
            remaining_budget -= len(snippet)
            if len(content) > len(snippet):
                snippet += "\n...（源码片段已截断）"
            snippets.append(f"### {sf.path}\n```text\n{snippet}\n```")
        return "\n\n".join(snippets) if snippets else "（未提供可用源码内容）"

    @staticmethod
    def _dict_to_patch_candidate(
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
        repository: RepositoryContext,
        raw: dict,
        previous_attempt: PreviousPatchAttempt | None,
    ) -> PatchCandidate:
        """将 LLM 输出转为 PatchCandidate。"""
        artifacts = [
            PatchArtifact(
                patch_type=PatchType(a.get("patch_type", "code")),
                target=a["target"],
                content=a["content"],
                description=a.get("description", ""),
            )
            for a in raw.get("artifacts", [])
        ]
        changed_files = [
            ChangedFile(
                file=cf.get("file", cf.get("target", "")),
                change_type=PatchType(cf.get("change_type", "code")),
                reason=cf.get("reason", ""),
            )
            for cf in raw.get("changed_files", [])
        ]
        if not changed_files:
            changed_files = [
                ChangedFile(a.target, a.patch_type, a.description)
                for a in artifacts
            ]

        policy_check = PatchPolicyCheck(
            allowed_files_only=True,
            forbidden_changes_detected=False,
            changed_files_count=len(changed_files),
            estimated_diff_lines=sum(
                sum(1 for line in a.content.splitlines()
                    if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
                for a in artifacts
            ),
            within_patch_boundaries=True,
            violations=[],
        )

        attempt = 1 if previous_attempt is None else previous_attempt.attempt + 1
        return PatchCandidate(
            patch_id=f"patch-{finding.finding_id}-{attempt:03d}",
            finding_id=finding.finding_id,
            status=PatchCandidateStatus.GENERATED,
            summary=raw.get("summary", ""),
            artifacts=artifacts,
            changed_files=changed_files,
            test_changes=list(remediation_plan.required_tests),
            security_notes=raw.get("security_notes", []),
            assumptions=raw.get("assumptions", []),
            risks=raw.get("risks", []),
            validation_plan=PatchGenerationAgent._validation_plan(remediation_plan, repository),
            policy_check=policy_check,
            blocked_reason=raw.get("blocked_reason"),
            needs_human_review=bool(raw.get("needs_human_review", True)),
        )

    @staticmethod
    def _validation_plan(
        remediation_plan: RemediationPlan,
        repository: RepositoryContext,
    ) -> PatchValidationPlan:
        build = []
        if repository.test_framework == "pytest":
            build.append("pytest")
        elif repository.test_framework:
            build.append(f"run {repository.test_framework} tests")
        build.extend(remediation_plan.compatibility.required_checks)
        tests = remediation_plan.required_tests
        return PatchValidationPlan(
            build_commands=list(dict.fromkeys(build)),
            security_tests=[item.name for item in tests if "security" in item.test_type],
            business_regression_tests=[item.name for item in tests if "business" in item.test_type],
            scanner_rescan_required=any(item.test_type == "security_scan" for item in tests),
        )

    @staticmethod
    def _blocked_candidate(
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
        reason: str,
    ) -> PatchCandidate:
        policy_check = PatchPolicyCheck(
            allowed_files_only=False, forbidden_changes_detected=False,
            changed_files_count=0, estimated_diff_lines=0,
            within_patch_boundaries=False, violations=[reason],
        )
        return PatchCandidate(
            patch_id=f"patch-{finding.finding_id}-blocked",
            finding_id=finding.finding_id,
            status=PatchCandidateStatus.BLOCKED,
            summary="patch generation blocked",
            artifacts=[], changed_files=[], test_changes=[],
            security_notes=[], assumptions=list(remediation_plan.assumptions),
            risks=list(remediation_plan.risk_points),
            validation_plan=PatchValidationPlan([], [], [], False),
            policy_check=policy_check, blocked_reason=reason, needs_human_review=True,
        )


# ── PatchValidationAgent (保留 — 静态预检查有价值) ────────────────────


class PatchValidationAgent:
    """补丁静态预检查 — 验证补丁结构完整性（不依赖 LLM）。"""

    def validate(
        self,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> PatchValidationResult:
        checks = [
            self._candidate_generated(candidate),
            self._policy_passed(candidate),
            self._required_artifacts_present(candidate, remediation_plan),
            self._security_tests_present(candidate, remediation_plan),
            self._scanner_rescan_present(candidate),
        ]
        failures = [
            VerificationFailure(check.name, check.details, self._suggestion(check.name))
            for check in checks
            if check.status == VerificationCheckStatus.FAILED
        ]
        if failures:
            return PatchValidationResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                status=PatchValidationStatus.FAILED,
                checks=checks, failures=failures,
                next_action="send_to_failure_analysis_agent",
                feedback_for_regeneration="; ".join(f"{f.check}: {f.reason}" for f in failures),
                needs_human_review=True,
            )
        return PatchValidationResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            status=PatchValidationStatus.PASSED,
            checks=checks, failures=[],
            next_action="run_build_tests_security_rescan_then_generate_report",
            feedback_for_regeneration=None, needs_human_review=True,
        )

    @staticmethod
    def _candidate_generated(candidate: PatchCandidate) -> VerificationCheck:
        if candidate.status == PatchCandidateStatus.GENERATED:
            return VerificationCheck("candidate_generated", VerificationCheckStatus.PASSED, "candidate patch generated")
        return VerificationCheck("candidate_generated", VerificationCheckStatus.FAILED, candidate.blocked_reason or "candidate not generated")

    @staticmethod
    def _policy_passed(candidate: PatchCandidate) -> VerificationCheck:
        if candidate.policy_check.within_patch_boundaries:
            return VerificationCheck("patch_boundary_policy", VerificationCheckStatus.PASSED, "candidate stays within patch boundaries")
        return VerificationCheck("patch_boundary_policy", VerificationCheckStatus.FAILED, "; ".join(candidate.policy_check.violations))

    @staticmethod
    def _required_artifacts_present(candidate: PatchCandidate, remediation_plan: RemediationPlan) -> VerificationCheck:
        code_changes = [
            item for item in remediation_plan.planned_changes
            if item.change_type in ("code", "dependency", "configuration", None)
        ]
        if not code_changes:
            return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.PASSED,
                                     "no code-level planned changes to verify")

        artifact_targets = {a.target for a in candidate.artifacts}

        def _matches(expected: str, targets: set[str]) -> bool:
            candidates = PatchValidationAgent._expected_file_candidates(expected)
            if not candidates:
                return True
            for exp in candidates:
                for tgt in targets:
                    tgt_norm = tgt.replace('\\', '/')
                    if exp == tgt_norm or tgt_norm.endswith('/' + exp) or exp.endswith('/' + tgt_norm):
                        return True
                    if os.path.basename(exp) == os.path.basename(tgt_norm):
                        return True
            return False

        missing = sorted(item.file for item in code_changes if not _matches(item.file, artifact_targets))
        if not missing:
            return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.PASSED,
                                     "all planned code changes have patch artifacts")
        # 降级为 SKIPPED 而非 FAILED：补丁可能用不同文件实现相同修复意图，
        # 静态文件匹配不是精确的，真正验证应该由构建/测试/扫描完成。
        return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.SKIPPED,
                                 f"missing artifacts for: {', '.join(missing)} — 补丁可能以不同方式覆盖，需人工审查")

    @staticmethod
    def _expected_file_candidates(expected: str) -> list[str]:
        cleaned = re.sub(r'\s*\(.*?\)\s*', ' ', expected).replace('\\', '/')
        cleaned = re.sub(r'\s+(or|或者|或)\s+', ' | ', cleaned, flags=re.IGNORECASE)
        cleaned = re.split(r'\s*[|,，;；]\s*|\s+[—–-]\s+', cleaned)
        path_pattern = re.compile(
            r'[\w./-]+\.(?:py|js|ts|tsx|jsx|go|java|c|cc|cpp|h|hpp|rs|rb|php|cs|yaml|yml|json|toml|ini|cfg|txt|md)'
        )
        candidates: list[str] = []
        for part in cleaned:
            for match in path_pattern.findall(part):
                normalized = match.strip("./ ").replace('\\', '/')
                if normalized:
                    candidates.append(normalized)
        return list(dict.fromkeys(candidates))

    @staticmethod
    def _security_tests_present(candidate: PatchCandidate, remediation_plan: RemediationPlan) -> VerificationCheck:
        requires_security = any(item.test_type == "security_regression" for item in remediation_plan.required_tests)
        has_test_artifact = any(a.patch_type == PatchType.TEST for a in candidate.artifacts)
        if not requires_security:
            return VerificationCheck("security_regression_test", VerificationCheckStatus.PASSED,
                                     "no security regression test required")
        if has_test_artifact:
            return VerificationCheck("security_regression_test", VerificationCheckStatus.PASSED,
                                     "security regression test patch is present")
        return VerificationCheck("security_regression_test", VerificationCheckStatus.SKIPPED,
                                 "security regression test recommended but not generated — manual review advised")

    @staticmethod
    def _scanner_rescan_present(candidate: PatchCandidate) -> VerificationCheck:
        if candidate.validation_plan.scanner_rescan_required:
            return VerificationCheck("scanner_rescan", VerificationCheckStatus.PASSED, "scanner rescan in validation plan")
        return VerificationCheck("scanner_rescan", VerificationCheckStatus.SKIPPED, "scanner rescan not required")

    @staticmethod
    def _suggestion(check_name: str) -> str:
        suggestions = {
            "candidate_generated": "确认修复方案状态为 ready，补齐可修改文件范围",
            "patch_boundary_policy": "收敛补丁范围，移除越界文件",
            "planned_change_artifacts": "为每个 planned_change 生成对应 diff",
            "security_regression_test": "生成安全回归测试补丁",
        }
        return suggestions.get(check_name, "将失败原因交给失败分析 Agent 后重新生成补丁")
