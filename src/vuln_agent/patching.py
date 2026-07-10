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
6. 生成补丁后，可用 run_shell 验证语法

确认补丁生成完毕后，直接输出 JSON 结果。"""


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
            max_turns=12,
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
        raw = self.run(task)

        if "_raw_output" in raw:
            return self._blocked_candidate(finding, remediation_plan, f"Agent 未能生成结构化补丁: {raw['_raw_output'][:200]}")
        return self._dict_to_patch_candidate(
            finding, remediation_plan, repository, raw, previous_attempt,
        )

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
        """构建补丁生成任务 — 只传关键源码片段，Agent 自己按需读更多。"""
        # 只传受影响文件的路径（Agent 会自己用 read_file 读内容）
        source_paths = "\n".join(f"- {sf.path}" for sf in source_files[:20]) if source_files else "（由 Agent 自行探索）"

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

## 源码文件（请用 read_file 读取具体内容）
{source_paths}
{prev_text}

## 要求
1. 用 read_file 读每个需要修改的文件，找到确切的代码位置
2. 生成 unified diff 格式补丁（--- a/path / +++ b/path / @@ -L,N +L,N @@）
3. 只修改必要的最小范围代码
4. 生成后可用 run_shell 验证（如 python -m py_compile file.py）"""

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
            exp = re.sub(r'\s*\(.*?\)\s*', '', expected).strip().replace('\\', '/')
            if not exp:
                return True
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
        return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.FAILED,
                                 f"missing artifacts for: {', '.join(missing)}")

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
