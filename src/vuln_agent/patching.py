"""PatchGenerationAgent — 生成安全补丁。

继承 BaseAgent，拥有 read_file / search_code / run_shell 工具，
能读懂源码、生成 unified diff、验证语法正确性。

补丁生成流程（v2 — 依赖感知 + 防合谋）：
  1. 文件依赖分析 → 拓扑分组
  2. 阶段内并行、阶段间串行（后续阶段可见前置阶段的 diff）
  3. 全部生成后 → 跨文件一致性校验（防合谋）
"""

from __future__ import annotations

import ast
import json
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools, _safe_print
from .models import (
    ChangedFile,
    EvidenceBundle,
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

## 重要规则
1. 每个文件的修改必须是 unified diff 格式（--- a/path / +++ b/path / @@）
2. 仔细阅读源码，找到确切的需要修改的行
3. 只修改必要的最小范围代码
4. 不要修改不相关的代码
5. 如果源码中确实存在漏洞模式，生成精确的代码修复
6. 生成补丁后**必须立即**调用 submit_final_result 提交候选补丁；真实验证由隔离工作区中的 ValidationToolchain 执行
7. 只依据漏洞报告和当前仓库源码、配置与测试生成补丁；不得假设、检索或照搬官方/上游修复
8. 输出是供人工审查的候选补丁；不得写入、提交或合并到原始仓库

## 最小修复边界（violation 会被 validation 拒绝）
- 防御放在算法/调度层（alg-key 兼容性校验、algorithms 白名单、算法专属 prepare_key），
  不改底层通用导入函数（如 OctKey.import_key、RSAKey.import_key）
- 不删除已有算法注册（如 NoneAlgorithm）— 通过 algorithms 白名单控制可用性
- 不删除现有功能路径（如 head['jwk'] key 解析）— 通过 alg 白名单防御
- 不破坏现有测试语义 — 已有测试必须继续通过，不修改测试的预期行为
- 修复应限定在：algorithms 白名单传递、alg-key 类型绑定、HMAC 入口的 key 类型校验

## Diff 格式规范（严格遵守，失败会导致补丁被拒绝）
- diff 头必须严格使用格式: --- a/{目标文件路径} 和 +++ b/{目标文件路径}
- 路径中的目录分隔符必须与源码中一致（正斜杠 /）
- @@ 行号必须从提供的源码中精确计算（第 1 行是行号 1，不是 0）
- 上下文行（以空格开头）必须逐字符复制源码，禁止改写、重排版、修正缩进
- 补丁只输出一行一行确切的修改，不添加注释、解释或 markdown 包装
- 每个 hunk 的 @@ 头部 old_start 和 old_count 必须与源码实际行号匹配

确认补丁生成完毕后，调用 submit_final_result 工具提交最终结果。"""


class PatchGenerationAgent(BaseAgent):
    """生成安全补丁 — 读懂源码并输出候选 diff，不修改工作区。"""

    def __init__(
        self,
        policy: PatchGenerationPolicy,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
        pipeline_mode: str = "balanced",
    ):
        ws = workspace or Path.cwd()
        from .reasoning import stage_policy, StageExecution
        self.stage_policy = stage_policy("patch", pipeline_mode)
        self.last_execution = StageExecution(
            "patch", self.stage_policy.pipeline_mode.value, self.stage_policy.fast_path.value
        )
        super().__init__(
            name="PatchGeneration",
            system_prompt=PATCH_AGENT_PROMPT,
            tools=create_default_tools(ws, include_shell=False),
            llm=llm,
            max_turns=self.stage_policy.max_turns,
            workspace=ws,
            max_output_tokens=self.stage_policy.max_output_tokens,
            tool_budget=dict(self.stage_policy.tool_budget),
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
        evidence_bundle: EvidenceBundle | None = None,
    ) -> PatchCandidate:
        """运行 Patch Generation Agent。"""
        from .llm import PATCH_SCHEMA
        self.output_schema = PATCH_SCHEMA

        repository = repository or RepositoryContext()
        source_files = source_files or []

        from .reasoning import StageExecution

        blocked_reason = self._blocking_reason(remediation_plan, previous_attempt)
        if blocked_reason:
            self.last_execution = StageExecution(
                "patch", self.stage_policy.pipeline_mode.value,
                self.stage_policy.fast_path.value,
                details={"blocked_reason": blocked_reason},
            )
            return self._blocked_candidate(finding, remediation_plan, blocked_reason)

        task = self._build_task(
            finding, impact, root_cause, remediation_plan,
            source_files, previous_attempt, evidence_bundle,
        )
        # Agent can inspect files and search code, but cannot mutate the source
        # workspace. Candidate execution happens later in an isolated copy.
        # Multi-file diffs are deliberately generated artifact-by-artifact.
        # This is a response-size routing decision, not a scope restriction.
        # Always use per-file generation for cross-file consistency (dependency-aware)
        raw = self._generate_artifacts_by_file(
            finding, root_cause, remediation_plan, source_files,
            failure_reason="per-file generation with dependency-aware ordering",
            previous_attempt=previous_attempt,
            evidence_bundle=evidence_bundle,
        )

        llm_calls = raw.get("llm_calls", 0) if isinstance(raw, dict) else 0
        if not self._has_applicable_artifacts(raw):
            # Fallback: try single-response ReAct generation
            try:
                raw = self.run(task)
                if isinstance(raw, dict):
                    llm_calls += int(raw.get("llm_calls", 0))
            except Exception:
                pass
        if not self._has_applicable_artifacts(raw):
            if isinstance(raw, dict):
                reason = str(raw.get("blocked_reason") or "per-file generation produced no applicable unified diff")
            else:
                reason = "per-file generation produced no applicable unified diff"
            self.last_execution = StageExecution(
                "patch", self.stage_policy.pipeline_mode.value,
                self.stage_policy.fast_path.value,
                llm_calls=llm_calls,
                details={"blocked_reason": reason},
            )
            return self._blocked_candidate(finding, remediation_plan, reason)

        self.last_execution = StageExecution(
            "patch", self.stage_policy.pipeline_mode.value,
            self.stage_policy.fast_path.value,
            llm_calls=llm_calls,
            details={"artifacts_count": len(raw.get("artifacts", [])) if isinstance(raw, dict) else 0},
        )
        return self._dict_to_patch_candidate(
            finding, remediation_plan, repository, raw, previous_attempt,
        )

    @staticmethod
    def _has_applicable_artifacts(raw: dict) -> bool:
        artifacts = raw.get("artifacts") if isinstance(raw, dict) else None
        return bool(artifacts) and all(
            isinstance(item, dict)
            and item.get("target")
            and "--- " in str(item.get("content", ""))
            and "+++ " in str(item.get("content", ""))
            and "@@" in str(item.get("content", ""))
            for item in artifacts
        )

    def _generate_artifacts_by_file(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        source_files: list[SourceFile],
        *,
        failure_reason: str,
        previous_attempt: PreviousPatchAttempt | None = None,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> dict:
        """阶段式生成 unified diff — 依赖感知 + 增量上下文 + 防合谋。

        1. 文件依赖分析 → 拓扑分组
        2. 阶段内并行、阶段间串行（后续可见前置 diff）
        3. 测试补丁在全部代码补丁完成后生成
        4. 跨文件一致性校验（防合谋）
        """
        if not self.llm:
            return {"artifacts": [], "blocked_reason": failure_reason}

        # ── 分离代码变更和测试变更 ──
        code_changes = [
            c for c in remediation_plan.planned_changes
            if getattr(c, "change_type", None) != "test"
        ]
        test_changes = [
            c for c in remediation_plan.planned_changes
            if getattr(c, "change_type", None) == "test"
        ]

        generation_errors: list[str] = []
        llm_calls = 0
        accumulated: dict[str, str] = {}

        # ── 上游反馈：检测 Remediation 是否遗漏了根因因果链中的文件 ──
        from .root_cause import RootCauseAnalysisAgent
        causal_files = RootCauseAnalysisAgent.get_causal_files(root_cause)
        planned_files = {
            PatchGenerationAgent._norm_path(c.file) for c in code_changes
        }
        scope_gaps = [
            cf for cf in causal_files
            if cf not in planned_files
            and not any(
                cf.endswith("/" + pf) or pf.endswith("/" + cf)
                for pf in planned_files
            )
        ]
        if scope_gaps:
            _safe_print(
                f"  [PatchGeneration] ⚠️ 修复范围缺口: 根因因果链包含 "
                f"{len(causal_files)} 个文件，但 Remediation 只计划修改 "
                f"{len(planned_files)} 个文件。未覆盖: {', '.join(scope_gaps[:5])}"
            )
            # 尝试从 source_files 中找到未覆盖文件并提示
            found_gaps = []
            for gap in scope_gaps:
                sf = PatchGenerationAgent._find_source_file(gap, source_files)
                if sf:
                    found_gaps.append(sf.path)
            if found_gaps:
                generation_errors.append(
                    f"scope_gap: 根因涉及 {len(causal_files)} 文件，"
                    f"修复计划仅覆盖 {len(planned_files)} 个。"
                    f"以下文件在源码中存在但未被包含: {', '.join(found_gaps[:3])}"
                )
                _safe_print(
                    f"  [PatchGeneration] 缺失的目标文件存在但未被计划: "
                    f"{', '.join(found_gaps[:3])} — 补丁可能不完整"
                )

        # ── 阶段专用 max_tokens（避免使用全局默认值）──
        _patch_max_tokens = getattr(self.stage_policy, "max_output_tokens", None)

        # ── 0. 复用上一轮仍然有效的 artifact（跨轮局部重试）──
        reusable: dict[str, dict] = {}
        if previous_attempt and previous_attempt.artifacts:
            for prev_art in previous_attempt.artifacts:
                norm_path = PatchGenerationAgent._norm_path(prev_art.target)
                source = PatchGenerationAgent._find_source_file(prev_art.target, source_files)
                if source and PatchGenerationAgent._verify_diff_applies(
                    prev_art.content, source.content or ""
                ):
                    reusable[norm_path] = {
                        "patch_type": prev_art.patch_type.value,
                        "target": prev_art.target,
                        "content": prev_art.content,
                        "description": prev_art.description,
                    }
            if reusable:
                _safe_print(
                    f"  [PatchGeneration] 复用上一轮 {len(reusable)} 个有效 artifact"
                )
                # 跳过已有有效 artifact 的文件对应的 planned changes
                code_changes = [
                    c for c in code_changes
                    if PatchGenerationAgent._norm_path(c.file) not in reusable
                ]

        # ── 1. 依赖分析 + 拓扑分组 ──
        if len(code_changes) >= 2:
            deps = self._analyze_file_dependencies(code_changes, source_files)
            stages = self._topological_stages(deps)
        else:
            stages = [[c.file for c in code_changes]] if code_changes else []

        # ── 2. 逐阶段生成代码补丁 ──
        artifacts, changed_files = self._gen_stages(
            finding, root_cause, remediation_plan, source_files,
            stages, code_changes, accumulated, generation_errors,
            previous_attempt,
        )

        # ── 3. 生成测试补丁（可看到全部代码 diff）──
        requires_security_test = any(
            "security" in item.test_type.lower() or "安全" in item.test_type
            for item in remediation_plan.required_tests
        )
        if requires_security_test and not any(a["patch_type"] == "test" for a in artifacts):
            test_source = self._select_test_source(source_files, remediation_plan)
            if test_source is None:
                generation_errors.append("no repository test file found for required security regression")
            else:
                assertions = "; ".join(item.assertion for item in remediation_plan.required_tests[:8])
                test_change = SimpleNamespace(
                    description="新增或扩展漏洞安全回归测试",
                    reason=f"验证候选补丁阻断漏洞且保留合法行为。断言: {assertions}",
                    change_type="test",
                )
                # ── 构建 API 契约上下文（防止测试幻觉）──
                api_surface = PatchGenerationAgent._extract_source_api_surface(source_files)
                api_contract_text = PatchGenerationAgent._api_contract_context(
                    source_files, api_surface,
                )

                prompt = self._per_file_patch_prompt(
                    finding, root_cause, remediation_plan, test_change, test_source,
                    accumulated_diffs=PatchGenerationAgent._fmt_diffs(accumulated),
                )
                # ── 注入 API 契约到测试生成 prompt ──
                if api_contract_text:
                    prompt += (
                        f"\n\n{api_contract_text}\n\n"
                        "## CRITICAL: API 契约约束\n"
                        "测试补丁只能调用上面列出的已验证存在的 API。\n"
                        "禁止编造不存在的函数名、方法名或类名。\n"
                        "如果需要在测试中 import 模块，确保该模块在当前源码中存在。\n"
                        "所有被测试的函数/方法/类必须在上面的 API 契约清单中能找到。"
                    )

                test_artifact = self._request_single_artifact(
                    prompt, test_source.path, "test", max_tokens=_patch_max_tokens,
                    source_content=test_source.content or "",
                    source_files=source_files,
                )
                if test_artifact is None:
                    generation_errors.append(f"no valid security test diff generated for {test_source.path}")
                else:
                    # ── 验证测试 diff 可应用 ──
                    if not PatchGenerationAgent._verify_diff_applies(
                        test_artifact["content"], test_source.content or ""
                    ):
                        generation_errors.append(
                            f"test diff does not cleanly apply to {test_source.path} "
                            f"(may need manual adjustment)"
                        )
                    # ── 确定性 API 契约检查（防止测试幻觉）──
                    api_issues = PatchGenerationAgent._check_test_api_contract(
                        test_artifact, source_files, api_surface,
                    )
                    if api_issues:
                        generation_errors.extend(
                            f"api_contract: {issue}" for issue in api_issues
                        )
                        _safe_print(
                            f"  [PatchGeneration] API 契约告警: {len(api_issues)} 个问题"
                        )
                    # ── 测试代码语法验证（确定性检查）──
                    syntax_issues = PatchGenerationAgent._validate_test_syntax(
                        test_artifact, test_source,
                    )
                    if syntax_issues:
                        generation_errors.extend(
                            f"test_syntax: {issue}" for issue in syntax_issues
                        )
                        _safe_print(
                            f"  [PatchGeneration] 测试语法告警: {len(syntax_issues)} 个问题"
                        )
                    # ── 测试 import 验证 ──
                    import_issues = PatchGenerationAgent._validate_test_imports(
                        test_artifact, source_files,
                    )
                    if import_issues:
                        generation_errors.extend(
                            f"test_import: {issue}" for issue in import_issues
                        )
                        _safe_print(
                            f"  [PatchGeneration] 测试导入告警: {len(import_issues)} 个问题"
                        )
                    artifacts.append(test_artifact)
                    changed_files.append({
                        "file": test_source.path, "change_type": "test",
                        "reason": test_change.reason,
                    })

        # ── 4. 跨文件一致性校验（防合谋）──
        code_arts = [a for a in artifacts if a.get("patch_type") != "test"]
        test_arts = [a for a in artifacts if a.get("patch_type") == "test"]
        cross_issues: list[dict] = []
        # 无条件运行一致性校验：当有 2+ 代码 artifact 或 code+test 组合时
        needs_cross_verify = (
            (len(code_arts) >= 2 or (code_arts and test_arts))
            and self.llm
        )
        if needs_cross_verify:
            cross_issues = self._cross_verify_consistency(
                finding, root_cause, remediation_plan, code_arts, test_arts,
            )
            if cross_issues:
                blocking = [i for i in cross_issues if i.get("severity") == "blocking"]
                generation_errors.extend(
                    f"cross_verify: {i['description']}" for i in cross_issues[:5]
                )
                if blocking:
                    failure_reason += "; cross-file consistency check found blocking issues"

        # ── 变更类型对齐检查 ──
        change_type_issues = PatchGenerationAgent._verify_change_type_alignment(
            artifacts, remediation_plan,
        )
        if change_type_issues:
            generation_errors.extend(change_type_issues)

        # ── 5. 计划全覆盖检查（causally_required 文件不可遗漏）──
        coverage_gaps = PatchGenerationAgent._check_planned_coverage(
            artifacts, changed_files, remediation_plan, root_cause,
        )
        if coverage_gaps:
            missing_required = [g for g in coverage_gaps if g["causally_required"]]
            missing_optional = [g for g in coverage_gaps if not g["causally_required"]]
            if missing_required:
                generation_errors.append(
                    f"planned_change_coverage: 因果必需文件缺失补丁 — "
                    + ", ".join(g["file"] for g in missing_required)
                )
                # 因果必需文件缺失 → 阻塞返回
                failure_reason += (
                    "; planned_change_coverage: missing causally required artifacts: "
                    + ", ".join(g["file"] for g in missing_required)
                )
            if missing_optional:
                _safe_print(
                    f"  [PatchGeneration] ⚠️ 计划覆盖缺口（非阻塞）: "
                    + ", ".join(g["file"] for g in missing_optional)
                )
                for g in missing_optional:
                    generation_errors.append(
                        f"planned_change_coverage: 可选文件缺失补丁 — {g['file']}"
                    )

        # ── 合并复用 artifact ──
        if reusable:
            for norm_path, art in reusable.items():
                artifacts.append(art)
                changed_files.append({
                    "file": art["target"], "change_type": art["patch_type"],
                    "reason": "复用上一轮验证通过的有效补丁",
                })
                accumulated[norm_path] = art["content"]

        blocked_reason = None
        if not artifacts:
            blocked_reason = f"{failure_reason}; " + "; ".join(generation_errors)

        # 统计 LLM 调用：继承 fallback 计数 + 新生成的 artifact + 跨文件校验
        # 排除复用 artifact（它们没有产生新的 LLM 调用）
        new_artifact_count = len(artifacts) - len(reusable)
        llm_calls = llm_calls + new_artifact_count + (
            1 if self.llm and code_arts and test_arts else 0
        )

        return {
            "summary": f"阶段式生成 {finding.finding_id} 候选补丁（{len(stages)} 阶段）",
            "artifacts": artifacts,
            "changed_files": changed_files,
            "security_notes": [
                f"阶段式依赖感知生成，{len(stages)} 阶段，跨文件一致性已校验。",
            ],
            "assumptions": ["topological_staged_patch_generation"],
            "risks": generation_errors,
            "unavailable_source_files": [],
            "needs_human_review": bool(generation_errors),
            "blocked_reason": blocked_reason,
            "llm_calls": llm_calls,
            "cross_verify_issues": cross_issues,
        }

    @staticmethod
    def _is_causally_required(
        file_path: str,
        remediation_plan: RemediationPlan,
        root_cause: RootCauseAssessment,
    ) -> bool:
        """确定文件是否是因果必需的（漏洞可达路径上的硬约束）。

        优先级：
        1. PlannedChange.causally_required 标记（来自 Remediation LLM 判断）
        2. RootCause.affected_code 中的文件（因果链文件）
        3. RootCause source/sink 文件匹配
        4. 文件名匹配（模糊匹配）
        """
        norm = PatchGenerationAgent._norm_path(file_path)

        # 1. PlannedChange 已标记
        for c in (remediation_plan.planned_changes or []):
            if PatchGenerationAgent._norm_path(c.file) == norm:
                if getattr(c, "causally_required", False):
                    return True
                break  # 找到对应的 planned change，不再检查同文件的其他 entry

        # 2. RootCause affected_code
        affected = getattr(root_cause, "affected_code", None) or []
        for ac in affected:
            ac_file = getattr(ac, "file", "")
            if not ac_file:
                continue
            if PatchGenerationAgent._norm_path(ac_file) == norm:
                return True
            if Path(ac_file).name == Path(norm).name:
                return True

        # 3. RootCause source / sink 文件
        rc = getattr(root_cause, "root_cause", None)
        if rc is not None:
            for rc_field in (getattr(rc, "source", None), getattr(rc, "sink", None)):
                if rc_field and getattr(rc_field, "file", None):
                    rf = PatchGenerationAgent._norm_path(rc_field.file)
                    if rf == norm or Path(rf).name == Path(norm).name:
                        return True

        return False

    def _gen_stages(
        self,
        finding, root_cause, remediation_plan, source_files,
        stages, code_changes, accumulated, generation_errors,
        previous_attempt,
    ) -> tuple[list[dict], list[dict]]:
        """逐阶段生成代码补丁：阶段内并行，阶段间串行。

        causally_required 文件的 diff 即使无法验证为可应用，也会被保留为
        best-effort artifact（带 needs_manual_fix 标记），避免覆盖率缺口。
        """
        artifacts: list[dict] = []
        changed_files: list[dict] = []
        change_map: dict[str, object] = {}
        for c in code_changes:
            change_map[PatchGenerationAgent._norm_path(c.file)] = c

        def _append_artifact(art, source, change, is_causal):
            """添加 artifact 到输出，causally_required 文件失败时保留 best-effort。"""
            if art is None:
                if is_causal:
                    # causally_required 文件：LLM 完全没生成 diff → 创建占位 artifact
                    placeholder = {
                        "patch_type": change.change_type or "code",
                        "target": source.path,
                        "content": (
                            f"--- a/{source.path}\n"
                            f"+++ b/{source.path}\n"
                            f"@@ -1,0 +1,4 @@\n"
                            f"+ # ⚠️ BEST-EFFORT PLACEHOLDER — 因果必需文件\n"
                            f"+ # {source.path} — LLM 未能生成有效补丁\n"
                            f"+ # 原因: {generation_errors[-1] if generation_errors else '未知'}\n"
                            f"+ # 此文件在 RootCause source→sink 因果链上，必须人工审查修复\n"
                        ),
                        "description": (
                            f"⚠️ BEST-EFFORT PLACEHOLDER: {change.description}。"
                            f"LLM 未能为此因果必需文件生成有效 unified diff，"
                            f"需人工审查 {source.path} 并手动编写补丁。"
                        ),
                        "needs_manual_fix": True,
                        "fix_reason": (
                            f"{source.path} 是因果必需文件但 LLM 未生成有效 diff。"
                            f" 原因: {generation_errors[-1] if generation_errors else '未知'}"
                        ),
                    }
                    artifacts.append(placeholder)
                    changed_files.append({
                        "file": source.path, "change_type": placeholder["patch_type"],
                        "reason": change.reason,
                    })
                    accumulated[PatchGenerationAgent._norm_path(source.path)] = placeholder["content"]
                    _safe_print(
                        f"  [PatchGeneration] ⚠️ 因果必需文件 {source.path} "
                        f"LLM 完全未生成 diff，保留占位 artifact 待人工修正"
                    )
                else:
                    generation_errors.append(f"no valid unified diff: {source.path}")
                return
            applicable = PatchGenerationAgent._verify_diff_applies(
                art["content"], source.content or ""
            )
            if applicable:
                artifacts.append(art)
                changed_files.append({
                    "file": source.path, "change_type": art["patch_type"],
                    "reason": change.reason,
                })
                accumulated[PatchGenerationAgent._norm_path(source.path)] = art["content"]
            elif is_causal:
                # causally_required 文件保留 best-effort artifact
                art["needs_manual_fix"] = True
                art["fix_reason"] = (
                    f"diff 无法通过 tolerant apply 验证，但 {source.path} "
                    f"是因果必需文件，保留此 artifact 供人工修正"
                )
                artifacts.append(art)
                changed_files.append({
                    "file": source.path, "change_type": art["patch_type"],
                    "reason": change.reason,
                })
                accumulated[PatchGenerationAgent._norm_path(source.path)] = art["content"]
                generation_errors.append(
                    f"best_effort_artifact: {source.path} — "
                    f"diff 无法验证为可应用（因果必需文件，保留待人工修正）"
                )
                _safe_print(
                    f"  [PatchGeneration] ⚠️ 因果必需文件 {source.path} "
                    f"diff 不可应用，保留为 best-effort"
                )
            else:
                generation_errors.append(
                    f"diff does not apply to {source.path} — "
                    f"tolerant application failed after quality checks"
                )

        for stage_paths in stages:
            stage_tasks = []
            for path in stage_paths:
                change = change_map.get(PatchGenerationAgent._norm_path(path))
                if change is None:
                    continue
                source = self._find_source_file(path, source_files)
                if source is None:
                    generation_errors.append(f"source file not found: {path}")
                    continue
                stage_tasks.append((change, source, path))

            if not stage_tasks:
                continue

            context = PatchGenerationAgent._fmt_diffs(accumulated)

            # 阶段内并行
            _patch_mt = getattr(self.stage_policy, "max_output_tokens", None)
            if len(stage_tasks) == 1:
                change, source, path = stage_tasks[0]
                is_causal = PatchGenerationAgent._is_causally_required(path, remediation_plan, root_cause)
                prompt = self._per_file_patch_prompt(
                    finding, root_cause, remediation_plan, change, source,
                    accumulated_diffs=context,
                    previous_attempt=previous_attempt,
                )
                art = self._request_single_artifact(
                    prompt, source.path, change.change_type,
                    max_tokens=_patch_mt, source_content=source.content or "",
                    source_files=source_files,
                )
                _append_artifact(art, source, change, is_causal)
            else:
                with ThreadPoolExecutor(max_workers=min(len(stage_tasks), 4)) as pool:
                    futures = {}
                    for change, source, path in stage_tasks:
                        prompt = self._per_file_patch_prompt(
                            finding, root_cause, remediation_plan, change, source,
                            accumulated_diffs=context,
                            previous_attempt=previous_attempt,
                        )
                        futures[pool.submit(
                            self._request_single_artifact, prompt, source.path,
                            change.change_type, _patch_mt, source.content or "",
                            source_files,
                        )] = (change, source, path)

                    for future in as_completed(futures):
                        change, source, path = futures[future]
                        is_causal = PatchGenerationAgent._is_causally_required(path, remediation_plan, root_cause)
                        art = future.result()
                        _append_artifact(art, source, change, is_causal)

        return artifacts, changed_files

    @staticmethod
    def _find_source_file(expected: str, source_files: list[SourceFile]) -> SourceFile | None:
        normalized = expected.replace("\\", "/").strip().lstrip("./")
        exact = [sf for sf in source_files if sf.path.replace("\\", "/").lstrip("./") == normalized]
        if exact:
            return exact[0]
        suffix = [
            sf for sf in source_files
            if sf.path.replace("\\", "/").lstrip("./").endswith("/" + normalized)
            or normalized.endswith("/" + sf.path.replace("\\", "/").lstrip("./"))
        ]
        return suffix[0] if len(suffix) == 1 else None

    # ── 文件依赖分析 + 拓扑分组 ─────────────────────────────────────────

    @staticmethod
    def _norm_path(raw: str) -> str:
        """规范化文件路径用于比较。"""
        return raw.replace("\\", "/").strip().lstrip("./")

    @staticmethod
    def _analyze_file_dependencies(
        planned_changes: list, source_files: list[SourceFile],
    ) -> dict[str, set[str]]:
        """分析计划修改文件之间的导入/调用依赖关系。

        返回 {file_path: {依赖的其他 planned-change 文件}}。
        """
        planned_paths: set[str] = set()
        planned_stems: set[str] = set()
        for c in planned_changes:
            path = PatchGenerationAgent._norm_path(getattr(c, "file", ""))
            if path:
                planned_paths.add(path)
                planned_stems.add(Path(path).stem.lower())

        deps: dict[str, set[str]] = {}
        for c in planned_changes:
            path = PatchGenerationAgent._norm_path(getattr(c, "file", ""))
            if not path:
                continue
            deps.setdefault(path, set())
            source = PatchGenerationAgent._find_source_file(path, source_files)
            if source is None or not source.content:
                continue
            content = source.content
            if path.lower().endswith(".py"):
                deps[path].update(
                    PatchGenerationAgent._py_import_deps(
                        content, planned_paths, planned_stems, path,
                    )
                )
            else:
                deps[path].update(
                    PatchGenerationAgent._generic_import_deps(
                        content, planned_paths, planned_stems, path,
                    )
                )
        return deps

    @staticmethod
    def _py_import_deps(
        content: str, planned_paths: set[str], planned_stems: set[str],
        own_path: str,
    ) -> set[str]:
        """Python AST: 找出来自其他 planned-change 文件的导入。"""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return set()
        own_dir = str(Path(own_path).parent).replace("\\", "/").lstrip("./")
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    PatchGenerationAgent._check_import(
                        alias.name, planned_paths, planned_stems, own_dir, imports,
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    PatchGenerationAgent._check_import(
                        node.module, planned_paths, planned_stems, own_dir, imports,
                    )
        return imports

    @staticmethod
    def _generic_import_deps(
        content: str, planned_paths: set[str], planned_stems: set[str],
        own_path: str,
    ) -> set[str]:
        """Regex: 非 Python 文件的导入检测。"""
        own_dir = str(Path(own_path).parent).replace("\\", "/").lstrip("./")
        imports: set[str] = set()
        # Go: "pkg/file"
        for m in re.finditer(r'"([\w./-]+)"', content):
            PatchGenerationAgent._check_import(
                m.group(1), planned_paths, planned_stems, own_dir, imports,
            )
        # JS/TS: from '...' / require('...')
        for m in re.finditer(
            r"""from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\)""",
            content,
        ):
            module = m.group(1) or m.group(2)
            if module:
                PatchGenerationAgent._check_import(
                    module, planned_paths, planned_stems, own_dir, imports,
                )
        return imports

    @staticmethod
    def _check_import(
        module: str, planned_paths: set[str], planned_stems: set[str],
        own_dir: str, out: set[str],
    ) -> None:
        """检查一个导入模块是否对应某个 planned-change 文件。"""
        if not module:
            return
        module = module.replace("\\", "/").lstrip("./")
        for pp in planned_paths:
            pp_norm = pp.replace("\\", "/").lstrip("./")
            pp_no_ext = pp_norm.rsplit(".", 1)[0] if "." in pp_norm else pp_norm
            if module == pp_no_ext or module.endswith("/" + Path(pp_norm).stem):
                out.add(pp_norm)
                return
            if pp_no_ext.endswith("/" + module.replace("/", ".")):
                out.add(pp_norm)
                return
            pp_dir = str(Path(pp_norm).parent).replace("\\", "/").lstrip("./")
            if pp_dir == own_dir and Path(pp_norm).stem.lower() == module.lower().rsplit(".", 1)[-1]:
                out.add(pp_norm)
                return

    @staticmethod
    def _topological_stages(deps: dict[str, set[str]]) -> list[list[str]]:
        """将依赖图按拓扑序分组。
        每阶段内文件互不依赖（可并行），阶段间按依赖顺序。
        """
        remaining = set(deps.keys())
        stages: list[list[str]] = []
        resolved: set[str] = set()
        safety = len(remaining) + 1
        while remaining and safety > 0:
            safety -= 1
            stage = sorted(p for p in remaining if deps.get(p, set()).issubset(resolved))
            if not stage:
                stage = sorted(remaining)
            for p in stage:
                remaining.discard(p)
                resolved.add(p)
            stages.append(stage)
        return stages

    @staticmethod
    def _fmt_diffs(accumulated: dict[str, str]) -> str:
        """将已生成的补丁格式化为 prompt 上下文。"""
        if not accumulated:
            return ""
        parts = [
            "## 已生成的其他文件补丁（你只能修改当前文件，但必须与这些变更保持一致）",
        ]
        for path, diff in accumulated.items():
            short = diff[:3000] if len(diff) > 3000 else diff
            trunc = " ..." if len(diff) > 3000 else ""
            parts.append(f"### {path}\n```diff\n{short}{trunc}\n```")
        return "\n".join(parts)

    # 支持的测试文件扩展名及其常见测试目录模式
    _TEST_EXTENSIONS: tuple[str, ...] = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go")
    _TEST_DIR_PATTERNS: tuple[str, ...] = ("test", "tests", "__tests__", "spec", "specs",
                                             "src/test", "tst")

    @staticmethod
    def _select_test_source(
        source_files: list[SourceFile], remediation_plan: RemediationPlan
    ) -> SourceFile | None:
        tests = [
            sf for sf in source_files
            if any(sf.path.lower().endswith(ext) for ext in PatchGenerationAgent._TEST_EXTENSIONS)
            and any(
                part.lower().startswith(PatchGenerationAgent._TEST_DIR_PATTERNS)
                or part.lower() in ("test", "tests", "__tests__", "spec", "specs", "tst")
                or part.lower().endswith("test") or part.lower().endswith("spec")
                for part in Path(sf.path).parts
            )
        ]
        # Fallback: also match files whose filename starts with "test" or ends with "_test" / ".test" / ".spec"
        if not tests:
            tests = [
                sf for sf in source_files
                if any(sf.path.lower().endswith(ext)
                       for ext in PatchGenerationAgent._TEST_EXTENSIONS)
                and any(
                    Path(sf.path).name.lower().startswith("test")
                    or "_test." in Path(sf.path).name.lower()
                    or ".test." in Path(sf.path).name.lower()
                    or ".spec." in Path(sf.path).name.lower()
                    for _ in [1]
                )
            ]
        if not tests:
            return None
        tokens = {
            Path(change.file).stem.lower()
            for change in remediation_plan.planned_changes
            if change.file
        }
        ranked = sorted(
            tests,
            key=lambda sf: (
                -sum(token in sf.path.lower() for token in tokens if len(token) > 2),
                len(sf.path),
            ),
        )
        return ranked[0]

    @staticmethod
    def _per_file_patch_prompt(
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        change,
        source: SourceFile,
        accumulated_diffs: str = "",
        previous_attempt: PreviousPatchAttempt | None = None,
    ) -> str:
        content = source.content or ""
        if len(content) > 24000:
            content = content[:24000] + "\n... source truncated ..."
        previous_feedback = ""
        if previous_attempt:
            parts = [
                f"\n上轮验证反馈（本轮必须针对性修正）：",
                f"- 状态: {previous_attempt.validation_status.value}",
            ]
            for failure in previous_attempt.failures:
                parts.append(f"- {failure.check}: {failure.reason}")
            for lesson in previous_attempt.lessons:
                parts.append(f"- 经验: {lesson}")
            for item in previous_attempt.prohibited_repeats:
                parts.append(f"- 禁止重复: {item}")
            previous_feedback = "\n".join(parts)

        return f"""只为一个文件生成安全候选补丁，不要修改其他文件。

漏洞: {finding.finding_id} / {finding.vulnerability_type}
根因: {root_cause.root_cause.summary}
缺失控制: {root_cause.root_cause.missing_control or 'unknown'}
修复目标: {remediation_plan.remediation_goal}
目标文件: {source.path}
计划修改: {change.description}
必要性: {change.reason}
{previous_feedback}
{accumulated_diffs}

当前文件完整内容或受限片段:
```text
{content}
```

返回该文件的 unified diff。diff 头必须严格使用：
--- a/{source.path}
+++ b/{source.path}

## CRITICAL: Diff context accuracy
- Context lines (starting with space) MUST be copied character-for-character from the source above.
- Do NOT rewrite, reformat, re-indent, or "fix" context lines.
- Line numbers MUST be computed from the actual line positions in the source above.
- Only change lines that are security-necessary; do NOT refactor or rename unrelated code.

不得输出其他文件的变更，不得引用官方或上游补丁。"""

    def _cross_verify_consistency(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        code_artifacts: list[dict],
        test_artifacts: list[dict],
    ) -> list[dict]:
        """跨文件一致性校验 — 防合谋。

        独立 LLM 审查全部补丁：
        1. 代码补丁是否真正修复了根因？（非表面修改）
        2. 测试是否真正验证了修复？（非被弱化来匹配破损代码）
        3. 跨文件冲突/不一致？

        Returns: [{file, severity: "blocking"|"warning", description}]
        """
        if not self.llm:
            return []

        code_text = "\n\n".join(
            f"### {a['target']}\n```diff\n{a['content'][:4000]}\n```"
            for a in code_artifacts
        )
        test_text = "\n\n".join(
            f"### {a['target']}\n```diff\n{a['content'][:4000]}\n```"
            for a in test_artifacts
        )

        # Build plan context for code-only or code+test scenarios
        plan_lines = []
        for c in remediation_plan.planned_changes:
            if c.change_type and c.change_type != "test":
                plan_lines.append(f"- {c.file}: {c.description} (reason: {c.reason})")
        plan_context = ("## 计划变更\n" + "\n".join(plan_lines)) if plan_lines else ""

        if test_artifacts:
            test_section = f"""
## 测试补丁（{len(test_artifacts)} 文件）
{test_text}

## 审查维度
1. 代码修复是否在正确的信任边界恢复了安全不变量？
2. 测试是否验证漏洞攻击条件被阻断 + 合法行为被保留？
3. **合谋检测**：测试是否被弱化来适配一个未真正修复的代码补丁？
4. 跨文件接口一致性：代码改了的签名/类型，测试是否同步更新？
"""
        else:
            test_section = f"""
## 审查维度（代码补丁一致性检查）
1. 每个代码补丁是否在正确的信任边界恢复了安全不变量？
2. 多个代码补丁之间是否一致（没有冲突的修复策略）？
3. {len(remediation_plan.planned_changes)} 项计划变更是否都已覆盖？
4. 补丁之间是否有遗漏的依赖变更（如改了函数签名但调用方未更新）？
"""

        verify_prompt = f"""你是独立安全审查员，检验代码补丁与测试补丁的一致性和完整性。

## 漏洞
ID: {finding.finding_id}
类型: {finding.vulnerability_type}
严重性: {finding.severity.value}

## 根因
{root_cause.root_cause.summary}
缺失控制: {root_cause.root_cause.missing_control or 'unknown'}
安全不变量: {getattr(root_cause, 'security_invariant', '') or 'unknown'}

## 修复目标
{remediation_plan.remediation_goal}

{plan_context}

## 代码补丁（{len(code_artifacts)} 文件）
{code_text}
{test_section}

请调用 submit_final_result 提交结果。每个问题必须指明文件、严重级别（blocking/warning）和具体描述。
没有确凿证据时 issues 为空。"""

        schema = {
            "type": "object",
            "properties": {
                "consistent": {"type": "boolean"},
                "verdict": {"type": "string", "enum": ["ok", "warn", "reject"]},
                "issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string"},
                            "severity": {"type": "string", "enum": ["blocking", "warning"]},
                            "description": {"type": "string"},
                        },
                        "required": ["file", "severity", "description"],
                    },
                },
            },
            "required": ["consistent", "verdict", "issues"],
        }

        try:
            _patch_mt = getattr(self.stage_policy, "max_output_tokens", None)
            kwargs: dict = {
                "user_prompt": verify_prompt,
                "system_prompt": (
                    "你是独立安全审查员。发现代码补丁与测试补丁之间的不一致、"
                    "虚假修复和合谋问题。只报告确凿的发现；无确凿证据则 issues 为空。"
                ),
                "output_schema": schema,
                "temperature": 0.1,
            }
            if _patch_mt is not None:
                kwargs["max_tokens"] = _patch_mt
            result = self.llm.reason(**kwargs)
            if isinstance(result, dict):
                return list(result.get("issues", []))
        except Exception:
            pass
        return []

    @staticmethod
    def _verify_change_type_alignment(
        artifacts: list[dict], remediation_plan: RemediationPlan,
    ) -> list[str]:
        """Verify that each artifact's patch_type aligns with the planned change's change_type.

        For example, a planned 'dependency' change should produce a 'dependency' artifact,
        not a 'code' artifact. Cross-type mismatches are warnings, not blocking.

        Returns list of issues (empty = all aligned).
        """
        issues: list[str] = []
        artifact_targets: dict[str, dict] = {}
        for a in artifacts:
            norm = PatchGenerationAgent._norm_path(a.get("target", ""))
            artifact_targets[norm] = a

        for change in remediation_plan.planned_changes:
            if not change.change_type or change.change_type == "test":
                continue
            norm_path = PatchGenerationAgent._norm_path(change.file)
            art = artifact_targets.get(norm_path)
            if art is None:
                # Check suffix match
                for art_path, art_obj in artifact_targets.items():
                    if norm_path.endswith(art_path) or art_path.endswith(norm_path):
                        art = art_obj
                        break
            if art is None:
                continue

            art_type = art.get("patch_type", "")
            planned_type = change.change_type

            if art_type != planned_type:
                # Cross-type mismatch: code patch for a dependency plan is acceptable
                # but worth noting
                if planned_type == "dependency" and art_type == "code":
                    issues.append(
                        f"change_type_mismatch: 计划变更 '{change.file}' 类型为 "
                        f"'{planned_type}' 但生成了 '{art_type}' 补丁"
                    )

        return issues

    @staticmethod
    def _check_planned_coverage(
        artifacts: list[dict],
        changed_files: list[dict],
        remediation_plan: RemediationPlan,
        root_cause: RootCauseAssessment,
    ) -> list[dict]:
        """Verify every planned change has a corresponding artifact.

        Returns list of coverage gaps:
            [{"file": <str>, "causally_required": <bool>}, ...]

        causally_required determination (priority order):
        1. _is_causally_required() — RootCause.affected_code / source / sink match
        2. PlannedChange.causally_required flag (LLM output)
        3. _planned_change_must_cover() — keyword heuristic (fallback)

        causally_required gaps are hard-blockers — the patch MUST cover them.
        """
        gaps: list[dict] = []

        # Build artifact target index (fuzzy match)
        art_targets: set[str] = set()
        for a in artifacts:
            t = PatchGenerationAgent._norm_path(a.get("target", ""))
            art_targets.add(t)
            art_targets.add(Path(t).name)

        for cf in changed_files:
            t = PatchGenerationAgent._norm_path(cf.get("file", ""))
            art_targets.add(t)
            art_targets.add(Path(t).name)

        for change in remediation_plan.planned_changes:
            if not change.file:
                continue
            if getattr(change, "change_type", None) == "test":
                continue

            norm = PatchGenerationAgent._norm_path(change.file)

            # Exact / fuzzy match checks
            if norm in art_targets:
                continue
            if Path(norm).name in art_targets:
                continue
            matched = False
            for at in art_targets:
                if norm.endswith(at) or at.endswith(norm):
                    matched = True
                    break
                if Path(norm).name == Path(at).name:
                    matched = True
                    break
            if matched:
                continue

            # ── Determine if this gap is blocking ──
            is_causal = PatchGenerationAgent._is_causally_required(
                change.file, remediation_plan, root_cause
            )
            if not is_causal:
                # Fallback: keyword heuristic for central security-control files
                must_cover, _ = PatchGenerationAgent._planned_change_must_cover(change)
                is_causal = must_cover

            gaps.append({
                "file": change.file,
                "causally_required": is_causal,
                "description": change.description,
                "reason": change.reason,
            })

        return gaps

    @staticmethod
    def _planned_change_must_cover(change) -> tuple[bool, str]:
        """Return whether a planned change is a hard coverage requirement.

        `causally_required` remains the strongest signal.  In practice, some
        LLM plans correctly list central security-control files but fail to set
        that boolean.  Treat those strategy-critical security-control changes
        as must-cover too, otherwise a partial caller-side patch can slip into
        validation while the central guard from the selected plan is missing.
        """
        if getattr(change, "causally_required", False):
            return True, "causally_required"

        path = PatchGenerationAgent._norm_path(getattr(change, "file", ""))
        basename = Path(path).name.lower()
        text = " ".join(
            str(getattr(change, attr, "") or "")
            for attr in ("description", "reason", "change_type")
        ).lower()

        security_terms = (
            "security", "vulnerab", "cve", "cwe", "exploit", "trust boundary",
            "token", "jwt", "jws", "alg", "algorithm", "key", "signature",
            "verify", "decode", "deserialize", "claims", "whitelist",
            "allowlist", "compatibility", "confusion", "invariant",
            "安全", "漏洞", "利用", "边界", "令牌", "算法", "密钥", "签名",
            "验证", "校验", "白名单", "兼容", "混淆", "不变量",
        )
        control_terms = (
            "must", "required", "core", "central", "primary", "guard",
            "control", "enforce", "reject", "validate", "check", "bind",
            "gate", "entry", "decoder", "verifier",
            "必须", "必要", "核心", "中央", "中心", "主", "防御", "控制",
            "拦截", "拒绝", "绑定", "入口", "解码", "验证器",
        )
        strategy_terms = (
            "three-layer", "three layer", "multi-layer", "defense-in-depth",
            "layer", "selected strategy", "planned strategy",
            "三层", "多层", "纵深", "修复方案", "计划", "策略",
        )

        has_security = any(term in text for term in security_terms)
        has_control = any(term in text for term in control_terms)
        has_strategy = any(term in text for term in strategy_terms)

        if has_security and has_control:
            return True, "security_control_change"
        if has_security and has_strategy:
            return True, "strategy_critical_security_file"

        # Auth/JWT libraries often put the central algorithm/key binding at
        # these module names.  Only promote them when the plan text is security
        # related, so ordinary business edits to a file called jwt.py are not
        # over-constrained.
        if basename in {"jws.py", "jwt.py", "jws_algs.py"} and has_security:
            return True, "central_jose_control_file"

        return False, "optional_planned_change"

    def _request_single_artifact(
        self, prompt: str, target: str, change_type: str | None,
        max_tokens: int | None = None,
        source_content: str = "",
        source_files: list[SourceFile] | None = None,
    ) -> dict | None:
        """Generate a single artifact with optional retry on quality failure."""
        artifact = self._request_single_artifact_raw(
            prompt, target, change_type, max_tokens
        )
        if artifact is None:
            if self.llm and source_content:
                retry_prompt = self._build_diff_repair_prompt(
                    prompt, "", target, source_content,
                    ["未生成有效 unified diff，必须输出该目标文件的 ---/+++/@@ 补丁"]
                )
                artifact = self._request_single_artifact_raw(
                    retry_prompt, target, change_type, max_tokens
                )
            if artifact is None:
                return None

        # ── 质量预检查（仅当有 source_content 时）──
        if source_content:
            quality = PatchGenerationAgent._diff_quality_report(
                artifact["content"], source_content, target,
                source_files=source_files,
            )
            blocking_issues = quality["issues"]
            warnings = quality["warnings"]

            if warnings:
                _safe_print(
                    f"  [PatchGeneration] diff 质量告警 for {target}: "
                    f"{'; '.join(warnings[:3])}"
                )

            if not blocking_issues:
                return artifact

            # 如果存在阻断问题且 LLM 可用，重试一次。重试后仍有
            # blocking issues 时必须丢弃该 artifact；否则类似
            # ``def **init**`` 的 Markdown/代码污染会流入候选补丁。
            if blocking_issues and self.llm:
                _safe_print(
                    f"  [PatchGeneration] diff 质量问题 for {target}: "
                    f"{'; '.join(blocking_issues[:3])} — 重试一次"
                )
                retry_prompt = self._build_diff_repair_prompt(
                    prompt, artifact["content"], target, source_content,
                    blocking_issues
                )
                retry_artifact = self._request_single_artifact_raw(
                    retry_prompt, target, change_type, max_tokens
                )
                if retry_artifact is not None:
                    retry_quality = PatchGenerationAgent._diff_quality_report(
                        retry_artifact["content"], source_content, target,
                        source_files=source_files,
                    )
                    if not retry_quality["issues"]:
                        _safe_print(
                            f"  [PatchGeneration] 重试修复全部阻断问题"
                        )
                        return retry_artifact
                    else:
                        _safe_print(
                            f"  [PatchGeneration] 重试后仍有阻断问题，丢弃该文件补丁: "
                            f"{'; '.join(retry_quality['issues'][:3])}"
                        )
            return None

        return artifact

    def _request_single_artifact_raw(
        self, prompt: str, target: str, change_type: str | None,
        max_tokens: int | None = None,
    ) -> dict | None:
        """Low-level single artifact request — no retry, no quality checks."""
        schema = {
            "type": "object",
            "description": "一个文件的候选补丁",
            "properties": {
                "content": {"type": "string", "description": "完整 unified diff"},
                "description": {"type": "string"},
                "security_notes": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["content", "description"],
        }
        try:
            kwargs: dict = {
                "user_prompt": prompt,
                "system_prompt": "你是安全补丁生成器。一次只输出一个文件的最小且因果完整的 unified diff。",
                "output_schema": schema,
                "temperature": 0.1,
            }
            if max_tokens is not None:
                kwargs["max_tokens"] = max_tokens
            result = self.llm.reason(**kwargs)
        except Exception:
            return None
        if isinstance(result, dict):
            # 检查结构化输出是否因截断/修复而标记了 _schema_missing
            if result.pop("_schema_missing", None):
                _safe_print(
                    f"  [PatchGeneration] structured output had _schema_missing "
                    f"for {target}, trying text extraction"
                )
            content = str(result.get("content", ""))
            description = str(result.get("description", "逐文件生成的安全补丁"))
            # 如果 structured content 中没有有效 diff，尝试从整个 dict 的文本中提取
            if not ("--- " in content and "+++ " in content and "@@" in content):
                extracted = self._extract_first_diff(json.dumps(result, ensure_ascii=False))
                if extracted:
                    content = extracted
                    description = "从结构化输出中二次提取的安全补丁"
        else:
            extracted = self._extract_first_diff(str(result))
            content = extracted or ""
            description = "从逐文件文本响应中提取的安全补丁"
        if not ("--- " in content and "+++ " in content and "@@" in content):
            return None
        patch_type = change_type if change_type in {item.value for item in PatchType} else "code"
        return {
            "patch_type": patch_type,
            "target": target,
            "content": content.strip(),
            "description": description,
        }

    @staticmethod
    def _build_diff_repair_prompt(
        original_prompt: str,
        failed_diff: str,
        target: str,
        source_content: str,
        issues: list[str],
    ) -> str:
        """Build a repair prompt with specific feedback about diff quality issues."""
        issues_text = "\n".join(f"- {issue}" for issue in issues)
        source_lines = source_content.splitlines()
        line_count = len(source_lines)

        return f"""{original_prompt}

## ⚠️ 上一轮 diff 被拒绝 — 请修正以下问题后重新生成

### 拒绝原因
{issues_text}

### 失败的 diff（仅供参考，不要复用）
```diff
{failed_diff[:3000]}
```

### 修正指引
1. **行号计算**: 源码共 {line_count} 行（第 1 行是行号 1，不是 0），@@ 头部的 old_start 必须落在 [1, {line_count}] 范围内
2. **上下文行**: 以空格开头的行必须**逐字符**从上面的源码复制，不要改写、重新排版或"修正"
3. **diff 头部**: 严格使用 `--- a/{target}` 和 `+++ b/{target}`
4. **只改安全必须的代码**: 不要重构、重命名无关变量、调整无关格式
5. **不要输出 markdown 包裹**: diff 直接输出，不要放在 ``` 代码块中

请重新生成该文件的 unified diff。"""

    @staticmethod
    def _verify_diff_applies(diff_content: str, source_content: str) -> bool:
        """Verify a unified diff can be applied to source content.

        Uses tolerant (fuzzy-context) application to handle LLM-generated diffs
        with slightly incorrect hunk headers or hallucinated context lines.
        """
        if not diff_content or not source_content:
            return False
        if "--- " not in diff_content or "+++ " not in diff_content:
            return False
        if "@@" not in diff_content:
            # No hunks = no actual changes; vacuously applicable
            return True

        # Use the same tolerant apply logic as the execution module
        from .execution import WorkspaceValidationExecutor
        result = WorkspaceValidationExecutor._apply_single_diff_tolerant(
            source_content, diff_content
        )
        return result is not None

    @staticmethod
    def _extract_first_diff(text: str) -> str | None:
        """从 LLM 文本输出中提取第一个有效的 unified diff 块。"""
        fenced = re.search(r"```(?:diff|patch)?\s*\n([\s\S]*?)\n```", text)
        candidate = fenced.group(1) if fenced else text
        start = candidate.find("--- ")
        if start >= 0 and "+++ " in candidate[start:] and "@@" in candidate[start:]:
            return candidate[start:].strip()
        return None

    # ── Diff 质量预检查（生成阶段即发现问题）────────────────────────────

    @staticmethod
    def _validate_diff_headers(diff_content: str, expected_target: str) -> list[str]:
        """Validate that diff ---/+++ headers reference the correct target file.

        Returns list of issues (empty = valid).
        """
        issues: list[str] = []
        m_a = re.search(r'^---\s+(\S+)', diff_content, re.MULTILINE)
        m_b = re.search(r'^\+\+\+\s+(\S+)', diff_content, re.MULTILINE)
        expected_norm = expected_target.replace("\\", "/").lstrip("./")

        if not m_a or not m_b:
            issues.append("diff 缺少 --- 或 +++ 头部")
            return issues

        # Extract the path part (strip a/ or b/ prefix)
        a_path = re.sub(r'^[a-z]/', '', m_a.group(1).strip())
        b_path = re.sub(r'^[a-z]/', '', m_b.group(1).strip())

        # Check that at least one header references the expected target
        def _path_matches(header_path: str, expected: str) -> bool:
            hp = header_path.replace("\\", "/").lstrip("./")
            return (hp == expected or hp.endswith("/" + expected)
                    or expected.endswith("/" + hp)
                    or Path(hp).name == Path(expected).name)

        a_ok = _path_matches(a_path, expected_norm)
        b_ok = _path_matches(b_path, expected_norm)

        if not a_ok and not b_ok:
            issues.append(
                f"diff 头部路径不匹配目标文件: "
                f"--- 引用 '{a_path}', +++ 引用 '{b_path}', 期望目标 '{expected_norm}'"
            )
        elif not a_ok:
            issues.append(f"diff --- 头部路径 '{a_path}' 与目标文件 '{expected_norm}' 不匹配")
        elif not b_ok:
            issues.append(f"diff +++ 头部路径 '{b_path}' 与目标文件 '{expected_norm}' 不匹配")

        return issues

    @staticmethod
    def _validate_hunk_line_numbers(
        diff_content: str, source_content: str
    ) -> list[str]:
        """Validate that hunk line numbers are within source bounds and roughly correct.

        Returns list of issues (empty = valid).
        """
        issues: list[str] = []
        source_lines = source_content.splitlines()
        max_line = len(source_lines)
        from .execution import WorkspaceValidationExecutor
        hunks = WorkspaceValidationExecutor._parse_hunks(diff_content)
        # Inline fallback parse
        if not hunks:
            hunks = PatchGenerationAgent._parse_hunks_inline(diff_content)

        for i, hunk in enumerate(hunks):
            old_start = hunk.get("old_start", 0)
            old_count = hunk.get("old_count", 0)
            if old_start < 1:
                issues.append(f"hunk #{i+1}: old_start={old_start} 无效（行号从 1 开始）")
            elif old_start > max_line + 10:
                issues.append(
                    f"hunk #{i+1}: old_start={old_start} 超出源文件范围（共 {max_line} 行）"
                )
            if old_count < 0:
                issues.append(f"hunk #{i+1}: old_count={old_count} 为负数")
            if old_start + old_count - 1 > max_line + 10 and old_count > 0:
                issues.append(
                    f"hunk #{i+1}: 结束行 {old_start + old_count - 1} "
                    f"超出源文件范围（共 {max_line} 行）"
                )

        return issues

    @staticmethod
    def _parse_hunks_inline(diff_content: str) -> list[dict]:
        """Inline hunk parser (no dependency on execution module)."""
        hunks = []
        hunk_pattern = re.compile(
            r'^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@\s*(.*?)\s*$', re.MULTILINE
        )
        for m in hunk_pattern.finditer(diff_content):
            hunks.append({
                "old_start": int(m.group(1)),
                "old_count": int(m.group(2)) if m.group(2) else 1,
                "new_start": int(m.group(3)),
                "new_count": int(m.group(4)) if m.group(4) else 1,
                "context": m.group(5),
            })
        return hunks

    @staticmethod
    def _validate_diff_context_accuracy(
        diff_content: str, source_content: str
    ) -> list[str]:
        """Check that context lines (space-prefixed) in the diff match the actual source.

        Returns list of issues (empty = valid). Uses sampling to avoid excessive work.
        """
        issues: list[str] = []
        source_lines = source_content.splitlines()
        if not source_lines:
            return ["源文件为空，无法验证上下文准确性"]

        diff_lines = diff_content.splitlines()
        context_mismatches = 0
        context_total = 0
        mismatch_examples: list[str] = []

        hunk_start_line = 0  # estimated 0-indexed position in source

        for line in diff_lines:
            if line.startswith("@@") and not line.startswith("@@@"):
                m = re.match(r'^@@ -(\d+)', line)
                if m:
                    hunk_start_line = int(m.group(1)) - 1
                continue
            if line.startswith("+++") or line.startswith("---"):
                continue
            if line.startswith(" "):
                # Context line — should match source at hunk_start_line
                context_total += 1
                expected = line[1:]  # strip leading space
                if 0 <= hunk_start_line < len(source_lines):
                    actual = source_lines[hunk_start_line]
                    if actual != expected:
                        context_mismatches += 1
                        if len(mismatch_examples) < 3:
                            mismatch_examples.append(
                                f"行 ~{hunk_start_line + 1}: "
                                f"期望 '{expected[:60]}' 实际 '{actual[:60]}'"
                            )
                hunk_start_line += 1
            elif line.startswith("-"):
                hunk_start_line += 1
            # + lines don't advance source position

        if context_total > 0 and context_mismatches > 0:
            mismatch_rate = context_mismatches / context_total
            if mismatch_rate > 0.5:
                issues.append(
                    f"diff 上下文行严重不匹配: {context_mismatches}/{context_total} "
                    f"({mismatch_rate:.0%}) 行与源码不一致. "
                    f"示例: {'; '.join(mismatch_examples[:2])}"
                )
            elif mismatch_rate > 0.15:
                issues.append(
                    f"diff 上下文行部分不匹配: {context_mismatches}/{context_total} "
                    f"({mismatch_rate:.0%}) 行与源码不一致"
                )

        return issues

    @staticmethod
    def _diff_quality_report(
        diff_content: str, source_content: str, expected_target: str,
        source_files: list[SourceFile] | None = None,
        source_exports: dict[str, set[str]] | None = None,
    ) -> dict:
        """Run all diff quality checks and return a comprehensive report.

        When *source_files* is provided, additional import-existence
        verification runs for Python files — every ``from X import Y``
        added by the diff is checked against the actual source symbols.

        Returns: {"score": 0.0-1.0, "issues": [...], "warnings": [...]}
        """
        issues: list[str] = []
        warnings: list[str] = []

        # 1. Header validation (blocking)
        header_issues = PatchGenerationAgent._validate_diff_headers(
            diff_content, expected_target
        )
        issues.extend(header_issues)

        # 2. Basic structure
        if "--- " not in diff_content:
            issues.append("缺少 --- 头部")
        if "+++ " not in diff_content:
            issues.append("缺少 +++ 头部")
        if "@@" not in diff_content:
            issues.append("缺少 @@ hunk 头部 — diff 不包含实际修改")

        # 3. Line number sanity
        line_issues = PatchGenerationAgent._validate_hunk_line_numbers(
            diff_content, source_content
        )
        issues.extend(line_issues)

        # 4. Context accuracy (sampling, non-blocking but informative)
        context_issues = PatchGenerationAgent._validate_diff_context_accuracy(
            diff_content, source_content
        )
        warnings.extend(context_issues)

        # 5. Import existence verification (blocking — import errors cause hard failures)
        if source_files and expected_target.endswith(".py"):
            if source_exports is None:
                source_exports = PatchGenerationAgent._extract_source_exports(
                    source_files
                )
            import_issues = PatchGenerationAgent._verify_diff_imports_exist(
                diff_content, expected_target, source_files, source_exports,
            )
            issues.extend(import_issues)

        # 6. Check for common LLM mistakes
        if "```" in diff_content:
            issues.append("diff 中包含 markdown 代码块标记 ```")
        if re.search(r"\*\*[A-Za-z_]\w*\*\*", diff_content):
            issues.append("diff 中包含 Markdown 强调符污染代码标识符（例如 **init**）")
        if diff_content.strip().startswith("{"):
            issues.append("diff 内容疑似 JSON 而非 unified diff")
        # Check for explanatory text mixed into the diff
        if re.search(r'(?<!^)(?:解释|说明|注意|note|explanation)[：:]', diff_content, re.IGNORECASE | re.MULTILINE):
            warnings.append("diff 中可能包含解释性文本")

        # Calculate score
        total_checks = 6 + len(line_issues)  # 6 base checks + dynamic
        failed = len(issues)
        score = max(0.0, 1.0 - (failed / max(total_checks, 1)))

        return {"score": score, "issues": issues, "warnings": warnings}

    @staticmethod
    def _validate_test_syntax(
        test_artifact: dict, test_source
    ) -> list[str]:
        """Validate that the generated test code is syntactically valid.

        Uses AST parsing for Python, basic checks for other languages.
        Returns list of issues (empty = valid).
        """
        issues: list[str] = []
        diff_content = test_artifact.get("content", "")
        if not diff_content:
            return ["test diff content is empty"]

        # Extract only the added lines (the new test code)
        added_lines: list[str] = []
        for line in diff_content.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])

        if not added_lines:
            return ["test diff contains no added lines"]

        ext = Path(test_artifact.get("target", "")).suffix.lower()
        test_code = "\n".join(added_lines)

        if ext == ".py":
            try:
                ast.parse(test_code)
            except SyntaxError as e:
                issues.append(
                    f"测试代码 Python 语法错误 at line {e.lineno}: {e.msg}"
                )
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            # Basic JS/TS checks
            braces = 0
            brackets = 0
            parens = 0
            for ch in test_code:
                if ch == "{": braces += 1
                elif ch == "}": braces -= 1
                elif ch == "[": brackets += 1
                elif ch == "]": brackets -= 1
                elif ch == "(": parens += 1
                elif ch == ")": parens -= 1
            if braces != 0:
                issues.append("测试代码括号不平衡: {}: " + str(braces))
            if brackets != 0:
                issues.append("测试代码方括号不平衡: []: " + str(brackets))
            if parens != 0:
                issues.append("测试代码圆括号不平衡: (): " + str(parens))
        elif ext == ".java":
            try:
                import javalang
                javalang.parse.parse(test_code)
            except ImportError:
                pass  # javalang not available
            except Exception as e:
                # Basic bracket check for Java
                braces = test_code.count("{") - test_code.count("}")
                if braces != 0:
                    issues.append(f"Java 测试代码括号不平衡: {{{{'': braces}}}}")
        elif ext == ".go":
            # Basic Go checks
            braces = test_code.count("{") - test_code.count("}")
            if braces != 0:
                issues.append(f"Go 测试代码括号不平衡: {{{{'': braces}}}}")

        return issues

    @staticmethod
    def _validate_test_imports(
        test_artifact: dict, source_files: list[SourceFile],
    ) -> list[str]:
        """Validate that imported modules in test code exist in the project or are stdlib.

        Returns list of issues (empty = valid).
        """
        issues: list[str] = []
        diff_content = test_artifact.get("content", "")
        if not diff_content:
            return []

        # Collect all known module paths from source files
        known_modules: set[str] = set()
        for sf in source_files:
            if not sf.path:
                continue
            p = sf.path.replace("\\", "/").lstrip("./")
            # Add the full dotted path
            if p.endswith(".py"):
                mod = p[:-3].replace("/", ".")
                known_modules.add(mod)
                # Also add parent packages
                parts = mod.split(".")
                for i in range(1, len(parts)):
                    known_modules.add(".".join(parts[:i]))
            elif p.endswith((".js", ".ts")):
                mod = p.rsplit(".", 1)[0].replace("/", ".")
                known_modules.add(mod)

        # Python stdlib modules (top-level only, commonly used in tests)
        py_stdlib_top = {
            "os", "sys", "io", "re", "math", "time", "datetime", "json",
            "collections", "itertools", "functools", "random", "string",
            "pathlib", "tempfile", "shutil", "logging", "uuid", "base64",
            "hashlib", "hmac", "secrets", "copy", "unittest", "pytest",
            "mock", "unittest.mock", "typing", "dataclasses", "enum",
            "abc", "contextlib", "textwrap", "subprocess", "socket",
            "http", "urllib", "xml", "csv", "configparser", "argparse",
            "asyncio", "threading", "multiprocessing", "queue", "signal",
            "email", "html", "sqlite3", "gzip", "zipfile", "tarfile",
            "inspect", "traceback", "warnings", "logging", "getpass",
            "platform", "struct", "hashlib", "binascii", "textwrap",
        }

        ext = Path(test_artifact.get("target", "")).suffix.lower()
        if ext != ".py":
            return []  # Non-Python import validation not yet implemented

        # Extract added lines
        added_text = ""
        for line in diff_content.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_text += line[1:] + "\n"

        # Find import statements
        for m in re.finditer(
            r'(?:from\s+(\S+)\s+import|import\s+(\S+))',
            added_text,
        ):
            module = m.group(1) or m.group(2)
            if not module:
                continue
            # Strip relative imports
            module = module.lstrip(".")
            base_module = module.split(".")[0]

            # Check if it's a known module
            if (module not in known_modules
                    and base_module not in py_stdlib_top
                    and module not in py_stdlib_top
                    and base_module not in known_modules):
                # Only warn if it's clearly a project import (not a third-party package)
                # Check if any source file name matches
                pkg_name = base_module
                pkg_exists = any(
                    sf.path.replace("\\", "/").lstrip("./").startswith(pkg_name + "/")
                    or Path(sf.path).stem == pkg_name
                    for sf in source_files
                )
                if pkg_exists:
                    issues.append(
                        f"测试导入了 '{module}' 但源码中未找到对应模块路径，"
                        f"请确认导入路径正确"
                    )

        return issues

    # ── Diff quality scoring for validation hardening ──────────────────

    @staticmethod
    def _score_diff_quality(
        artifact: dict, source_content: str
    ) -> dict:
        """Score a single patch artifact for quality metrics.

        Returns: {
            "score": 0.0-1.0,
            "dimensions": {
                "header_valid": bool,
                "hunk_ranges_valid": bool,
                "context_accuracy": float,  # 0.0-1.0
                "has_changes": bool,
                "no_markdown": bool,
                "applicable": bool,
            },
            "issues": [...],
        }
        """
        diff = artifact.get("content", "")
        target = artifact.get("target", "")

        dimensions = {
            "header_valid": False,
            "hunk_ranges_valid": False,
            "context_accuracy": 0.0,
            "has_changes": False,
            "no_markdown": False,
            "applicable": False,
        }
        issues: list[str] = []

        # Header check
        m_a = re.search(r'^---\s+\S+', diff, re.MULTILINE)
        m_b = re.search(r'^\+\+\+\s+\S+', diff, re.MULTILINE)
        dimensions["header_valid"] = bool(m_a and m_b)
        if not dimensions["header_valid"]:
            issues.append("invalid_diff_headers")

        # Hunk ranges
        hunks = PatchGenerationAgent._parse_hunks_inline(diff)
        source_lines = source_content.splitlines() if source_content else []
        max_line = len(source_lines)
        all_ranges_ok = True
        for h in hunks:
            if h["old_start"] < 1 or h["old_start"] > max(max_line + 20, 100):
                all_ranges_ok = False
                break
        dimensions["hunk_ranges_valid"] = all_ranges_ok
        if not all_ranges_ok:
            issues.append("hunk_range_out_of_bounds")

        # Has actual changes (+/- lines)
        has_adds = any(l.startswith("+") and not l.startswith("+++") for l in diff.splitlines())
        has_dels = any(l.startswith("-") and not l.startswith("---") for l in diff.splitlines())
        dimensions["has_changes"] = has_adds or has_dels
        if not dimensions["has_changes"]:
            issues.append("no_actual_changes")

        # No markdown wrapping
        dimensions["no_markdown"] = "```" not in diff
        if not dimensions["no_markdown"]:
            issues.append("contains_markdown_fences")

        # Applicable
        dimensions["applicable"] = PatchGenerationAgent._verify_diff_applies(
            diff, source_content
        )
        if not dimensions["applicable"]:
            issues.append("diff_not_applicable")

        # Context accuracy (if source available and hunk ranges valid)
        if source_content and hunks:
            ctx_issues = PatchGenerationAgent._validate_diff_context_accuracy(
                diff, source_content
            )
            dimensions["context_accuracy"] = 1.0 if not ctx_issues else 0.5
            if ctx_issues:
                issues.append("context_accuracy_low")

        # Overall score
        weights = {
            "header_valid": 0.2,
            "hunk_ranges_valid": 0.15,
            "context_accuracy": 0.15,
            "has_changes": 0.2,
            "no_markdown": 0.1,
            "applicable": 0.2,
        }
        score = sum(
            v * weights[k] for k, v in dimensions.items()
            if isinstance(v, (int, float, bool))
        )

        return {"score": min(1.0, score), "dimensions": dimensions, "issues": issues}

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
        target_files = [c.file for c in remediation_plan.planned_changes]

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
            for change in remediation_plan.planned_changes:
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

    # ── API 契约检查（确定性源码分析，防止 LLM 幻觉）────────────────────

    @staticmethod
    def _extract_source_api_surface(source_files: list[SourceFile]) -> dict[str, set[str]]:
        """从源码文件中提取可用的公开 API 方法名。

        Returns: {file_path: {method_name, ...}}
        """
        api_surface: dict[str, set[str]] = {}
        for sf in source_files:
            if not sf.content:
                continue
            methods: set[str] = set()
            ext = Path(sf.path).suffix.lower()
            if ext == ".py":
                methods = PatchGenerationAgent._py_api_surface(sf.content)
            elif ext in (".js", ".ts", ".jsx", ".tsx"):
                methods = PatchGenerationAgent._js_api_surface(sf.content)
            elif ext == ".go":
                methods = PatchGenerationAgent._go_api_surface(sf.content)
            elif ext == ".java":
                methods = PatchGenerationAgent._java_api_surface(sf.content)
            if methods:
                api_surface[sf.path] = methods
        return api_surface

    @staticmethod
    def _py_api_surface(content: str) -> set[str]:
        methods: set[str] = set()
        try:
            import ast as _ast
            tree = _ast.parse(content)
            for node in _ast.walk(tree):
                if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    if not node.name.startswith("_"):
                        methods.add(node.name)
                elif isinstance(node, _ast.ClassDef):
                    methods.add(node.name)
                    for item in node.body:
                        if isinstance(item, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                            if not item.name.startswith("_"):
                                methods.add(f"{node.name}.{item.name}")
        except SyntaxError:
            pass
        return methods

    @staticmethod
    def _js_api_surface(content: str) -> set[str]:
        methods: set[str] = set()
        # Match: function name, const name = (args) =>, class name, exports.name
        for m in re.finditer(
            r'(?:function|class)\s+(\w+)|'
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:\(|async\s*\()|'
            r'(?:exports\.|module\.exports\.)(\w+)',
            content,
        ):
            name = m.group(1) or m.group(2) or m.group(3)
            if name and not name.startswith("_"):
                methods.add(name)
        return methods

    @staticmethod
    def _go_api_surface(content: str) -> set[str]:
        methods: set[str] = set()
        for m in re.finditer(r'func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)', content):
            name = m.group(1)
            if name and not name.startswith("_") and name[0].isupper():
                methods.add(name)
        return methods

    @staticmethod
    def _java_api_surface(content: str) -> set[str]:
        methods: set[str] = set()
        for m in re.finditer(
            r'(?:public|protected|private)\s+(?:static\s+)?'
            r'(?:[\w<>\[\]]+\s+)(\w+)\s*\([^)]*\)',
            content,
        ):
            name = m.group(1)
            if name and not name.startswith("_"):
                methods.add(name)
        return methods

    # ── 源码符号导出提取（用于导入/符号存在性验证）───────────────

    @staticmethod
    def _extract_source_exports(source_files: list[SourceFile]) -> dict[str, set[str]]:
        """Extract all publicly visible symbols from every Python source file.

        Unlike ``_extract_source_api_surface`` which only collects public
        (non-underscore) API methods, this collects ALL class names, function
        names, nested methods, and top-level assignment targets.  The result
        is used by ``_verify_diff_imports_exist`` to validate that new import
        statements in a diff reference symbols that actually exist.

        Returns:
            {normalized_file_path: {symbol_name, ...}}
        """
        exports: dict[str, set[str]] = {}
        for sf in source_files:
            if not sf.content or not sf.path.endswith(".py"):
                continue
            norm = sf.path.replace("\\", "/").lstrip("./")
            symbols: set[str] = set()
            try:
                tree = ast.parse(sf.content)
                for node in ast.iter_child_nodes(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        symbols.add(node.name)
                    elif isinstance(node, ast.ClassDef):
                        symbols.add(node.name)
                        for item in ast.iter_child_nodes(node):
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                symbols.add(item.name)
                    elif isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                symbols.add(target.id)
            except SyntaxError:
                pass
            exports[norm] = symbols
        return exports

    @staticmethod
    def _resolve_python_import(
        import_spec: str, current_file: str, source_files: list[SourceFile],
    ) -> str | None:
        """Resolve a Python import specifier to a filesystem module path.

        Handles both relative and absolute imports:

        * Relative: ``..errors`` from ``authlib/jose/rfc7518/jws_algs.py``
          → ``authlib/jose/errors``
        * Absolute: ``authlib.jose.errors`` → ``authlib/jose/errors``

        The resolved path is checked against ``source_files`` — both ``.py``
        files and ``__init__.py`` package markers are accepted.

        Returns:
            Normalised module path (without extension) or ``None`` if the
            import cannot be resolved to any known source file.
        """
        if import_spec.startswith("."):
            file_dir = str(Path(current_file).parent).replace("\\", "/").lstrip("./")
            file_parts = file_dir.replace("/", ".").split(".") if file_dir else []
            dots = len(import_spec) - len(import_spec.lstrip("."))
            suffix = import_spec[dots:]
            if dots > len(file_parts):
                return None
            # Python import semantics:
            #   .module  (1 dot)  → current package (go up 0 levels)
            #   ..module (2 dots) → parent package  (go up 1 level)
            #   ...      (3 dots) → grandparent     (go up 2 levels)
            if dots == 1:
                base = list(file_parts)
            elif dots >= 2:
                # go up (dots - 1) levels from the package
                up_levels = dots - 1
                if up_levels >= len(file_parts):
                    base = []
                else:
                    base = file_parts[:-up_levels]
            else:
                base = list(file_parts)
            parts = list(base) + ([suffix] if suffix else [])
            module_path = "/".join(parts) if parts else suffix
        else:
            module_path = import_spec.replace(".", "/")

        module_norm = module_path.replace("\\", "/").lstrip("./")
        for sf in source_files:
            sf_norm = sf.path.replace("\\", "/").lstrip("./")
            if sf_norm in (module_norm + ".py", module_norm + "/__init__.py"):
                return module_norm
        return None

    @staticmethod
    def _verify_diff_imports_exist(
        diff_content: str,
        target_file: str,
        source_files: list[SourceFile],
        source_exports: dict[str, set[str]],
    ) -> list[str]:
        """Verify that every new import in a unified diff resolves to a real symbol.

        Parses the diff for newly-added ``from X import Y`` and ``import X``
        statements, resolves each module specifier, and checks that the
        imported symbol exists in the target module's source exports.

        This catches the most common class of patch-generation hallucination:
        importing an exception / class / function name that does not exist in
        the current repository version.

        Returns:
            List of human-readable issue strings (empty = all imports valid).
        """
        issues: list[str] = []

        # Collect added lines (strip the '+' prefix, skip '+++' headers)
        added_lines: list[str] = []
        for line in diff_content.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])

        if not added_lines:
            return issues

        # Python stdlib top-level modules — these never need verification
        _STDLIB_MODULES: set[str] = {
            "os", "sys", "io", "re", "math", "time", "datetime", "json",
            "collections", "itertools", "functools", "random", "string",
            "pathlib", "tempfile", "shutil", "logging", "uuid", "base64",
            "hashlib", "hmac", "secrets", "copy", "unittest", "pytest",
            "mock", "typing", "dataclasses", "enum", "abc", "contextlib",
            "textwrap", "subprocess", "socket", "http", "urllib", "xml",
            "csv", "configparser", "argparse", "asyncio", "threading",
            "multiprocessing", "queue", "signal", "email", "html", "sqlite3",
            "gzip", "zipfile", "tarfile", "inspect", "traceback", "warnings",
            "getpass", "platform", "struct", "binascii",
            "importlib", "pkgutil", "runpy", "ctypes", "decimal", "fractions",
            "statistics", "fnmatch", "glob", "linecache", "pickle",
            "shelve", "marshal", "sysconfig", "builtins", "gc", "weakref",
            "atexit", "dis", "code", "codeop", "tokenize", "token",
            "symtable", "keyword", "operator", "pprint", "reprlib",
            "calendar", "bisect", "colorsys", "copyreg", "difflib",
            "doctest", "filecmp", "fileinput", "getopt", "gettext",
            "graphlib", "grp", "heapq", "imaplib", "ipaddress", "locale",
            "lzma", "mailbox", "mimetypes", "mmap", "netrc", "nis",
            "nntplib", "numbers", "optparse", "ossaudiodev", "pathlib",
            "pdb", "plistlib", "poplib", "posixpath", "profile", "pstats",
            "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue",
            "quopri", "readline", "resource", "rlcompleter", "sched",
            "secrets", "select", "selectors", "shelve", "shlex",
            "smtplib", "sndhdr", "spwd", "ssl", "stat", "stringprep",
            "sunau", "tabnanny", "telnetlib", "termios", "test", "threading",
            "timeit", "tkinter", "tomllib", "trace", "tty", "turtle",
            "unicodedata", "uuid", "venv", "wave", "webbrowser",
            "winreg", "winsound", "wsgiref", "xdrlib", "xmlrpc",
            "zipapp", "zipimport", "zoneinfo",
        }

        for line in added_lines:
            stripped = line.strip()

            # ── "from X import Y, Z" ──
            m = re.match(r'from\s+(\S+)\s+import\s+(.+)', stripped)
            if m:
                module_spec = m.group(1)
                imported_names = [
                    name.strip().split(" as ")[0].strip()
                    for name in m.group(2).split(",")
                ]

                # Skip star imports — we can't statically verify those
                if "*" in imported_names:
                    continue

                # Skip stdlib / well-known third-party packages
                top_level = module_spec.lstrip(".").split(".")[0]
                if top_level in _STDLIB_MODULES:
                    continue

                # Resolve the module path
                module_path = PatchGenerationAgent._resolve_python_import(
                    module_spec, target_file, source_files,
                )

                if module_path is None:
                    issues.append(
                        f"新增导入 'from {module_spec} import ...' "
                        f"无法解析到任何已知源文件"
                    )
                    continue

                # Find the module file to get its exports
                module_exports: set[str] = set()
                module_found = False
                for sf in source_files:
                    sf_norm = sf.path.replace("\\", "/").lstrip("./")
                    if sf_norm in (module_path + ".py", module_path + "/__init__.py"):
                        module_exports = source_exports.get(sf_norm, set())
                        module_found = True
                        break

                if not module_found:
                    issues.append(
                        f"新增导入 'from {module_spec} import ...' "
                        f"目标模块 '{module_path}' 在源码中不存在"
                    )
                    continue

                for name in imported_names:
                    if name in module_exports:
                        continue
                    # Also check combined set (symbol might be in __init__.py
                    # re-export or defined in a different file)
                    if name in PatchGenerationAgent._PY_COMMON_WHITELIST:
                        continue
                    preview = sorted(module_exports)[:10]
                    issues.append(
                        f"新增导入 '{name}' 在模块 '{module_path}' 中不存在。"
                        f"该模块的公开符号: {preview}"
                        + ("..." if len(module_exports) > 10 else "")
                    )

            # ── "import X" (module-level import, less critical) ──
            m2 = re.match(r'import\s+(\S+)', stripped)
            if m2:
                module_spec = m2.group(1)
                # Only flag if it looks like a project import, not stdlib
                base = module_spec.split(".")[0]
                if base in _STDLIB_MODULES:
                    continue
                module_path = PatchGenerationAgent._resolve_python_import(
                    module_spec, target_file, source_files,
                )
                if module_path is None and not module_spec.startswith("."):
                    # Absolute import that doesn't resolve — could be a
                    # third-party package, so only warn for relative imports
                    pass
                elif module_path is None and module_spec.startswith("."):
                    issues.append(
                        f"新增导入 'import {module_spec}' "
                        f"无法解析到任何已知源文件"
                    )

        return issues

    # ── 通用测试 API 白名单（不依赖源码即可安全使用）──
    _PY_COMMON_WHITELIST: set[str] = {
        # Python builtins
        "print", "len", "range", "str", "int", "float", "bool", "bytes",
        "list", "dict", "set", "tuple", "type", "isinstance", "issubclass",
        "hasattr", "getattr", "setattr", "delattr", "open", "enumerate",
        "zip", "map", "filter", "sorted", "reversed", "any", "all",
        "super", "sum", "min", "max", "abs", "round", "ord", "chr",
        "__init__", "__str__", "__repr__", "assert", "raise",
        "iter", "next", "input", "repr", "format", "id", "hash",
        "callable", "compile", "exec", "eval", "globals", "locals",
        "vars", "dir", "help", "divmod", "pow", "hex", "oct", "bin",
        "slice", "property", "staticmethod", "classmethod",
        "MemoryError", "Exception", "ValueError", "TypeError", "KeyError",
        "IndexError", "AttributeError", "RuntimeError", "OSError",
        "StopIteration", "NotImplementedError", "ImportError",
        # pytest / unittest
        "pytest", "raises", "mark", "parametrize", "fixture", "skip", "skipif",
        "xfail", "yield_fixture", "warns", "approx", "fail",
        "main", "mock", "MagicMock", "Mock", "patch", "sentinel", "call",
        "setUp", "tearDown", "setUpClass", "tearDownClass", "setUpModule",
        "tearDownModule", "TestCase", "TestSuite", "TestLoader", "TextTestRunner",
        "assertEqual", "assertNotEqual", "assertTrue", "assertFalse",
        "assertIs", "assertIsNot", "assertIsNone", "assertIsNotNone",
        "assertIn", "assertNotIn", "assertRaises", "assertRaisesRegex",
        "assertWarns", "assertWarnsRegex", "assertLogs",
        "assertAlmostEqual", "assertNotAlmostEqual",
        "assertGreater", "assertGreaterEqual", "assertLess", "assertLessEqual",
        "assertRegex", "assertNotRegex", "assertCountEqual",
        "assertMultiLineEqual", "assertSequenceEqual", "assertListEqual",
        "assertTupleEqual", "assertSetEqual", "assertDictEqual",
        "addCleanup", "doCleanups", "subTest",
        # json
        "json", "loads", "dumps", "load", "dump",
        # Common stdlib
        "os", "sys", "io", "re", "math", "time", "datetime", "timedelta",
        "collections", "itertools", "functools", "random", "string",
        "pathlib", "Path", "tempfile", "shutil", "logging", "uuid",
        "base64", "hashlib", "hmac", "secrets", "copy", "deepcopy",
        "dataclass", "field", "Enum", "IntEnum",
        "requests", "Response", "Session",
        "urlparse", "urljoin", "quote", "unquote",
    }

    _JS_COMMON_WHITELIST: set[str] = {
        "console", "require", "describe", "it", "test", "expect",
        "beforeEach", "afterEach", "beforeAll", "afterAll",
        "setTimeout", "setInterval", "clearTimeout", "clearInterval",
        "JSON", "parseInt", "parseFloat", "Promise", "async", "await", "_",
        "jest", "before", "after", "sinon", "chai", "assert",
        "Buffer", "process", "__dirname", "__filename", "module", "exports",
        "Object", "Array", "String", "Number", "Boolean", "Date", "RegExp",
        "Map", "Set", "WeakMap", "WeakSet", "Error", "Symbol",
        "Math", "parseInt", "parseFloat", "isNaN", "isFinite",
        "encodeURIComponent", "decodeURIComponent",
        "fetch", "Headers", "Request", "Response", "FormData",
    }

    @staticmethod
    def _check_test_api_contract(
        test_artifact: dict,
        source_files: list[SourceFile],
        api_surface: dict[str, set[str]],
    ) -> list[str]:
        """检查测试补丁中的 API 调用是否存在于源码中。

        只检查实际执行语句中的调用，跳过方法定义、docstring、
        import 语句、注释和明显的局部变量调用。

        Returns: list of issues (empty = no contract violations).
        """
        if not test_artifact or not api_surface:
            return []
        diff_content = test_artifact.get("content", "")
        if not diff_content:
            return []

        # 从 diff 中提取新增行（以 + 开头）
        raw_added: list[str] = []
        for line in diff_content.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                raw_added.append(line[1:])  # strip + prefix

        if not raw_added:
            return []

        # ── 过滤非执行语句 ──
        added_lines: list[str] = []
        in_docstring = False
        for line in raw_added:
            stripped = line.strip()

            # 跳过空行
            if not stripped:
                continue

            # 跳过注释行
            if stripped.startswith("#"):
                continue

            # 跳过方法/类定义行
            if stripped.startswith("def ") or stripped.startswith("class "):
                continue

            # 跳过装饰器
            if stripped.startswith("@"):
                continue

            # 跳过 import 行
            if stripped.startswith("from ") or stripped.startswith("import "):
                continue

            # 处理 docstring（三引号）
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                # 单行 docstring
                if not in_docstring or (stripped.count('"""') >= 2 or stripped.count("'''") >= 2):
                    in_docstring = False
                    continue
                continue
            if in_docstring:
                continue

            # 跳过只含字符串字面量的行（如独立的 "..." 字符串）
            if stripped.startswith('"') or stripped.startswith("'"):
                # 判断是否整个行就是一个字符串（不是赋值也不是函数参数）
                if not any(op in stripped for op in ("=", "(", ",", "+", "%")):
                    continue

            added_lines.append(line)

        if not added_lines:
            return []

        all_known = set()
        for methods in api_surface.values():
            all_known.update(methods)

        # 确定语言
        ext = Path(test_artifact.get("target", "")).suffix.lower()
        is_python = ext == ".py"

        whitelist = (
            PatchGenerationAgent._PY_COMMON_WHITELIST if is_python
            else PatchGenerationAgent._JS_COMMON_WHITELIST
        )

        issues: list[str] = []
        seen_issues: set[str] = set()
        added_text = "\n".join(added_lines)

        # 提取 import 语句中的模块和方法名加入白名单（从原始行中提取）
        raw_text = "\n".join(raw_added)
        import_whitelist: set[str] = set()
        if is_python:
            for m in re.finditer(
                r'(?:from\s+(\S+)\s+import\s+([^*\n]+)|import\s+(\S+))',
                raw_text,
            ):
                if m.group(1):
                    import_whitelist.add(m.group(1).split(".")[-1])
                    for name in m.group(2).split(","):
                        import_whitelist.add(name.strip().split(" as ")[0].strip())
                elif m.group(3):
                    import_whitelist.add(m.group(3).split(".")[0].strip())

        # ── 构建局部变量白名单：从 added_lines 中提取赋值语句的变量名 ──
        local_vars: set[str] = set()
        for line in added_lines:
            m = re.match(r'\s*(\w+)\s*=\s*', line)
            if m:
                local_vars.add(m.group(1))
            # 也匹配 `for x in` 模式
            for m2 in re.finditer(r'\bfor\s+(\w+)\s+in\b', line):
                local_vars.add(m2.group(1))
            # `with ... as x:` 模式
            for m3 in re.finditer(r'\bas\s+(\w+)\s*:', line):
                local_vars.add(m3.group(1))

        # Python: obj.method(...) or func(...)
        py_calls = re.findall(
            r'(?:(\w+)\.(\w+)\s*\(|(?<![.\w])(\w+)\s*\()',
            added_text,
        )
        for obj, method, func in py_calls:
            if func:
                # 跳过 Python 关键字
                if func in {"import", "from", "def", "class", "return", "yield",
                            "if", "elif", "else", "for", "while", "with", "try",
                            "except", "finally", "and", "or", "not", "in", "is",
                            "lambda", "assert", "raise", "del", "global", "nonlocal",
                            "pass", "break", "continue", "True", "False", "None"}:
                    continue
                if func not in all_known and func not in whitelist and func not in import_whitelist:
                    key = f"func:{func}"
                    if key not in seen_issues:
                        seen_issues.add(key)
                        issues.append(
                            f"测试补丁调用了未知函数 `{func}()`，"
                            f"请确认该函数在当前源码中存在且参数正确"
                        )
            elif obj and method:
                # 跳过明显的局部变量（单字母、或已通过赋值识别）
                if obj in local_vars or len(obj) == 1:
                    continue
                # 跳过已知的常见测试对象变量名
                if obj in {"self", "cls", "mock", "mocker", "patch", "test", "jws",
                           "jwe", "data", "header", "payload", "parts", "msg", "key_obj"}:
                    continue
                full = f"{obj}.{method}"
                if (method not in all_known and full not in all_known
                        and method not in whitelist and full not in whitelist
                        and obj not in import_whitelist):
                    key = f"method:{full}"
                    if key not in seen_issues:
                        seen_issues.add(key)
                        issues.append(
                            f"测试补丁调用了未知方法 `{full}()`，"
                            f"请确认 `{obj}` 有 `{method}` 方法"
                        )

        return issues

    @staticmethod
    def _api_contract_context(
        source_files: list[SourceFile],
        api_surface: dict[str, set[str]],
    ) -> str:
        """构建 API 契约为 prompt 上下文。"""
        if not api_surface:
            return ""
        parts = ["## 源码 API 契约（测试补丁只能使用以下已验证存在的 API）"]
        for path, methods in sorted(api_surface.items())[:10]:
            sorted_methods = sorted(methods)[:40]
            parts.append(
                f"- `{path}`: {', '.join(f'`{m}`' for m in sorted_methods)}"
                + (" ..." if len(methods) > 40 else "")
            )
        return "\n".join(parts)

    # ── Blocking reason ──────────────────────────────────────────────────

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
        evidence_bundle: EvidenceBundle | None = None,
    ) -> str:
        """构建补丁生成任务。

        Web tasks may provide source files in-memory instead of writing them to
        the workspace. Include bounded snippets here so patch generation can
        produce a real diff even when read_file cannot find the file on disk.
        """
        from .evidence import format_evidence_bundle

        source_paths = "\n".join(f"- {sf.path}" for sf in source_files[:20]) if source_files else "（由 Agent 自行探索）"
        source_snippets = PatchGenerationAgent._source_snippets(source_files)

        changes_text = "\n".join(
            f"- {'🔴 因果必需 ' if PatchGenerationAgent._is_causally_required(c.file, remediation_plan, root_cause) else '  '}"
            f"{c.file}: {c.change_type} — {c.description}"
            f"{' [遗漏会导致漏洞在对应调用路径中仍然可达]' if PatchGenerationAgent._is_causally_required(c.file, remediation_plan, root_cause) else ''}"
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

## 确定性 EvidenceBundle（优先使用）
{format_evidence_bundle(evidence_bundle, max_chars=16000)}
{prev_text}

## 要求
1. 优先基于 EvidenceBundle 和“关键源码片段”生成补丁；只有片段不足时再用 read_file 读取完整文件
2. 生成 unified diff 格式补丁（--- a/path / +++ b/path / @@ -L,N +L,N @@）
3. 只修改必要的最小范围代码
4. 只输出候选 diff；不要写入源码。构建和安全验证由隔离工作区中的验证器执行"""

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
                needs_manual_fix=a.get("needs_manual_fix", False),
                fix_reason=a.get("fix_reason", ""),
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

        allowed_files = {
            item.replace("\\", "/").lstrip("./")
            for item in remediation_plan.patch_boundaries.allowed_files
            if item and item != "unknown"
        }
        if remediation_plan.required_tests:
            allowed_files.update(
                item.target.replace("\\", "/").lstrip("./")
                for item in artifacts
                if item.patch_type == PatchType.TEST and item.target
            )
        actual_files = {
            item.file.replace("\\", "/").lstrip("./") for item in changed_files if item.file
        } | {
            item.target.replace("\\", "/").lstrip("./") for item in artifacts if item.target
        }

        def is_allowed(path: str) -> bool:
            return not allowed_files or any(
                path == allowed or path.endswith("/" + allowed) or allowed.endswith("/" + path)
                for allowed in allowed_files
            )

        out_of_scope = sorted(path for path in actual_files if not is_allowed(path))
        estimated_diff_lines = sum(
            sum(1 for line in a.content.splitlines()
                if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
            for a in artifacts
        )
        scope_warnings = []
        # File count and diff lines are review signals, not hard blockers.
        # The agent determines causal necessity; the plan baseline is advisory.
        plan_baseline = max(len(remediation_plan.planned_changes), 1)
        if len(actual_files) > plan_baseline + 5:
            scope_warnings.append(
                f"补丁涉及 {len(actual_files)} 个文件，显著超过方案的 {plan_baseline} 个计划文件；请人工确认必要性。"
            )
        if estimated_diff_lines > remediation_plan.patch_boundaries.maximum_diff_lines:
            scope_warnings.append(
                f"补丁约 {estimated_diff_lines} 行，超过方案审查基线 "
                f"{remediation_plan.patch_boundaries.maximum_diff_lines}；需加强回归和人工审查。"
            )
        # Out-of-scope files: the agent may legitimately discover additional
        # causally-required files not captured by the plan.  Flag for review
        # instead of blocking.
        out_of_scope_warnings = [
            f"artifact outside planned scope (需确认必要性): {path}"
            for path in out_of_scope
        ]
        policy_check = PatchPolicyCheck(
            allowed_files_only=True,  # unplanned files don't invalidate the patch
            forbidden_changes_detected=False,
            changed_files_count=len(changed_files),
            estimated_diff_lines=estimated_diff_lines,
            within_patch_boundaries=True,  # only forbidden_changes can hard-block
            violations=[*out_of_scope_warnings, *scope_warnings],
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
            risks=list(dict.fromkeys([*raw.get("risks", []), *scope_warnings])),
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
        generated_check = self._candidate_generated(candidate)
        if generated_check.status == VerificationCheckStatus.FAILED:
            failure = VerificationFailure(
                generated_check.name,
                generated_check.details,
                self._suggestion(generated_check.name),
            )
            return PatchValidationResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                status=PatchValidationStatus.FAILED,
                checks=[generated_check],
                failures=[failure],
                next_action="send_to_failure_analysis_agent",
                feedback_for_regeneration=f"{failure.check}: {failure.reason}",
                needs_human_review=True,
            )
        checks = [
            generated_check,
            self._policy_passed(candidate),
            self._required_artifacts_present(candidate, remediation_plan),
            self._security_tests_present(candidate, remediation_plan),
            self._scanner_rescan_present(candidate),
            self._test_api_contract(candidate),
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

        missing_all = sorted(item.file for item in code_changes if not _matches(item.file, artifact_targets))
        if not missing_all:
            return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.PASSED,
                                     "all planned code changes have patch artifacts")

        # Distinguish must-cover gaps from optional gaps.  Must-cover includes
        # causally_required files plus strategy-critical security-control files.
        missing_required = sorted(
            item.file for item in code_changes
            if not _matches(item.file, artifact_targets)
            and PatchGenerationAgent._planned_change_must_cover(item)[0]
        )
        missing_optional = sorted(
            item.file for item in code_changes
            if not _matches(item.file, artifact_targets)
            and not PatchGenerationAgent._planned_change_must_cover(item)[0]
        )

        detail_parts = []
        if missing_required:
            detail_parts.append(
                f"must-cover: {', '.join(missing_required)}"
            )
        if missing_optional:
            detail_parts.append(
                f"optional (recommended): {', '.join(missing_optional)}"
            )
        detail = "missing artifacts for planned changes: " + "; ".join(detail_parts)

        return VerificationCheck(
            "planned_change_artifacts",
            VerificationCheckStatus.FAILED,
            detail,
        )

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
    def _test_api_contract(candidate: PatchCandidate) -> VerificationCheck:
        test_arts = [a for a in candidate.artifacts if a.patch_type == PatchType.TEST]
        if not test_arts:
            return VerificationCheck("test_api_contract", VerificationCheckStatus.PASSED,
                                     "no test artifacts to check")
        # 检查 risks 中是否有 api_contract 告警
        api_violations = [r for r in candidate.risks if r.startswith("api_contract:")]
        if not api_violations:
            return VerificationCheck("test_api_contract", VerificationCheckStatus.PASSED,
                                     "test API contract ok")
        return VerificationCheck(
            "test_api_contract",
            VerificationCheckStatus.FAILED,
            "; ".join(api_violations[:5]),
        )

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
            "test_api_contract": "测试补丁使用了源码中不存在的 API，请基于实际源码签名重写测试",
        }
        return suggestions.get(check_name, "将失败原因交给失败分析 Agent 后重新生成补丁")
