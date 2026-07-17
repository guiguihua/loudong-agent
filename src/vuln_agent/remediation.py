"""RemediationPlanAgent — 制定修复方案。

继承 BaseAgent，拥有 read_file / search_code / list_dir 工具，
能自己探索项目结构，选择最优修复策略（代码修改/依赖升级/配置变更）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .reasoning import (
    PipelineMode,
    ReasoningMode,
    StageExecution,
    normalize_pipeline_mode,
    stage_policy,
)
from .models import (
    CompatibilityAssessment,
    DependencyUpgradePlan,
    EngineeringContext,
    EvidenceBundle,
    FailureAnalysisResult,
    ImpactAssessment,
    NormalizedVulnerability,
    PatchBoundaries,
    PlannedChange,
    RejectedAlternative,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationStrategy,
    RemediationStrategyType,
    RollbackPlan,
    RootCauseAssessment,
    Severity,
    SourceFile,
    TestPlanItem,
)

if TYPE_CHECKING:
    from .llm import LLMBackend

REMEDIATION_AGENT_PROMPT = """你是一位资深安全修复工程师，负责为漏洞设计最优修复方案。

## 你的任务
根据根因分析和影响面评估，制定修复方案：
1. 选择修复策略（code_change / dependency_upgrade / configuration_change）
2. 列出计划变更的文件和原因
3. 评估风险和兼容性
4. 定义必需的回归测试
5. 制定回滚方案

## 可用工具
- read_file: 读取源码或配置文件
- search_code: 搜索相关代码模式
- list_dir: 了解项目结构（构建文件、测试目录等）

## 工作方式
1. 了解项目的构建系统和测试框架
2. 评估不同修复策略的优劣
3. 选择最优策略并给出具体步骤
4. 考虑向后兼容性和回滚

## 修复范围原则（必须遵守）
- 目标是“因果完整且尽可能小”，不是追求固定文件数。修复必须覆盖恢复安全不变量所需的全部代码、配置、依赖声明和回归测试。
- planned_changes 中的每个文件都必须说明它与已确认根因、受影响调用路径、兼容性要求或必要验证之间的直接关系。
- 不得仅因为文件较多或 diff 较大而截断必要修复；多模块、共享底层组件、生成代码、配置与锁文件联动等场景可以合理修改多个文件。
- 仅属一般性加固、日志、清理或无关架构优化的内容，通常放入 rejected_alternatives 或后续建议；如果它是恢复安全不变量不可缺少的一部分，可以进入候选补丁，但必须给出源码证据和不可替代性说明。
- 修复决策只能依据当前漏洞报告、当前源码、配置、依赖和测试证据；不得依赖尚不存在的上游/官方补丁，也不得照搬外部参考实现。
- 如果评测数据中附带官方修复或参考答案，它们只允许在流水线完成后的离线评分阶段使用，不能进入修复规划或补丁生成上下文。
- 文件数和 diff 行数只用于风险分级和人工审查提示，不作为自动截断或拒绝修复的硬阈值。
- 不得把”可能更安全”当成扩大范围的充分理由；每项变更都要有可追溯证据，同时保证补丁可审查、可回滚、可验证。
- causally_required: 根因 source→sink 因果链直接命中的文件必须标记 causally_required=true。这些文件是漏洞可达路径上的硬约束——遗漏任何一个都会导致漏洞在对应调用路径中仍然可达。非因果链上的辅助文件（如测试、日志、格式调整）标记为 false。标记为 true 的文件如果最终补丁未覆盖，会被 validation 直接拒绝。
- forbidden_changes（patch_boundaries 中的禁止变更清单）必须是具体的、可验证的约束，而非泛泛的"不要破坏安全"。违反 forbidden_changes 的补丁会在 validation 被拒绝。禁止变更应聚焦"修复层级"而非"不要引入 bug"：
  - 禁止绕过或删除现有安全检查
  - 禁止修改既有测试预期来掩盖回归
  - 禁止改动与根因、兼容性或必要验证无关的文件
  - 禁止扩大公共 API 或权限边界，除非有明确源码证据和回归验证

确认分析完成后，调用 submit_final_result 工具提交最终结果。"""


class RemediationPlanAgent(BaseAgent):
    """制定修复方案 — 自主选择最优策略。"""

    def __init__(
        self,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
        prefer_static: bool = False,
        max_turns: int | None = None,
        pipeline_mode: str | PipelineMode = PipelineMode.BALANCED,
    ):
        ws = workspace or Path.cwd()
        self.pipeline_mode = normalize_pipeline_mode(pipeline_mode)
        self.policy = stage_policy("remediation", self.pipeline_mode)
        super().__init__(
            name="RemediationPlan",
            system_prompt=REMEDIATION_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=max_turns or self.policy.max_turns,
            workspace=ws,
            reasoning_mode=self.policy.deep_path.value,
            tool_budget=dict(self.policy.tool_budget),
            no_progress_limit=self.policy.no_progress_limit,
            max_output_tokens=self.policy.max_output_tokens,
        )
        self.prefer_static = prefer_static
        self.last_execution = StageExecution(
            "remediation", self.pipeline_mode.value, self.policy.fast_path.value
        )

    def plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext | None = None,
        failure_analysis: FailureAnalysisResult | None = None,
        evidence_bundle: EvidenceBundle | None = None,
        source_files: list[SourceFile] | None = None,
    ) -> RemediationPlan:
        """运行 Remediation Plan Agent。"""
        from .llm import REMEDIATION_PLAN_SCHEMA
        self.output_schema = REMEDIATION_PLAN_SCHEMA

        engineering = engineering or EngineeringContext()
        if self.prefer_static:
            static_plan = self._static_plan(finding, impact, root_cause, engineering, failure_analysis)
            if static_plan is not None:
                self.last_execution = StageExecution(
                    "remediation", self.pipeline_mode.value, ReasoningMode.PLAN_SELECT.value,
                    details={"planner": "deterministic_template"},
                )
                return self._reconcile_plan_paths(
                    static_plan, finding, root_cause, evidence_bundle, source_files
                )

        task = self._build_task(
            finding, impact, root_cause, engineering, failure_analysis, evidence_bundle
        )
        context_gaps = self._context_gaps(
            root_cause, engineering, evidence_bundle, failure_analysis
        )
        use_bounded_react = (
            self.policy.allow_escalation
            and bool(context_gaps)
            and not self._gaps_are_unresolvable_by_search(context_gaps)
        )
        if use_bounded_react:
            try:
                raw = self.run(
                    task + self._ranking_instructions(),
                    context={
                        "reasoning_mode": "bounded_react_then_plan_and_solve",
                        "context_gaps": context_gaps,
                        "tool_budget": self.policy.tool_budget,
                        "stop_condition": "gaps resolved or tool budget exhausted; then rank and select a plan",
                    },
                )
            except Exception as exc:
                fallback = self._static_plan(
                    finding, impact, root_cause, engineering, failure_analysis
                )
                if fallback is None:
                    raise
                # Discard generic target expansion.  Path reconciliation will
                # rebuild the minimum executable change set from the confirmed
                # primary root-cause file.
                fallback.planned_changes = []
                fallback.patch_boundaries.allowed_files = []
                fallback.unknowns = list(dict.fromkeys([
                    *fallback.unknowns,
                    f"LLM remediation finalization failed; deterministic root-cause plan used: {exc}",
                ]))
                fallback.assumptions = list(dict.fromkeys([
                    *fallback.assumptions,
                    "deterministic_root_cause_plan_after_bounded_reasoning_failure",
                ]))
                fallback.needs_human_review = True
                self.last_execution = StageExecution(
                    "remediation", self.pipeline_mode.value, ReasoningMode.BOUNDED_REACT.value,
                    escalated=True,
                    escalation_reasons=context_gaps,
                    llm_calls=int(self.last_run_stats.get("llm_calls", 0)),
                    tool_calls=dict(self.last_run_stats.get("tool_calls", {})),
                    stopped_reason=self.last_run_stats.get("stopped_reason") or "structured_finalization_failed",
                    details={
                        "final_decision": "deterministic_root_cause_plan",
                        "fallback_reason": str(exc),
                    },
                )
                return self._reconcile_plan_paths(
                    fallback, finding, root_cause, evidence_bundle, source_files
                )
            self.last_execution = StageExecution(
                "remediation", self.pipeline_mode.value, ReasoningMode.BOUNDED_REACT.value,
                escalated=True,
                escalation_reasons=context_gaps,
                llm_calls=int(self.last_run_stats.get("llm_calls", 0)),
                tool_calls=dict(self.last_run_stats.get("tool_calls", {})),
                stopped_reason=self.last_run_stats.get("stopped_reason"),
                details={"final_decision": "plan_and_solve_with_candidate_ranking"},
            )
        else:
            raw = self._plan_select_single_shot(task)
            self.last_execution = StageExecution(
                "remediation", self.pipeline_mode.value, ReasoningMode.PLAN_SELECT.value,
                escalation_reasons=context_gaps,
                llm_calls=1,
                details={
                    "final_decision": "generate_rank_select",
                    "candidate_rankings": raw.get("candidate_rankings", []) if isinstance(raw, dict) else [],
                },
            )

        if "_raw_output" in raw:
            # Use LLM re-extraction (was dead code, now wired in).
            extracted = self._extract_plan_from_raw(raw["_raw_output"], finding, root_cause)
            plan = self._dict_to_plan(
                finding, impact, root_cause, engineering, extracted, failure_analysis
            )
            return self._reconcile_plan_paths(
                plan, finding, root_cause, evidence_bundle, source_files
            )
        plan = self._dict_to_plan(finding, impact, root_cause, engineering, raw, failure_analysis)
        rankings = raw.get("candidate_rankings", []) if isinstance(raw, dict) else []
        if not 2 <= len(rankings) <= 3:
            plan.needs_human_review = True
            plan.unknowns.append("candidate ranking incomplete: expected 2-3 remediation strategies")
            plan.unknowns = list(dict.fromkeys(plan.unknowns))
        return self._reconcile_plan_paths(
            plan, finding, root_cause, evidence_bundle, source_files
        )

    @staticmethod
    def _reconcile_plan_paths(
        plan: RemediationPlan,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        evidence_bundle: EvidenceBundle | None,
        source_files: list[SourceFile] | None,
    ) -> RemediationPlan:
        """Resolve planned changes to real repository files before patching.

        LLM plans may contain prose such as ``config.py (or equivalent)`` or
        combine several alternatives in a single ``file`` field.  Such values
        are not patch targets.  Resolve exact/suffix matches against the files
        loaded for this run and, when every proposed path is invalid, recover a
        minimal plan from the confirmed root-cause source/sink evidence.
        """
        known_paths = RemediationPlanAgent._known_repository_paths(
            evidence_bundle, source_files
        )
        if not known_paths:
            # Human-reference patches must only target files confirmed in the
            # supplied repository inventory.
            plan.status = RemediationPlanStatus.NEEDS_CONTEXT
            plan.unknowns = list(dict.fromkeys([
                *plan.unknowns,
                "repository path inventory is unavailable; candidate patch generation is unsafe",
            ]))
            plan.needs_human_review = True
            plan.patch_boundaries.allowed_files = []
            return plan

        valid_changes: list[PlannedChange] = []
        invalid_paths: list[str] = []
        seen: set[str] = set()
        for change in plan.planned_changes:
            if RemediationPlanAgent._is_descriptive_path(change.file):
                invalid_paths.append(change.file)
                continue
            resolved = RemediationPlanAgent._resolve_repository_path(change.file, known_paths)
            if resolved is None:
                invalid_paths.append(change.file)
                continue
            # A source repository must be fixed in source.  Do not turn a
            # report's "upgrade to fixed release" recommendation into a
            # self-dependency edit unless this finding is actually SCA data.
            if (
                change.change_type == "dependency"
                and finding.dependency is None
                and root_cause.root_cause_category.value != "vulnerable_dependency"
            ):
                invalid_paths.append(change.file)
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            valid_changes.append(PlannedChange(
                file=resolved,
                change_type=change.change_type,
                description=change.description,
                reason=change.reason,
                risk_level=change.risk_level,
            ))

        if not valid_changes:
            for path in RemediationPlanAgent._root_cause_change_paths(
                finding, root_cause, evidence_bundle, known_paths
            ):
                if path in seen:
                    continue
                seen.add(path)
                valid_changes.append(PlannedChange(
                    file=path,
                    change_type="code",
                    description="在已确认的根因位置恢复缺失的安全控制。",
                    reason=(
                        root_cause.root_cause.missing_control
                        or root_cause.security_invariant
                        or root_cause.root_cause.summary
                    ),
                    risk_level=Severity.MEDIUM,
                ))

        if not valid_changes:
            plan.status = RemediationPlanStatus.NEEDS_CONTEXT
            plan.needs_human_review = True
            plan.unknowns = list(dict.fromkeys([
                *plan.unknowns,
                "no planned change resolves to a confirmed repository file",
            ]))
            plan.patch_boundaries.allowed_files = []
            return plan

        if invalid_paths:
            for path in invalid_paths:
                plan.rejected_alternatives.append(RejectedAlternative(
                    alternative=f"修改未解析路径 {path}",
                    reason="该值不是当前仓库中唯一存在的文件，不能作为候选补丁目标。",
                ))
            plan.assumptions = list(dict.fromkeys([
                *plan.assumptions,
                "planned_change_paths_reconciled_with_repository_inventory",
            ]))
            plan.risk_points = list(dict.fromkeys([
                *plan.risk_points,
                "LLM 提出的描述性或不存在路径已被确定性路径门禁移出候选补丁。",
            ]))
            plan.needs_human_review = True

        plan.planned_changes = valid_changes
        plan.patch_boundaries.allowed_files = [change.file for change in valid_changes]
        plan.patch_boundaries.maximum_changed_files = max(
            len(valid_changes), plan.patch_boundaries.maximum_changed_files
        )

        # ── 根因覆盖检查：确保 planned_changes 覆盖所有 causally-related 文件 ──
        from .root_cause import RootCauseAnalysisAgent
        causal_files = RootCauseAnalysisAgent.get_causal_files(root_cause)
        planned_files = {c.file.replace("\\", "/").lstrip("./") for c in valid_changes}
        uncovered = [
            f for f in causal_files
            if f not in planned_files
            and not any(f.endswith("/" + pf) or pf.endswith("/" + f) for pf in planned_files)
        ]
        if uncovered:
            # 尝试从 known_paths 中解析未覆盖文件
            for uf in uncovered:
                resolved = RemediationPlanAgent._resolve_repository_path(uf, known_paths)
                if resolved and resolved not in seen:
                    seen.add(resolved)
                    valid_changes.append(PlannedChange(
                        file=resolved,
                        change_type="code",
                        description=f"根因因果链涉及的文件: {uf}",
                        reason=(
                            f"该文件在 source→sink→affected_code 链中，"
                            f"修复根因 '{root_cause.root_cause.summary[:80]}' 可能需要修改此文件"
                        ),
                        risk_level=Severity.MEDIUM,
                    ))
            # 仍未覆盖的作为风险点
            still_uncovered = [
                f for f in uncovered
                if not any(
                    f.replace("\\", "/").lstrip("./") == c.file.replace("\\", "/").lstrip("./")
                    for c in valid_changes
                )
            ]
            if still_uncovered:
                plan.risk_points = list(dict.fromkeys([
                    *plan.risk_points,
                    f"根因覆盖缺口: {len(still_uncovered)} 个因果链文件不在修复计划中: "
                    f"{', '.join(still_uncovered[:5])}",
                ]))
                plan.needs_human_review = True

        # Rebuild allowed_files after coverage expansion
        plan.planned_changes = valid_changes
        plan.patch_boundaries.allowed_files = [change.file for change in valid_changes]
        plan.patch_boundaries.maximum_changed_files = max(
            len(valid_changes), plan.patch_boundaries.maximum_changed_files
        )

        if not any(
            "security" in item.test_type.lower() or "安全" in item.test_type
            for item in plan.required_tests
        ):
            plan.required_tests.append(TestPlanItem(
                name=f"{finding.finding_id} exploit regression",
                test_type="security_regression",
                target=valid_changes[0].file,
                assertion=(
                    "the reported exploit condition is rejected at the confirmed trust boundary, "
                    "while the corresponding legitimate operation remains supported"
                ),
            ))
            plan.risk_points = list(dict.fromkeys([
                *plan.risk_points,
                "The LLM omitted a security regression test; a mandatory exploit/legitimate-behavior test was added.",
            ]))
            plan.needs_human_review = True
        if not any("business" in item.test_type.lower() for item in plan.required_tests):
            plan.required_tests.append(TestPlanItem(
                name=f"{finding.finding_id} compatibility regression",
                test_type="business_regression",
                target=valid_changes[0].file,
                assertion="existing public API defaults and legitimate inputs preserve their previous behavior",
            ))
        if root_cause.confidence_score < 0.7:
            plan.risk_points = list(dict.fromkeys([
                *plan.risk_points,
                "Root-cause confidence is below 0.70; patch placement requires explicit human review.",
            ]))
            plan.needs_human_review = True
        # 低置信度(<0.45)时扩大范围，不要压窄
        if root_cause.confidence_score < 0.45:
            plan.risk_points = list(dict.fromkeys([
                *plan.risk_points,
                "根因置信度 < 0.45: source/sink 未确认，修复范围已自动扩大。"
                "需要人工确认实际修复目标文件。",
            ]))
            plan.needs_human_review = True

        # ── 符号存在性验证（修复方案引用的 API/异常必须真实存在）──
        if source_files and hasattr(plan, 'planned_changes') and plan.planned_changes:
            symbol_issues = RemediationPlanAgent._verify_plan_symbols_exist(
                plan, source_files,
            )
            if symbol_issues:
                plan.risk_points = list(dict.fromkeys([
                    *plan.risk_points,
                    *symbol_issues,
                ]))
                plan.needs_human_review = True

        plan.status = RemediationPlanStatus.READY
        return plan

    @staticmethod
    def _verify_plan_symbols_exist(
        plan: RemediationPlan,
        source_files: list[SourceFile],
    ) -> list[str]:
        """Check that API symbols mentioned in planned changes exist in source.

        Scans ``description`` and ``reason`` fields of every PlannedChange
        for CamelCase identifiers that look like exception / class names.
        Each candidate is checked against a combined symbol index built
        from all source files.  Stdlib exception names are whitelisted.

        Returns:
            List of human-readable issue strings (empty = all referenced
            symbols verified, or no symbols could be extracted).
        """
        import re as _re

        # Build combined symbol index from source files
        all_symbols: set[str] = set()
        try:
            from .patching import PatchGenerationAgent
            exports = PatchGenerationAgent._extract_source_exports(source_files)
            for symbols in exports.values():
                all_symbols.update(symbols)
        except Exception:
            return []  # If symbol extraction fails, don't block the plan

        if not all_symbols:
            return []

        # Collect symbol-like tokens from planned changes
        mentioned: set[str] = set()
        for change in plan.planned_changes:
            for field in (change.description, change.reason):
                if not field:
                    continue
                # Match CamelCase exception/error class names only
                for m in _re.finditer(
                    r'\b([A-Z][a-zA-Z0-9]*(?:Error|Exception|Warning))\b',
                    str(field),
                ):
                    mentioned.add(m.group(1))

        if not mentioned:
            return []

        # Python stdlib exception/error/warning classes
        _STDLIB_ERRORS: set[str] = {
            "ValueError", "TypeError", "KeyError", "IndexError", "AttributeError",
            "RuntimeError", "OSError", "IOError", "ImportError", "StopIteration",
            "NotImplementedError", "MemoryError", "SystemError", "ReferenceError",
            "OverflowError", "ZeroDivisionError", "AssertionError", "EOFError",
            "FloatingPointError", "GeneratorExit", "KeyboardInterrupt", "SystemExit",
            "UnboundLocalError", "UnicodeError", "UnicodeDecodeError",
            "UnicodeEncodeError", "UnicodeTranslateError", "Warning",
            "DeprecationWarning", "PendingDeprecationWarning", "FutureWarning",
            "ImportWarning", "ResourceWarning", "BytesWarning", "Exception",
            "BaseException", "ArithmeticError", "BufferError", "LookupError",
            "PermissionError", "FileNotFoundError", "NotADirectoryError",
            "ConnectionError", "TimeoutError", "BlockingIOError",
            "FileExistsError", "IsADirectoryError", "ChildProcessError",
            "InterruptedError", "ProcessLookupError", "BrokenPipeError",
            "ConnectionAbortedError", "ConnectionRefusedError", "ConnectionResetError",
            "ModuleNotFoundError", "RecursionError", "StopAsyncIteration",
            "TabError", "IndentationError", "SyntaxError", "NameError",
            "UnicodeWarning", "BytesWarning", "SyntaxWarning", "RuntimeWarning",
            "UserWarning", "EncodingWarning",
        }

        issues: list[str] = []
        for sym in sorted(mentioned):
            if sym in _STDLIB_ERRORS:
                continue
            if sym in all_symbols:
                continue
            issues.append(
                f"修复方案引用了未在源码中找到的异常/类 '{sym}'。"
                f"请确认该符号在源码中存在，或改用标准库中已有的异常类型。"
            )

        return issues

    @staticmethod
    def _known_repository_paths(
        evidence_bundle: EvidenceBundle | None,
        source_files: list[SourceFile] | None,
    ) -> list[str]:
        paths = [item.path for item in (source_files or []) if item.path]
        if evidence_bundle:
            paths.extend(item.path for item in evidence_bundle.target_files if item.path)
            paths.extend(item.path for item in evidence_bundle.code_slices if item.path)
            paths.extend(item.path for item in evidence_bundle.source_candidates if item.path)
            paths.extend(item.path for item in evidence_bundle.sink_candidates if item.path)
            paths.extend(item.path for item in evidence_bundle.test_evidence if item.path)
            paths.extend(item.path for item in evidence_bundle.config_evidence if item.path)
            paths.extend(item.path for item in evidence_bundle.dependency_evidence if item.path)
        return list(dict.fromkeys(
            path.replace("\\", "/").lstrip("./") for path in paths if path
        ))

    @staticmethod
    def _is_descriptive_path(path: str) -> bool:
        value = (path or "").strip().lower()
        if not value or value == "unknown":
            return True
        markers = (
            " / ", " 或 ", " or ", "—", "(if ", "if using",
            "equivalent", "all modules", "documentation /", "*", "...",
        )
        return any(marker in value for marker in markers)

    @staticmethod
    def _resolve_repository_path(path: str, known_paths: list[str]) -> str | None:
        requested = path.replace("\\", "/").strip().lstrip("./")
        exact = [item for item in known_paths if item == requested]
        if len(exact) == 1:
            return exact[0]
        suffix = [
            item for item in known_paths
            if item.endswith("/" + requested) or requested.endswith("/" + item)
        ]
        return suffix[0] if len(suffix) == 1 else None

    @staticmethod
    def _root_cause_change_paths(
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        evidence_bundle: EvidenceBundle | None,
        known_paths: list[str],
    ) -> list[str]:
        rc = root_cause.root_cause
        primary_markers = ("root", "primary", "核心", "根因", "缺陷", "control", "guard")
        primary_candidates = [
            item.file for item in root_cause.affected_code
            if any(marker in (item.role or "").lower() for marker in primary_markers)
        ]
        mechanism_candidates: list[str] = []
        if rc.sink and rc.sink.file:
            mechanism_candidates.append(rc.sink.file)
        if rc.source and rc.source.file:
            mechanism_candidates.append(rc.source.file)
        reported_candidates: list[str] = []
        if evidence_bundle:
            reported_candidates.extend(item.path for item in evidence_bundle.target_files)
        reported_candidates.extend(location.file for location in finding.locations if location.file)

        # Prefer files explicitly labelled as the primary/root control point.
        # Only fall back to source/sink or report locations when no such file
        # resolves, which avoids turning every affected caller into a patch.
        for candidates in (primary_candidates, mechanism_candidates, reported_candidates):
            resolved: list[str] = []
            for candidate in candidates:
                if RemediationPlanAgent._is_descriptive_path(candidate):
                    continue
                path = RemediationPlanAgent._resolve_repository_path(candidate, known_paths)
                if path and path not in resolved:
                    resolved.append(path)
            if resolved:
                return resolved
        return []

    def _plan_select_single_shot(self, task: str) -> dict:
        from .llm import REMEDIATION_PLAN_SCHEMA

        try:
            raw = self.llm.reason(  # type: ignore[union-attr]
                user_prompt=task + self._ranking_instructions(),
                system_prompt=(
                    "执行 Plan-and-Solve + Generate-Rank-Select。不要调用工具。"
                    "候选方案必须恢复已确认安全不变量，并根据证据选择首选方案。"
                ),
                output_schema=REMEDIATION_PLAN_SCHEMA,
                temperature=0.1,
                max_tokens=self.policy.max_output_tokens,
            )
            return RemediationPlanAgent._normalize_single_shot(raw)
        except Exception as exc:
            return {"_raw_output": f"single-shot remediation failed: {exc}"}

    @staticmethod
    def _normalize_single_shot(raw: dict | str) -> dict:
        """Handle _schema_missing: convert to _raw_output so the caller
        triggers fallback instead of accepting an incomplete plan."""
        if isinstance(raw, dict) and raw.pop("_schema_missing", None):
            partial = {k: v for k, v in raw.items() if not k.startswith("_")}
            raw["_raw_output"] = json.dumps(partial, ensure_ascii=False, indent=2)
            raw["_partial_structured"] = partial
            return raw
        return raw if isinstance(raw, dict) else {"_raw_output": str(raw)}

    @staticmethod
    def _ranking_instructions() -> str:
        return """

## Plan-and-Solve + Candidate Ranking
先生成 2-3 个候选修复策略，再按以下权重比较后选择首选方案：
- 完整切断漏洞因果链：35%
- 恢复安全不变量：25%
- 业务兼容性：15%
- 可验证性：15%
- 改动和回滚风险：10%
最终 planned_changes 只能来自首选方案。纵深防御、日志和无关架构改造放入 rejected_alternatives。

## 源码契约与补丁边界门禁
- 每个 planned_change 必须指出当前文件中真实存在的符号，以及它在因果链中的职责。
- 不得仅因漏洞报告建议某个参数/API 就假设源码支持它；必须核对真实签名、构造器传值和消费方。
- 新增参数、字段或类型元数据时，必须证明存在实际消费方，并把必要的生产者/消费者变更一起纳入方案；否则拒绝该方案。
- 不得把测试路由、示例应用或仓库别名当作生产服务文件。
- 优先在接受不安全值的最小信任边界修复，避免改变无关公共 API 默认行为。
- 高危代码漏洞必须同时规划：攻击载荷被拒绝的安全测试，以及合法输入保持兼容的正向测试。"""

    @staticmethod
    def _context_gaps(root_cause, engineering, evidence_bundle, failure_analysis) -> list[str]:
        gaps: list[str] = []
        if evidence_bundle is None or not evidence_bundle.target_files:
            gaps.append("target_file_context_missing")
        if evidence_bundle and not evidence_bundle.test_evidence and not engineering.available_test_commands:
            gaps.append("test_framework_or_test_target_missing")
        if root_cause.confidence_score < 0.5:
            gaps.append("root_cause_confidence_below_0.5")
        if root_cause.unknowns:
            gaps.append("root_cause_has_unknowns")
        if failure_analysis and failure_analysis.requires_root_cause_recheck:
            gaps.append("previous_failure_requires_source_recheck")
        return list(dict.fromkeys(gaps))

    @staticmethod
    def _gaps_are_unresolvable_by_search(gaps: list[str]) -> bool:
        """Returns True when Bounded ReAct tool exploration won't help close the gaps.

        ``target_file_context_missing`` means the EvidenceCollector could not
        match any reported file path to a source file that was actually
        supplied.  No amount of read_file / search_code / list_dir calls will
        conjure a file that isn't there.  The agent already receives the full
        source_files list and evidence bundle in its prompt — it should plan
        from what IS available rather than burn turns searching for what isn't.
        """
        if not gaps:
            return False
        # Gaps that tool exploration can actually resolve:
        actionable = {
            "test_framework_or_test_target_missing",
            "previous_failure_requires_source_recheck",
        }
        return not any(g in actionable for g in gaps)

    def _extract_plan_from_raw(
        self,
        raw_text: str,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
    ) -> dict:
        """从非结构化的修复方案文本中二次提取结构化字段。"""
        if not self.llm:
            return RemediationPlanAgent._fallback_plan_extraction(raw_text, finding, root_cause)

        from .llm import REMEDIATION_PLAN_SCHEMA

        extraction_prompt = f"""以下是一段修复方案的原始分析文本。请从中提取关键信息，填入指定 JSON 结构。

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 根因摘要: {root_cause.root_cause.summary[:500] if root_cause.root_cause.summary else '无'}

## 原始分析文本
{raw_text[:8000]}

## 要求
请仔细阅读上面的分析文本，尽量提取所有你能找到的结构化信息。
如果某个字段找不到对应信息，使用合理的默认值，不要编造。"""

        try:
            structured = self.llm.reason(
                user_prompt=extraction_prompt,
                system_prompt="你是一个结构化数据提取器。从安全修复分析文本中提取关键信息。只输出 JSON。",
                output_schema={
                    "type": "object",
                    "description": "从原始分析文本中提取的修复方案",
                    "properties": {
                        k: v for k, v in REMEDIATION_PLAN_SCHEMA.get("properties", {}).items()
                        if k not in ("reasoning",)
                    },
                    "required": ["status", "remediation_goal", "strategies", "planned_changes", "required_tests", "risk_points", "needs_human_review"],
                },
                temperature=0.1,
            )
            if isinstance(structured, dict) and structured.get("remediation_goal"):
                return structured
        except Exception:
            pass

        return RemediationPlanAgent._fallback_plan_extraction(raw_text, finding, root_cause)

    @staticmethod
    def _fallback_plan_extraction(
        raw_text: str,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
    ) -> dict:
        """Last-resort extraction when both JSON repair and LLM re-extraction failed.

        Attempts to find the largest valid/reparable JSON object first, then
        falls back to constructing minimal sensible defaults.
        """
        from .json_repair import extract_largest_json_object

        # Attempt to find and repair the largest JSON object in the text.
        obj = extract_largest_json_object(raw_text)
        if obj is not None and isinstance(obj, dict):
            # Ensure required fields exist.
            obj.setdefault("status", "ready")
            obj.setdefault("strategies", [{
                "strategy_type": "code_change",
                "summary": f"针对 {finding.vulnerability_type} 的最小化安全修复",
                "steps": ["读取受影响文件并定位漏洞触发路径", "在关键位置补全缺失的安全控制", "保持 API 与现有行为不变"],
                "preferred": True,
            }])
            obj.setdefault("planned_changes", [])
            obj.setdefault("required_tests", [])
            obj.setdefault("risk_points", ["修复方案从非结构化文本中提取，信息可能不完整", "需要人工审查确认修复精准度"])
            obj.setdefault("rejected_alternatives", [])
            obj.setdefault("assumptions", ["从非结构化 LLM 输出中尽力提取"])
            obj.setdefault("unknowns", ["修复方案的具体实施细节需要人工补充"])
            obj.setdefault("confidence_score", 0.3)
            obj.setdefault("needs_human_review", True)
            return obj

        # True last resort: minimal template.
        vuln_type = finding.vulnerability_type or "unknown vulnerability"
        return {
            "status": "ready",
            "remediation_goal": f"修复 {vuln_type} 漏洞，具体方案需人工审查确定。",
            "strategies": [{
                "strategy_type": "code_change",
                "summary": f"针对 {vuln_type} 的最小化安全修复",
                "steps": [
                    "读取受影响文件并定位漏洞触发路径",
                    "在关键位置补全缺失的安全控制",
                    "保持 API 与现有行为不变",
                ],
                "preferred": True,
            }],
            "planned_changes": [],
            "risk_points": [
                "修复方案从非结构化文本中提取，信息可能不完整",
                "需要人工审查确认修复精准度",
            ],
            "required_tests": [
                {
                    "name": f"{finding.finding_id} 安全回归",
                    "test_type": "security_regression",
                    "target": finding.finding_id,
                    "assertion": "漏洞利用条件在补丁后被阻断",
                },
            ],
            "rejected_alternatives": [],
            "assumptions": ["从非结构化 LLM 输出中尽力提取"],
            "unknowns": ["修复方案的具体实施细节需要人工补充"],
            "confidence_score": 0.3,
            "needs_human_review": True,
        }

    @staticmethod
    def _build_task(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
        failure_analysis: FailureAnalysisResult | None,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> str:
        from .evidence import format_evidence_bundle

        constraints = "\n".join(
            f"- {c}" for c in root_cause.recommended_fix_constraints
        ) if root_cause.recommended_fix_constraints else "无"

        fb = ""
        if failure_analysis:
            fb = (
                f"\n## 上次失败反馈\n"
                f"- 原因: {failure_analysis.summary}\n"
                f"- 建议: {'; '.join(failure_analysis.remediation_feedback)}\n"
            )

        # 判断根因分析是否稀疏（LLM 未产出结构化结果）
        rc = root_cause.root_cause
        sparse_root_cause = (
            not rc.summary
            or "static fallback" in (rc.summary or "").lower()
            or "could not fully confirm" in (rc.summary or "").lower()
            or not rc.missing_control
            or str(rc.missing_control).strip().lower() in ("missing_control", "missing_security_control", "missing control", "")
        )

        independence_note = ""
        if sparse_root_cause:
            independence_note = """
## ⚠️ 根因分析不完整 — 请独立分析
根因分析 Agent 未产出足够的结构化信息。**你必须自己读取相关源码文件**，
独立判断漏洞的触发路径和缺失的安全控制，然后再制定修复方案。
不要依赖上面不完整的根因信息——它可能只是占位符。"""

        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        evidence_lines = "\n".join(f"- {e}" for e in (finding.evidence or []) if e.strip()) or "无"

        return f"""为以下漏洞设计修复方案：

## 漏洞
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 受影响文件: {', '.join(locs) if locs else 'unknown'}
- 证据:
{evidence_lines}
- 报告建议（仅作风险提示，不能替代源码证据，也不能直接转成 planned_changes）: {finding.recommendation or '未提供'}
- 根因: {rc.summary or '（根因分析未产出有效结果）'}
- 缺失控制: {rc.missing_control or '（未识别）'}
- 根因分类: {root_cause.root_cause_category.value}
{independence_note}
## 修复约束
{constraints}

## 影响面
- 服务: {impact.affected_services}
- 入口: {[(e.route, e.method) for e in impact.entry_points]}
- 数据分类: {impact.data_classification}

## 工程上下文
- 语言: {engineering.language or 'unknown'}
- 框架: {engineering.framework or 'unknown'}
- 包管理器: {engineering.package_manager or 'unknown'}
- 测试命令: {engineering.available_test_commands or 'none'}

## 确定性 EvidenceBundle（优先使用）
{format_evidence_bundle(evidence_bundle, max_chars=16000)}
{fb}
优先依据 EvidenceBundle 中已确认的目标文件、代码切片、依赖和测试能力制定方案；只有关键修复证据缺失时才补充探索。选择最优修复策略并给出具体步骤。

planned_changes.file 必须是 EvidenceBundle/当前仓库中唯一存在的单个文件路径。禁止填写
`a.py / b.py`、`or equivalent`、`if using`、`all modules`、目录名或其他描述性占位符。
当前任务修复的是已加载仓库本身：除非 finding 明确是依赖漏洞，否则不得把“升级到后续版本”
当成修改当前源码仓库的方案，也不得虚构业务应用的 config、provider 或 route 文件。
制定方案前必须核对真实 API 契约：方法签名、构造器状态传递、调用顺序、异常和类型定义。
报告 recommendation 仅是待验证假设。新增参数/字段必须同时证明并覆盖真实消费方；无消费方的改动必须进入 rejected_alternatives。
至少规划一个漏洞负向测试和一个合法行为正向测试；不得以 compileall 代替行为验证。"""

    @staticmethod
    def _static_plan(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
        failure_analysis: FailureAnalysisResult | None,
    ) -> RemediationPlan | None:
        vuln_type = (finding.vulnerability_type or "").lower()
        cwe = (finding.cwe or "").lower()
        is_sqli = "sql injection" in vuln_type or "sqli" in vuln_type or cwe == "cwe-89"
        is_dependency = finding.dependency is not None or "depend" in vuln_type

        target_files = [item.file for item in root_cause.affected_code] or [loc.file for loc in finding.locations]
        if is_dependency and finding.dependency is not None:
            target_files = target_files or [finding.dependency.component]
        # 从 finding.locations 兜底，避免 "unknown" 占位符
        if not target_files or target_files == ["unknown"]:
            target_files = [loc.file for loc in finding.locations if loc.file]
        if not target_files:
            target_files = ["unknown"]
        # 去重保留顺序
        seen: set[str] = set()
        target_files = [f for f in target_files if f not in seen and not seen.add(f)]

        if is_sqli:
            goal = "Replace SQL string construction with parameterized queries while preserving existing query semantics."
            strategy = RemediationStrategy(
                strategy_type=RemediationStrategyType.CODE_CHANGE,
                summary="Use bound SQL parameters for every user-controlled value.",
                steps=[
                    "Locate the vulnerable SQL execution path.",
                    "Move user-controlled values into driver placeholders instead of SQL text.",
                    "Preserve existing filters, result shape, and error behavior.",
                    "Add or run a SQL injection regression check before merging.",
                ],
                preferred=True,
            )
            planned_changes = [
                PlannedChange(
                    file=target,
                    change_type="code",
                    description="Replace SQL concatenation/interpolation with parameterized query execution.",
                    reason=root_cause.root_cause.missing_control or "parameterized query is required",
                    risk_level=Severity.MEDIUM,
                )
                for target in target_files[:5]
            ]
            tests = [
                TestPlanItem(
                    name=f"{finding.finding_id} SQL injection regression",
                    test_type="security_regression",
                    target=finding.finding_id,
                    assertion="malicious SQL payload is treated as data and cannot change query structure",
                ),
                TestPlanItem(
                    name=f"{finding.finding_id} search behavior regression",
                    test_type="business_regression",
                    target=target_files[0],
                    assertion="normal queries keep the previous response shape and matching behavior",
                ),
            ]
            rejected = [
                RejectedAlternative(
                    "input blacklist only",
                    "blacklists are bypass-prone and do not enforce the SQL parameterization invariant",
                )
            ]
            risk_points = [
                "LIKE wildcard semantics must remain compatible after parameter binding",
                "existing tests may be absent, so generated patch still needs human review",
            ]
            confidence = 0.72
        elif is_dependency:
            component = finding.dependency.component if finding.dependency else target_files[0]
            fixed = finding.dependency.fixed_versions if finding.dependency else []
            version = fixed[0] if fixed else "a fixed version"
            goal = f"Upgrade or mitigate vulnerable dependency {component} to {version}."
            strategy = RemediationStrategy(
                strategy_type=RemediationStrategyType.DEPENDENCY_UPGRADE,
                summary="Update the dependency declaration to a fixed version and run compatibility checks.",
                steps=[
                    "Find the package manifest or lockfile that declares the vulnerable dependency.",
                    "Raise the dependency to the minimum fixed version or a compatible stable version.",
                    "Refresh lockfiles only when the project uses them.",
                    "Run build and dependency compatibility checks before merging.",
                ],
                preferred=True,
            )
            planned_changes = [
                PlannedChange(
                    file=target,
                    change_type="dependency",
                    description=f"Update dependency declaration for {component}.",
                    reason=f"reported vulnerable dependency requires {version}",
                    risk_level=Severity.MEDIUM,
                )
                for target in target_files[:5]
            ]
            tests = [
                TestPlanItem(
                    name=f"{finding.finding_id} dependency compatibility",
                    test_type="business_regression",
                    target=component,
                    assertion="application builds and dependency consumers remain compatible",
                ),
                TestPlanItem(
                    name=f"{finding.finding_id} dependency rescan",
                    test_type="security_scan",
                    target=component,
                    assertion="scanner no longer reports the vulnerable version",
                ),
            ]
            rejected = [
                RejectedAlternative(
                    "ignore vulnerable dependency",
                    "the vulnerable component remains present without an upgrade or mitigation",
                )
            ]
            risk_points = [
                "dependency upgrade may introduce API or transitive dependency changes",
                "lockfile updates should match the project's package manager",
            ]
            confidence = 0.66
        else:
            # 未匹配到专用模板的漏洞类型 → 尽量利用已有的根因信息构建方案
            rc = root_cause.root_cause
            has_meaningful_root_cause = bool(
                rc.summary
                and "static fallback" not in rc.summary.lower()
                and "could not fully confirm" not in rc.summary.lower()
            )
            has_meaningful_missing_control = bool(
                rc.missing_control
                and rc.missing_control not in ("missing_control", "missing_security_control", "missing control")
                and len(str(rc.missing_control)) > 10
            )
            has_evidence = bool(finding.evidence and any(e.strip() for e in finding.evidence))

            # 从漏洞报告本身提取有用描述
            evidence_text = "; ".join(e for e in (finding.evidence or []) if e.strip())
            rec_text = finding.recommendation or ""
            vuln_desc = finding.vulnerability_type or "unknown vulnerability"

            # 尝试从根因中获取更有意义的缺失控制描述
            if has_meaningful_missing_control:
                control_label = rc.missing_control
            elif finding.cwe:
                control_label = f"针对 {finding.cwe} 的必要安全控制（{vuln_desc}）"
            elif rec_text:
                control_label = f"安全控制（修复建议: {rec_text[:150]}）"
            elif has_evidence:
                control_label = f"安全控制（漏洞证据: {evidence_text[:150]}）"
            else:
                control_label = f"针对 {vuln_desc} 的必要安全防护"

            if has_meaningful_root_cause:
                cause_detail = rc.summary
            elif finding.recommendation:
                cause_detail = f"{vuln_desc}: {finding.recommendation[:200]}"
            elif has_evidence:
                cause_detail = f"{vuln_desc}: {evidence_text[:200]}"
            else:
                cause_detail = f"根因分析未产出结构化结果，需人工审查 {vuln_desc} 的具体触发路径"

            goal = f"修复 {vuln_desc}，阻断漏洞利用路径，同时保持现有业务行为不变。"
            strategy = RemediationStrategy(
                strategy_type=RemediationStrategyType.CODE_CHANGE,
                summary=f"针对 {vuln_desc} 的最小化安全修复，补全缺失的安全控制。",
                steps=[
                    f"读取受影响文件并定位 {vuln_desc} 的触发代码路径。",
                    f"补全缺失的安全控制: {control_label}。",
                    "保持公开 API 和现有业务行为不变，除非漏洞本身要求拒绝请求。",
                    "优先做最小聚焦的 diff，避免大范围重构。",
                ],
                preferred=True,
            )
            # 构建 planned_changes（已去重 target_files）
            seen_files: set[str] = set()
            planned_changes = []
            for target in target_files[:5]:
                if target.lower() not in seen_files:
                    seen_files.add(target.lower())
                    planned_changes.append(PlannedChange(
                        file=target,
                        change_type="code",
                        description=f"在漏洞代码路径中添加或恢复 {vuln_desc} 的安全控制。",
                        reason=cause_detail,
                        risk_level=Severity.MEDIUM,
                    ))
            tests = [
                TestPlanItem(
                    name=f"{finding.finding_id} 安全回归",
                    test_type="security_regression",
                    target=finding.finding_id,
                    assertion=f"{vuln_desc} 的利用条件在补丁后被阻断",
                ),
                TestPlanItem(
                    name=f"{finding.finding_id} 兼容性回归",
                    test_type="business_regression",
                    target=target_files[0] if target_files else finding.finding_id,
                    assertion="现有受支持的业务行为在安全修复后保持不变",
                ),
            ]
            rejected = [
                RejectedAlternative(
                    "安全修复前做大范围重构",
                    "无关的大范围变更会增加差异风险，减缓审查速度",
                )
            ]
            risk_points = [
                f"通用修复方案用于 {vuln_desc}，未匹配到专用模板",
                "生成的补丁需人工审查确认修复精准度",
            ]
            if not has_meaningful_root_cause:
                risk_points.append("根因分析不完整，修复可能遗漏边缘情况")
            confidence = 0.55 if has_meaningful_root_cause else 0.40

        plan = RemediationPlan(
            finding_id=finding.finding_id,
            status=RemediationPlanStatus.READY,
            remediation_goal=goal,
            strategies=[strategy],
            planned_changes=planned_changes,
            dependency_upgrade=None,
            compatibility=CompatibilityAssessment(
                summary="静态模板化修复方案（LLM 分析不可用时的回退）。",
                risks=list(risk_points),
                required_checks=engineering.available_test_commands if engineering else [],
            ),
            risk_points=list(risk_points),
            required_tests=tests,
            rejected_alternatives=rejected,
            rollback=RollbackPlan(
                summary="Revert the generated code or manifest changes and rerun validation.",
                steps=["revert patch", "rerun build and security checks"],
            ),
            patch_boundaries=PatchBoundaries(
                allowed_files=[change.file for change in planned_changes],
                forbidden_changes=[
                    "不得绕过、弱化或删除现有安全检查",
                    "不得修改既有测试预期来掩盖行为回归",
                    "不得修改与根因、兼容性或必要验证无直接关系的文件",
                    "不得扩大公共 API、信任边界或权限范围，除非计划中有证据和验证",
                ],
                maximum_changed_files=max(len(planned_changes) + 3, 8),
                maximum_diff_lines=500,
            ),
            assumptions=["static_remediation_plan_from_template"],
            unknowns=[],
            confidence_score=confidence,
            needs_human_review=True,
        )
        if failure_analysis:
            plan = RemediationPlanAgent._apply_failure_feedback(plan, failure_analysis)
        return plan

    @staticmethod
    def _dict_to_plan(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
        raw: dict,
        failure_analysis: FailureAnalysisResult | None,
    ) -> RemediationPlan:
        """将 LLM 输出转为 RemediationPlan。"""
        status = RemediationPlanStatus(raw.get("status", "ready"))
        strategies = [
            RemediationStrategy(
                strategy_type=RemediationStrategyType(s["strategy_type"]),
                summary=s["summary"],
                steps=s.get("steps", []),
                preferred=s.get("preferred", True),
            )
            for s in raw.get("strategies", [])
        ]
        planned_changes = [
            PlannedChange(
                file=str(pc.get("file") or pc.get("target") or "unknown"),
                change_type=RemediationPlanAgent._normalize_change_type(pc),
                description=str(pc.get("description") or pc.get("summary") or "Apply required remediation change."),
                reason=str(pc.get("reason") or pc.get("rationale") or raw.get("remediation_goal", "")),
                risk_level=RemediationPlanAgent._normalize_severity(pc.get("risk_level", "medium")),
                causally_required=bool(pc.get("causally_required", False)),
            )
            for pc in raw.get("planned_changes", [])
            if isinstance(pc, dict)
        ]
        if not planned_changes:
            target_files = [item.file for item in root_cause.affected_code] or [loc.file for loc in finding.locations]
            planned_changes = [
                PlannedChange(
                    file=target or "unknown",
                    change_type="code",
                    description="Apply the minimal code change required by the remediation goal.",
                    reason=raw.get("remediation_goal", root_cause.root_cause.summary),
                    risk_level=Severity.MEDIUM,
                )
                for target in target_files[:5]
            ]
        # Preserve every causally justified change.  De-duplication is safe;
        # truncating by a global file-count limit is not, because some fixes
        # legitimately span shared code, callers, configuration and tests.
        deduped_changes = []
        seen_files: set[str] = set()
        for change in planned_changes:
            if change.file in seen_files:
                continue
            seen_files.add(change.file)
            deduped_changes.append(change)
        planned_changes = deduped_changes
        required_tests = [
            TestPlanItem(name=t["name"], test_type=t["test_type"],
                        target=t["target"], assertion=t["assertion"])
            for t in raw.get("required_tests", [])
        ]
        rejected = [
            RejectedAlternative(ra["alternative"], ra["reason"])
            for ra in raw.get("rejected_alternatives", [])
        ]
        boundary_data = raw.get("patch_boundaries") if isinstance(raw.get("patch_boundaries"), dict) else {}
        default_diff_budget = max(250, 150 * max(1, len(planned_changes)))
        boundaries = PatchBoundaries(
            allowed_files=[pc.file for pc in planned_changes],
            forbidden_changes=[
                "不得在通用 key import 层添加防御 — 防御放在算法专属入口",
                "不得删除已有算法注册 — 通过 algorithms 白名单控制",
                "不得删除现有功能路径 — 通过 alg 白名单和类型绑定防御",
                "不得破坏现有测试语义 — 补丁必须向后兼容",
            ],
            maximum_changed_files=max(
                len(planned_changes), int(boundary_data.get("maximum_changed_files", len(planned_changes) or 1))
            ),
            maximum_diff_lines=int(boundary_data.get("maximum_diff_lines", default_diff_budget)),
        )
        unknowns = list(dict.fromkeys(raw.get("unknowns", [])))
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            status=status,
            remediation_goal=raw.get("remediation_goal", ""),
            strategies=strategies,
            planned_changes=planned_changes,
            dependency_upgrade=None,
            compatibility=CompatibilityAssessment(
                summary="Agent 生成的修复方案",
                risks=raw.get("risk_points", []),
                required_checks=engineering.available_test_commands if engineering else [],
            ),
            risk_points=raw.get("risk_points", []),
            required_tests=required_tests,
            rejected_alternatives=rejected,
            rollback=RollbackPlan(summary="回滚修复变更", steps=["revert changes", "重新运行回归测试"]),
            patch_boundaries=boundaries,
            assumptions=raw.get("assumptions", []),
            unknowns=unknowns,
            confidence_score=float(raw.get("confidence_score", 0.5)),
            needs_human_review=bool(raw.get("needs_human_review", True)),
        )
        if failure_analysis:
            plan = RemediationPlanAgent._apply_failure_feedback(plan, failure_analysis)
        return plan

    @staticmethod
    def _normalize_change_type(change: dict) -> str:
        value = str(
            change.get("change_type")
            or change.get("type")
            or change.get("operation")
            or ""
        ).strip().lower()
        aliases = {
            "": "code",
            "add": "code",
            "addition": "code",
            "create": "code",
            "modify": "code",
            "modification": "code",
            "update": "code",
            "edit": "code",
            "source": "code",
            "config": "configuration",
            "configuration_change": "configuration",
            "dependency_upgrade": "dependency",
            "package": "dependency",
            "tests": "test",
            "test_only": "test",
            "doc": "documentation",
            "docs": "documentation",
        }
        return aliases.get(value, value)

    @staticmethod
    def _normalize_severity(value: object) -> Severity:
        try:
            return Severity(str(value or "medium").strip().lower())
        except ValueError:
            return Severity.MEDIUM

    @staticmethod
    def _apply_failure_feedback(
        plan: RemediationPlan,
        failure_analysis: FailureAnalysisResult,
    ) -> RemediationPlan:
        """将失败反馈融入修复方案。"""
        from .models import FailureCategory

        plan.assumptions.append(f"replanned_after_failure: {failure_analysis.patch_id}")
        plan.risk_points.extend(failure_analysis.remediation_feedback)
        plan.compatibility.risks.extend(failure_analysis.remediation_feedback)
        plan.compatibility.required_checks.extend(failure_analysis.validation_feedback)
        plan.unknowns.extend(
            f"previous_failure:{f.category.value}"
            for f in failure_analysis.findings
            if f.category in {FailureCategory.TOOLING_GAP, FailureCategory.UNKNOWN}
        )

        if failure_analysis.requires_root_cause_recheck:
            plan.needs_human_review = True
            plan.risk_points.append("previous validation suggests root cause may be incomplete")

        categories = {f.category for f in failure_analysis.findings}
        if FailureCategory.SECURITY_NOT_FIXED in categories:
            plan.required_tests.append(TestPlanItem(
                name="reproduced exploit regression from failed validation",
                test_type="security_regression",
                target=plan.finding_id,
                assertion="the exact payload from the failed validation no longer succeeds",
            ))
        if FailureCategory.BUSINESS_REGRESSION in categories:
            plan.required_tests.append(TestPlanItem(
                name="business contract regression from failed validation",
                test_type="business_regression",
                target=plan.finding_id,
                assertion="existing API response shape and semantics remain unchanged",
            ))
        if FailureCategory.BUILD_FAILURE in categories:
            plan.compatibility.required_checks.append("re-run failed build command before security validation")
        if FailureCategory.TEST_HARNESS_FAILURE in categories:
            plan.compatibility.required_checks.append(
                "regenerate the test artifact using only APIs and fixtures observed in the supplied repository version"
            )

        plan.risk_points = list(dict.fromkeys(plan.risk_points))
        plan.compatibility.risks = list(dict.fromkeys(plan.compatibility.risks))
        plan.compatibility.required_checks = list(dict.fromkeys(plan.compatibility.required_checks))
        plan.assumptions = list(dict.fromkeys(plan.assumptions))
        plan.unknowns = list(dict.fromkeys(plan.unknowns))
        return plan
