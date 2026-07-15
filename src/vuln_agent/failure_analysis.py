"""FailureAnalysisAgent — 诊断补丁验证失败根因。

消费隔离验证器记录的命令、退出码和日志，诊断问题根因。
"""

from __future__ import annotations

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
    FailureAnalysisResult,
    FailureCategory,
    FailureFinding,
    FailureSeverity,
    PatchCandidate,
    PatchValidationStatus,
    RemediationFeedbackTarget,
    RemediationPlan,
    ValidationLayer,
    ValidationToolchainResult,
)

if TYPE_CHECKING:
    from .llm import LLMBackend

FAILURE_AGENT_PROMPT = """你是一位 CI/CD 安全验证专家，负责诊断补丁验证失败的根本原因。

## 你的任务
分析验证失败的原因，分类为：
- build_failure: 编译/构建失败
- test_harness_failure: 新生成的测试自身存在导入、fixture 或目标版本 API 不兼容，尚未执行到安全断言
- business_regression: 业务回归（原有功能被破坏）
- security_not_fixed: 安全验证（漏洞未修复）
- scanner_still_reports: 扫描器仍报告
- differential_risk: 补丁范围过大或有风险
- patch_policy_violation: 补丁策略违规
- tooling_gap: 验证工具缺失

## 工作方式
1. 分析每层验证失败的具体原因
2. 只使用隔离 ValidationToolchain 提供的真实执行证据
3. 给出具体可执行的修复建议
4. 分析完成后**必须立即**调用 submit_final_result 提交诊断结果

确认诊断完毕后，调用 submit_final_result 工具提交最终结果。"""


class FailureAnalysisAgent(BaseAgent):
    """诊断验证失败 — 读日志、跑命令、定位根因。"""

    def __init__(
        self,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
        pipeline_mode: str | PipelineMode = PipelineMode.BALANCED,
    ):
        ws = workspace or Path.cwd()
        self.pipeline_mode = normalize_pipeline_mode(pipeline_mode)
        self.policy = stage_policy("failure", self.pipeline_mode)
        super().__init__(
            name="FailureAnalysis",
            system_prompt=FAILURE_AGENT_PROMPT,
            # Validation commands run only in ValidationToolchain's isolated
            # workspace. Failure diagnosis consumes their auditable evidence.
            tools=create_default_tools(ws, include_shell=False),
            llm=llm,
            max_turns=self.policy.max_turns,
            workspace=ws,
            reasoning_mode=ReasoningMode.REFLEXION_DIAGNOSIS.value,
            tool_budget={},
            max_output_tokens=self.policy.max_output_tokens,
        )
        self.last_execution = StageExecution(
            "failure", self.pipeline_mode.value, ReasoningMode.REFLEXION_DIAGNOSIS.value
        )

    def analyze(
        self,
        validation: ValidationToolchainResult,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> FailureAnalysisResult:
        """运行 Failure Analysis Agent。"""
        if validation.status != PatchValidationStatus.FAILED:
            return FailureAnalysisResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                primary_category=FailureCategory.UNKNOWN,
                summary="validation passed; no failure analysis required",
                findings=[], route_to=RemediationFeedbackTarget.HUMAN_REVIEW,
                remediation_feedback=[], patch_generation_feedback=[],
                validation_feedback=[], requires_root_cause_recheck=False,
                needs_human_review=False,
            )

        from .llm import FAILURE_ANALYSIS_SCHEMA
        self.output_schema = FAILURE_ANALYSIS_SCHEMA

        deterministic = self._deterministic_diagnosis(validation, candidate)
        task = self._build_task(validation, candidate, remediation_plan)
        try:
            raw_result = self.llm.reason(  # type: ignore[union-attr]
                user_prompt=task,
                system_prompt=(
                    "执行按验证层路由的 Hypothesis-Test + Reflexion。"
                    "只依据真实命令、退出码和日志证据诊断，不重新执行命令。"
                    "输出可证伪原因、精准反馈目标、经验和禁止重复项。"
                ),
                output_schema=FAILURE_ANALYSIS_SCHEMA,
                temperature=0.1,
                max_tokens=self.policy.max_output_tokens,
            )
            raw = raw_result if isinstance(raw_result, dict) else {"summary": str(raw_result)}
        except Exception as exc:
            raw = {"summary": f"LLM reflexion unavailable: {exc}"}

        analysis = self._dict_to_analysis(candidate, raw, deterministic)
        self.last_execution = StageExecution(
            "failure", self.pipeline_mode.value, ReasoningMode.REFLEXION_DIAGNOSIS.value,
            llm_calls=1,
            details={
                "failed_layers": [item.failed_layer.value for item in analysis.findings if item.failed_layer],
                "route_to": analysis.route_to.value,
                "reflection_count": len(analysis.reflection),
            },
        )
        return analysis

    @staticmethod
    def _build_task(
        validation: ValidationToolchainResult,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> str:
        layers_detail = []
        for layer in validation.layers:
            status = layer.status.value
            layers_detail.append(f"- {layer.layer.value}: {status} — {layer.summary}")
            for tool in layer.tool_results:
                layers_detail.append(
                    f"  - {tool.tool_name}: {tool.status.value} ({tool.summary}); "
                    f"command={tool.command or 'none'}; exit_code={tool.exit_code}; "
                    f"evidence={tool.evidence}"
                )

        return f"""补丁验证失败，请诊断原因：

## 补丁信息
- patch_id: {candidate.patch_id}
- finding_id: {candidate.finding_id}
- 摘要: {candidate.summary}

## 验证层结果
{chr(10).join(layers_detail)}

## 修复方案
- 目标: {remediation_plan.remediation_goal}

## 要求
先按失败层建立候选原因和反证条件，再给出具体可执行的修复建议与反馈目标。
不得在原始工作区重跑命令；只使用上面由隔离验证器记录的命令、退出码和证据。
最后输出 reflection（本轮经验）和 do_not_repeat（下一轮禁止重复的策略或错误）。"""

    @staticmethod
    def _dict_to_analysis(
        candidate: PatchCandidate,
        raw: dict,
        deterministic: FailureAnalysisResult | None = None,
    ) -> FailureAnalysisResult:
        findings: list[FailureFinding] = []
        for item in raw.get("findings", []) if isinstance(raw.get("findings", []), list) else []:
            try:
                category = FailureCategory(item.get("category", "unknown"))
            except ValueError:
                category = FailureCategory.UNKNOWN
            try:
                severity = FailureSeverity(item.get("severity", "high"))
            except ValueError:
                severity = FailureSeverity.HIGH
            try:
                failed_layer = ValidationLayer(item["failed_layer"]) if item.get("failed_layer") else None
            except ValueError:
                failed_layer = None
            findings.append(FailureFinding(
                category=category,
                severity=severity,
                failed_layer=failed_layer,
                summary=item.get("summary", ""),
                evidence=item.get("evidence", []),
                suspected_reason=item.get("suspected_reason", ""),
                suggested_adjustment=item.get("suggested_adjustment", ""),
            ))
        # Layer classification and routing are deterministic. LLM output may
        # enrich hypotheses and feedback, but cannot override observed layers.
        if deterministic and deterministic.findings:
            findings = deterministic.findings
        primary = findings[0].category if findings else FailureCategory.UNKNOWN
        route = deterministic.route_to if deterministic else FailureAnalysisAgent._route_for_findings(findings)
        return FailureAnalysisResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            primary_category=primary,
            summary=raw.get("summary") or (deterministic.summary if deterministic else ""),
            findings=findings,
            route_to=route,
            remediation_feedback=raw.get("remediation_feedback", []) or (deterministic.remediation_feedback if deterministic else []),
            patch_generation_feedback=raw.get("patch_generation_feedback", []) or (deterministic.patch_generation_feedback if deterministic else []),
            validation_feedback=raw.get("validation_feedback", []) or (deterministic.validation_feedback if deterministic else []),
            requires_root_cause_recheck=(
                deterministic.requires_root_cause_recheck
                if deterministic else bool(raw.get("requires_root_cause_recheck", False))
            ),
            needs_human_review=bool(raw.get("needs_human_review", True)),
            diagnostic_hypotheses=raw.get("diagnostic_hypotheses", []) or (
                deterministic.diagnostic_hypotheses if deterministic else []
            ),
            reflection=raw.get("reflection", []) or [f"{item.category.value}: {item.suspected_reason}" for item in findings],
            do_not_repeat=raw.get("do_not_repeat", []) or [
                f"do not repeat patch behavior that caused {item.category.value}: {item.summary}"
                for item in findings
            ],
        )

    @staticmethod
    def _deterministic_diagnosis(validation, candidate) -> FailureAnalysisResult:
        category_by_layer = {
            ValidationLayer.BUILD: FailureCategory.BUILD_FAILURE,
            ValidationLayer.BUSINESS_REGRESSION: FailureCategory.BUSINESS_REGRESSION,
            ValidationLayer.SECURITY_REGRESSION: FailureCategory.SECURITY_NOT_FIXED,
            ValidationLayer.SCANNER_RESCAN: FailureCategory.SCANNER_STILL_REPORTS,
            ValidationLayer.DIFFERENTIAL_RISK: FailureCategory.DIFFERENTIAL_RISK,
        }
        test_harness_failure = FailureAnalysisAgent._is_test_harness_failure(
            validation, candidate
        )
        findings: list[FailureFinding] = []
        for layer in validation.layers:
            if layer.status.value != "failed":
                continue
            category = category_by_layer.get(layer.layer, FailureCategory.UNKNOWN)
            if layer.layer == ValidationLayer.SECURITY_REGRESSION and test_harness_failure:
                category = FailureCategory.TEST_HARNESS_FAILURE
            evidence = []
            for tool in layer.tool_results:
                evidence.extend(tool.evidence)
                if tool.command:
                    evidence.append(f"command={tool.command}; exit_code={tool.exit_code}")
            # ── Diff 专项诊断（BUILD 层失败时）──
            suspected_reason = FailureAnalysisAgent._layer_hypothesis(category)
            suggested_adjustment = FailureAnalysisAgent._layer_adjustment(category)
            if category == FailureCategory.BUILD_FAILURE:
                diff_diags = FailureAnalysisAgent._diagnose_diff_failure(evidence, candidate)
                if diff_diags:
                    suspected_reason += " | Diff diagnostics: " + "; ".join(diff_diags[:3])
                    # Prepend diff-specific advice to adjustment
                    if any("hunk" in d or "target" in d or "path" in d for d in diff_diags):
                        suggested_adjustment = (
                            "DIFF QUALITY: " + diff_diags[0] + " | " + suggested_adjustment
                        )

            findings.append(FailureFinding(
                category=category,
                severity=FailureSeverity.BLOCKER if category in {FailureCategory.BUILD_FAILURE, FailureCategory.SECURITY_NOT_FIXED} else FailureSeverity.HIGH,
                failed_layer=layer.layer,
                summary=layer.summary,
                evidence=evidence,
                suspected_reason=suspected_reason,
                suggested_adjustment=suggested_adjustment,
            ))
        route = FailureAnalysisAgent._route_for_findings(findings)
        return FailureAnalysisResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            primary_category=findings[0].category if findings else FailureCategory.UNKNOWN,
            summary="; ".join(item.summary for item in findings) or "validation failed without a classified layer",
            findings=findings,
            route_to=route,
            remediation_feedback=[item.suggested_adjustment for item in findings if route == RemediationFeedbackTarget.REMEDIATION_PLAN_AGENT],
            patch_generation_feedback=[item.suggested_adjustment for item in findings if route == RemediationFeedbackTarget.PATCH_GENERATION_AGENT],
            validation_feedback=[item.suggested_adjustment for item in findings if route == RemediationFeedbackTarget.VALIDATION_TOOLCHAIN],
            requires_root_cause_recheck=route == RemediationFeedbackTarget.ROOT_CAUSE_AGENT,
            needs_human_review=True,
            diagnostic_hypotheses=[item.suspected_reason for item in findings],
            reflection=[f"observed {item.category.value} at {item.failed_layer.value}" for item in findings if item.failed_layer],
            do_not_repeat=[f"do not repeat the implementation that produced: {item.summary}" for item in findings],
        )

    @staticmethod
    def _route_for_findings(findings) -> RemediationFeedbackTarget:
        categories = {item.category for item in findings}
        if FailureCategory.TEST_HARNESS_FAILURE in categories:
            return RemediationFeedbackTarget.PATCH_GENERATION_AGENT
        if categories.intersection({FailureCategory.SECURITY_NOT_FIXED, FailureCategory.SCANNER_STILL_REPORTS}):
            return RemediationFeedbackTarget.ROOT_CAUSE_AGENT
        if FailureCategory.BUSINESS_REGRESSION in categories:
            return RemediationFeedbackTarget.REMEDIATION_PLAN_AGENT
        if categories.intersection({FailureCategory.BUILD_FAILURE, FailureCategory.DIFFERENTIAL_RISK, FailureCategory.PATCH_POLICY_VIOLATION}):
            return RemediationFeedbackTarget.PATCH_GENERATION_AGENT
        if FailureCategory.TOOLING_GAP in categories:
            return RemediationFeedbackTarget.VALIDATION_TOOLCHAIN
        return RemediationFeedbackTarget.HUMAN_REVIEW

    @staticmethod
    def _layer_hypothesis(category) -> str:
        return {
            FailureCategory.BUILD_FAILURE: (
                "generated code or dependency changes are syntactically/API incompatible, "
                "or the diff could not be applied to the source files. Check: "
                "(1) diff headers match actual file paths, "
                "(2) hunk line numbers are within source file bounds, "
                "(3) context lines match source exactly (no reformatting)"
            ),
            FailureCategory.TEST_HARNESS_FAILURE: (
                "the generated test failed during import/setup or an API call before reaching its security assertion"
            ),
            FailureCategory.BUSINESS_REGRESSION: "the selected remediation changed an existing business contract",
            FailureCategory.SECURITY_NOT_FIXED: "the root cause or patch coverage is incomplete",
            FailureCategory.SCANNER_STILL_REPORTS: "the vulnerable pattern remains or the scanner matched another call site",
            FailureCategory.DIFFERENTIAL_RISK: "the patch changed files or behavior outside the justified boundary",
        }.get(category, "the available validation evidence is insufficient to isolate one cause")

    @staticmethod
    def _layer_adjustment(category) -> str:
        return {
            FailureCategory.BUILD_FAILURE: (
                "If diff failed to apply: verify diff headers use correct paths (--- a/path, +++ b/path), "
                "compute line numbers from actual source (line 1 = first line), "
                "copy context lines verbatim from source without reformatting. "
                "If syntax/API error: repair the concrete compile/API error without changing the remediation goal"
            ),
            FailureCategory.TEST_HARNESS_FAILURE: (
                "preserve the code patch and regenerate only the test artifact using API signatures, imports, "
                "fixtures and call forms observed in the target repository version"
            ),
            FailureCategory.BUSINESS_REGRESSION: "re-rank remediation candidates with the failed business contract as a hard constraint",
            FailureCategory.SECURITY_NOT_FIXED: "recheck source/sink/missing-control hypotheses before regenerating the patch",
            FailureCategory.SCANNER_STILL_REPORTS: "locate every remaining scanner match and distinguish real coverage gaps from scanner configuration",
            FailureCategory.DIFFERENTIAL_RISK: "remove unjustified changes and regenerate only allowed artifacts",
        }.get(category, "request human review with the raw validation evidence")

    @staticmethod
    def _is_test_harness_failure(validation, candidate: PatchCandidate) -> bool:
        """Identify generated-test failures that occur before security assertions.

        A failed security command is not automatically proof that the fix is
        incomplete.  Attribute/import errors and unexpected keyword arguments
        originating in a generated test file mean the test harness itself is
        incompatible with the checked-out version and should be regenerated.
        """
        test_targets = {
            artifact.target.replace("\\", "/").lower()
            for artifact in candidate.artifacts
            if artifact.patch_type.value == "test"
        }
        if not test_targets:
            return False
        evidence_parts: list[str] = []
        for layer in validation.layers:
            if layer.layer != ValidationLayer.SECURITY_REGRESSION:
                continue
            evidence_parts.append(layer.summary)
            for tool in layer.tool_results:
                evidence_parts.extend(tool.evidence)
        rendered = "\n".join(evidence_parts).replace("\\", "/").lower()
        contract_error = any(marker in rendered for marker in (
            "attributeerror", "has no attribute", "unexpected keyword argument",
            "modulenotfounderror", "importerror", "fixture '", "fixture \"",
            "error collecting", "failed during collection",
        ))
        target_in_trace = any(
            target in rendered or Path(target).name in rendered
            for target in test_targets
        )
        return contract_error and target_in_trace

    @staticmethod
    def _diagnose_diff_failure(evidence: list[str], candidate) -> list[str]:
        """Diagnose specific reasons why a diff failed to apply, for targeted feedback.

        Returns a list of specific diagnostic strings, or empty if unable to diagnose.
        """
        diagnostics: list[str] = []
        rendered = "\n".join(evidence).lower() if evidence else ""

        # Check for missing target file
        if "not found in workspace" in rendered or "does not exist" in rendered:
            diagnostics.append(
                "diff_target_missing: patch references files that don't exist in the "
                "repository. Verify that ---/+++ header paths match actual file layout."
            )

        # Check for hunk application failure
        if "patch does not apply" in rendered or "hunk" in rendered:
            # Extract which hunk failed
            import re
            hunk_match = re.search(r'hunk\s+(?:#)?(\d+)', rendered)
            hunk_info = f" (hunk #{hunk_match.group(1)})" if hunk_match else ""
            diagnostics.append(
                f"diff_hunk_failure{hunk_info}: context lines in the diff do not match "
                "the actual source file. The LLM may have hallucinated context lines, "
                "reformatted existing code, or computed wrong line numbers. "
                "Ensure context lines are copied verbatim from source."
            )

        # Check for path mismatch
        if candidate and candidate.artifacts:
            for art in candidate.artifacts:
                content = art.content or ""
                if "--- " in content and "+++ " in content:
                    # Check for common path errors
                    if "a/None" in content or "b/None" in content:
                        diagnostics.append(
                            "diff_null_path: diff header contains 'None' as file path. "
                            "The target file must be a concrete path, not None."
                        )
                    if "/dev/null" in content:
                        diagnostics.append(
                            "diff_dev_null: diff references /dev/null — this indicates "
                            "file creation/deletion. Ensure file creation is intentional."
                        )

        # Check for markdown wrapping
        for art in (candidate.artifacts if candidate else []):
            if "```" in (art.content or ""):
                diagnostics.append(
                    "diff_markdown_wrapped: diff contains markdown code fences (```). "
                    "Remove ```diff and ``` markers; output only the unified diff."
                )
                break

        # Check for JSON-instead-of-diff
        for art in (candidate.artifacts if candidate else []):
            content = (art.content or "").strip()
            if content.startswith("{") and '"content"' in content:
                diagnostics.append(
                    "diff_json_not_diff: artifact content appears to be JSON, not a "
                    "unified diff. The LLM may have output the structured schema wrapper "
                    "instead of just the diff content."
                )
                break

        if not diagnostics:
            diagnostics.append(
                "diff_apply_unknown: the diff could not be applied. Common causes: "
                "(1) incorrect line numbers in @@ headers, "
                "(2) context lines don't match source (reformatted/rewritten), "
                "(3) file paths in ---/+++ headers don't exist in the repo, "
                "(4) the diff tries to modify code that isn't in the source file."
            )

        return diagnostics