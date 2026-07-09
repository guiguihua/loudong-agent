from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import (
    FailureAnalysisResult,
    FailureCategory,
    FailureFinding,
    FailureSeverity,
    PatchCandidate,
    PatchValidationStatus,
    RemediationFeedbackTarget,
    RemediationPlan,
    ToolExecutionStatus,
    ValidationLayer,
    ValidationToolchainResult,
)

if TYPE_CHECKING:
    from .llm import LLMBackend


@dataclass(slots=True)
class FailureAnalysisAgent:
    llm: "LLMBackend | None" = None

    def analyze(
        self,
        validation: ValidationToolchainResult,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> FailureAnalysisResult:
        if self.llm and validation.status == PatchValidationStatus.FAILED:
            return self._llm_analyze(validation, candidate, remediation_plan)
        return self._deterministic_analyze(validation, candidate, remediation_plan)

    def _llm_analyze(
        self,
        validation: ValidationToolchainResult,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> FailureAnalysisResult:
        """使用 LLM 诊断验证失败原因并给出可执行的修复反馈。"""
        from .llm import FAILURE_ANALYSIS_SCHEMA

        prompt = self._build_failure_prompt(validation, candidate, remediation_plan)
        raw = self.llm.reason(  # type: ignore[union-attr]
            prompt,
            system_prompt="你是 CI/CD 安全验证专家。诊断补丁验证失败的根本原因，给出具体可执行的修复建议。",
            output_schema=FAILURE_ANALYSIS_SCHEMA,
        )
        if isinstance(raw, str):
            return self._deterministic_analyze(validation, candidate, remediation_plan)
        return self._dict_to_failure_analysis(candidate, raw)

    def _deterministic_analyze(
        self,
        validation: ValidationToolchainResult,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> FailureAnalysisResult:
        if validation.status == PatchValidationStatus.PASSED:
            return FailureAnalysisResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                primary_category=FailureCategory.UNKNOWN,
                summary="validation passed; no failure analysis required",
                findings=[],
                route_to=RemediationFeedbackTarget.HUMAN_REVIEW,
                remediation_feedback=[],
                patch_generation_feedback=[],
                validation_feedback=[],
                requires_root_cause_recheck=False,
                needs_human_review=False,
            )

        findings = self._findings(validation)
        primary = findings[0].category if findings else FailureCategory.UNKNOWN
        remediation_feedback = self._remediation_feedback(findings, remediation_plan)
        patch_feedback = self._patch_feedback(findings, candidate)
        validation_feedback = self._validation_feedback(findings)
        root_cause_recheck = any(item.category in {
            FailureCategory.SECURITY_NOT_FIXED,
            FailureCategory.SCANNER_STILL_REPORTS,
        } for item in findings)

        return FailureAnalysisResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            primary_category=primary,
            summary=self._summary(findings),
            findings=findings,
            route_to=RemediationFeedbackTarget.REMEDIATION_PLAN_AGENT,
            remediation_feedback=remediation_feedback,
            patch_generation_feedback=patch_feedback,
            validation_feedback=validation_feedback,
            requires_root_cause_recheck=root_cause_recheck,
            needs_human_review=any(item.severity in {FailureSeverity.BLOCKER, FailureSeverity.HIGH} for item in findings),
        )

    def _findings(self, validation: ValidationToolchainResult) -> list[FailureFinding]:
        findings: list[FailureFinding] = []
        for layer in validation.layers:
            if layer.status not in {ToolExecutionStatus.FAILED, ToolExecutionStatus.NOT_CONFIGURED}:
                continue
            category = self._category(layer.layer, layer.status)
            findings.append(FailureFinding(
                category=category,
                severity=self._severity(category),
                failed_layer=layer.layer,
                summary=layer.summary,
                evidence=self._evidence(layer),
                suspected_reason=self._suspected_reason(category),
                suggested_adjustment=self._suggested_adjustment(category),
            ))

        for failure in validation.failures:
            if any(item.summary == failure.reason for item in findings):
                continue
            category = self._category_from_check(failure.check)
            findings.append(FailureFinding(
                category=category,
                severity=self._severity(category),
                failed_layer=self._layer_from_check(failure.check),
                summary=failure.reason,
                evidence=[failure.check],
                suspected_reason=self._suspected_reason(category),
                suggested_adjustment=failure.suggested_adjustment or self._suggested_adjustment(category),
            ))
        return findings

    @staticmethod
    def _category(layer: ValidationLayer, status: ToolExecutionStatus) -> FailureCategory:
        if status == ToolExecutionStatus.NOT_CONFIGURED:
            return FailureCategory.TOOLING_GAP
        mapping = {
            ValidationLayer.BUILD: FailureCategory.BUILD_FAILURE,
            ValidationLayer.BUSINESS_REGRESSION: FailureCategory.BUSINESS_REGRESSION,
            ValidationLayer.SECURITY_REGRESSION: FailureCategory.SECURITY_NOT_FIXED,
            ValidationLayer.SCANNER_RESCAN: FailureCategory.SCANNER_STILL_REPORTS,
            ValidationLayer.DIFFERENTIAL_RISK: FailureCategory.DIFFERENTIAL_RISK,
        }
        return mapping.get(layer, FailureCategory.UNKNOWN)

    @staticmethod
    def _category_from_check(check: str) -> FailureCategory:
        if "boundary" in check or "policy" in check:
            return FailureCategory.PATCH_POLICY_VIOLATION
        if "security" in check:
            return FailureCategory.SECURITY_NOT_FIXED
        if "build" in check:
            return FailureCategory.BUILD_FAILURE
        if "business" in check:
            return FailureCategory.BUSINESS_REGRESSION
        if "scanner" in check or "scan" in check:
            return FailureCategory.SCANNER_STILL_REPORTS
        return FailureCategory.UNKNOWN

    @staticmethod
    def _layer_from_check(check: str) -> ValidationLayer | None:
        if "security" in check:
            return ValidationLayer.SECURITY_REGRESSION
        if "build" in check:
            return ValidationLayer.BUILD
        if "business" in check:
            return ValidationLayer.BUSINESS_REGRESSION
        if "scanner" in check or "scan" in check:
            return ValidationLayer.SCANNER_RESCAN
        if "boundary" in check or "policy" in check:
            return ValidationLayer.DIFFERENTIAL_RISK
        return None

    @staticmethod
    def _severity(category: FailureCategory) -> FailureSeverity:
        if category in {FailureCategory.SECURITY_NOT_FIXED, FailureCategory.SCANNER_STILL_REPORTS}:
            return FailureSeverity.BLOCKER
        if category in {FailureCategory.BUILD_FAILURE, FailureCategory.BUSINESS_REGRESSION, FailureCategory.PATCH_POLICY_VIOLATION}:
            return FailureSeverity.HIGH
        if category == FailureCategory.DIFFERENTIAL_RISK:
            return FailureSeverity.MEDIUM
        return FailureSeverity.LOW

    @staticmethod
    def _evidence(layer) -> list[str]:
        evidence = [layer.summary]
        for result in layer.tool_results:
            evidence.extend(result.evidence)
            if result.command:
                evidence.append(f"command: {result.command}")
            if result.exit_code is not None:
                evidence.append(f"exit_code: {result.exit_code}")
        return list(dict.fromkeys(item for item in evidence if item))

    @staticmethod
    def _suspected_reason(category: FailureCategory) -> str:
        reasons = {
            FailureCategory.BUILD_FAILURE: "candidate patch likely introduced syntax, dependency, or build configuration incompatibility",
            FailureCategory.BUSINESS_REGRESSION: "candidate patch changed existing business behavior or API contract",
            FailureCategory.SECURITY_NOT_FIXED: "candidate patch did not fully address the root cause or exploit path",
            FailureCategory.SCANNER_STILL_REPORTS: "scanner still detects the same pattern, residual vulnerable path, or untriaged false positive",
            FailureCategory.DIFFERENTIAL_RISK: "candidate patch scope or content introduces new risk beyond the remediation plan",
            FailureCategory.PATCH_POLICY_VIOLATION: "candidate patch violated patch boundaries or forbidden-change policy",
            FailureCategory.TOOLING_GAP: "required validation evidence is missing, so the patch cannot be trusted yet",
            FailureCategory.UNKNOWN: "failure cannot be classified from current validation evidence",
        }
        return reasons[category]

    @staticmethod
    def _suggested_adjustment(category: FailureCategory) -> str:
        adjustments = {
            FailureCategory.BUILD_FAILURE: "add build compatibility constraints and require the next patch to preserve dependency and syntax compatibility",
            FailureCategory.BUSINESS_REGRESSION: "add explicit business contract preservation requirements and strengthen business regression tests",
            FailureCategory.SECURITY_NOT_FIXED: "re-plan around the original root cause and require an executable exploit regression test before patch generation",
            FailureCategory.SCANNER_STILL_REPORTS: "compare scanner evidence with changed code and decide whether to expand fix scope or document false positive evidence",
            FailureCategory.DIFFERENTIAL_RISK: "reduce patch scope, avoid unrelated changes, and add differential risk checks as hard constraints",
            FailureCategory.PATCH_POLICY_VIOLATION: "tighten patch boundaries and regenerate only within allowed files",
            FailureCategory.TOOLING_GAP: "configure missing validation tools or request explicit human approval for a temporary exception",
            FailureCategory.UNKNOWN: "collect more logs and require human review before re-planning",
        }
        return adjustments[category]

    @staticmethod
    def _remediation_feedback(findings: list[FailureFinding], remediation_plan: RemediationPlan) -> list[str]:
        feedback = [item.suggested_adjustment for item in findings]
        if any(item.category == FailureCategory.SECURITY_NOT_FIXED for item in findings):
            feedback.append(f"keep remediation goal focused on: {remediation_plan.remediation_goal}")
        if any(item.category == FailureCategory.BUSINESS_REGRESSION for item in findings):
            feedback.append("add a non-negotiable constraint: preserve existing API response shape and business semantics")
        if any(item.category == FailureCategory.BUILD_FAILURE for item in findings):
            feedback.append("include build commands and dependency compatibility checks as required checks in the revised plan")
        return list(dict.fromkeys(feedback))

    @staticmethod
    def _patch_feedback(findings: list[FailureFinding], candidate: PatchCandidate) -> list[str]:
        feedback = []
        if any(item.category == FailureCategory.PATCH_POLICY_VIOLATION for item in findings):
            feedback.append("regenerate patch within allowed_files only")
        if any(item.category == FailureCategory.BUSINESS_REGRESSION for item in findings):
            feedback.append("avoid changing return values, error semantics, or public API contract")
        if any(item.category == FailureCategory.SECURITY_NOT_FIXED for item in findings):
            feedback.append("modify the code path that reaches the dangerous sink, not only nearby comments or tests")
        if not feedback:
            feedback.append(f"regenerate candidate based on failure analysis for {candidate.patch_id}")
        return feedback

    @staticmethod
    def _validation_feedback(findings: list[FailureFinding]) -> list[str]:
        feedback = []
        if any(item.category == FailureCategory.TOOLING_GAP for item in findings):
            feedback.append("missing validation layer must be configured before the next candidate can be accepted")
        for item in findings:
            if item.failed_layer:
                feedback.append(f"rerun {item.failed_layer.value} validation after re-planning")
        return list(dict.fromkeys(feedback))

    @staticmethod
    def _summary(findings: list[FailureFinding]) -> str:
        if not findings:
            return "validation failed but no structured failure evidence was available"
        primary = findings[0]
        return f"{primary.category.value}: {primary.summary}"

    # ── LLM 推理方法 ──────────────────────────────────────────────────

    @staticmethod
    def _build_failure_prompt(validation, candidate, remediation_plan) -> str:
        layers_detail = []
        for layer in validation.layers:
            status = layer.status.value
            layers_detail.append(f"- {layer.layer.value}: {status} — {layer.summary}")
            for tool in layer.tool_results:
                layers_detail.append(f"  - {tool.tool_name}: {tool.status.value} ({tool.summary})")

        return f"""补丁验证失败，请诊断原因：

补丁: {candidate.patch_id}
漏洞: {candidate.finding_id}
摘要: {candidate.summary}

验证层结果:
{chr(10).join(layers_detail)}

修复方案目标: {remediation_plan.remediation_goal}

请分析每层失败的根本原因，分类为 build_failure / business_regression / security_not_fixed / scanner_still_reports / differential_risk / patch_policy_violation / tooling_gap。
对每个失败给出具体可执行的修复建议。"""

    @staticmethod
    def _dict_to_failure_analysis(candidate, raw: dict) -> FailureAnalysisResult:
        findings = [
            FailureFinding(
                category=FailureCategory(f.get("category", "unknown")),
                severity=FailureSeverity(f.get("severity", "high")),
                failed_layer=ValidationLayer(f["failed_layer"]) if f.get("failed_layer") else None,
                summary=f.get("summary", ""),
                evidence=f.get("evidence", []),
                suspected_reason=f.get("suspected_reason", ""),
                suggested_adjustment=f.get("suggested_adjustment", ""),
            )
            for f in raw.get("findings", [])
        ]
        primary = findings[0].category if findings else FailureCategory.UNKNOWN
        return FailureAnalysisResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            primary_category=primary,
            summary=raw.get("summary", ""),
            findings=findings,
            route_to=RemediationFeedbackTarget.REMEDIATION_PLAN_AGENT,
            remediation_feedback=raw.get("remediation_feedback", []),
            patch_generation_feedback=raw.get("patch_generation_feedback", []),
            validation_feedback=raw.get("validation_feedback", []),
            requires_root_cause_recheck=bool(raw.get("requires_root_cause_recheck", False)),
            needs_human_review=bool(raw.get("needs_human_review", True)),
        )
