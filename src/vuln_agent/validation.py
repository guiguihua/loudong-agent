from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .models import (
    PatchCandidate,
    PatchValidationStatus,
    RemediationPlan,
    ToolExecutionStatus,
    ValidationLayer,
    ValidationLayerResult,
    ValidationToolResult,
    ValidationToolchainResult,
    VerificationFailure,
)
from .patching import PatchValidationAgent


REQUIRED_VALIDATION_LAYERS = (
    ValidationLayer.BUILD,
    ValidationLayer.BUSINESS_REGRESSION,
    ValidationLayer.SECURITY_REGRESSION,
    ValidationLayer.SCANNER_RESCAN,
    ValidationLayer.DIFFERENTIAL_RISK,
)


@dataclass(slots=True)
class ValidationToolchain:
    required_layers: tuple[ValidationLayer, ...] = REQUIRED_VALIDATION_LAYERS
    static_precheck: PatchValidationAgent = field(default_factory=PatchValidationAgent)
    executor: Callable[[PatchCandidate], list[ValidationToolResult]] | None = None

    def validate(
        self,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
        tool_results: list[ValidationToolResult],
    ) -> ValidationToolchainResult:
        precheck = self.static_precheck.validate(candidate, remediation_plan)
        if precheck.status == PatchValidationStatus.FAILED:
            failures = list(precheck.failures)
            layer = ValidationLayerResult(
                layer=ValidationLayer.DIFFERENTIAL_RISK,
                status=ToolExecutionStatus.FAILED,
                tool_results=[],
                summary="candidate failed static precheck; external validation was not started",
            )
            return ValidationToolchainResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                status=PatchValidationStatus.FAILED,
                layers=[layer],
                failures=self._deduplicate_failures(failures),
                next_action="send_to_failure_analysis_agent",
                feedback_for_failure_analysis=self._feedback(failures),
                report_ready=False,
                needs_human_review=True,
            )
        if self.executor is not None:
            tool_results = self.executor(candidate)
        grouped = self._group_results(tool_results)
        layers = self._layer_results(grouped)

        failures: list[VerificationFailure] = []
        validation_gaps: list[VerificationFailure] = []
        for layer_result in layers:
            if layer_result.status == ToolExecutionStatus.FAILED:
                failures.append(VerificationFailure(
                    check=layer_result.layer.value,
                    reason=layer_result.summary,
                    suggested_adjustment=self._suggestion(layer_result.layer, layer_result.status),
                ))
            elif layer_result.status in {ToolExecutionStatus.NOT_CONFIGURED, ToolExecutionStatus.SKIPPED}:
                validation_gaps.append(VerificationFailure(
                    check=layer_result.layer.value,
                    reason=layer_result.summary,
                    suggested_adjustment=self._suggestion(layer_result.layer, layer_result.status),
                ))

        if failures:
            return ValidationToolchainResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                status=PatchValidationStatus.FAILED,
                layers=self._deduplicate_layer_results(layers),
                failures=self._deduplicate_failures(failures),
                next_action="send_to_failure_analysis_agent",
                feedback_for_failure_analysis=self._feedback(failures),
                report_ready=False,
                needs_human_review=True,
            )

        if validation_gaps:
            return ValidationToolchainResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                status=PatchValidationStatus.NEEDS_HUMAN_REVIEW,
                layers=self._deduplicate_layer_results(layers),
                failures=self._deduplicate_failures(validation_gaps),
                next_action="send_candidate_report_to_human_and_complete_missing_validation",
                feedback_for_failure_analysis=self._feedback(validation_gaps),
                report_ready=True,
                needs_human_review=True,
            )

        return ValidationToolchainResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            status=PatchValidationStatus.PASSED,
            layers=layers,
            failures=[],
            next_action="send_to_remediation_report_agent",
            feedback_for_failure_analysis=None,
            report_ready=True,
            needs_human_review=True,
        )

    def _layer_results(
        self,
        grouped: dict[ValidationLayer, list[ValidationToolResult]],
    ) -> list[ValidationLayerResult]:
        results: list[ValidationLayerResult] = []
        for layer in self.required_layers:
            tools = grouped.get(layer, [])
            if not tools:
                results.append(ValidationLayerResult(
                    layer=layer,
                    status=ToolExecutionStatus.NOT_CONFIGURED,
                    tool_results=[],
                    summary=f"no validation tool result provided for {layer.value}",
                ))
                continue
            if any(item.status == ToolExecutionStatus.FAILED for item in tools):
                failed = [item.summary for item in tools if item.status == ToolExecutionStatus.FAILED]
                results.append(ValidationLayerResult(
                    layer=layer,
                    status=ToolExecutionStatus.FAILED,
                    tool_results=tools,
                    summary="; ".join(failed),
                ))
                continue
            if any(item.status == ToolExecutionStatus.NOT_CONFIGURED for item in tools):
                missing = [item.summary for item in tools if item.status == ToolExecutionStatus.NOT_CONFIGURED]
                results.append(ValidationLayerResult(
                    layer=layer,
                    status=ToolExecutionStatus.NOT_CONFIGURED,
                    tool_results=tools,
                    summary="; ".join(missing),
                ))
                continue
            unsubstantiated = [
                item for item in tools
                if item.status == ToolExecutionStatus.PASSED
                and (not item.command or item.exit_code != 0 or not item.evidence)
            ]
            if unsubstantiated:
                results.append(ValidationLayerResult(
                    layer=layer,
                    status=ToolExecutionStatus.NOT_CONFIGURED,
                    tool_results=tools,
                    summary=(
                        f"{layer.value} has pass labels but no auditable command, "
                        "zero exit code, and captured evidence"
                    ),
                ))
                continue
            if all(item.status == ToolExecutionStatus.SKIPPED for item in tools):
                results.append(ValidationLayerResult(
                    layer=layer,
                    status=ToolExecutionStatus.SKIPPED,
                    tool_results=tools,
                    summary=f"all tools skipped for {layer.value}",
                ))
                continue
            results.append(ValidationLayerResult(
                layer=layer,
                status=ToolExecutionStatus.PASSED,
                tool_results=tools,
                summary=f"{layer.value} validation passed",
            ))
        return results

    @staticmethod
    def _group_results(tool_results: list[ValidationToolResult]) -> dict[ValidationLayer, list[ValidationToolResult]]:
        grouped: dict[ValidationLayer, list[ValidationToolResult]] = {}
        for result in tool_results:
            grouped.setdefault(result.layer, []).append(result)
        return grouped

    @staticmethod
    def _suggestion(layer: ValidationLayer, status: ToolExecutionStatus) -> str:
        if status == ToolExecutionStatus.SKIPPED:
            return f"执行 {layer.value} 的真实验证并保存命令、退出码和日志证据"
        if status == ToolExecutionStatus.NOT_CONFIGURED:
            return f"为 {layer.value} 接入对应验证工具或明确人工豁免"
        suggestions = {
            ValidationLayer.BUILD: "把构建日志交给失败分析 Agent，判断是依赖、语法还是环境问题",
            ValidationLayer.BUSINESS_REGRESSION: "把失败用例和断言差异交给失败分析 Agent，判断是否业务回归",
            ValidationLayer.SECURITY_REGRESSION: "把漏洞 payload 和安全断言结果交给失败分析 Agent，判断是否未修复根因",
            ValidationLayer.SCANNER_RESCAN: "把扫描器复验告警交给失败分析 Agent，判断是残留漏洞还是误报",
            ValidationLayer.DIFFERENTIAL_RISK: "把 diff 风险点交给失败分析 Agent，收敛修改范围或补充安全控制",
        }
        return suggestions[layer]

    @staticmethod
    def _feedback(failures: list[VerificationFailure]) -> str:
        return "; ".join(
            f"{failure.check}: {failure.reason}"
            for failure in failures
        )

    @staticmethod
    def _deduplicate_failures(failures: list[VerificationFailure]) -> list[VerificationFailure]:
        seen: set[tuple[str, str]] = set()
        deduped: list[VerificationFailure] = []
        for failure in failures:
            key = (failure.check, failure.reason)
            if key not in seen:
                seen.add(key)
                deduped.append(failure)
        return deduped

    @staticmethod
    def _deduplicate_layer_results(layers: list[ValidationLayerResult]) -> list[ValidationLayerResult]:
        by_layer: dict[ValidationLayer, ValidationLayerResult] = {}
        for layer in layers:
            existing = by_layer.get(layer.layer)
            if existing is None or existing.status != ToolExecutionStatus.FAILED:
                by_layer[layer.layer] = layer
        return list(by_layer.values())


def passed_tool(layer: ValidationLayer, tool_name: str, summary: str = "passed") -> ValidationToolResult:
    return ValidationToolResult(layer=layer, tool_name=tool_name, status=ToolExecutionStatus.PASSED, summary=summary)


def failed_tool(layer: ValidationLayer, tool_name: str, summary: str) -> ValidationToolResult:
    return ValidationToolResult(layer=layer, tool_name=tool_name, status=ToolExecutionStatus.FAILED, summary=summary)


def skipped_tool(layer: ValidationLayer, tool_name: str, summary: str = "skipped") -> ValidationToolResult:
    return ValidationToolResult(layer=layer, tool_name=tool_name, status=ToolExecutionStatus.SKIPPED, summary=summary)
