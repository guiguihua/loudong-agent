from __future__ import annotations

from dataclasses import dataclass

from .failure_analysis import FailureAnalysisAgent
from .models import (
    EngineeringContext,
    FailureAnalysisResult,
    ImpactAssessment,
    NormalizedVulnerability,
    PatchCandidateStatus,
    PatchValidationStatus,
    PreviousPatchAttempt,
    RemediationPlan,
    RepairLoopAttempt,
    RepairLoopResult,
    RepairLoopStatus,
    RepositoryContext,
    RootCauseAssessment,
    SourceFile,
    ValidationToolResult,
    VerificationFailure,
)
from .patching import PatchGenerationAgent
from .remediation import RemediationPlanAgent
from .reporting import RemediationReportAgent
from .validation import ValidationToolchain


@dataclass(slots=True)
class PatchRepairLoopOrchestrator:
    remediation_agent: RemediationPlanAgent
    patch_generation_agent: PatchGenerationAgent
    validation_toolchain: ValidationToolchain
    failure_analysis_agent: FailureAnalysisAgent
    report_agent: RemediationReportAgent
    max_attempts: int = 3

    def run(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext | None = None,
        repository: RepositoryContext | None = None,
        source_files: list[SourceFile] | None = None,
        validation_tool_results_by_attempt: list[list[ValidationToolResult]] | None = None,
    ) -> RepairLoopResult:
        attempts: list[RepairLoopAttempt] = []
        failure_analysis: FailureAnalysisResult | None = None
        previous_attempt: PreviousPatchAttempt | None = None
        tool_results_by_attempt = validation_tool_results_by_attempt or []

        for attempt_number in range(1, self.max_attempts + 1):
            remediation_plan = self.remediation_agent.plan(
                finding,
                impact,
                root_cause,
                engineering,
                failure_analysis,
            )
            patch_candidate = self.patch_generation_agent.generate(
                finding,
                impact,
                root_cause,
                remediation_plan,
                repository,
                source_files,
                previous_attempt,
            )
            tool_results = self._tool_results_for_attempt(tool_results_by_attempt, attempt_number)
            validation = self.validation_toolchain.validate(
                patch_candidate,
                remediation_plan,
                tool_results,
            )

            if validation.status == PatchValidationStatus.PASSED:
                report = self.report_agent.generate(
                    finding,
                    impact,
                    root_cause,
                    remediation_plan,
                    patch_candidate,
                    validation,
                )
                attempts.append(RepairLoopAttempt(
                    attempt=attempt_number,
                    remediation_plan=remediation_plan,
                    patch_candidate=patch_candidate,
                    validation=validation,
                    failure_analysis=None,
                ))
                return RepairLoopResult(
                    finding_id=finding.finding_id,
                    status=RepairLoopStatus.SUCCEEDED,
                    attempts=attempts,
                    final_report=report,
                    final_failure_analysis=None,
                    next_action="send_to_human_review_and_pr_creation",
                    needs_human_review=True,
                )

            if patch_candidate.status == PatchCandidateStatus.BLOCKED:
                report = self.report_agent.generate(
                    finding,
                    impact,
                    root_cause,
                    remediation_plan,
                    patch_candidate,
                    validation,
                )
                attempts.append(RepairLoopAttempt(
                    attempt=attempt_number,
                    remediation_plan=remediation_plan,
                    patch_candidate=patch_candidate,
                    validation=validation,
                    failure_analysis=None,
                ))
                return RepairLoopResult(
                    finding_id=finding.finding_id,
                    status=RepairLoopStatus.BLOCKED,
                    attempts=attempts,
                    final_report=report,
                    final_failure_analysis=None,
                    next_action="patch_generation_needs_deep_mode_or_human_patch",
                    needs_human_review=True,
                )

            failure_analysis = self.failure_analysis_agent.analyze(
                validation,
                patch_candidate,
                remediation_plan,
            )
            attempts.append(RepairLoopAttempt(
                attempt=attempt_number,
                remediation_plan=remediation_plan,
                patch_candidate=patch_candidate,
                validation=validation,
                failure_analysis=failure_analysis,
            ))
            previous_attempt = PreviousPatchAttempt(
                attempt=attempt_number,
                patch_id=patch_candidate.patch_id,
                validation_status=validation.status,
                failures=[
                    VerificationFailure(
                        check=finding.category.value,
                        reason=finding.summary,
                        suggested_adjustment=finding.suggested_adjustment,
                    )
                    for finding in failure_analysis.findings
                ],
            )

        return RepairLoopResult(
            finding_id=finding.finding_id,
            status=RepairLoopStatus.EXHAUSTED,
            attempts=attempts,
            final_report=None,
            final_failure_analysis=failure_analysis,
            next_action="send_to_human_security_review_after_retry_exhaustion",
            needs_human_review=True,
        )

    @staticmethod
    def _tool_results_for_attempt(
        tool_results_by_attempt: list[list[ValidationToolResult]],
        attempt_number: int,
    ) -> list[ValidationToolResult]:
        index = attempt_number - 1
        if index < len(tool_results_by_attempt):
            return tool_results_by_attempt[index]
        return []
