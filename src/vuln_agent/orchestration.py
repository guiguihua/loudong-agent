from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .failure_analysis import FailureAnalysisAgent
from .models import (
    EngineeringContext,
    EvidenceBundle,
    FailureAnalysisResult,
    ImpactAssessment,
    NormalizedVulnerability,
    PatchCandidateStatus,
    PatchValidationStatus,
    PreviousPatchAttempt,
    RemediationFeedbackTarget,
    RemediationPlan,
    RemediationPlanStatus,
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
from .root_cause import RootCauseAnalysisAgent
from .validation import ValidationToolchain


@dataclass(slots=True)
class PatchRepairLoopOrchestrator:
    remediation_agent: RemediationPlanAgent
    patch_generation_agent: PatchGenerationAgent
    validation_toolchain: ValidationToolchain
    failure_analysis_agent: FailureAnalysisAgent
    report_agent: RemediationReportAgent
    root_cause_agent: RootCauseAnalysisAgent | None = None
    max_attempts: int = 3
    progress_callback: Callable[[str, int | None], None] | None = field(default=None)

    def run(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext | None = None,
        repository: RepositoryContext | None = None,
        source_files: list[SourceFile] | None = None,
        validation_tool_results_by_attempt: list[list[ValidationToolResult]] | None = None,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> RepairLoopResult:
        attempts: list[RepairLoopAttempt] = []
        failure_analysis: FailureAnalysisResult | None = None
        previous_attempt: PreviousPatchAttempt | None = None
        previous_remediation_plan: RemediationPlan | None = None
        tool_results_by_attempt = validation_tool_results_by_attempt or []

        def _progress(msg: str) -> None:
            if self.progress_callback:
                self.progress_callback(msg, None)

        for attempt_number in range(1, self.max_attempts + 1):
            if attempt_number > 1:
                _progress(f"第 {attempt_number} 轮修复尝试...")

            # ── 最小回退：FailureAnalysis 路由到 patch_generation_agent 时跳过 Remediation ──
            if (
                attempt_number > 1
                and failure_analysis is not None
                and failure_analysis.route_to == RemediationFeedbackTarget.PATCH_GENERATION_AGENT
                and previous_remediation_plan is not None
            ):
                _progress("复用修复方案，重新生成补丁...")
                remediation_plan = RemediationPlanAgent._apply_failure_feedback(
                    previous_remediation_plan, failure_analysis,
                )
            else:
                _progress("制定修复方案...")
                remediation_plan = self.remediation_agent.plan(
                    finding,
                    impact,
                    root_cause,
                    engineering,
                    failure_analysis,
                    evidence_bundle,
                    source_files,
                )
            previous_remediation_plan = remediation_plan

            _progress("生成候选补丁...")
            patch_candidate = self.patch_generation_agent.generate(
                finding,
                impact,
                root_cause,
                remediation_plan,
                repository,
                source_files,
                previous_attempt,
                evidence_bundle,
            )

            _progress("静态预检查...")
            tool_results = self._tool_results_for_attempt(tool_results_by_attempt, attempt_number)
            validation = self.validation_toolchain.validate(
                patch_candidate,
                remediation_plan,
                tool_results,
            )

            if validation.status == PatchValidationStatus.PASSED:
                _progress("验证通过，生成报告...")
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

            if validation.status == PatchValidationStatus.NEEDS_HUMAN_REVIEW:
                _progress("需人工审查，生成报告...")
                report = self.report_agent.generate(
                    finding, impact, root_cause, remediation_plan, patch_candidate, validation,
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
                    next_action="human_review_candidate_and_complete_missing_validation",
                    needs_human_review=True,
                )

            if patch_candidate.status == PatchCandidateStatus.BLOCKED:
                # 尝试回退到静态修复方案（如果当前方案不是静态的）
                blocked_reason = patch_candidate.blocked_reason or ""
                if "remediation plan" in blocked_reason.lower() and attempt_number < self.max_attempts:
                    from .models import EngineeringContext
                    static_plan = self.remediation_agent._static_plan(
                        finding, impact, root_cause,
                        engineering or EngineeringContext(), failure_analysis,
                    )
                    if static_plan is not None and static_plan.planned_changes:
                        static_plan = self.remediation_agent._reconcile_plan_paths(
                            static_plan, finding, root_cause, evidence_bundle, source_files,
                        )
                    if static_plan is not None and static_plan.planned_changes and static_plan.status == RemediationPlanStatus.READY:
                        remediation_plan = static_plan
                        patch_candidate = self.patch_generation_agent.generate(
                            finding, impact, root_cause, remediation_plan,
                            repository, source_files, previous_attempt, evidence_bundle,
                        )
                        if patch_candidate.status == PatchCandidateStatus.GENERATED:
                            tool_results = self._tool_results_for_attempt(tool_results_by_attempt, attempt_number)
                            validation = self.validation_toolchain.validate(
                                patch_candidate, remediation_plan, tool_results,
                            )
                            if validation.status == PatchValidationStatus.PASSED:
                                report = self.report_agent.generate(
                                    finding, impact, root_cause, remediation_plan, patch_candidate, validation,
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
                # 静态回退也失败 → 报告 BLOCKED
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
            _progress(f"失败分析: {failure_analysis.summary[:80]}...")
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
                lessons=list(failure_analysis.reflection),
                prohibited_repeats=list(failure_analysis.do_not_repeat),
                route_to=failure_analysis.route_to,
                artifacts=list(patch_candidate.artifacts),
            )
            if (
                failure_analysis.route_to.value == "root_cause_agent"
                and self.root_cause_agent is not None
                and attempt_number < self.max_attempts
            ):
                root_cause = self.root_cause_agent.analyze(
                    finding, impact, evidence_bundle, force_deep=True
                )
            if (
                failure_analysis.route_to.value == "human_review"
                and attempt_number < self.max_attempts
            ):
                break

        blocked_report = None
        if attempts:
            last = attempts[-1]
            blocked_report = self.report_agent.generate(
                finding,
                impact,
                root_cause,
                last.remediation_plan,
                last.patch_candidate,
                last.validation,
            )
        return RepairLoopResult(
            finding_id=finding.finding_id,
            status=RepairLoopStatus.EXHAUSTED,
            attempts=attempts,
            final_report=blocked_report,
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
