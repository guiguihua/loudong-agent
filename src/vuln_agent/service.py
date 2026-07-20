from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .failure_analysis import FailureAnalysisAgent
from .evidence import EvidenceCollector
from .impact import ImpactAnalysisAgent
from .models import EngineeringContext, PatchValidationStatus, RepositoryContext, SourceFile
from .normalization import VulnerabilityNormalizer
from .patching import PatchGenerationAgent, PatchValidationAgent
from .reporting import RemediationReportAgent
from .remediation import RemediationPlanAgent
from .root_cause import RootCauseAnalysisAgent
from .validation import ValidationToolchain


@dataclass(slots=True)
class IntakeImpactService:
    normalizer: VulnerabilityNormalizer
    impact_agent: ImpactAnalysisAgent
    root_cause_agent: RootCauseAnalysisAgent | None = None
    remediation_agent: RemediationPlanAgent | None = None
    patch_generation_agent: PatchGenerationAgent | None = None
    patch_validation_agent: PatchValidationAgent | None = None
    validation_toolchain: ValidationToolchain | None = None
    failure_analysis_agent: FailureAnalysisAgent | None = None
    remediation_report_agent: RemediationReportAgent | None = None
    engineering_context: EngineeringContext | None = None
    repository_context: RepositoryContext | None = None
    source_files: list[SourceFile] | None = None
    validation_tool_results: list[Any] | None = None

    def process(self, raw: dict[str, Any]) -> dict[str, Any]:
        finding = self.normalizer.normalize(raw)
        evidence_bundle = EvidenceCollector().collect(
            finding,
            self.source_files,
            self.repository_context,
            self.engineering_context,
        )
        impact = self.impact_agent.analyze(finding, evidence_bundle)
        result = {
            "finding": finding.to_dict(),
            "evidence_bundle": evidence_bundle.to_dict(),
            "impact": impact.to_dict(),
        }
        if self.root_cause_agent:
            root_cause = self.root_cause_agent.analyze(finding, impact, evidence_bundle)
            result["root_cause"] = root_cause.to_dict()
            if self.remediation_agent:
                remediation_plan = self.remediation_agent.plan(
                    finding,
                    impact,
                    root_cause,
                    self.engineering_context,
                    None,
                    evidence_bundle,
                )
                result["remediation_plan"] = remediation_plan.to_dict()
                if self.patch_generation_agent:
                    patch_candidate = self.patch_generation_agent.generate(
                        finding,
                        impact,
                        root_cause,
                        remediation_plan,
                        self.repository_context,
                        self.source_files,
                        None,
                        evidence_bundle,
                    )
                    result["patch_candidate"] = patch_candidate.to_dict()
                    if self.patch_validation_agent:
                        result["patch_validation"] = self.patch_validation_agent.validate(
                            patch_candidate,
                            remediation_plan,
                        ).to_dict()
                    if self.validation_toolchain:
                        validation_result = self.validation_toolchain.validate(
                            patch_candidate,
                            remediation_plan,
                            self.validation_tool_results or [],
                        )
                        result["validation_toolchain"] = validation_result.to_dict()
                        if (
                            self.failure_analysis_agent
                            and validation_result.status == PatchValidationStatus.FAILED
                        ):
                            failure_analysis = self.failure_analysis_agent.analyze(
                                validation_result,
                                patch_candidate,
                                remediation_plan,
                            )
                            result["failure_analysis"] = failure_analysis.to_dict()
                            result["revised_remediation_plan"] = self.remediation_agent.plan(
                                finding,
                                impact,
                                root_cause,
                                self.engineering_context,
                                failure_analysis,
                                evidence_bundle,
                            ).to_dict()
                        if (
                            self.remediation_report_agent
                            and validation_result.status == PatchValidationStatus.PASSED
                        ):
                            result["remediation_report"] = self.remediation_report_agent.generate(
                                finding,
                                impact,
                                root_cause,
                                remediation_plan,
                                patch_candidate,
                                validation_result,
                            ).to_dict()
        return result
