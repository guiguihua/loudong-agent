from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class AssessmentStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class RootCauseCategory(StrEnum):
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    MISSING_OUTPUT_ENCODING = "missing_output_encoding"
    MISSING_AUTHORIZATION = "missing_authorization"
    INCORRECT_AUTHORIZATION_SCOPE = "incorrect_authorization_scope"
    UNSAFE_API_USAGE = "unsafe_api_usage"
    MISSING_SECURITY_CONTROL = "missing_security_control"
    INSECURE_CONFIGURATION = "insecure_configuration"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    PATH_BOUNDARY_VIOLATION = "path_boundary_violation"
    UNKNOWN = "unknown"


class RemediationPlanStatus(StrEnum):
    READY = "ready"
    NEEDS_CONTEXT = "needs_context"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    BLOCKED = "blocked"


class RemediationStrategyType(StrEnum):
    CODE_CHANGE = "code_change"
    DEPENDENCY_UPGRADE = "dependency_upgrade"
    CONFIGURATION_CHANGE = "configuration_change"
    VIRTUAL_PATCH = "virtual_patch"
    TEST_ONLY = "test_only"
    MANUAL_REMEDIATION = "manual_remediation"
    INVESTIGATION_REQUIRED = "investigation_required"


class PatchType(StrEnum):
    CODE = "code"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    TEST = "test"
    VIRTUAL = "virtual"
    DOCUMENTATION = "documentation"


class PatchCandidateStatus(StrEnum):
    GENERATED = "generated"
    BLOCKED = "blocked"
    NEEDS_CONTEXT = "needs_context"


class PatchValidationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class VerificationCheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ValidationLayer(StrEnum):
    BUILD = "build"
    BUSINESS_REGRESSION = "business_regression"
    SECURITY_REGRESSION = "security_regression"
    SCANNER_RESCAN = "scanner_rescan"
    DIFFERENTIAL_RISK = "differential_risk"


class ToolExecutionStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_CONFIGURED = "not_configured"


class FailureCategory(StrEnum):
    BUILD_FAILURE = "build_failure"
    TEST_HARNESS_FAILURE = "test_harness_failure"
    BUSINESS_REGRESSION = "business_regression"
    SECURITY_NOT_FIXED = "security_not_fixed"
    SCANNER_STILL_REPORTS = "scanner_still_reports"
    DIFFERENTIAL_RISK = "differential_risk"
    PATCH_POLICY_VIOLATION = "patch_policy_violation"
    TOOLING_GAP = "tooling_gap"
    UNKNOWN = "unknown"


class FailureSeverity(StrEnum):
    BLOCKER = "blocker"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationFeedbackTarget(StrEnum):
    REMEDIATION_PLAN_AGENT = "remediation_plan_agent"
    ROOT_CAUSE_AGENT = "root_cause_agent"
    PATCH_GENERATION_AGENT = "patch_generation_agent"
    VALIDATION_TOOLCHAIN = "validation_toolchain"
    HUMAN_REVIEW = "human_review"


class RemediationReportStatus(StrEnum):
    READY = "ready"
    CANDIDATE = "candidate"
    BLOCKED = "blocked"


class RepairLoopStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED_RETRYABLE = "failed_retryable"
    EXHAUSTED = "exhausted"
    BLOCKED = "blocked"


@dataclass(slots=True)
class Location:
    file: str
    function: str | None = None
    line: int | None = None


@dataclass(slots=True)
class DependencyDetails:
    component: str
    current_version: str | None = None
    fixed_versions: list[str] = field(default_factory=list)
    breaking_upgrade: bool | None = None
    usage_locations: list[Location] = field(default_factory=list)
    affected_artifacts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NormalizedVulnerability:
    schema_version: str
    finding_id: str
    vulnerability_type: str
    severity: Severity
    confidence: Confidence
    scanner: str
    locations: list[Location]
    evidence: list[str]
    recommendation: str | None = None
    cve: str | None = None
    cwe: str | None = None
    repository: str | None = None
    revision: str | None = None
    dependency: DependencyDetails | None = None
    raw_reference: str | None = None
    normalization_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Evidence:
    evidence_id: str
    source: str
    assertion: str
    value: Any
    confidence: Confidence = Confidence.MEDIUM


@dataclass(slots=True)
class ApiEntryPoint:
    route: str
    method: str = "ANY"
    authentication: str = "unknown"
    internet_exposed: bool | None = None


@dataclass(slots=True)
class ImpactAssessment:
    finding_id: str
    status: AssessmentStatus
    affected_services: list[str]
    entry_points: list[ApiEntryPoint]
    call_paths: list[list[str]]
    affected_assets: list[str]
    affected_artifacts: list[str]
    data_classification: list[str]
    upstream_dependencies: list[str]
    downstream_dependencies: list[str]
    regression_targets: list[str]
    suggested_tests: list[str]
    evidence: list[Evidence]
    unknowns: list[str]
    confidence_score: float
    needs_human_review: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CodePoint:
    symbol: str
    file: str | None = None
    line: int | None = None


@dataclass(slots=True)
class PropagationStep:
    symbol: str
    operation: str


@dataclass(slots=True)
class FailedControl:
    control: str
    reason: str


@dataclass(slots=True)
class AffectedCode:
    file: str
    function: str | None
    lines: list[int]
    role: str


@dataclass(slots=True)
class AlternativeHypothesis:
    hypothesis: str
    result: str
    reason: str


@dataclass(slots=True)
class RootCause:
    summary: str
    source: CodePoint | None
    propagation: list[PropagationStep]
    sink: CodePoint | None
    missing_control: str | None
    failed_existing_controls: list[FailedControl]
    trigger_conditions: list[str]


@dataclass(slots=True)
class RootCauseAssessment:
    finding_id: str
    status: AssessmentStatus
    root_cause_category: RootCauseCategory
    root_cause: RootCause
    contributing_factors: list[str]
    causal_chain: list[str]
    affected_code: list[AffectedCode]
    evidence: list[Evidence]
    alternative_hypotheses: list[AlternativeHypothesis]
    confidence_score: float
    unknowns: list[str]
    needs_human_review: bool
    recommended_fix_constraints: list[str]
    security_invariant: str | None = None
    guardrail: str | None = None
    broken_mechanism: list[str] = field(default_factory=list)
    exploitability_note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EngineeringContext:
    language: str | None = None
    framework: str | None = None
    database: str | None = None
    data_access_library: str | None = None
    package_manager: str | None = None
    dependency_versions: dict[str, str] = field(default_factory=dict)
    available_test_commands: list[str] = field(default_factory=list)
    related_tests: list[str] = field(default_factory=list)
    deployment_targets: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RemediationPolicy:
    automation_level: str = "plan_only"
    allow_dependency_upgrade: bool = True
    require_security_regression_test: bool = True
    require_business_regression_test: bool = True
    maximum_changed_files: int = 8
    maximum_diff_lines: int = 400


@dataclass(slots=True)
class PlannedChange:
    file: str
    change_type: str
    description: str
    reason: str
    risk_level: Severity = Severity.MEDIUM


@dataclass(slots=True)
class RemediationStrategy:
    strategy_type: RemediationStrategyType
    summary: str
    steps: list[str]
    preferred: bool = True


@dataclass(slots=True)
class DependencyUpgradePlan:
    component: str
    current_version: str | None
    minimum_safe_version: str | None
    recommended_stable_version: str | None
    breaking_upgrade_risk: str
    code_adaptation_required: bool | None
    temporary_mitigation: str | None = None


@dataclass(slots=True)
class TestPlanItem:
    name: str
    test_type: str
    target: str
    assertion: str


@dataclass(slots=True)
class CompatibilityAssessment:
    summary: str
    risks: list[str]
    required_checks: list[str]


@dataclass(slots=True)
class RejectedAlternative:
    alternative: str
    reason: str


@dataclass(slots=True)
class RollbackPlan:
    summary: str
    steps: list[str]


@dataclass(slots=True)
class PatchBoundaries:
    allowed_files: list[str]
    forbidden_changes: list[str]
    maximum_changed_files: int
    maximum_diff_lines: int


@dataclass(slots=True)
class RemediationPlan:
    finding_id: str
    status: RemediationPlanStatus
    remediation_goal: str
    strategies: list[RemediationStrategy]
    planned_changes: list[PlannedChange]
    dependency_upgrade: DependencyUpgradePlan | None
    compatibility: CompatibilityAssessment
    risk_points: list[str]
    required_tests: list[TestPlanItem]
    rejected_alternatives: list[RejectedAlternative]
    rollback: RollbackPlan
    patch_boundaries: PatchBoundaries
    assumptions: list[str]
    unknowns: list[str]
    confidence_score: float
    needs_human_review: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RepositoryContext:
    repository: str | None = None
    branch: str | None = None
    base_revision: str | None = None
    language: str | None = None
    framework: str | None = None
    package_manager: str | None = None
    test_framework: str | None = None


@dataclass(slots=True)
class SourceFile:
    path: str
    content: str


@dataclass(slots=True)
class RepositorySummary:
    repository: str | None
    revision: str | None
    file_count: int
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FileEvidence:
    path: str
    matched_by: str
    line_count: int
    sha256: str
    language: str | None = None


@dataclass(slots=True)
class CodeSlice:
    slice_id: str
    path: str
    start_line: int
    end_line: int
    content: str
    reason: str


@dataclass(slots=True)
class EntryPointEvidence:
    route: str
    method: str
    path: str
    line: int
    framework: str | None = None
    snippet_id: str | None = None


@dataclass(slots=True)
class CodePointEvidence:
    symbol: str
    path: str
    line: int
    kind: str
    pattern: str
    reason: str
    snippet_id: str | None = None


@dataclass(slots=True)
class DependencyEvidence:
    component: str
    version: str | None
    path: str | None
    line: int | None
    source: str


@dataclass(slots=True)
class TestEvidence:
    path: str | None
    framework: str | None
    command: str | None
    related: bool
    snippet_id: str | None = None


@dataclass(slots=True)
class ConfigEvidence:
    path: str
    key: str
    line: int | None
    value: str
    source: str


@dataclass(slots=True)
class ValidationCapabilities:
    build_commands: list[str] = field(default_factory=list)
    test_commands: list[str] = field(default_factory=list)
    security_commands: list[str] = field(default_factory=list)
    scanner_commands: list[str] = field(default_factory=list)
    detected_tools: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EvidenceBundle:
    finding_id: str
    repository_summary: RepositorySummary
    target_files: list[FileEvidence]
    code_slices: list[CodeSlice]
    entry_points: list[EntryPointEvidence]
    source_candidates: list[CodePointEvidence]
    sink_candidates: list[CodePointEvidence]
    dependency_evidence: list[DependencyEvidence]
    test_evidence: list[TestEvidence]
    config_evidence: list[ConfigEvidence]
    validation_capabilities: ValidationCapabilities
    collection_warnings: list[str]
    bundle_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PatchGenerationPolicy:
    mode: str = "diff_only"
    allow_file_create: bool = True
    require_test_patch: bool = True
    include_virtual_patch: bool = False
    include_documentation_patch: bool = True
    max_attempts: int = 3


@dataclass(slots=True)
class VerificationFailure:
    check: str
    reason: str
    suggested_adjustment: str | None = None


@dataclass(slots=True)
class PreviousPatchAttempt:
    attempt: int
    patch_id: str
    validation_status: PatchValidationStatus
    failures: list[VerificationFailure] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)
    prohibited_repeats: list[str] = field(default_factory=list)
    route_to: RemediationFeedbackTarget | None = None
    artifacts: list["PatchArtifact"] = field(default_factory=list)


@dataclass(slots=True)
class PatchArtifact:
    patch_type: PatchType
    target: str
    content: str
    description: str


@dataclass(slots=True)
class ChangedFile:
    file: str
    change_type: PatchType
    reason: str


@dataclass(slots=True)
class PatchPolicyCheck:
    allowed_files_only: bool
    forbidden_changes_detected: bool
    changed_files_count: int
    estimated_diff_lines: int
    within_patch_boundaries: bool
    violations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PatchValidationPlan:
    build_commands: list[str]
    security_tests: list[str]
    business_regression_tests: list[str]
    scanner_rescan_required: bool


@dataclass(slots=True)
class PatchCandidate:
    patch_id: str
    finding_id: str
    status: PatchCandidateStatus
    summary: str
    artifacts: list[PatchArtifact]
    changed_files: list[ChangedFile]
    test_changes: list[TestPlanItem]
    security_notes: list[str]
    assumptions: list[str]
    risks: list[str]
    validation_plan: PatchValidationPlan
    policy_check: PatchPolicyCheck
    blocked_reason: str | None = None
    needs_human_review: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class VerificationCheck:
    name: str
    status: VerificationCheckStatus
    details: str


@dataclass(slots=True)
class PatchValidationResult:
    patch_id: str
    finding_id: str
    status: PatchValidationStatus
    checks: list[VerificationCheck]
    failures: list[VerificationFailure]
    next_action: str
    feedback_for_regeneration: str | None = None
    needs_human_review: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ValidationToolResult:
    layer: ValidationLayer
    tool_name: str
    status: ToolExecutionStatus
    summary: str
    command: str | None = None
    evidence: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int | None = None


@dataclass(slots=True)
class ValidationLayerResult:
    layer: ValidationLayer
    status: ToolExecutionStatus
    tool_results: list[ValidationToolResult]
    summary: str


@dataclass(slots=True)
class ValidationToolchainResult:
    patch_id: str
    finding_id: str
    status: PatchValidationStatus
    layers: list[ValidationLayerResult]
    failures: list[VerificationFailure]
    next_action: str
    feedback_for_failure_analysis: str | None = None
    report_ready: bool = False
    needs_human_review: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FailureFinding:
    category: FailureCategory
    severity: FailureSeverity
    failed_layer: ValidationLayer | None
    summary: str
    evidence: list[str]
    suspected_reason: str
    suggested_adjustment: str


@dataclass(slots=True)
class FailureAnalysisResult:
    patch_id: str
    finding_id: str
    primary_category: FailureCategory
    summary: str
    findings: list[FailureFinding]
    route_to: RemediationFeedbackTarget
    remediation_feedback: list[str]
    patch_generation_feedback: list[str]
    validation_feedback: list[str]
    requires_root_cause_recheck: bool
    needs_human_review: bool
    diagnostic_hypotheses: list[str] = field(default_factory=list)
    reflection: list[str] = field(default_factory=list)
    do_not_repeat: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ReportSection:
    title: str
    content: str


@dataclass(slots=True)
class RemediationReport:
    report_id: str
    finding_id: str
    patch_id: str
    status: RemediationReportStatus
    title: str
    executive_summary: str
    root_cause_summary: str
    remediation_summary: str
    changed_files: list[str]
    test_results: list[str]
    security_validation_results: list[str]
    validation_summary: list[str]
    risk_summary: list[str]
    rollback_summary: str
    human_review_focus: list[str]
    pr_description_markdown: str
    ticket_comment_markdown: str
    sections: list[ReportSection]
    blocked_reason: str | None = None
    needs_human_review: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RepairLoopAttempt:
    attempt: int
    remediation_plan: RemediationPlan
    patch_candidate: PatchCandidate
    validation: ValidationToolchainResult
    failure_analysis: FailureAnalysisResult | None = None


@dataclass(slots=True)
class RepairLoopResult:
    finding_id: str
    status: RepairLoopStatus
    attempts: list[RepairLoopAttempt]
    final_report: RemediationReport | None
    final_failure_analysis: FailureAnalysisResult | None
    next_action: str
    needs_human_review: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
