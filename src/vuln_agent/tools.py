from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .models import ApiEntryPoint, CodePoint, FailedControl, NormalizedVulnerability, PropagationStep


@dataclass(slots=True)
class CodeContext:
    services: list[str] = field(default_factory=list)
    call_paths: list[list[str]] = field(default_factory=list)
    entry_points: list[ApiEntryPoint] = field(default_factory=list)
    data_classification: list[str] = field(default_factory=list)
    upstream_dependencies: list[str] = field(default_factory=list)
    downstream_dependencies: list[str] = field(default_factory=list)
    related_tests: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AssetContext:
    deployed_assets: list[str] = field(default_factory=list)
    affected_artifacts: list[str] = field(default_factory=list)
    internet_exposure_known: bool = False


@dataclass(slots=True)
class RuntimeContext:
    observed_routes: list[str] = field(default_factory=list)
    observed_call_paths: list[list[str]] = field(default_factory=list)
    evidence_available: bool = False


@dataclass(slots=True)
class RootCauseCodeContext:
    source: CodePoint | None = None
    propagation: list[PropagationStep] = field(default_factory=list)
    sink: CodePoint | None = None
    guards: list[str] = field(default_factory=list)
    failed_controls: list[FailedControl] = field(default_factory=list)
    trigger_conditions: list[str] = field(default_factory=list)
    vulnerable_code: str | None = None
    language: str | None = None
    framework: str | None = None
    evidence_available: bool = False


@dataclass(slots=True)
class ConfigurationContext:
    key: str
    effective_value: str
    secure_value: str | None = None
    source_file: str | None = None
    unsafe: bool = False


@dataclass(slots=True)
class DependencyRootCauseContext:
    component: str
    dependency_path: list[str] = field(default_factory=list)
    runtime_used: bool | None = None
    vulnerable_feature_used: bool | None = None
    cve_match_confirmed: bool = False


class CodeContextTool(Protocol):
    def collect(self, finding: NormalizedVulnerability) -> CodeContext: ...


class AssetInventoryTool(Protocol):
    def collect(self, finding: NormalizedVulnerability) -> AssetContext: ...


class RuntimeEvidenceTool(Protocol):
    def collect(self, finding: NormalizedVulnerability) -> RuntimeContext: ...


class RootCauseEvidenceTool(Protocol):
    def collect_code_evidence(self, finding: NormalizedVulnerability) -> RootCauseCodeContext: ...

    def collect_configuration_evidence(self, finding: NormalizedVulnerability) -> list[ConfigurationContext]: ...

    def collect_dependency_evidence(self, finding: NormalizedVulnerability) -> DependencyRootCauseContext | None: ...


@dataclass(slots=True)
class StaticCodeContextTool:
    """MVP adapter; replace with AST/index/call-graph adapters."""

    contexts: dict[str, CodeContext]

    def collect(self, finding: NormalizedVulnerability) -> CodeContext:
        return self.contexts.get(finding.finding_id, CodeContext())


@dataclass(slots=True)
class StaticAssetInventoryTool:
    contexts: dict[str, AssetContext]

    def collect(self, finding: NormalizedVulnerability) -> AssetContext:
        return self.contexts.get(finding.finding_id, AssetContext())


@dataclass(slots=True)
class StaticRuntimeEvidenceTool:
    contexts: dict[str, RuntimeContext]

    def collect(self, finding: NormalizedVulnerability) -> RuntimeContext:
        return self.contexts.get(finding.finding_id, RuntimeContext())


@dataclass(slots=True)
class StaticRootCauseEvidenceTool:
    code_contexts: dict[str, RootCauseCodeContext] = field(default_factory=dict)
    configuration_contexts: dict[str, list[ConfigurationContext]] = field(default_factory=dict)
    dependency_contexts: dict[str, DependencyRootCauseContext] = field(default_factory=dict)

    def collect_code_evidence(self, finding: NormalizedVulnerability) -> RootCauseCodeContext:
        return self.code_contexts.get(finding.finding_id, RootCauseCodeContext())

    def collect_configuration_evidence(self, finding: NormalizedVulnerability) -> list[ConfigurationContext]:
        return self.configuration_contexts.get(finding.finding_id, [])

    def collect_dependency_evidence(self, finding: NormalizedVulnerability) -> DependencyRootCauseContext | None:
        return self.dependency_contexts.get(finding.finding_id)
