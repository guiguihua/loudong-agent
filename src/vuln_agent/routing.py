"""Deterministic vulnerability routing and validation-profile selection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .models import EvidenceBundle, NormalizedVulnerability, ValidationLayer


class VulnerabilityFamily(StrEnum):
    SAST_CODE = "sast_code"
    DEPENDENCY = "dependency"
    MEMORY_SAFETY = "memory_safety"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    GENERIC = "generic"


class RepairExecutor(StrEnum):
    SAST_CODE = "sast_code_executor"
    SCA_DEPENDENCY = "sca_dependency_executor"
    POC_PATCH_AGENT = "poc_patch_agent"
    WEB_AUTHORIZATION = "web_authorization_executor"
    CONFIGURATION = "configuration_executor"
    GENERIC_CODE = "generic_code_executor"


@dataclass(frozen=True, slots=True)
class VerificationProfile:
    name: str
    required_layers: tuple[ValidationLayer, ...]
    optional_layers: tuple[ValidationLayer, ...]
    rationale: str
    security_oracles: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "required_layers": [layer.value for layer in self.required_layers],
            "optional_layers": [layer.value for layer in self.optional_layers],
            "rationale": self.rationale,
            "security_oracles": list(self.security_oracles),
        }


@dataclass(frozen=True, slots=True)
class RepairRoute:
    family: VulnerabilityFamily
    preferred_executor: RepairExecutor
    active_executor: RepairExecutor
    verification_profile: VerificationProfile
    confidence: float
    automation_eligible: bool = True
    blocking_reasons: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    fallback_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "family": self.family.value,
            "preferred_executor": self.preferred_executor.value,
            "active_executor": self.active_executor.value,
            "verification_profile": self.verification_profile.to_dict(),
            "confidence": self.confidence,
            "automation_eligible": self.automation_eligible,
            "blocking_reasons": list(self.blocking_reasons),
            "missing_evidence": list(self.missing_evidence),
            "fallback_reason": self.fallback_reason,
        }


class VulnerabilityRouter:
    """Route by stable finding/evidence signals, not by model intuition.

    The project currently implements generic code/config/dependency execution.
    Routes for PoC-driven memory-safety and authorization specialists are made
    explicit, but truthfully report the generic fallback until those adapters
    are connected.
    """

    _MEMORY_TERMS = (
        "buffer overflow", "heap overflow", "stack overflow", "out-of-bounds",
        "use-after-free", "double free", "memory corruption", "integer overflow",
        "sanitizer", "asan", "ubsan", "内存破坏", "越界", "释放后使用",
    )
    _AUTHORIZATION_TERMS = (
        "idor", "authorization", "access control", "privilege escalation",
        "permission", "tenant isolation", "越权", "权限", "未授权访问",
    )
    _CONFIG_TERMS = (
        "configuration", "misconfiguration", "hardening", "tls", "cors",
        "security header", "配置", "错误配置",
    )
    _SAST_TERMS = (
        "sql injection", "command injection", "code injection", "xss",
        "cross-site scripting", "path traversal", "ssrf", "deserialization",
        "template injection", "open redirect", "csrf", "注入", "路径遍历",
        "跨站脚本", "反序列化",
    )

    def route(
        self,
        finding: NormalizedVulnerability,
        evidence: EvidenceBundle,
    ) -> RepairRoute:
        text = " ".join(
            [
                finding.vulnerability_type,
                finding.cve or "",
                finding.cwe or "",
                *finding.evidence,
            ]
        ).lower()

        missing: list[str] = []
        if not evidence.target_files and finding.dependency is None:
            missing.append("target_source_file")
        if not evidence.validation_capabilities.test_commands:
            missing.append("business_regression_command")
        if not evidence.validation_capabilities.security_commands:
            missing.append("security_regression_command")

        if finding.dependency is not None or "dependency" in text or "component" in text:
            family = VulnerabilityFamily.DEPENDENCY
            preferred = active = RepairExecutor.SCA_DEPENDENCY
            confidence = 0.98
            dependency = finding.dependency
            if dependency is None or not dependency.current_version:
                missing.append("dependency_current_version")
            if dependency is None or not dependency.fixed_versions:
                missing.append("dependency_fixed_version")
            if not evidence.target_files and not any(
                item.path for item in evidence.dependency_evidence
            ):
                missing.append("dependency_manifest")
        elif any(term in text for term in self._MEMORY_TERMS):
            family = VulnerabilityFamily.MEMORY_SAFETY
            preferred = RepairExecutor.POC_PATCH_AGENT
            active = RepairExecutor.GENERIC_CODE
            confidence = 0.9
            if not any(term in text for term in ("poc", "reproducer", "crash", "sanitizer", "asan", "ubsan")):
                missing.append("poc_or_sanitizer_reproducer")
        elif any(term in text for term in self._AUTHORIZATION_TERMS):
            family = VulnerabilityFamily.AUTHORIZATION
            preferred = RepairExecutor.WEB_AUTHORIZATION
            active = RepairExecutor.GENERIC_CODE
            confidence = 0.9
        elif any(term in text for term in self._CONFIG_TERMS):
            family = VulnerabilityFamily.CONFIGURATION
            preferred = RepairExecutor.CONFIGURATION
            active = RepairExecutor.GENERIC_CODE
            confidence = 0.85
        elif any(term in text for term in self._SAST_TERMS):
            family = VulnerabilityFamily.SAST_CODE
            preferred = RepairExecutor.SAST_CODE
            active = (
                RepairExecutor.SAST_CODE
                if self._supported_sast_family(text)
                else RepairExecutor.GENERIC_CODE
            )
            confidence = 0.95
        else:
            family = VulnerabilityFamily.GENERIC
            preferred = active = RepairExecutor.GENERIC_CODE
            confidence = 0.55

        profile = self._profile(family, evidence, text)
        blocking_reasons = self._blocking_reasons(
            family,
            active,
            tuple(dict.fromkeys(missing)),
        )
        fallback_reason = None
        if active != preferred:
            fallback_reason = (
                f"{preferred.value} is not connected; using {active.value} with "
                "the family-specific verification profile"
            )
        return RepairRoute(
            family=family,
            preferred_executor=preferred,
            active_executor=active,
            verification_profile=profile,
            confidence=confidence,
            automation_eligible=not blocking_reasons,
            blocking_reasons=blocking_reasons,
            missing_evidence=tuple(dict.fromkeys(missing)),
            fallback_reason=fallback_reason,
        )

    @staticmethod
    def _supported_sast_family(text: str) -> bool:
        return (
            ("sql" in text and "inject" in text)
            or "command injection" in text
            or "os command" in text
            or "命令注入" in text
            or "path traversal" in text
            or "directory traversal" in text
            or "路径遍历" in text
        )

    @staticmethod
    def _blocking_reasons(
        family: VulnerabilityFamily,
        active: RepairExecutor,
        missing: tuple[str, ...],
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        required_evidence = {
            VulnerabilityFamily.DEPENDENCY: {
                "dependency_current_version",
                "dependency_fixed_version",
                "dependency_manifest",
            },
            VulnerabilityFamily.SAST_CODE: {"target_source_file"},
            VulnerabilityFamily.MEMORY_SAFETY: {
                "target_source_file",
                "poc_or_sanitizer_reproducer",
            },
            VulnerabilityFamily.AUTHORIZATION: {"target_source_file"},
            VulnerabilityFamily.CONFIGURATION: {"target_source_file"},
            VulnerabilityFamily.GENERIC: {"target_source_file"},
        }[family]
        reasons.extend(item for item in missing if item in required_evidence)
        if (
            family in {
                VulnerabilityFamily.SAST_CODE,
                VulnerabilityFamily.MEMORY_SAFETY,
                VulnerabilityFamily.AUTHORIZATION,
                VulnerabilityFamily.CONFIGURATION,
            }
            and active == RepairExecutor.GENERIC_CODE
        ):
            reasons.append("specialist_executor_unavailable")
        return tuple(dict.fromkeys(reasons))

    @staticmethod
    def _profile(
        family: VulnerabilityFamily,
        evidence: EvidenceBundle,
        finding_text: str = "",
    ) -> VerificationProfile:
        scanner_available = bool(evidence.validation_capabilities.scanner_commands)
        scanner = (ValidationLayer.SCANNER_RESCAN,) if scanner_available else ()

        if family == VulnerabilityFamily.DEPENDENCY:
            required = (
                ValidationLayer.BUILD,
                ValidationLayer.BUSINESS_REGRESSION,
                *scanner,
                ValidationLayer.DIFFERENTIAL_RISK,
            )
            optional = (
                ValidationLayer.SECURITY_REGRESSION,
                *(() if scanner_available else (ValidationLayer.SCANNER_RESCAN,)),
            )
            return VerificationProfile(
                "dependency_upgrade",
                required,
                optional,
                "Require install/build, regression, lockfile diff risk, and scanner rescan when available.",
                ("dependency_resolution", "compatibility_regression", "sca_rescan"),
            )

        if family == VulnerabilityFamily.CONFIGURATION:
            required = (
                ValidationLayer.BUILD,
                ValidationLayer.SECURITY_REGRESSION,
                *scanner,
                ValidationLayer.DIFFERENTIAL_RISK,
            )
            optional = (
                ValidationLayer.BUSINESS_REGRESSION,
                *(() if scanner_available else (ValidationLayer.SCANNER_RESCAN,)),
            )
            return VerificationProfile(
                "configuration_security",
                required,
                optional,
                "Require configuration load/build and a security behavior check.",
                ("configuration_load", "runtime_security_probe"),
            )

        required = (
            ValidationLayer.BUILD,
            ValidationLayer.BUSINESS_REGRESSION,
            ValidationLayer.SECURITY_REGRESSION,
            *scanner,
            ValidationLayer.DIFFERENTIAL_RISK,
        )
        optional = () if scanner_available else (ValidationLayer.SCANNER_RESCAN,)
        name = {
            VulnerabilityFamily.MEMORY_SAFETY: "memory_safety_poc",
            VulnerabilityFamily.AUTHORIZATION: "authorization_behavior",
            VulnerabilityFamily.SAST_CODE: "sast_code_dataflow",
            VulnerabilityFamily.GENERIC: "generic_code",
        }[family]
        oracles: tuple[str, ...] = (
            "exact_patch_apply",
            "attack_regression",
            "legitimate_behavior_regression",
        )
        if family == VulnerabilityFamily.SAST_CODE:
            if "sql" in finding_text and "inject" in finding_text:
                name = "sast_sql_injection"
                oracles = (*oracles, "parameterized_query_or_safe_query_builder")
            elif "command" in finding_text or "命令注入" in finding_text:
                name = "sast_command_injection"
                oracles = (*oracles, "no_shell_interpretation")
            elif "path traversal" in finding_text or "directory traversal" in finding_text or "路径遍历" in finding_text:
                name = "sast_path_traversal"
                oracles = (*oracles, "resolved_path_containment")
        return VerificationProfile(
            name,
            required,
            optional,
            "Require exact application, business regression, exploit/security regression, and diff-risk review.",
            oracles,
        )


class RepairTaskClassifier(VulnerabilityRouter):
    """Phase-2 public name for deterministic task classification.

    ``VulnerabilityRouter`` remains as a compatibility alias for existing API
    callers; both expose the same evidence-aware route contract.
    """
