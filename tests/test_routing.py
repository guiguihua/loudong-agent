from __future__ import annotations

import unittest

from vuln_agent.models import (
    DependencyEvidence,
    EvidenceBundle,
    FileEvidence,
    RepositorySummary,
    ValidationCapabilities,
    ValidationLayer,
)
from vuln_agent.normalization import VulnerabilityNormalizer
from vuln_agent.routing import RepairExecutor, VulnerabilityFamily, VulnerabilityRouter


def finding(vulnerability_type: str, **extra):
    raw = {
        "finding_id": "route-test",
        "vulnerability_type": vulnerability_type,
        "severity": "high",
        "scanner": "test",
        "affected_file": "src/app.py",
        "evidence": "confirmed vulnerable call path",
        **extra,
    }
    return VulnerabilityNormalizer().normalize(raw)


def bundle(*, scanner: bool = False, manifest: bool = False) -> EvidenceBundle:
    return EvidenceBundle(
        finding_id="route-test",
        repository_summary=RepositorySummary(None, None, 1, ["Python"]),
        target_files=(
            [FileEvidence("requirements.txt", "exact_path", 1, "hash", None)]
            if manifest else []
        ),
        code_slices=[],
        entry_points=[],
        source_candidates=[],
        sink_candidates=[],
        dependency_evidence=(
            [DependencyEvidence(
                "example:library",
                "1.0.0",
                "requirements.txt",
                1,
                "manifest",
            )]
            if manifest else []
        ),
        test_evidence=[],
        config_evidence=[],
        validation_capabilities=ValidationCapabilities(
            build_commands=["python -m compileall ."],
            test_commands=["pytest"],
            security_commands=["pytest tests/security"],
            scanner_commands=["semgrep scan"] if scanner else [],
        ),
        collection_warnings=[],
        bundle_hash="test",
    )


class VulnerabilityRouterTests(unittest.TestCase):
    def test_sast_route_requires_scanner_only_when_available(self):
        route = VulnerabilityRouter().route(finding("SQL Injection"), bundle(scanner=True))
        self.assertEqual(route.family, VulnerabilityFamily.SAST_CODE)
        self.assertEqual(route.active_executor, RepairExecutor.SAST_CODE)
        self.assertEqual(
            route.verification_profile.name,
            "sast_sql_injection",
        )
        self.assertIn(
            "parameterized_query_or_safe_query_builder",
            route.verification_profile.security_oracles,
        )
        self.assertIn(
            ValidationLayer.SCANNER_RESCAN,
            route.verification_profile.required_layers,
        )

    def test_dependency_route_uses_sca_profile(self):
        route = VulnerabilityRouter().route(
            finding(
                "dependency",
                component="example:library",
                current_version="1.0.0",
                fixed_versions=["1.0.1"],
            ),
            bundle(scanner=False),
        )
        self.assertEqual(route.family, VulnerabilityFamily.DEPENDENCY)
        self.assertEqual(route.active_executor, RepairExecutor.SCA_DEPENDENCY)
        self.assertNotIn(
            ValidationLayer.SECURITY_REGRESSION,
            route.verification_profile.required_layers,
        )
        self.assertIn(
            ValidationLayer.SCANNER_RESCAN,
            route.verification_profile.optional_layers,
        )
        self.assertIn("dependency_manifest", route.missing_evidence)
        self.assertFalse(route.automation_eligible)

    def test_dependency_route_reports_missing_version_evidence(self):
        route = VulnerabilityRouter().route(
            finding("dependency", component="example:library"),
            bundle(scanner=False),
        )
        self.assertIn("dependency_current_version", route.missing_evidence)
        self.assertIn("dependency_fixed_version", route.missing_evidence)
        self.assertFalse(route.automation_eligible)

    def test_complete_dependency_evidence_is_automation_eligible(self):
        route = VulnerabilityRouter().route(
            finding(
                "dependency",
                affected_file="requirements.txt",
                component="example:library",
                current_version="1.0.0",
                fixed_versions=["1.0.1"],
            ),
            bundle(scanner=False, manifest=True),
        )
        self.assertTrue(route.automation_eligible)
        self.assertEqual(route.blocking_reasons, ())

    def test_unsupported_sast_family_reports_truthful_ineligible_fallback(self):
        route = VulnerabilityRouter().route(
            finding("Cross-Site Scripting"),
            bundle(),
        )
        self.assertEqual(route.family, VulnerabilityFamily.SAST_CODE)
        self.assertEqual(route.preferred_executor, RepairExecutor.SAST_CODE)
        self.assertEqual(route.active_executor, RepairExecutor.GENERIC_CODE)
        self.assertFalse(route.automation_eligible)
        self.assertIn("specialist_executor_unavailable", route.blocking_reasons)

    def test_memory_safety_route_reports_truthful_fallback(self):
        route = VulnerabilityRouter().route(
            finding("heap buffer overflow"),
            bundle(),
        )
        self.assertEqual(route.family, VulnerabilityFamily.MEMORY_SAFETY)
        self.assertEqual(route.preferred_executor, RepairExecutor.POC_PATCH_AGENT)
        self.assertEqual(route.active_executor, RepairExecutor.GENERIC_CODE)
        self.assertIsNotNone(route.fallback_reason)
        self.assertIn("poc_or_sanitizer_reproducer", route.missing_evidence)


if __name__ == "__main__":
    unittest.main()
