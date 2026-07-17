from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace

from vuln_agent.execution import WorkspaceValidationExecutor
from vuln_agent.models import (
    CompatibilityAssessment,
    EvidenceBundle,
    PatchBoundaries,
    PatchCandidateStatus,
    PatchValidationStatus,
    PatchGenerationPolicy,
    PlannedChange,
    RemediationPlan,
    RemediationPlanStatus,
    RepositoryContext,
    RepositorySummary,
    RollbackPlan,
    Severity,
    SourceFile,
    TestPlanItem as PlanTestItem,
    ValidationCapabilities,
    ValidationLayer,
)
from vuln_agent.normalization import VulnerabilityNormalizer
from vuln_agent.patching import PatchGenerationAgent
from vuln_agent.sca_executor import SCADependencyRepairExecutor
from vuln_agent.routing import RepairTaskClassifier
from vuln_agent.validation import ValidationToolchain


def make_finding(
    component: str,
    current: str,
    fixed: list[str],
    path: str,
    *,
    breaking: bool | None = False,
):
    return VulnerabilityNormalizer().normalize({
        "finding_id": "sca-executor-test",
        "vulnerability_type": "dependency",
        "severity": "high",
        "scanner": "test-sca",
        "affected_file": path,
        "component": component,
        "current_version": current,
        "fixed_versions": fixed,
        "breaking_upgrade": breaking,
        "evidence": f"{component} {current} is vulnerable",
    })


def make_plan(paths: list[str]) -> RemediationPlan:
    return RemediationPlan(
        finding_id="sca-executor-test",
        status=RemediationPlanStatus.READY,
        remediation_goal="remove the vulnerable direct dependency version",
        strategies=[],
        planned_changes=[
            PlannedChange(
                path,
                "dependency",
                "upgrade the vulnerable direct dependency",
                "reported fixed version is available",
                Severity.MEDIUM,
                causally_required=True,
            )
            for path in paths
        ],
        dependency_upgrade=None,
        compatibility=CompatibilityAssessment(
            "requires_regression",
            [],
            ["run the project build and consumer tests"],
        ),
        risk_points=[],
        required_tests=[
            PlanTestItem(
                "dependency compatibility",
                "business_regression",
                paths[0],
                "consumers still build and pass tests",
            ),
            PlanTestItem(
                "dependency rescan",
                "security_scan",
                paths[0],
                "the vulnerable version is absent",
            ),
        ],
        rejected_alternatives=[],
        rollback=RollbackPlan("revert manifests", ["revert the dependency diff"]),
        patch_boundaries=PatchBoundaries(paths, [], max(3, len(paths)), 200),
        assumptions=[],
        unknowns=[],
        confidence_score=1.0,
        needs_human_review=True,
    )


def make_evidence() -> EvidenceBundle:
    return EvidenceBundle(
        finding_id="sca-executor-test",
        repository_summary=RepositorySummary(None, None, 1, []),
        target_files=[],
        code_slices=[],
        entry_points=[],
        source_candidates=[],
        sink_candidates=[],
        dependency_evidence=[],
        test_evidence=[],
        config_evidence=[],
        validation_capabilities=ValidationCapabilities(),
        collection_warnings=[],
        bundle_hash="test",
    )


class SCAWorkspaceExecutorTests(unittest.TestCase):
    def _execute(
        self,
        component: str,
        current: str,
        fixed: list[str],
        path: str,
        content: str,
        *,
        breaking: bool | None = False,
        extra: list[SourceFile] | None = None,
        lockfile_regenerator=None,
    ):
        finding = make_finding(
            component,
            current,
            fixed,
            path,
            breaking=breaking,
        )
        return SCADependencyRepairExecutor(
            lockfile_regenerator=lockfile_regenerator,
        ).execute(
            finding,
            make_plan([path]),
            [SourceFile(path, content), *(extra or [])],
            make_evidence(),
        )

    def test_requirements_selects_lowest_same_major_fixed_version(self):
        result = self._execute(
            "django",
            "5.0.6",
            ["6.0.0", "5.0.8", "5.1.1"],
            "requirements.txt",
            "Django==5.0.6\npytest==8.0.0\n",
        )
        self.assertIsNone(result["blocked_reason"])
        self.assertIn("-Django==5.0.6", result["artifacts"][0]["content"])
        self.assertIn("+Django==5.0.8", result["artifacts"][0]["content"])
        self.assertTrue(all(item["passed"] for item in result["workspace_checks"]))

    def test_pep621_pyproject_dependency_is_updated(self):
        result = self._execute(
            "django",
            "5.0.6",
            ["5.0.8"],
            "pyproject.toml",
            (
                "[project]\n"
                "name = \"demo\"\n"
                "version = \"1.0.0\"\n"
                "dependencies = [\"Django==5.0.6\"]\n"
            ),
        )
        self.assertIsNone(result["blocked_reason"])
        self.assertIn("Django==5.0.8", result["artifacts"][0]["content"])

    def test_package_json_range_preserves_operator(self):
        result = self._execute(
            "lodash",
            "4.17.20",
            ["4.17.21"],
            "package.json",
            (
                "{\n"
                "  \"name\": \"demo\",\n"
                "  \"version\": \"1.0.0\",\n"
                "  \"dependencies\": {\n"
                "    \"lodash\": \"^4.17.20\"\n"
                "  }\n"
                "}\n"
            ),
        )
        self.assertIsNone(result["blocked_reason"])
        self.assertIn('"lodash": "^4.17.21"', result["artifacts"][0]["content"])

    def test_maven_direct_dependency_is_updated(self):
        result = self._execute(
            "org.apache.struts:struts2-core",
            "2.3.31",
            ["2.5.10.1", "2.3.32"],
            "pom.xml",
            (
                "<project><modelVersion>4.0.0</modelVersion><dependencies>"
                "<dependency><groupId>org.apache.struts</groupId>"
                "<artifactId>struts2-core</artifactId>"
                "<version>2.3.31</version></dependency>"
                "</dependencies></project>"
            ),
        )
        self.assertIsNone(result["blocked_reason"])
        self.assertIn("<version>2.3.32</version>", result["artifacts"][0]["content"])

    def test_go_mod_and_cargo_manifest_are_supported(self):
        cases = [
            (
                "golang.org/x/text",
                "0.3.7",
                "0.3.8",
                "go.mod",
                "module example.com/demo\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.7\n",
            ),
            (
                "time",
                "0.3.20",
                "0.3.36",
                "Cargo.toml",
                (
                    "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n"
                    "[dependencies]\ntime = \"=0.3.20\"\n"
                ),
            ),
        ]
        for component, current, fixed, path, content in cases:
            with self.subTest(path=path):
                result = self._execute(
                    component,
                    current,
                    [fixed],
                    path,
                    content,
                    breaking=True,
                )
                self.assertIsNone(result["blocked_reason"])
                self.assertIn(fixed, result["artifacts"][0]["content"])

    def test_phase2_stability_matrix_15_direct_dependency_upgrades(self):
        cases = [
            ("flask", "2.2.2", "2.2.5", "requirements.txt", "Flask==2.2.2\n"),
            ("requests", "2.31.0", "2.32.4", "requirements.txt", "requests~=2.31.0\n"),
            ("PyYAML", "5.3.0", "5.4.1", "requirements.txt", "PyYAML>=5.3.0\n"),
            (
                "django", "5.0.6", "5.0.8", "pyproject.toml",
                "[project]\nname='demo'\nversion='1.0.0'\ndependencies=['Django==5.0.6']\n",
            ),
            (
                "urllib3", "2.1.0", "2.2.2", "pyproject.toml",
                "[project]\nname='demo'\nversion='1.0.0'\ndependencies=['urllib3>=2.1.0']\n",
            ),
            (
                "jinja2", "3.1.2", "3.1.4", "pyproject.toml",
                "[tool.poetry]\nname='demo'\nversion='1.0.0'\n"
                "[tool.poetry.dependencies]\npython='^3.11'\njinja2='^3.1.2'\n",
            ),
            (
                "lodash", "4.17.20", "4.17.21", "package.json",
                '{"name":"demo","version":"1.0.0","dependencies":{\n'
                '  "lodash": "^4.17.20"\n}}\n',
            ),
            (
                "axios", "1.6.0", "1.6.8", "package.json",
                '{"name":"demo","version":"1.0.0","dependencies":{\n'
                '  "axios": "~1.6.0"\n}}\n',
            ),
            (
                "minimist", "1.2.5", "1.2.8", "package.json",
                '{"name":"demo","version":"1.0.0","dependencies":{\n'
                '  "minimist": ">=1.2.5"\n}}\n',
            ),
            (
                "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1", "pom.xml",
                "<project><dependencies><dependency>"
                "<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>"
                "<version>2.14.1</version></dependency></dependencies></project>",
            ),
            (
                "org.apache.commons:commons-text", "1.9", "1.10.0", "pom.xml",
                "<project><dependencies><dependency><groupId>org.apache.commons</groupId>"
                "<artifactId>commons-text</artifactId><version>1.9</version>"
                "</dependency></dependencies></project>",
            ),
            (
                "org.springframework:spring-core", "5.3.17", "5.3.20", "pom.xml",
                "<project><properties><spring-core.version>5.3.17</spring-core.version>"
                "</properties><dependencies><dependency><groupId>org.springframework</groupId>"
                "<artifactId>spring-core</artifactId><version>${spring-core.version}</version>"
                "</dependency></dependencies></project>",
            ),
            (
                "golang.org/x/text", "0.3.7", "0.3.8", "go.mod",
                "module example.com/demo\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.7\n",
            ),
            (
                "golang.org/x/net", "0.17.0", "0.23.0", "go.mod",
                "module example.com/demo\n\ngo 1.22\n\nrequire golang.org/x/net v0.17.0\n",
            ),
            (
                "time", "0.3.20", "0.3.36", "Cargo.toml",
                "[package]\nname='demo'\nversion='0.1.0'\n"
                "[dependencies]\ntime={ version='=0.3.20', features=['formatting'] }\n",
            ),
        ]
        for index, (component, current, target, path, content) in enumerate(cases):
            with self.subTest(case=index, ecosystem=path):
                result = self._execute(
                    component,
                    current,
                    [target],
                    path,
                    content,
                    breaking=False,
                )
                self.assertIsNone(result["blocked_reason"])
                self.assertTrue(result["artifacts"])
                self.assertTrue(
                    all(item["passed"] for item in result["workspace_checks"])
                )

    def test_matching_lockfile_blocks_instead_of_faking_metadata(self):
        result = self._execute(
            "lodash",
            "4.17.20",
            ["4.17.21"],
            "package.json",
            (
                "{\n"
                "  \"name\": \"demo\",\n"
                "  \"version\": \"1.0.0\",\n"
                "  \"dependencies\": {\n"
                "    \"lodash\": \"4.17.20\"\n"
                "  }\n"
                "}\n"
            ),
            extra=[SourceFile(
                "package-lock.json",
                (
                    '{"lockfileVersion":3,"packages":'
                    '{"node_modules/lodash":{"version":"4.17.20"}}}\n'
                ),
            )],
            lockfile_regenerator=(
                lambda workspace, ecosystem, component, target, lockfiles:
                (False, "offline registry cache is unavailable")
            ),
        )
        self.assertIsNotNone(result["blocked_reason"])
        self.assertIn("could not be reproduced safely offline", result["blocked_reason"])
        self.assertEqual(result["artifacts"], [])

    def test_reproducible_lockfile_regeneration_is_included_in_candidate(self):
        def regenerate(workspace, ecosystem, component, target, lockfiles):
            self.assertEqual(ecosystem, "npm")
            self.assertEqual(component, "lodash")
            self.assertEqual(target, "4.17.21")
            (workspace / "package-lock.json").write_text(
                (
                    '{"lockfileVersion":3,"packages":'
                    '{"node_modules/lodash":{"version":"4.17.21"}}}\n'
                ),
                encoding="utf-8",
            )
            return True, "fixture package manager completed offline"

        result = self._execute(
            "lodash",
            "4.17.20",
            ["4.17.21"],
            "package.json",
            (
                "{\n"
                "  \"name\": \"demo\",\n"
                "  \"version\": \"1.0.0\",\n"
                "  \"dependencies\": {\n"
                "    \"lodash\": \"4.17.20\"\n"
                "  }\n"
                "}\n"
            ),
            extra=[SourceFile(
                "package-lock.json",
                (
                    '{"lockfileVersion":3,"packages":'
                    '{"node_modules/lodash":{"version":"4.17.20"}}}\n'
                ),
            )],
            lockfile_regenerator=regenerate,
        )
        self.assertIsNone(result["blocked_reason"])
        self.assertEqual(
            {item["target"] for item in result["artifacts"]},
            {"package.json", "package-lock.json"},
        )
        lock_check = next(
            item for item in result["workspace_checks"]
            if item["name"] == "lockfile_resolution"
        )
        self.assertTrue(lock_check["passed"])

    def test_transitive_lockfile_only_dependency_is_blocked(self):
        finding = make_finding(
            "lodash",
            "4.17.20",
            ["4.17.21"],
            "package.json",
        )
        result = SCADependencyRepairExecutor().execute(
            finding,
            make_plan(["package.json"]),
            [
                SourceFile(
                    "package.json",
                    (
                        "{\n"
                        "  \"name\": \"demo\",\n"
                        "  \"version\": \"1.0.0\",\n"
                        "  \"dependencies\": {\"express\": \"4.18.0\"}\n"
                        "}\n"
                    ),
                ),
                SourceFile(
                    "package-lock.json",
                    (
                        '{"lockfileVersion":3,"packages":'
                        '{"node_modules/lodash":{"version":"4.17.20"}}}\n'
                    ),
                ),
            ],
            make_evidence(),
        )
        self.assertIn("transitive", result["blocked_reason"])
        self.assertEqual(result["artifacts"], [])

    def test_missing_fixed_version_blocks(self):
        result = self._execute(
            "django",
            "5.0.6",
            [],
            "requirements.txt",
            "Django==5.0.6\n",
        )
        self.assertIn("fixed_version", result["blocked_reason"])

    def test_non_breaking_upgrade_without_same_major_fixed_version_blocks(self):
        result = self._execute(
            "django",
            "5.0.6",
            ["6.0.0"],
            "requirements.txt",
            "Django==5.0.6\n",
            breaking=False,
        )
        self.assertIn("no fixed version shares", result["blocked_reason"])
        self.assertEqual(result["artifacts"], [])

    def test_manifest_version_must_match_reported_current_version(self):
        result = self._execute(
            "django",
            "5.0.6",
            ["5.0.8"],
            "requirements.txt",
            "Django==5.0.5\n",
        )
        self.assertIn("no exact vulnerable declaration", result["blocked_reason"])
        self.assertEqual(result["artifacts"], [])

    def test_patch_generation_routes_dependency_to_sca_executor(self):
        path = "requirements.txt"
        source = "Django==5.0.6\n"
        finding = make_finding("django", "5.0.6", ["5.0.8"], path)
        agent = PatchGenerationAgent(PatchGenerationPolicy(), llm=None)
        candidate = agent.generate(
            finding,
            SimpleNamespace(),
            SimpleNamespace(),
            make_plan([path]),
            RepositoryContext(language="Python", package_manager="pip"),
            [SourceFile(path, source)],
            evidence_bundle=make_evidence(),
        )
        self.assertEqual(candidate.status, PatchCandidateStatus.GENERATED)
        self.assertEqual(
            agent.last_execution.details["executor"],
            "sca_dependency_workspace_executor",
        )
        self.assertEqual(candidate.artifacts[0].patch_type.value, "dependency")

    def test_classifier_ineligibility_stops_before_patch_synthesis(self):
        path = "requirements.txt"
        finding = make_finding("django", "5.0.6", ["5.0.8"], path)
        evidence = make_evidence()
        route = RepairTaskClassifier().route(finding, evidence)
        self.assertFalse(route.automation_eligible)
        agent = PatchGenerationAgent(
            PatchGenerationPolicy(),
            llm=None,
            repair_route=route,
        )
        candidate = agent.generate(
            finding,
            SimpleNamespace(),
            SimpleNamespace(),
            make_plan([path]),
            RepositoryContext(language="Python", package_manager="pip"),
            [SourceFile(path, "Django==5.0.6\n")],
            evidence_bundle=evidence,
        )
        self.assertEqual(candidate.status, PatchCandidateStatus.BLOCKED)
        self.assertIn("dependency_manifest", candidate.blocked_reason)
        self.assertEqual(candidate.artifacts, [])

    def test_sca_candidate_completes_mandatory_workspace_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text(
                "Django==5.0.6\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "def dependency_consumer_contract():\n    return 'compatible'\n",
                encoding="utf-8",
            )
            (root / "tests").mkdir()
            (root / "tests" / "test_app.py").write_text(
                (
                    "from app import dependency_consumer_contract\n\n"
                    "def test_dependency_consumer_contract():\n"
                    "    assert dependency_consumer_contract() == 'compatible'\n"
                ),
                encoding="utf-8",
            )
            finding = make_finding(
                "django",
                "5.0.6",
                ["5.0.8"],
                "requirements.txt",
            )
            agent = PatchGenerationAgent(
                PatchGenerationPolicy(),
                llm=None,
                workspace=root,
            )
            remediation = make_plan(["requirements.txt"])
            candidate = agent.generate(
                finding,
                SimpleNamespace(),
                SimpleNamespace(),
                remediation,
                RepositoryContext(language="Python", package_manager="pip"),
                [
                    SourceFile("requirements.txt", "Django==5.0.6\n"),
                    SourceFile(
                        "app.py",
                        "def dependency_consumer_contract():\n    return 'compatible'\n",
                    ),
                    SourceFile(
                        "tests/test_app.py",
                        (
                            "from app import dependency_consumer_contract\n\n"
                            "def test_dependency_consumer_contract():\n"
                            "    assert dependency_consumer_contract() == 'compatible'\n"
                        ),
                    ),
                ],
                evidence_bundle=make_evidence(),
            )
            executor = WorkspaceValidationExecutor(
                root,
                {
                    "build": "python -m py_compile app.py",
                    "business_regression": (
                        "python -m pytest tests/test_app.py -q -p no:cacheprovider"
                    ),
                },
            )
            result = ValidationToolchain(
                required_layers=(
                    ValidationLayer.BUILD,
                    ValidationLayer.BUSINESS_REGRESSION,
                    ValidationLayer.DIFFERENTIAL_RISK,
                ),
                executor=executor,
            ).validate(candidate, remediation, [])
            self.assertEqual(result.status, PatchValidationStatus.PASSED)
            self.assertTrue(all(layer.status.value == "passed" for layer in result.layers))


if __name__ == "__main__":
    unittest.main()
