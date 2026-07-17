from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vuln_agent.execution import WorkspaceValidationExecutor
from vuln_agent.models import (
    CompatibilityAssessment,
    PatchArtifact,
    PatchBoundaries,
    PatchCandidate,
    PatchCandidateStatus,
    PatchGenerationPolicy,
    PatchPolicyCheck,
    PatchType,
    PatchValidationPlan,
    PatchValidationStatus,
    PlannedChange,
    RemediationPlan,
    RemediationPlanStatus,
    RollbackPlan,
    Severity,
    SourceFile,
    ToolExecutionStatus,
    ValidationLayer,
)
from vuln_agent.validation import ValidationToolchain, passed_tool
from vuln_agent.reporting import RemediationReportAgent
from vuln_agent.patching import PatchGenerationAgent
from vuln_agent.remediation import RemediationPlanAgent
from vuln_agent.models import EngineeringContext


def candidate(diff: str) -> PatchCandidate:
    return PatchCandidate(
        patch_id="patch-test-001",
        finding_id="test",
        status=PatchCandidateStatus.GENERATED,
        summary="minimal fix",
        artifacts=[PatchArtifact(PatchType.CODE, "app.py", diff, "one-line fix")],
        changed_files=[],
        test_changes=[],
        security_notes=[],
        assumptions=[],
        risks=[],
        validation_plan=PatchValidationPlan([], [], [], True),
        policy_check=PatchPolicyCheck(True, False, 1, 2, True, []),
    )


def plan() -> RemediationPlan:
    return RemediationPlan(
        finding_id="test",
        status=RemediationPlanStatus.READY,
        remediation_goal="minimal fix",
        strategies=[],
        planned_changes=[PlannedChange("app.py", "code", "fix", "root cause", Severity.LOW)],
        dependency_upgrade=None,
        compatibility=CompatibilityAssessment("compatible", [], []),
        risk_points=[],
        required_tests=[],
        rejected_alternatives=[],
        rollback=RollbackPlan("revert", ["revert"]),
        patch_boundaries=PatchBoundaries(["app.py"], [], 2, 150),
        assumptions=[],
        unknowns=[],
        confidence_score=1.0,
        needs_human_review=True,
    )


class ValidationEvidenceTests(unittest.TestCase):
    def test_per_file_fallback_assembles_valid_artifact(self):
        class FakeLLM:
            def reason(self, **kwargs):
                return {
                    "content": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n",
                    "description": "replace vulnerable behavior",
                }

        agent = PatchGenerationAgent(PatchGenerationPolicy(), llm=FakeLLM())
        finding = SimpleNamespace(finding_id="fallback", vulnerability_type="test vulnerability")
        root = SimpleNamespace(root_cause=SimpleNamespace(summary="unsafe old behavior", missing_control="safe behavior"))
        result = agent._generate_artifacts_by_file(
            finding, root, plan(), [SourceFile("app.py", "old\n")],
            failure_reason="large response was truncated",
        )
        self.assertTrue(agent._has_applicable_artifacts(result))
        self.assertEqual(result["artifacts"][0]["target"], "app.py")

    def test_missing_validation_tools_produce_candidate_review_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("old\n", encoding="utf-8")
            diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
            executor = WorkspaceValidationExecutor(root, {})
            result = ValidationToolchain(executor=executor).validate(candidate(diff), plan(), [])
            self.assertEqual(result.status, PatchValidationStatus.NEEDS_HUMAN_REVIEW)
            self.assertTrue(result.report_ready)

    def test_remediation_plan_does_not_truncate_justified_files(self):
        finding = SimpleNamespace(finding_id="multi-file", locations=[])
        root_cause = SimpleNamespace(
            affected_code=[], root_cause=SimpleNamespace(summary="shared control must be restored")
        )
        raw = {
            "status": "ready",
            "remediation_goal": "restore the shared security invariant",
            "planned_changes": [
                {
                    "file": f"module_{index}.py",
                    "change_type": "code",
                    "description": "update affected path",
                    "reason": f"confirmed call path {index}",
                    "risk_level": "medium",
                }
                for index in range(4)
            ],
            "required_tests": [],
        }
        result = RemediationPlanAgent._dict_to_plan(
            finding, SimpleNamespace(), root_cause, EngineeringContext(), raw, None
        )
        self.assertEqual(len(result.planned_changes), 4)
        self.assertEqual(result.patch_boundaries.allowed_files, [f"module_{i}.py" for i in range(4)])

    def test_patch_agent_has_no_shell_write_path(self):
        agent = PatchGenerationAgent(PatchGenerationPolicy())
        self.assertNotIn("run_shell", {tool.name for tool in agent.tools})

    def test_report_patch_section_contains_unified_diff(self):
        diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
        rendered = RemediationReportAgent._patch_markdown(candidate(diff))
        self.assertIn("```diff", rendered)
        self.assertIn("+new", rendered)

    def test_pass_labels_without_evidence_do_not_pass(self):
        labels = [
            passed_tool(layer, layer.value, "passed")
            for layer in ValidationLayer
        ]
        result = ValidationToolchain().validate(candidate("--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"), plan(), labels)
        self.assertEqual(result.status, PatchValidationStatus.NEEDS_HUMAN_REVIEW)
        self.assertTrue(result.report_ready)

    def test_missing_strategy_critical_planned_artifact_is_fatal_precheck(self):
        remediation = plan()
        remediation.remediation_goal = "three-layer JWT algorithm/key confusion defense"
        remediation.planned_changes = [
            PlannedChange(
                "authlib/jose/rfc7515/jws.py", "code",
                "central JWS algorithm allowlist and key compatibility validation",
                "core control for CVE algorithm confusion",
                Severity.HIGH,
            ),
            PlannedChange(
                "authlib/jose/rfc7519/jwt.py", "code",
                "JWT decode trust boundary must enforce the selected algorithm strategy",
                "central decoder guard for token verification",
                Severity.HIGH,
            ),
            PlannedChange(
                "authlib/jose/rfc7518/jws_algs.py", "code",
                "reject asymmetric public keys as HMAC secrets",
                "algorithm/key compatibility check",
                Severity.HIGH,
            ),
        ]
        remediation.patch_boundaries = PatchBoundaries(
            [change.file for change in remediation.planned_changes], [], 3, 150,
        )
        partial = PatchCandidate(
            patch_id="patch-partial",
            finding_id="test",
            status=PatchCandidateStatus.GENERATED,
            summary="partial fix",
            artifacts=[PatchArtifact(
                PatchType.CODE,
                "authlib/jose/rfc7518/jws_algs.py",
                "--- a/authlib/jose/rfc7518/jws_algs.py\n"
                "+++ b/authlib/jose/rfc7518/jws_algs.py\n"
                "@@ -1 +1 @@\n-old\n+new\n",
                "partial guard",
            )],
            changed_files=[],
            test_changes=[],
            security_notes=[],
            assumptions=[],
            risks=[],
            validation_plan=PatchValidationPlan([], [], [], False),
            policy_check=PatchPolicyCheck(True, False, 1, 2, True, []),
        )

        result = ValidationToolchain().validate(partial, remediation, [])

        self.assertEqual(result.status, PatchValidationStatus.FAILED)
        self.assertFalse(result.report_ready)
        self.assertTrue(any(f.check == "planned_change_artifacts" for f in result.failures))
        feedback = result.feedback_for_failure_analysis or ""
        self.assertIn("authlib/jose/rfc7515/jws.py", feedback)
        self.assertIn("authlib/jose/rfc7519/jwt.py", feedback)

    def test_executor_applies_diff_and_captures_real_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("old\n", encoding="utf-8")
            diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
            commands = {
                "build": "python -m py_compile app.py",
                "business_regression": "python -c \"assert open('app.py').read() == 'new\\n'\"",
                "security_regression": "python -c \"assert 'old' not in open('app.py').read()\"",
                "scanner_rescan": "python -c \"assert 'old' not in open('app.py').read()\"",
            }
            results = WorkspaceValidationExecutor(root, commands)(candidate(diff))
            self.assertEqual({item.layer for item in results}, set(ValidationLayer))
            self.assertTrue(all(item.status == ToolExecutionStatus.PASSED for item in results))
            self.assertTrue(all(item.command and item.exit_code == 0 and item.evidence for item in results))


if __name__ == "__main__":
    unittest.main()
