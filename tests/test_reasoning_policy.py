from __future__ import annotations

import json
import unittest

from vuln_agent.agent import BaseAgent, Tool
from vuln_agent.evidence import EvidenceCollector
from vuln_agent.failure_analysis import FailureAnalysisAgent
from vuln_agent.impact import ImpactAnalysisAgent
from vuln_agent.llm import ChatResponse
from vuln_agent.models import (
    CompatibilityAssessment,
    EngineeringContext,
    FailureCategory,
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
    RemediationFeedbackTarget,
    RemediationPlan,
    RemediationPlanStatus,
    RollbackPlan,
    Severity,
    SourceFile,
    ToolExecutionStatus,
    ValidationLayer,
    ValidationLayerResult,
    ValidationToolResult,
    ValidationToolchainResult,
)
from vuln_agent.normalization import VulnerabilityNormalizer
from vuln_agent.patching import PatchGenerationAgent
from vuln_agent.reasoning import ReasoningMode, stage_policy
from vuln_agent.remediation import RemediationPlanAgent
from vuln_agent.root_cause import RootCauseAnalysisAgent
from vuln_agent.tools import (
    AssetContext,
    CodeContext,
    RuntimeContext,
    StaticAssetInventoryTool,
    StaticCodeContextTool,
    StaticRootCauseEvidenceTool,
    StaticRuntimeEvidenceTool,
)


def make_finding():
    return VulnerabilityNormalizer().normalize({
        "finding_id": "F-POLICY", "vulnerability_type": "SQL Injection",
        "severity": "high", "scanner": "SAST", "affected_file": "src/users.py",
        "affected_function": "find", "line": 4, "evidence": "input reaches query",
    })


def make_bundle():
    return EvidenceCollector().collect(make_finding(), [
        SourceFile(
            "src/users.py",
            "@app.get('/users')\ndef find():\n    value = request.args['q']\n"
            "    return db.execute('select ' + value)\n",
        ),
        SourceFile("tests/test_users.py", "def test_users():\n    assert True\n"),
        SourceFile("pyproject.toml", "[project]\nname='sample'\n"),
    ])


def impact_raw(confidence=0.9):
    return {
        "status": "confirmed", "affected_services": ["users"],
        "entry_points": [{"route": "/users", "method": "GET"}],
        "call_paths": [["/users", "find", "execute"]],
        "affected_assets": [], "affected_artifacts": [], "data_classification": [],
        "upstream_dependencies": [], "downstream_dependencies": [],
        "regression_targets": [], "suggested_tests": [], "unknowns": [],
        "confidence_score": confidence, "needs_human_review": False,
    }


def root_raw(confidence=0.9):
    return {
        "status": "confirmed", "root_cause_category": "unsafe_api_usage",
        "summary": "untrusted value reaches query execution",
        "source": {"symbol": "request args", "file": "src/users.py", "line": 3},
        "propagation": [{"symbol": "value", "operation": "joins query text"}],
        "sink": {"symbol": "execute", "file": "src/users.py", "line": 4},
        "missing_control": "bound query parameters",
        "failed_existing_controls": [], "trigger_conditions": ["GET request"],
        "contributing_factors": [], "causal_chain": ["request", "value", "execute"],
        "affected_code": [{
            "file": "src/users.py", "function": "find", "lines": [3, 4],
            "role": "primary_cause",
        }],
        "alternative_hypotheses": [], "confidence_score": confidence,
        "unknowns": [], "needs_human_review": False,
        "recommended_fix_constraints": ["preserve result shape"],
        "security_invariant": "input is data rather than query structure",
        "hypotheses": [{
            "hypothesis": "direct flow", "required_evidence": ["source", "sink"],
            "support": ["lines 3-4"], "counter_evidence": [], "verdict": "confirmed",
        }, {
            "hypothesis": "guard exists", "required_evidence": ["guard"],
            "support": [], "counter_evidence": ["direct flow"], "verdict": "rejected",
        }],
    }


def make_plan():
    return RemediationPlan(
        finding_id="F-POLICY", status=RemediationPlanStatus.READY,
        remediation_goal="bind parameters", strategies=[],
        planned_changes=[PlannedChange("src/users.py", "code", "bind", "root", Severity.MEDIUM)],
        dependency_upgrade=None,
        compatibility=CompatibilityAssessment("compatible", [], []),
        risk_points=[], required_tests=[], rejected_alternatives=[],
        rollback=RollbackPlan("revert", ["revert"]),
        patch_boundaries=PatchBoundaries(["src/users.py"], [], 1, 100),
        assumptions=[], unknowns=[], confidence_score=0.9, needs_human_review=True,
    )


def make_candidate():
    return PatchCandidate(
        patch_id="patch-policy", finding_id="F-POLICY",
        status=PatchCandidateStatus.GENERATED, summary="fix",
        artifacts=[PatchArtifact(
            PatchType.CODE, "src/users.py",
            "--- a/src/users.py\n+++ b/src/users.py\n@@ -1 +1 @@\n-a\n+b\n", "fix",
        )],
        changed_files=[], test_changes=[], security_notes=[], assumptions=[], risks=[],
        validation_plan=PatchValidationPlan([], [], [], True),
        policy_check=PatchPolicyCheck(True, False, 1, 2, True, []),
    )


class ReasoningPolicyTests(unittest.TestCase):
    def test_stage_policies_use_specialized_modes_and_patch_limits(self):
        self.assertEqual(stage_policy("impact", "deep").deep_path, ReasoningMode.BOUNDED_REACT)
        self.assertEqual(stage_policy("root_cause", "deep").deep_path, ReasoningMode.HYPOTHESIS_TEST)
        self.assertEqual(stage_policy("remediation", "deep").fast_path, ReasoningMode.PLAN_SELECT)
        self.assertEqual(stage_policy("patch", "deep").deep_path, ReasoningMode.PATCH_SYNTHESIS)
        self.assertEqual(stage_policy("failure", "deep").deep_path, ReasoningMode.REFLEXION_DIAGNOSIS)
        self.assertEqual([stage_policy("patch", mode).max_turns for mode in ("fast", "balanced", "deep")], [4, 6, 10])

    def test_impact_complete_evidence_uses_direct_path(self):
        class LLM:
            def reason(self, **kwargs):
                return impact_raw()

            def chat(self, *args, **kwargs):
                raise AssertionError("ReAct should not run")

        item = make_finding()
        agent = ImpactAnalysisAgent(
            StaticCodeContextTool({item.finding_id: CodeContext()}),
            StaticAssetInventoryTool({item.finding_id: AssetContext()}),
            StaticRuntimeEvidenceTool({item.finding_id: RuntimeContext()}),
            llm=LLM(), pipeline_mode="balanced",
        )
        result = agent.analyze(item, make_bundle())
        self.assertEqual(result.confidence_score, 0.9)
        self.assertFalse(agent.last_execution.escalated)
        self.assertEqual(agent.last_execution.reasoning_mode, ReasoningMode.DIRECT_STRUCTURED.value)

    def test_impact_low_confidence_escalates(self):
        class LLM:
            def reason(self, **kwargs):
                return impact_raw(0.2) | {"entry_points": [], "call_paths": []}

            def chat(self, messages, **kwargs):
                return ChatResponse(None, [{
                    "id": "submit-impact", "type": "function",
                    "function": {
                        "name": "submit_final_result",
                        "arguments": json.dumps(impact_raw(0.85)),
                    },
                }], "tool_calls")

        item = make_finding()
        agent = ImpactAnalysisAgent(
            StaticCodeContextTool({item.finding_id: CodeContext()}),
            StaticAssetInventoryTool({item.finding_id: AssetContext()}),
            StaticRuntimeEvidenceTool({item.finding_id: RuntimeContext()}),
            llm=LLM(), pipeline_mode="balanced",
        )
        result = agent.analyze(item, make_bundle())
        self.assertEqual(result.confidence_score, 0.85)
        self.assertTrue(agent.last_execution.escalated)
        self.assertIn("confidence_below_0.4", agent.last_execution.escalation_reasons)

    def test_impact_removes_routes_and_paths_not_supported_by_evidence(self):
        item = make_finding()
        raw = impact_raw() | {
            "entry_points": [
                {"route": "/users", "method": "GET"},
                {"route": "/admin/fixture", "method": "POST"},
            ],
            "call_paths": [
                ["/users", "find", "execute"],
                ["/admin/fixture", "assume_admin", "authorize"],
            ],
        }

        result = ImpactAnalysisAgent._ground_assessment(
            item,
            make_bundle(),
            ImpactAnalysisAgent._dict_to_assessment(item, raw),
        )

        self.assertEqual([(entry.route, entry.method) for entry in result.entry_points], [("/users", "GET")])
        self.assertEqual(result.call_paths, [["/users", "find", "execute"]])
        self.assertTrue(any("/admin/fixture" in unknown for unknown in result.unknowns))
        self.assertTrue(result.needs_human_review)

    def test_impact_keeps_source_grounded_library_api_entry(self):
        item = VulnerabilityNormalizer().normalize({
            "finding_id": "F-LIBRARY",
            "vulnerability_type": "JWT algorithm confusion",
            "severity": "high",
            "scanner": "manual",
            "affected_file": "lib/jwt.py",
            "affected_function": "jwt.decode()",
            "evidence": "untrusted compact token reaches signature verification",
        })
        bundle = EvidenceCollector().collect(item, [
            SourceFile(
                "lib/jwt.py",
                "class JsonWebToken:\n"
                "    def decode(self, token, key):\n"
                "        return verify(token, key)\n",
            ),
        ])
        raw = impact_raw() | {
            "entry_points": [{"route": "jwt.decode", "method": "CALL"}],
            "call_paths": [["jwt.decode", "verify"]],
        }

        result = ImpactAnalysisAgent._ground_assessment(
            item,
            bundle,
            ImpactAnalysisAgent._dict_to_assessment(item, raw),
        )

        self.assertEqual(
            [(entry.route, entry.method) for entry in result.entry_points],
            [("jwt.decode", "CALL")],
        )

    def test_root_incomplete_result_escalates_to_hypothesis_test(self):
        class LLM:
            def reason(self, **kwargs):
                return root_raw(0.3) | {"source": {}, "sink": {}, "missing_control": "unknown"}

            def chat(self, messages, **kwargs):
                return ChatResponse(None, [{
                    "id": "submit-root", "type": "function",
                    "function": {
                        "name": "submit_final_result",
                        "arguments": json.dumps(root_raw()),
                    },
                }], "tool_calls")

        item = make_finding()
        agent = RootCauseAnalysisAgent(StaticRootCauseEvidenceTool(), llm=LLM(), pipeline_mode="balanced")
        result = agent.analyze(
            item, ImpactAnalysisAgent._dict_to_assessment(item, impact_raw()), make_bundle()
        )
        self.assertEqual(result.root_cause.sink.symbol, "execute")
        self.assertTrue(agent.last_execution.escalated)
        self.assertEqual(agent.last_execution.reasoning_mode, ReasoningMode.HYPOTHESIS_TEST.value)

    def test_root_removes_invented_locations_and_downgrades_confidence(self):
        item = make_finding()
        raw = root_raw() | {
            "source": {"symbol": "imaginary_header", "file": "src/auth.py", "line": 1},
            "sink": {"symbol": "dangerous_decode", "file": "src/auth.py", "line": 2},
            "affected_code": [{
                "file": "src/auth.py", "function": "dangerous_decode",
                "lines": [1, 2], "role": "primary_cause",
            }],
            "confidence_score": 0.98,
            "needs_human_review": False,
        }

        result = RootCauseAnalysisAgent._ground_assessment(
            item,
            make_bundle(),
            RootCauseAnalysisAgent._dict_to_root_cause(item, raw),
        )

        self.assertIsNone(result.root_cause.source)
        self.assertIsNone(result.root_cause.sink)
        self.assertEqual(result.affected_code, [])
        self.assertLessEqual(result.confidence_score, 0.45)
        self.assertTrue(result.needs_human_review)
        self.assertNotEqual(result.status.value, "confirmed")

    def test_root_fallback_does_not_inject_cve_specific_api_claims(self):
        item = VulnerabilityNormalizer().normalize({
            "finding_id": "CVE-2024-37568",
            "vulnerability_type": "JWT algorithm confusion",
            "severity": "high",
            "scanner": "manual",
            "affected_file": "authlib/jose/rfc7519/jwt.py",
            "evidence": "asymmetric key material may reach an HMAC verification path",
            "recommendation": "add an algorithms argument to jwt.decode and expose JWKS",
        })

        raw = RootCauseAnalysisAgent._fallback_raw_extraction(
            "model failed before producing a structured root-cause result",
            item,
        )
        rendered = json.dumps(raw, ensure_ascii=False)

        self.assertNotIn("jwt.decode", rendered)
        self.assertNotIn("JWKS", rendered)
        self.assertNotIn("升级到 Authlib", rendered)
        self.assertLessEqual(raw["confidence_score"], 0.3)
        self.assertTrue(raw["needs_human_review"])

    def test_remediation_complete_context_uses_plan_select(self):
        raw = {
            "status": "ready", "remediation_goal": "bind parameters",
            "strategies": [{
                "strategy_type": "code_change", "summary": "bind values",
                "steps": ["replace joining"], "preferred": True,
            }],
            "planned_changes": [{
                "file": "src/users.py", "change_type": "code", "description": "bind",
                "reason": "restore invariant", "risk_level": "medium",
            }],
            "risk_points": [], "required_tests": [{
                "name": "query regression", "test_type": "security_regression",
                "target": "tests/test_users.py", "assertion": "value is data",
            }],
            "rejected_alternatives": [], "assumptions": [], "unknowns": [],
            "confidence_score": 0.9, "needs_human_review": True,
            "candidate_rankings": [
                {"strategy": "binding", "weighted_score": 0.9, "selected": True},
                {"strategy": "filter", "weighted_score": 0.3, "selected": False},
            ],
        }

        class LLM:
            def reason(self, **kwargs):
                return raw

        item = make_finding()
        sources = [
            SourceFile("src/users.py", "def find():\n    pass\n"),
            SourceFile("tests/test_users.py", "def test_users():\n    pass\n"),
        ]
        agent = RemediationPlanAgent(llm=LLM(), pipeline_mode="balanced")
        result = agent.plan(
            item,
            ImpactAnalysisAgent._dict_to_assessment(item, impact_raw()),
            RootCauseAnalysisAgent._dict_to_root_cause(item, root_raw()),
            EngineeringContext(language="Python", available_test_commands=["python -m unittest"]),
            evidence_bundle=make_bundle(), source_files=sources,
        )
        self.assertEqual(result.planned_changes[0].file, "src/users.py")
        self.assertEqual(agent.last_execution.reasoning_mode, ReasoningMode.PLAN_SELECT.value)

    def test_repeated_empty_search_stops_bounded_agent(self):
        class LLM:
            calls = 0

            def chat(self, messages, **kwargs):
                self.calls += 1
                if self.calls <= 2:
                    return ChatResponse(None, [{
                        "id": f"search-{self.calls}", "type": "function",
                        "function": {"name": "search_code", "arguments": '{"pattern":"absent"}'},
                    }], "tool_calls")
                return ChatResponse('{"status":"done"}', None, "stop")

        agent = BaseAgent(
            name="bounded",
            tools=[Tool(
                "search_code", "search", {"pattern": {"type": "string"}}, ["pattern"],
                lambda **_: "未找到结果",
            )],
            llm=LLM(), max_turns=8, tool_budget={"search_code": 4}, no_progress_limit=2,
            output_schema={"type": "object", "properties": {"status": {"type": "string"}}},
        )
        result = agent.run("search")
        self.assertEqual(result["status"], "done")
        self.assertEqual(agent.last_run_stats["tool_calls"]["search_code"], 2)
        self.assertEqual(agent.last_run_stats["stopped_reason"], "no_new_evidence")

    def test_security_failure_routes_to_root_with_reflexion(self):
        class Offline:
            def reason(self, **kwargs):
                raise RuntimeError("offline")

        tool = ValidationToolResult(
            layer=ValidationLayer.SECURITY_REGRESSION, tool_name="security-test",
            status=ToolExecutionStatus.FAILED, summary="guard did not reject case",
            command="python -m unittest", evidence=["one failure"], exit_code=1,
        )
        validation = ValidationToolchainResult(
            patch_id="patch-policy", finding_id="F-POLICY",
            status=PatchValidationStatus.FAILED,
            layers=[ValidationLayerResult(
                ValidationLayer.SECURITY_REGRESSION, ToolExecutionStatus.FAILED,
                [tool], "security regression failed",
            )],
            failures=[], next_action="analyze", report_ready=False,
        )
        agent = FailureAnalysisAgent(llm=Offline())
        result = agent.analyze(validation, make_candidate(), make_plan())
        self.assertEqual(result.route_to, RemediationFeedbackTarget.ROOT_CAUSE_AGENT)
        self.assertTrue(result.requires_root_cause_recheck)
        self.assertTrue(result.reflection)
        self.assertTrue(result.do_not_repeat)

    def test_generated_test_api_failure_routes_to_patch_without_root_recheck(self):
        class Offline:
            def reason(self, **kwargs):
                raise RuntimeError("offline")

        candidate = make_candidate()
        candidate.artifacts.append(PatchArtifact(
            PatchType.TEST,
            "tests/util.py",
            "--- a/tests/util.py\n+++ b/tests/util.py\n@@ -1 +1,2 @@\n a\n+test\n",
            "generated security test",
        ))
        tool = ValidationToolResult(
            layer=ValidationLayer.SECURITY_REGRESSION,
            tool_name="pytest generated test",
            status=ToolExecutionStatus.FAILED,
            summary="security regression command completed; exit code 1",
            command="python -m pytest -q tests/util.py",
            evidence=[
                "tests/util.py:36: AttributeError: module 'authlib.jose.jwk' "
                "has no attribute 'generate_key'"
            ],
            exit_code=1,
        )
        validation = ValidationToolchainResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            status=PatchValidationStatus.FAILED,
            layers=[ValidationLayerResult(
                ValidationLayer.SECURITY_REGRESSION,
                ToolExecutionStatus.FAILED,
                [tool],
                "generated security test failed before assertions",
            )],
            failures=[], next_action="analyze", report_ready=False,
        )

        result = FailureAnalysisAgent(llm=Offline()).analyze(
            validation, candidate, make_plan()
        )

        self.assertEqual(result.primary_category, FailureCategory.TEST_HARNESS_FAILURE)
        self.assertEqual(result.route_to, RemediationFeedbackTarget.PATCH_GENERATION_AGENT)
        self.assertFalse(result.requires_root_cause_recheck)

    def test_patch_path_boundary_rejects_unplanned_file(self):
        agent = PatchGenerationAgent(PatchGenerationPolicy(), pipeline_mode="balanced")
        agent.allowed_paths = ["src/users.py", "tests/test_users.py"]
        self.assertTrue(agent._path_allowed("read_file", {"path": "src/users.py"}))
        self.assertFalse(agent._path_allowed("read_file", {"path": "src/admin.py"}))
        self.assertFalse(agent._path_allowed("search_code", {"path": "."}))
        self.assertTrue(agent._path_allowed("search_code", {"path": "src"}))


if __name__ == "__main__":
    unittest.main()
