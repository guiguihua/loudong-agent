from __future__ import annotations

import json
import unittest

from vuln_agent.agent import BaseAgent, Tool
from vuln_agent.evidence import EvidenceCollector
from vuln_agent.impact import ImpactAnalysisAgent
from vuln_agent.llm import ChatResponse
from vuln_agent.models import (
    CompatibilityAssessment,
    EngineeringContext,
    PatchBoundaries,
    PatchGenerationPolicy,
    PatchValidationStatus,
    PlannedChange,
    RemediationPlan,
    RemediationPlanStatus,
    RollbackPlan,
    Severity,
    SourceFile,
    ValidationToolchainResult,
)
from vuln_agent.normalization import VulnerabilityNormalizer
from vuln_agent.patching import PatchGenerationAgent
from vuln_agent.remediation import RemediationPlanAgent
from vuln_agent.reporting import RemediationReportAgent
from vuln_agent.root_cause import RootCauseAnalysisAgent


def finding():
    return VulnerabilityNormalizer().normalize({
        "finding_id": "F-CONTRACT",
        "vulnerability_type": "algorithm/key mismatch",
        "severity": "high",
        "scanner": "manual",
        "affected_file": "lib/jws.py or lib/jwt.py",
        "evidence": "header algorithm is not checked against key type",
    })


def impact(item):
    return ImpactAnalysisAgent._dict_to_assessment(item, {
        "status": "confirmed", "affected_services": ["jose"],
        "entry_points": [{"route": "decode", "method": "CALL"}],
        "call_paths": [["decode", "prepare", "verify"]],
        "affected_assets": [], "affected_artifacts": [], "data_classification": [],
        "upstream_dependencies": [], "downstream_dependencies": [],
        "regression_targets": [], "suggested_tests": [], "unknowns": [],
        "confidence_score": 0.9, "needs_human_review": False,
    })


def root(item):
    return RootCauseAnalysisAgent._dict_to_root_cause(item, {
        "status": "confirmed", "root_cause_category": "missing_input_validation",
        "summary": "algorithm selection is not bound to the key type",
        "source": {"symbol": "header alg", "file": "lib/jws.py", "line": 10},
        "propagation": [],
        "sink": {"symbol": "prepare key", "file": "lib/jws.py", "line": 20},
        "missing_control": "algorithm/key compatibility check",
        "failed_existing_controls": [], "trigger_conditions": ["mismatched key"],
        "contributing_factors": [], "causal_chain": ["header", "prepare"],
        "affected_code": [{
            "file": "lib/jws.py", "function": "prepare", "lines": [10, 20],
            "role": "primary_cause",
        }],
        "alternative_hypotheses": [], "confidence_score": 0.9,
        "unknowns": [], "needs_human_review": False,
        "recommended_fix_constraints": ["preserve valid algorithms"],
        "security_invariant": "algorithm family matches key type",
    })


def plan(item):
    return RemediationPlan(
        finding_id=item.finding_id,
        status=RemediationPlanStatus.READY,
        remediation_goal="bind algorithm to key type",
        strategies=[],
        planned_changes=[PlannedChange("lib/jws.py", "code", "add guard", "root", Severity.MEDIUM)],
        dependency_upgrade=None,
        compatibility=CompatibilityAssessment("compatible", [], []),
        risk_points=[], required_tests=[], rejected_alternatives=[],
        rollback=RollbackPlan("revert", ["revert"]),
        patch_boundaries=PatchBoundaries(["lib/jws.py"], [], 1, 100),
        assumptions=[], unknowns=[], confidence_score=0.9, needs_human_review=True,
    )


class GenerationContractTests(unittest.TestCase):
    def test_text_rendered_tool_call_is_executed(self):
        observed = []

        class LLM:
            calls = 0

            def chat(self, messages, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    opening = "<" + "search_code>"
                    closing = "</" + "search_code>"
                    content = opening + "<pattern>def target</pattern><path>lib</path>" + closing
                    return ChatResponse(content, None, "stop")
                return ChatResponse(None, [{
                    "id": "submit", "type": "function",
                    "function": {"name": "submit_final_result", "arguments": '{"status":"done"}'},
                }], "tool_calls")

        def handler(**kwargs):
            observed.append(kwargs)
            return "lib/jws.py:1:def target():"

        agent = BaseAgent(
            name="adapter",
            tools=[Tool(
                "search_code", "search",
                {"pattern": {"type": "string"}, "path": {"type": "string"}},
                ["pattern"], handler,
            )],
            llm=LLM(),
            output_schema={"type": "object", "properties": {"status": {"type": "string"}}},
        )
        result = agent.run("inspect")
        self.assertEqual(result["status"], "done")
        self.assertEqual(observed, [{"pattern": "def target", "path": "lib"}])

    def test_descriptive_plan_paths_are_replaced_by_confirmed_file(self):
        item = finding()
        sources = [
            SourceFile("package/lib/jws.py", "def prepare():\n    pass\n"),
            SourceFile("package/tests/test_jws.py", "def test_guard():\n    pass\n"),
        ]
        bundle = EvidenceCollector().collect(item, sources)
        raw = {
            "status": "ready", "remediation_goal": "bind algorithm and key",
            "strategies": [{
                "strategy_type": "code_change", "summary": "change callers",
                "steps": ["change callers"], "preferred": True,
            }],
            "planned_changes": [
                {"file": "provider.py / routes.py / all modules",
                 "change_type": "code", "description": "change callers", "reason": "extra", "risk_level": "medium"},
                {"file": "config.py (or equivalent)", "change_type": "configuration",
                 "description": "add config", "reason": "extra", "risk_level": "medium"},
                {"file": "requirements.txt", "change_type": "dependency",
                 "description": "upgrade self", "reason": "later release", "risk_level": "medium"},
            ],
            "risk_points": [],
            "required_tests": [{
                "name": "guard regression", "test_type": "security_regression",
                "target": "tests/test_jws.py", "assertion": "mismatch is rejected",
            }],
            "rejected_alternatives": [], "assumptions": [], "unknowns": [],
            "confidence_score": 0.7, "needs_human_review": True,
            "candidate_rankings": [
                {"strategy": "core", "weighted_score": 0.9, "selected": True},
                {"strategy": "callers", "weighted_score": 0.4, "selected": False},
            ],
        }

        class LLM:
            def reason(self, **kwargs):
                return raw

            def chat(self, messages, **kwargs):
                return ChatResponse(None, [{
                    "id": "submit-plan", "type": "function",
                    "function": {
                        "name": "submit_final_result",
                        "arguments": json.dumps(raw),
                    },
                }], "tool_calls")

        agent = RemediationPlanAgent(llm=LLM(), pipeline_mode="balanced")
        result = agent.plan(
            item, impact(item), root(item),
            EngineeringContext(language="Python", available_test_commands=["python -m unittest"]),
            evidence_bundle=bundle, source_files=sources,
        )
        self.assertEqual(
            [change.file for change in result.planned_changes],
            ["package/lib/jws.py"],
        )
        self.assertEqual(result.patch_boundaries.allowed_files, ["package/lib/jws.py"])
        self.assertTrue(any(test.test_type == "security_regression" for test in result.required_tests))
        self.assertTrue(any(test.test_type == "business_regression" for test in result.required_tests))

    def test_remediation_finalization_failure_uses_root_cause_fallback(self):
        item = finding()
        sources = [
            SourceFile("package/lib/jws.py", "def prepare():\n    pass\n"),
            SourceFile("package/tests/test_jws.py", "def test_guard():\n    pass\n"),
        ]

        class LLM:
            def chat(self, messages, **kwargs):
                raise RuntimeError("structured finalization unavailable")

        agent = RemediationPlanAgent(llm=LLM(), pipeline_mode="balanced")
        result = agent.plan(
            item, impact(item), root(item), EngineeringContext(language="Python"),
            evidence_bundle=EvidenceCollector().collect(item, sources),
            source_files=sources,
        )

        self.assertEqual(result.status, RemediationPlanStatus.READY)
        self.assertEqual(
            [change.file for change in result.planned_changes],
            ["package/lib/jws.py"],
        )
        # EvidenceCollector now resolves "lib/jws.py or lib/jwt.py" → plan_select
        # path is taken (gaps are resolvable, so Bounded ReAct is correctly skipped).
        # The plan_select path falls back to _fallback_plan_extraction when LLM
        # errors, producing output equivalent to the old Bounded-ReAct fallback.
        self.assertIn(
            agent.last_execution.details.get("final_decision", ""),
            {"generate_rank_select", "deterministic_root_cause_plan"},
        )

    def test_generation_block_is_not_reported_as_test_failure(self):
        item = finding()
        candidate = PatchGenerationAgent._blocked_candidate(
            item, plan(item), "model returned no structured diff"
        )
        validation = ValidationToolchainResult(
            patch_id=candidate.patch_id,
            finding_id=item.finding_id,
            status=PatchValidationStatus.FAILED,
            layers=[], failures=[], next_action="fix_generation",
            feedback_for_failure_analysis="candidate_generated: no structured diff",
            report_ready=False,
        )
        report = RemediationReportAgent().generate(
            item, impact(item), root(item), plan(item), candidate, validation
        )
        self.assertIn("候选补丁生成被阻断", report.title)
        self.assertIn("外部构建、测试和安全验证尚未开始", report.executive_summary)


# ── 导入/符号存在性验证测试 ────────────────────────────────────────────


class ImportVerificationTests(unittest.TestCase):
    """验证 Patch Agent 新增的导入/符号存在性检查逻辑。"""

    # ── 模拟 authlib 风格的源文件 ──
    _AUTHLIB_SOURCES = [
        SourceFile(
            "authlib/jose/errors.py",
            "class BadSignatureError(Exception):\n    pass\n\n"
            "class DecodeError(Exception):\n    pass\n\n"
            "class UnsupportedAlgorithmError(Exception):\n    pass\n",
        ),
        SourceFile(
            "authlib/jose/rfc7518/jws_algs.py",
            "from authlib.jose.rfc7515 import JWSAlgorithm\n\n"
            "class HMACAlgorithm(JWSAlgorithm):\n"
            "    def prepare_key(self, raw_data):\n"
            "        return raw_data\n",
        ),
        SourceFile(
            "authlib/jose/rfc7515/jws.py",
            "class JsonWebSignature:\n"
            "    def serialize(self, header, payload, key):\n"
            "        pass\n"
            "    def deserialize(self, s, key):\n"
            "        pass\n",
        ),
        SourceFile(
            "authlib/jose/rfc7519/jwt.py",
            "from authlib.jose.errors import DecodeError\n\n"
            "class JsonWebToken:\n"
            "    def decode(self, s, key):\n"
            "        pass\n",
        ),
    ]

    # 不包含 InvalidKeyError 的 errors.py（模拟真实 authlib 1.3.0）
    _ERRORS_WITHOUT_INVALID = SourceFile(
        "authlib/jose/errors.py",
        "class BadSignatureError(Exception):\n    pass\n\n"
        "class DecodeError(Exception):\n    pass\n\n"
        "class UnsupportedAlgorithmError(Exception):\n    pass\n",
    )

    # 包含 InvalidKeyError 的 errors.py（模拟修复后的版本）
    _ERRORS_WITH_INVALID = SourceFile(
        "authlib/jose/errors.py",
        "class BadSignatureError(Exception):\n    pass\n\n"
        "class DecodeError(Exception):\n    pass\n\n"
        "class InvalidKeyError(Exception):\n    pass\n",
    )

    def test_extract_source_exports_includes_exception_classes(self):
        """_extract_source_exports should include exception class names."""
        exports = PatchGenerationAgent._extract_source_exports(
            [self._ERRORS_WITHOUT_INVALID]
        )
        norm = "authlib/jose/errors.py"
        self.assertIn(norm, exports)
        self.assertIn("BadSignatureError", exports[norm])
        self.assertIn("DecodeError", exports[norm])
        self.assertIn("UnsupportedAlgorithmError", exports[norm])
        self.assertNotIn("InvalidKeyError", exports[norm])

    def test_extract_source_exports_includes_module_level_funcs_and_classes(self):
        """_extract_source_exports should capture funcs and classes in any source file."""
        exports = PatchGenerationAgent._extract_source_exports(
            [SourceFile("lib/mod.py", "def foo():\n    pass\n\nclass Bar:\n    def baz(self):\n        pass\n")]
        )
        norm = "lib/mod.py"
        self.assertIn(norm, exports)
        self.assertIn("foo", exports[norm])
        self.assertIn("Bar", exports[norm])
        self.assertIn("baz", exports[norm])

    def test_resolve_python_import_relative(self):
        """Relative import ..errors from jws_algs.py should resolve to authlib/jose/errors."""
        result = PatchGenerationAgent._resolve_python_import(
            "..errors",
            "authlib/jose/rfc7518/jws_algs.py",
            self._AUTHLIB_SOURCES,
        )
        self.assertEqual(result, "authlib/jose/errors")

    def test_resolve_python_import_relative_dot(self):
        """Single-dot relative import .errors resolves correctly but returns
        None when the target file is not in source_files."""
        result = PatchGenerationAgent._resolve_python_import(
            ".errors",
            "authlib/jose/rfc7519/jwt.py",
            self._AUTHLIB_SOURCES,
        )
        # .errors from authlib/jose/rfc7519/jwt.py resolves to
        # authlib/jose/rfc7519/errors, which does not exist in our fixture.
        self.assertIsNone(result)
        # Actually jwt.py's directory is authlib/jose/rfc7519, and .errors would
        # be authlib/jose/rfc7519/errors — which doesn't exist in our fixture.
        self.assertIsNone(result)

    def test_resolve_python_import_absolute(self):
        """Absolute import should resolve to the correct module path."""
        result = PatchGenerationAgent._resolve_python_import(
            "authlib.jose.errors",
            "any/file.py",
            self._AUTHLIB_SOURCES,
        )
        self.assertEqual(result, "authlib/jose/errors")

    def test_resolve_python_import_nonexistent(self):
        """Non-existent module returns None."""
        result = PatchGenerationAgent._resolve_python_import(
            "nonexistent.module",
            "any/file.py",
            self._AUTHLIB_SOURCES,
        )
        self.assertIsNone(result)

    def test_verify_diff_imports_catches_nonexistent_symbol(self):
        """A diff that adds 'from ..errors import InvalidKeyError' must be flagged."""
        diff = (
            "--- a/authlib/jose/rfc7518/jws_algs.py\n"
            "+++ b/authlib/jose/rfc7518/jws_algs.py\n"
            "@@ -1,4 +1,6 @@\n"
            " from authlib.jose.rfc7515 import JWSAlgorithm\n"
            "+from ..errors import InvalidKeyError\n"
            " \n"
            " class HMACAlgorithm(JWSAlgorithm):\n"
        )
        sources = [
            self._ERRORS_WITHOUT_INVALID,  # No InvalidKeyError here!
            self._AUTHLIB_SOURCES[1],  # jws_algs.py
        ]
        exports = PatchGenerationAgent._extract_source_exports(sources)
        issues = PatchGenerationAgent._verify_diff_imports_exist(
            diff, "authlib/jose/rfc7518/jws_algs.py", sources, exports,
        )
        self.assertTrue(len(issues) > 0, f"Expected import issues, got none")
        self.assertTrue(
            any("InvalidKeyError" in issue for issue in issues),
            f"Issues should mention InvalidKeyError: {issues}",
        )

    def test_verify_diff_imports_accepts_existing_symbol(self):
        """A diff that adds 'from ..errors import DecodeError' should pass."""
        diff = (
            "--- a/authlib/jose/rfc7518/jws_algs.py\n"
            "+++ b/authlib/jose/rfc7518/jws_algs.py\n"
            "@@ -1,4 +1,6 @@\n"
            " from authlib.jose.rfc7515 import JWSAlgorithm\n"
            "+from ..errors import DecodeError\n"
            " \n"
            " class HMACAlgorithm(JWSAlgorithm):\n"
        )
        sources = [
            self._ERRORS_WITHOUT_INVALID,  # Has DecodeError
            self._AUTHLIB_SOURCES[1],  # jws_algs.py
        ]
        exports = PatchGenerationAgent._extract_source_exports(sources)
        issues = PatchGenerationAgent._verify_diff_imports_exist(
            diff, "authlib/jose/rfc7518/jws_algs.py", sources, exports,
        )
        self.assertEqual(len(issues), 0, f"Expected no issues, got: {issues}")

    def test_verify_diff_imports_with_invalid_key_error_present(self):
        """When InvalidKeyError IS defined, the import should pass."""
        diff = (
            "--- a/authlib/jose/rfc7518/jws_algs.py\n"
            "+++ b/authlib/jose/rfc7518/jws_algs.py\n"
            "@@ -1,4 +1,6 @@\n"
            " from authlib.jose.rfc7515 import JWSAlgorithm\n"
            "+from ..errors import InvalidKeyError\n"
            " \n"
            " class HMACAlgorithm(JWSAlgorithm):\n"
        )
        sources = [
            self._ERRORS_WITH_INVALID,  # HAS InvalidKeyError
            self._AUTHLIB_SOURCES[1],
        ]
        exports = PatchGenerationAgent._extract_source_exports(sources)
        issues = PatchGenerationAgent._verify_diff_imports_exist(
            diff, "authlib/jose/rfc7518/jws_algs.py", sources, exports,
        )
        self.assertEqual(len(issues), 0, f"Expected no issues, got: {issues}")

    def test_diff_quality_report_includes_import_issues_when_source_files_provided(self):
        """_diff_quality_report should flag import issues when source_files is given."""
        diff = (
            "--- a/authlib/jose/rfc7518/jws_algs.py\n"
            "+++ b/authlib/jose/rfc7518/jws_algs.py\n"
            "@@ -1,4 +1,6 @@\n"
            " from authlib.jose.rfc7515 import JWSAlgorithm\n"
            "+from ..errors import InvalidKeyError\n"
            " \n"
            " class HMACAlgorithm(JWSAlgorithm):\n"
        )
        sources = [
            self._ERRORS_WITHOUT_INVALID,
            self._AUTHLIB_SOURCES[1],
        ]
        report = PatchGenerationAgent._diff_quality_report(
            diff, "content placeholder", "authlib/jose/rfc7518/jws_algs.py",
            source_files=sources,
        )
        self.assertTrue(
            len(report["issues"]) > 0,
            f"Expected blocking issues for invalid import, got: {report}",
        )

    def test_diff_quality_report_without_source_files_skips_import_check(self):
        """When source_files is not provided, import check is skipped (backward compat)."""
        diff = (
            "--- a/authlib/jose/rfc7518/jws_algs.py\n"
            "+++ b/authlib/jose/rfc7518/jws_algs.py\n"
            "@@ -1,2 +1,3 @@\n"
            " from authlib.jose.rfc7515 import JWSAlgorithm\n"
            "+from ..errors import InvalidKeyError\n"
        )
        # No source_files passed → import check skipped, no errors
        report = PatchGenerationAgent._diff_quality_report(
            diff, "from authlib.jose.rfc7515 import JWSAlgorithm\n",
            "authlib/jose/rfc7518/jws_algs.py",
        )
        # May still have other issues (context accuracy), but should NOT have
        # import-specific issues
        for issue in report["issues"]:
            self.assertNotIn("InvalidKeyError", issue,
                             f"Should not check imports without source_files: {issue}")

    def test_verify_diff_imports_stdlib_skipped(self):
        """Imports from stdlib (like 'import os') should not be flagged."""
        diff = (
            "--- a/lib/mod.py\n"
            "+++ b/lib/mod.py\n"
            "@@ -1,1 +1,2 @@\n"
            " pass\n"
            "+import os\n"
            "+from datetime import datetime\n"
        )
        sources = [SourceFile("lib/mod.py", "pass\n")]
        exports = PatchGenerationAgent._extract_source_exports(sources)
        issues = PatchGenerationAgent._verify_diff_imports_exist(
            diff, "lib/mod.py", sources, exports,
        )
        self.assertEqual(len(issues), 0, f"Stdlib imports should be skipped: {issues}")

    def test_verify_diff_no_new_imports_no_issues(self):
        """A diff with no new imports should return empty issues."""
        diff = (
            "--- a/lib/mod.py\n"
            "+++ b/lib/mod.py\n"
            "@@ -1,2 +1,3 @@\n"
            " def foo():\n"
            "-    return 1\n"
            "+    return 2\n"
        )
        sources = [SourceFile("lib/mod.py", "def foo():\n    return 1\n")]
        exports = PatchGenerationAgent._extract_source_exports(sources)
        issues = PatchGenerationAgent._verify_diff_imports_exist(
            diff, "lib/mod.py", sources, exports,
        )
        self.assertEqual(len(issues), 0)


class RemediationSymbolVerificationTests(unittest.TestCase):
    """验证 RemediationPlanAgent 新增的方案符号验证逻辑。"""

    def _make_plan(self, description: str, reason: str = "") -> RemediationPlan:
        return RemediationPlan(
            finding_id="F-TEST",
            status=RemediationPlanStatus.READY,
            remediation_goal="fix the bug",
            strategies=[],
            planned_changes=[
                PlannedChange(
                    file="lib/mod.py", change_type="code",
                    description=description, reason=reason,
                    risk_level=Severity.MEDIUM,
                )
            ],
            dependency_upgrade=None,
            compatibility=CompatibilityAssessment("ok", [], []),
            risk_points=[], required_tests=[], rejected_alternatives=[],
            rollback=RollbackPlan("revert", ["revert"]),
            patch_boundaries=PatchBoundaries(["lib/mod.py"], [], 1, 100),
            assumptions=[], unknowns=[], confidence_score=0.8,
            needs_human_review=False,
        )

    def test_verify_plan_symbols_flags_nonexistent_exception(self):
        """PlannedChange mentioning a non-existent exception class should be flagged."""
        sources = [
            SourceFile("lib/mod.py", "def handle():\n    pass\n"),
            SourceFile("lib/errors.py", "class DecodeError(Exception):\n    pass\n"),
        ]
        plan = self._make_plan(
            "在 HMACAlgorithm.prepare_key() 中检测非对称密钥并抛出 InvalidKeyError"
        )
        issues = RemediationPlanAgent._verify_plan_symbols_exist(plan, sources)
        self.assertTrue(len(issues) > 0, f"Should flag InvalidKeyError: {issues}")
        self.assertTrue(
            any("InvalidKeyError" in i for i in issues),
            f"Issues should mention InvalidKeyError: {issues}",
        )

    def test_verify_plan_symbols_accepts_existing_exception(self):
        """PlannedChange mentioning an existing exception class should pass."""
        sources = [
            SourceFile("lib/mod.py", "def handle():\n    pass\n"),
            SourceFile("lib/errors.py", "class InvalidKeyError(Exception):\n    pass\n"),
        ]
        plan = self._make_plan(
            "在 HMACAlgorithm.prepare_key() 中抛出 InvalidKeyError 阻止非对称密钥"
        )
        issues = RemediationPlanAgent._verify_plan_symbols_exist(plan, sources)
        self.assertEqual(len(issues), 0, f"Should accept existing symbol: {issues}")

    def test_verify_plan_symbols_stdlib_exceptions_skipped(self):
        """References to stdlib exceptions like ValueError should not be flagged."""
        sources = [SourceFile("lib/mod.py", "def handle():\n    pass\n")]
        plan = self._make_plan(
            "如果输入无效则抛出 ValueError",
            "参数校验失败时 raise ValueError",
        )
        issues = RemediationPlanAgent._verify_plan_symbols_exist(plan, sources)
        self.assertEqual(len(issues), 0, f"Stdlib exceptions should be skipped: {issues}")

    def test_verify_plan_symbols_no_exception_like_tokens(self):
        """Plan with no exception/class-like tokens should return no issues."""
        sources = [SourceFile("lib/mod.py", "def handle():\n    pass\n")]
        plan = self._make_plan(
            "在入口点添加输入校验逻辑",
            "确保所有输入经过 sanitize 函数处理",
        )
        issues = RemediationPlanAgent._verify_plan_symbols_exist(plan, sources)
        self.assertEqual(len(issues), 0, f"Should have no issues: {issues}")


if __name__ == "__main__":
    unittest.main()
