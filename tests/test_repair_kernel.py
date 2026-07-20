from __future__ import annotations

import unittest
from types import SimpleNamespace

from vuln_agent.models import (
    CompatibilityAssessment,
    EvidenceBundle,
    PatchBoundaries,
    PlannedChange,
    RemediationPlan,
    RemediationPlanStatus,
    RepositorySummary,
    RollbackPlan,
    Severity,
    SourceFile,
    TestPlanItem,
    ValidationCapabilities,
)
from vuln_agent.normalization import VulnerabilityNormalizer
from vuln_agent.repair import (
    PatchQualityMetrics,
    QualityObservation,
    RepairKernel,
    default_phase1_inventory,
)
from vuln_agent.scenarios.sql_injection import SQLInjectionRepairScenario


SOURCE_PATH = "src/user/search.py"
TEST_PATH = "tests/test_user_search.py"
VULNERABLE_SOURCE = (
    "from flask import request\n\n\n"
    "def search_users(cursor):\n"
    "    keyword = request.args.get(\"q\", \"\")\n"
    "    sql = \"select * from users where name like '%\" + keyword + \"%'\"\n"
    "    cursor.execute(sql)\n"
    "    return cursor.fetchall()\n"
)
SAFE_SOURCE = (
    "from flask import request\n\n\n"
    "def search_users(cursor):\n"
    "    keyword = request.args.get(\"q\", \"\")\n"
    "    sql = \"select * from users where name like %s\"\n"
    "    cursor.execute(sql, (f\"%{keyword}%\",))\n"
    "    return cursor.fetchall()\n"
)


def finding():
    return VulnerabilityNormalizer().normalize({
        "finding_id": "repair-kernel-sql",
        "vulnerability_type": "SQL Injection",
        "severity": "high",
        "scanner": "test",
        "affected_file": SOURCE_PATH,
        "affected_function": "search_users",
        "line": 4,
        "evidence": "dynamic input reaches cursor.execute",
    })


def root():
    point = SimpleNamespace(file=SOURCE_PATH, symbol="search_users", line=4)
    return SimpleNamespace(
        root_cause=SimpleNamespace(
            summary="dynamic SQL reaches cursor.execute",
            missing_control="bound query parameters",
            source=point,
            sink=point,
        ),
        affected_code=[],
        security_invariant="untrusted input must remain bound data",
    )


def plan():
    return RemediationPlan(
        finding_id="repair-kernel-sql",
        status=RemediationPlanStatus.READY,
        remediation_goal="bind untrusted values as SQL parameters",
        strategies=[],
        planned_changes=[
            PlannedChange(
                SOURCE_PATH,
                "code",
                "parameterize search_users",
                "confirmed source-to-sink path",
                Severity.LOW,
                causally_required=True,
            )
        ],
        dependency_upgrade=None,
        compatibility=CompatibilityAssessment("compatible", [], []),
        risk_points=[],
        required_tests=[
            TestPlanItem(
                "attack and legitimate query",
                "security",
                TEST_PATH,
                "attack remains data and legitimate query works",
            )
        ],
        rejected_alternatives=[],
        rollback=RollbackPlan("revert patch", ["git revert"]),
        patch_boundaries=PatchBoundaries([SOURCE_PATH], [], 2, 120),
        assumptions=[],
        unknowns=[],
        confidence_score=1.0,
        needs_human_review=True,
    )


def evidence(*, commands: bool) -> EvidenceBundle:
    command = "python -c \"print('oracle-ok')\""
    poc = (
        "python -c \"from pathlib import Path; import sys; "
        f"s=Path('{SOURCE_PATH}').read_text(); "
        "sys.exit(0 if 'cursor.execute(sql, (' in s else 1)\""
    )
    return EvidenceBundle(
        finding_id="repair-kernel-sql",
        repository_summary=RepositorySummary(None, None, 2, ["Python"]),
        target_files=[],
        code_slices=[],
        entry_points=[],
        source_candidates=[],
        sink_candidates=[],
        dependency_evidence=[],
        test_evidence=[],
        config_evidence=[],
        validation_capabilities=ValidationCapabilities(
            test_commands=[command] if commands else [],
            security_commands=[command] if commands else [],
            poc_commands=[poc] if commands else [],
        ),
        collection_warnings=[],
        bundle_hash="repair-kernel",
    )


def scenario(source: str, *, commands: bool, llm=None):
    return SQLInjectionRepairScenario(
        finding(),
        root(),
        plan(),
        [
            SourceFile(SOURCE_PATH, source),
            SourceFile(TEST_PATH, "def test_existing():\n    assert True\n"),
        ],
        evidence(commands=commands),
        llm,
    )


class RepairKernelTests(unittest.TestCase):
    def test_phase1_inventory_has_declared_60_case_distribution(self):
        inventory = default_phase1_inventory()
        counts = {}
        for item in inventory:
            counts[item.family] = counts.get(item.family, 0) + 1
            self.assertTrue(item.finding_input)
            self.assertTrue(item.business_commands)
            self.assertTrue(item.security_commands)
        self.assertEqual(len(inventory), 60)
        self.assertEqual(counts["sql_injection"], 20)
        self.assertEqual(counts["command_injection"], 15)
        self.assertEqual(counts["path_traversal"], 15)
        self.assertEqual(counts["dependency"], 10)

    def test_quality_metrics_report_precision_and_pass_at_k(self):
        metrics = PatchQualityMetrics.from_observations([
            QualityObservation("a", True, True, True, True, True, True, True, 1),
            QualityObservation("b", True, True, True, True, True, True, True, 2),
            QualityObservation("c", True, True, True, False, True, False, False, 3, 1),
        ])
        self.assertEqual(metrics.total, 3)
        self.assertEqual(metrics.accepted_patch_precision, 1.0)
        self.assertEqual(metrics.pass_at_1, 0.3333)
        self.assertEqual(metrics.pass_at_3, 0.6667)
        self.assertEqual(metrics.duplicate_failure_rate, 0.3333)

    def test_missing_business_oracle_produces_candidate_only(self):
        result = RepairKernel(max_attempts=3).run(
            scenario(VULNERABLE_SOURCE, commands=False),
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.session.mode.value, "candidate_only")
        self.assertEqual(result.session.status, "candidate_only")
        self.assertTrue(result.raw_result["artifacts"])
        self.assertIn(
            "business_oracle",
            result.session.contract.missing_for_automation,
        )

    def test_complete_contract_accepts_verified_sql_patch(self):
        result = RepairKernel(max_attempts=3).run(
            scenario(VULNERABLE_SOURCE, commands=True),
        )
        self.assertTrue(result.accepted)
        self.assertEqual(result.session.status, "accepted")
        self.assertEqual(len(result.session.candidates), 1)
        categories = {
            item.category.value
            for item in result.session.candidates[0].oracle_results
            if item.passed
        }
        self.assertIn("security", categories)
        self.assertIn("business", categories)
        self.assertIn("side_effect", categories)
        self.assertIn("diff_risk", categories)
        serialized = result.to_raw()["repair_session"]["candidates"][0]
        self.assertTrue(serialized["raw_result"]["artifacts"])
        self.assertTrue(serialized["raw_result"]["workspace_checks"])
        self.assertIn("change_set", serialized["raw_result"])

    def test_safe_baseline_is_blocked_instead_of_patched(self):
        result = RepairKernel(max_attempts=3).run(
            scenario(SAFE_SOURCE, commands=True),
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.session.mode.value, "blocked")
        self.assertEqual(result.session.status, "baseline_blocked")
        self.assertIn("vulnerability_not_reproduced", result.raw_result["blocked_reason"])
        self.assertEqual(result.session.failure_stage, "verify_baseline")
        self.assertIn(
            "vulnerability_not_reproduced",
            result.session.terminal_reason,
        )

    def test_contract_and_baseline_exceptions_return_blocked_sessions(self):
        contract_error = scenario(VULNERABLE_SOURCE, commands=True)
        contract_error.build_contract = lambda: (_ for _ in ()).throw(
            RuntimeError("contract exploded")
        )
        contract_result = RepairKernel().run(contract_error)
        self.assertEqual(contract_result.session.status, "build_contract_error")
        self.assertEqual(contract_result.session.mode.value, "blocked")
        self.assertEqual(contract_result.session.failure_stage, "build_contract")
        self.assertEqual(
            contract_result.to_raw()["repair_session"]["failure_stage"],
            "build_contract",
        )

        baseline_error = scenario(VULNERABLE_SOURCE, commands=True)
        baseline_error.verify_baseline = lambda contract: (
            _ for _ in ()
        ).throw(RuntimeError("baseline exploded"))
        baseline_result = RepairKernel().run(baseline_error)
        self.assertEqual(baseline_result.session.status, "verify_baseline_error")
        self.assertEqual(baseline_result.session.failure_stage, "verify_baseline")
        self.assertIn("RuntimeError", baseline_result.raw_result["blocked_reason"])

    def test_session_creation_exception_returns_blocked_session(self):
        broken = scenario(VULNERABLE_SOURCE, commands=True)
        broken.source_snapshot = {"not-json": object()}
        result = RepairKernel().run(broken)
        self.assertEqual(result.session.status, "session_creation_error")
        self.assertEqual(result.session.failure_stage, "create_session")
        self.assertEqual(result.session.source_snapshot_hash, "unavailable")
        self.assertEqual(
            result.to_raw()["repair_session"]["failure_stage"],
            "create_session",
        )

    def test_candidate_stage_exceptions_are_recorded_until_exhausted(self):
        stage_setups = {
            "generate_candidate": lambda item: setattr(
                item,
                "generate_candidate",
                lambda **kwargs: (_ for _ in ()).throw(
                    RuntimeError("generation exploded")
                ),
            ),
            "edit_ir": lambda item: setattr(
                item,
                "edit_ir",
                lambda raw: (_ for _ in ()).throw(
                    RuntimeError("edit exploded")
                ),
            ),
            "evaluate_candidate": lambda item: setattr(
                item,
                "evaluate_candidate",
                lambda raw, contract: (_ for _ in ()).throw(
                    RuntimeError("evaluation exploded")
                ),
            ),
        }
        for stage, setup in stage_setups.items():
            with self.subTest(stage=stage):
                broken = scenario(VULNERABLE_SOURCE, commands=True)
                setup(broken)
                result = RepairKernel(max_attempts=2).run(broken)
                serialized = result.to_raw()["repair_session"]
                self.assertEqual(result.session.status, "exhausted")
                self.assertEqual(len(serialized["candidates"]), 2)
                for candidate in serialized["candidates"]:
                    self.assertEqual(
                        candidate["raw_result"]["failure_stage"],
                        stage,
                    )
                    self.assertEqual(
                        candidate["raw_result"]["exception_type"],
                        "RuntimeError",
                    )
                    self.assertTrue(candidate["raw_result"]["blocked_reason"])

    def test_failed_model_strategy_becomes_counterexample_then_fallback_succeeds(self):
        class UnsafeFirstLLM:
            def reason(self, **kwargs):
                return {
                    "summary": "keep string concatenation",
                    "edits": [{
                        "file": SOURCE_PATH,
                        "operation": "replace_symbol",
                        "symbol": "search_users",
                        "replacement": (
                            "def search_users(cursor):\n"
                            "    keyword = request.args.get('q', '')\n"
                            "    sql = \"select * from users where name = '\" + keyword + \"'\"\n"
                            "    cursor.execute(sql)\n"
                            "    return cursor.fetchall()"
                        ),
                        "rationale": "incorrect attempted repair",
                    }],
                }

        result = RepairKernel(max_attempts=3).run(
            scenario(VULNERABLE_SOURCE, commands=True, llm=UnsafeFirstLLM()),
        )
        self.assertTrue(result.accepted)
        self.assertEqual(len(result.session.candidates), 3)
        self.assertEqual(len(result.session.counterexamples), 2)
        self.assertEqual(
            result.session.candidates[1].strategy,
            "model_counterexample_retry",
        )
        self.assertEqual(
            result.session.candidates[2].strategy,
            "deterministic_counterexample_fallback",
        )
        self.assertEqual(
            result.session.counterexamples[0].strategy_fingerprint,
            result.session.counterexamples[1].strategy_fingerprint,
        )

    def test_phase4_sql_benchmark_20_cases(self):
        observations = []
        for case in [
            item for item in default_phase1_inventory()
            if item.family == "sql_injection"
        ]:
            case_finding = VulnerabilityNormalizer().normalize(case.finding_input)
            point = SimpleNamespace(
                file=case.source_path,
                symbol=case.function,
                line=1,
            )
            case_root = SimpleNamespace(
                root_cause=SimpleNamespace(
                    summary="dynamic SQL reaches cursor.execute",
                    missing_control="bound query parameters",
                    source=point,
                    sink=point,
                ),
                affected_code=[],
                security_invariant="untrusted input must remain bound data",
            )
            case_plan = plan()
            case_plan.finding_id = case.case_id
            case_plan.planned_changes[0].file = case.source_path
            case_plan.planned_changes[0].description = f"parameterize {case.function}"
            case_plan.patch_boundaries.allowed_files = [case.source_path]
            case_evidence = evidence(commands=False)
            case_evidence.validation_capabilities.test_commands = list(
                case.business_commands
            )
            case_evidence.validation_capabilities.security_commands = list(
                case.security_commands
            )
            case_evidence.validation_capabilities.poc_commands = [
                "python -c \"from pathlib import Path; import sys; "
                f"s=Path('{case.source_path}').read_text(); "
                "sys.exit(0 if 'cursor.execute(sql, (' in s else 1)\""
            ]
            scenario_adapter = SQLInjectionRepairScenario(
                case_finding,
                case_root,
                case_plan,
                [
                    SourceFile(case.source_path, case.source),
                    SourceFile(case.test_path, case.test_source),
                ],
                case_evidence,
                None,
            )
            result = RepairKernel(max_attempts=3).run(scenario_adapter)
            record = result.session.candidates[-1] if result.session.candidates else None
            categories = {
                item.category.value: item.passed
                for item in (record.oracle_results if record else [])
            }
            observations.append(QualityObservation(
                case.case_id,
                baseline_reproduced=any(
                    item.category.value == "reproduction" and item.passed
                    for item in result.session.baseline_results
                ),
                exact_apply=categories.get("diff_risk", False),
                build_passed=categories.get("baseline_build", False),
                security_passed=categories.get("security", False),
                business_passed=categories.get("business", False),
                accepted=result.accepted,
                correct=result.accepted,
                attempts=len(result.session.candidates),
                duplicate_failures=0,
            ))

        metrics = PatchQualityMetrics.from_observations(observations)
        self.assertEqual(metrics.total, 20)
        self.assertEqual(metrics.baseline_reproduction_rate, 1.0)
        self.assertEqual(metrics.exact_apply_rate, 1.0)
        self.assertEqual(metrics.security_pass_rate, 1.0)
        self.assertEqual(metrics.business_pass_rate, 1.0)
        self.assertEqual(metrics.accepted_patch_precision, 1.0)
        self.assertEqual(metrics.pass_at_1, 1.0)


if __name__ == "__main__":
    unittest.main()
