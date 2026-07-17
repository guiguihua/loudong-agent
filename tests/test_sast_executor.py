from __future__ import annotations

import unittest
from types import SimpleNamespace

from vuln_agent.models import (
    CompatibilityAssessment,
    EvidenceBundle,
    PatchBoundaries,
    PatchCandidateStatus,
    PatchGenerationPolicy,
    RemediationPlan,
    RemediationPlanStatus,
    RepositorySummary,
    RepositoryContext,
    RollbackPlan,
    Severity,
    SourceFile,
    ValidationCapabilities,
    TestPlanItem as PlanTestItem,
)
from vuln_agent.normalization import VulnerabilityNormalizer
from vuln_agent.patching import PatchGenerationAgent
from vuln_agent.sast_executor import SASTCodeRepairExecutor
from vuln_agent.semantic import PythonSemanticContextBuilder
from vuln_agent.models import PlannedChange


def make_finding(vulnerability_type: str, path: str, function: str):
    return VulnerabilityNormalizer().normalize({
        "finding_id": "sast-executor-test",
        "vulnerability_type": vulnerability_type,
        "severity": "high",
        "scanner": "test",
        "affected_file": path,
        "affected_function": function,
        "line": 4,
        "evidence": "untrusted input reaches dangerous sink",
    })


def make_plan(path: str, function: str) -> RemediationPlan:
    return RemediationPlan(
        finding_id="sast-executor-test",
        status=RemediationPlanStatus.READY,
        remediation_goal="restore the security invariant",
        strategies=[],
        planned_changes=[
            PlannedChange(
                path,
                "code",
                f"repair {function}",
                "confirmed source-to-sink path",
                Severity.LOW,
                causally_required=True,
            )
        ],
        dependency_upgrade=None,
        compatibility=CompatibilityAssessment("compatible", [], []),
        risk_points=[],
        required_tests=[
            PlanTestItem(
                "dual direction security regression",
                "security",
                "tests/test_user_search.py",
                "attack is blocked and legitimate behavior remains valid",
            )
        ],
        rejected_alternatives=[],
        rollback=RollbackPlan("revert", ["revert"]),
        patch_boundaries=PatchBoundaries([path], [], 3, 200),
        assumptions=[],
        unknowns=[],
        confidence_score=1.0,
        needs_human_review=True,
    )


def make_root(path: str, function: str):
    point = SimpleNamespace(file=path, symbol=function, line=4)
    return SimpleNamespace(
        root_cause=SimpleNamespace(
            summary="untrusted input reaches a dangerous sink",
            missing_control="family-specific security guard",
            source=point,
            sink=point,
        ),
        affected_code=[],
        security_invariant="untrusted input must remain data",
    )


def make_evidence(*commands: str) -> EvidenceBundle:
    return EvidenceBundle(
        finding_id="sast-executor-test",
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
            test_commands=list(commands),
            security_commands=list(commands),
        ),
        collection_warnings=[],
        bundle_hash="test",
    )


class SASTWorkspaceExecutorTests(unittest.TestCase):
    def test_patch_generation_main_path_uses_workspace_executor(self):
        path = "src/user/search.py"
        source = (
            "from flask import request\n\n\n"
            "def search_users(cursor):\n"
            "    keyword = request.args.get(\"q\", \"\")\n"
            "    sql = \"select * from users where name like '%\" + keyword + \"%'\"\n"
            "    cursor.execute(sql)\n"
            "    return cursor.fetchall()\n"
        )
        finding = make_finding("SQL Injection", path, "search_users")
        agent = PatchGenerationAgent(PatchGenerationPolicy(), llm=None)
        candidate = agent.generate(
            finding,
            SimpleNamespace(),
            make_root(path, "search_users"),
            make_plan(path, "search_users"),
            RepositoryContext(language="Python", test_framework="pytest"),
            [
                SourceFile(path, source),
                SourceFile(
                    "tests/test_user_search.py",
                    "def test_existing():\n    assert True\n",
                ),
            ],
            evidence_bundle=make_evidence(),
        )
        self.assertEqual(candidate.status, PatchCandidateStatus.GENERATED)
        self.assertEqual(
            agent.last_execution.details["executor"],
            "sast_workspace_executor",
        )
        self.assertEqual(len(candidate.artifacts), 2)

    def test_sql_injection_uses_ast_edit_and_git_generated_diff(self):
        path = "src/user/search.py"
        source = (
            "from flask import request\n\n\n"
            "def search_users(cursor):\n"
            "    keyword = request.args.get(\"q\", \"\")\n"
            "    sql = \"select * from users where name like '%\" + keyword + \"%'\"\n"
            "    cursor.execute(sql)\n"
            "    return cursor.fetchall()\n"
        )
        sources = [
            SourceFile(path, source),
            SourceFile("tests/test_user_search.py", "def test_existing():\n    assert True\n"),
        ]
        result = SASTCodeRepairExecutor(None).execute(
            make_finding("SQL Injection", path, "search_users"),
            make_root(path, "search_users"),
            make_plan(path, "search_users"),
            sources,
            make_evidence(),
        )
        self.assertIsNone(result["blocked_reason"])
        self.assertEqual(result["executor"], "sast_workspace_executor")
        code = next(item for item in result["artifacts"] if item["target"] == path)
        self.assertIn("cursor.execute(sql, (f\"%{keyword}%\",))", code["content"])
        self.assertTrue(PatchGenerationAgent._verify_diff_applies(code["content"], source))
        test = next(item for item in result["artifacts"] if item["patch_type"] == "test")
        self.assertIn("attack", test["content"])
        self.assertIn("legitimate", test["content"])

    def test_semantic_builder_keeps_complete_target_after_large_prefix(self):
        path = "app.py"
        prefix = "\n".join(f"VALUE_{index} = {index}" for index in range(3000))
        source = prefix + "\n\ndef vulnerable(value):\n    return value\n"
        package = PythonSemanticContextBuilder().build(
            make_finding("Command Injection", path, "vulnerable"),
            make_root(path, "vulnerable"),
            make_plan(path, "vulnerable"),
            [SourceFile(path, source)],
            make_evidence(),
            "command_injection",
        )
        self.assertEqual(package.symbols[0].symbol, "vulnerable")
        self.assertEqual(
            package.symbols[0].source,
            "def vulnerable(value):\n    return value\n",
        )

    def test_command_injection_structured_edit_is_verified(self):
        class FakeLLM:
            def reason(self, **kwargs):
                return {
                    "summary": "use argv execution",
                    "edits": [
                        {
                            "file": "app.py",
                            "operation": "insert_import",
                            "symbol": None,
                            "replacement": "import subprocess",
                            "rationale": "use safe process API",
                        },
                        {
                            "file": "app.py",
                            "operation": "replace_symbol",
                            "symbol": "ping",
                            "replacement": (
                                "def ping(host):\n"
                                "    return subprocess.run([\"ping\", host], check=True)"
                            ),
                            "rationale": "avoid shell parsing",
                        },
                    ],
                }

        source = "import os\n\n\ndef ping(host):\n    return os.system(\"ping \" + host)\n"
        result = SASTCodeRepairExecutor(FakeLLM()).execute(
            make_finding("Command Injection", "app.py", "ping"),
            make_root("app.py", "ping"),
            make_plan("app.py", "ping"),
            [SourceFile("app.py", source)],
            make_evidence(),
        )
        self.assertIsNone(result["blocked_reason"])
        diff = result["artifacts"][0]["content"]
        self.assertIn("subprocess.run([\"ping\", host], check=True)", diff)
        self.assertNotIn("+    return os.system", diff)

    def test_command_injection_has_conservative_deterministic_fallback(self):
        source = (
            "import os\n\n\n"
            "def ping(host):\n"
            "    return os.system(\"ping -c 1 \" + host)\n"
        )
        result = SASTCodeRepairExecutor(None).execute(
            make_finding("Command Injection", "app.py", "ping"),
            make_root("app.py", "ping"),
            make_plan("app.py", "ping"),
            [
                SourceFile("app.py", source),
                SourceFile("tests/test_app.py", "def test_existing():\n    assert True\n"),
            ],
            make_evidence("python -m pytest tests/test_app.py -q"),
        )
        self.assertIsNone(result["blocked_reason"])
        code = next(item for item in result["artifacts"] if item["target"] == "app.py")
        self.assertIn("subprocess.run(['ping', '-c', '1', host]", code["content"])
        self.assertIn(".returncode", code["content"])
        self.assertTrue(any(item["patch_type"] == "test" for item in result["artifacts"]))

    def test_path_traversal_requires_resolved_containment(self):
        class FakeLLM:
            def reason(self, **kwargs):
                return {
                    "summary": "resolve and contain path",
                    "edits": [{
                        "file": "files.py",
                        "operation": "replace_symbol",
                        "symbol": "read_user_file",
                        "replacement": (
                            "def read_user_file(base, user_path):\n"
                            "    base_path = Path(base).resolve()\n"
                            "    candidate = (base_path / user_path).resolve()\n"
                            "    if not candidate.is_relative_to(base_path):\n"
                            "        raise ValueError(\"path escapes base directory\")\n"
                            "    return candidate.read_text()"
                        ),
                        "rationale": "enforce resolved path containment",
                    }],
                }

        source = (
            "from pathlib import Path\n\n\n"
            "def read_user_file(base, user_path):\n"
            "    return (Path(base) / user_path).read_text()\n"
        )
        result = SASTCodeRepairExecutor(FakeLLM()).execute(
            make_finding("Path Traversal", "files.py", "read_user_file"),
            make_root("files.py", "read_user_file"),
            make_plan("files.py", "read_user_file"),
            [SourceFile("files.py", source)],
            make_evidence(),
        )
        self.assertIsNone(result["blocked_reason"])
        self.assertIn("is_relative_to", result["artifacts"][0]["content"])

    def test_path_oracle_cannot_be_satisfied_by_marker_string(self):
        class FakeLLM:
            def reason(self, **kwargs):
                return {
                    "summary": "fake marker",
                    "edits": [{
                        "file": "files.py",
                        "operation": "replace_symbol",
                        "symbol": "read_user_file",
                        "replacement": (
                            "def read_user_file(base, user_path):\n"
                            "    marker = '.resolve() is_relative_to'\n"
                            "    return (Path(base) / user_path).read_text()"
                        ),
                        "rationale": "not a real boundary check",
                    }],
                }

        source = (
            "from pathlib import Path\n\n\n"
            "def read_user_file(base, user_path):\n"
            "    return (Path(base) / user_path).read_text()\n"
        )
        result = SASTCodeRepairExecutor(FakeLLM()).execute(
            make_finding("Path Traversal", "files.py", "read_user_file"),
            make_root("files.py", "read_user_file"),
            make_plan("files.py", "read_user_file"),
            [SourceFile("files.py", source)],
            make_evidence(),
        )
        self.assertIsNotNone(result["blocked_reason"])

    def test_path_traversal_has_conservative_deterministic_fallback(self):
        source = (
            "from pathlib import Path\n\n\n"
            "def read_user_file(base, user_path):\n"
            "    return (Path(base) / user_path).read_text(encoding=\"utf-8\")\n"
        )
        result = SASTCodeRepairExecutor(None).execute(
            make_finding("Path Traversal", "files.py", "read_user_file"),
            make_root("files.py", "read_user_file"),
            make_plan("files.py", "read_user_file"),
            [
                SourceFile("files.py", source),
                SourceFile("tests/test_files.py", "def test_existing():\n    assert True\n"),
            ],
            make_evidence("python -m pytest tests/test_files.py -q"),
        )
        self.assertIsNone(result["blocked_reason"])
        code = next(item for item in result["artifacts"] if item["target"] == "files.py")
        self.assertIn("candidate_path.is_relative_to(base_path)", code["content"])
        self.assertIn("candidate_path.read_text", code["content"])
        self.assertTrue(any(item["patch_type"] == "test" for item in result["artifacts"]))

    def test_phase1_stability_matrix_12_sql_10_command_10_path(self):
        sql_prefixes = [
            ("users", "name"), ("accounts", "email"), ("orders", "reference"),
            ("products", "title"), ("tickets", "subject"), ("devices", "label"),
            ("projects", "slug"), ("teams", "display_name"), ("notes", "body"),
            ("articles", "headline"), ("customers", "company"), ("events", "kind"),
        ]
        for index, (table, column) in enumerate(sql_prefixes):
            with self.subTest(family="sql", case=index):
                path = f"src/sql_case_{index}.py"
                test_path = f"tests/test_sql_case_{index}.py"
                source = (
                    "from flask import request\n\n\n"
                    "def search_users(cursor):\n"
                    "    keyword = request.args.get(\"q\", \"\")\n"
                    f"    sql = \"select * from {table} where {column} like '%\" + keyword + \"%'\"\n"
                    "    cursor.execute(sql)\n"
                    "    return cursor.fetchall()\n"
                )
                result = SASTCodeRepairExecutor(None).execute(
                    make_finding("SQL Injection", path, "search_users"),
                    make_root(path, "search_users"),
                    make_plan(path, "search_users"),
                    [
                        SourceFile(path, source),
                        SourceFile(test_path, "def test_existing():\n    assert True\n"),
                    ],
                    make_evidence(),
                )
                self.assertIsNone(result["blocked_reason"])
                self.assertTrue(all(check["passed"] for check in result["workspace_checks"]))

        command_prefixes = [
            "ping -c 1 ", "nslookup ", "dig ", "host ", "traceroute ",
            "whois ", "curl --head ", "stat ", "file ", "getent hosts ",
        ]
        for index, prefix in enumerate(command_prefixes):
            with self.subTest(family="command", case=index):
                path = f"src/command_case_{index}.py"
                source = (
                    "import os\n\n\n"
                    "def run_target(value):\n"
                    f"    return os.system({prefix!r} + value)\n"
                )
                result = SASTCodeRepairExecutor(None).execute(
                    make_finding("Command Injection", path, "run_target"),
                    make_root(path, "run_target"),
                    make_plan(path, "run_target"),
                    [
                        SourceFile(path, source),
                        SourceFile(
                            f"tests/test_command_case_{index}.py",
                            "def test_existing():\n    assert True\n",
                        ),
                    ],
                    make_evidence(),
                )
                self.assertIsNone(result["blocked_reason"])
                self.assertTrue(all(check["passed"] for check in result["workspace_checks"]))

        path_methods = [
            "read_text()", "read_text(encoding='utf-8')", "read_bytes()",
            "read_text(errors='replace')", "read_text(encoding='ascii')",
            "read_bytes()", "read_text()", "read_text(encoding='utf-8')",
            "read_bytes()", "read_text()",
        ]
        for index, method in enumerate(path_methods):
            with self.subTest(family="path", case=index):
                path = f"src/path_case_{index}.py"
                source = (
                    "from pathlib import Path\n\n\n"
                    "def read_user_file(base, user_path):\n"
                    f"    return (Path(base) / user_path).{method}\n"
                )
                result = SASTCodeRepairExecutor(None).execute(
                    make_finding("Path Traversal", path, "read_user_file"),
                    make_root(path, "read_user_file"),
                    make_plan(path, "read_user_file"),
                    [
                        SourceFile(path, source),
                        SourceFile(
                            f"tests/test_path_case_{index}.py",
                            "def test_existing():\n    assert True\n",
                        ),
                    ],
                    make_evidence(),
                )
                self.assertIsNone(result["blocked_reason"])
                self.assertTrue(all(check["passed"] for check in result["workspace_checks"]))


if __name__ == "__main__":
    unittest.main()
