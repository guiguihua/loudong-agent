from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from vuln_agent.evidence import EvidenceCollector, format_evidence_bundle
from vuln_agent.models import EngineeringContext, RepositoryContext, SourceFile
from vuln_agent.normalization import VulnerabilityNormalizer


def finding(**overrides):
    raw = {
        "finding_id": "F-EVIDENCE-1",
        "vulnerability_type": "SQL Injection",
        "severity": "high",
        "scanner": "SAST",
        "affected_file": "src/api/users.py",
        "affected_function": "find_user",
        "line": 4,
        "evidence": "request input is concatenated into SQL",
    }
    raw.update(overrides)
    return VulnerabilityNormalizer().normalize(raw)


class EvidenceCollectorTests(unittest.TestCase):
    def test_collects_target_route_source_sink_and_validation_capabilities(self):
        sources = [
            SourceFile(
                "src/api/users.py",
                "from flask import request\n"
                "@app.get('/users')\n"
                "def find_user():\n"
                "    query = request.args['q']\n"
                "    return db.execute('select * from users where name=' + query)\n",
            ),
            SourceFile("tests/test_users.py", "def test_find_user():\n    assert True\n"),
            SourceFile("pyproject.toml", "[project]\nname = 'sample'\n"),
        ]
        bundle = EvidenceCollector().collect(
            finding(),
            sources,
            RepositoryContext(repository="example/repo", base_revision="abc123"),
            EngineeringContext(language="Python", framework="Flask"),
        )

        self.assertEqual(bundle.target_files[0].path, "src/api/users.py")
        self.assertEqual(bundle.entry_points[0].route, "/users")
        self.assertTrue(any(item.path == "src/api/users.py" for item in bundle.source_candidates))
        self.assertTrue(any(item.path == "src/api/users.py" for item in bundle.sink_candidates))
        self.assertIn("python -m pytest", bundle.validation_capabilities.test_commands)
        self.assertIn("python -m compileall -q .", bundle.validation_capabilities.build_commands)
        self.assertEqual(bundle.validation_capabilities.security_commands, [])
        self.assertEqual(bundle.validation_capabilities.poc_commands, [])
        self.assertTrue(any(item.path == "tests/test_users.py" and item.related for item in bundle.test_evidence))
        self.assertTrue(bundle.code_slices)

    def test_only_explicit_security_and_poc_commands_become_oracles(self):
        security = "python -m pytest tests/security/test_sql.py"
        poc = "python -m pytest tests/security/test_sql.py::test_exploit"
        bundle = EvidenceCollector().collect(
            finding(),
            [
                SourceFile("src/api/users.py", "def find_user():\n    pass\n"),
                SourceFile(
                    "tests/test_users.py",
                    "def test_find_user():\n    assert True\n",
                ),
            ],
            engineering=EngineeringContext(
                available_test_commands=["python -m pytest tests/test_users.py"],
                available_security_commands=[security],
                available_poc_commands=[poc],
            ),
        )
        self.assertEqual(bundle.validation_capabilities.security_commands, [security])
        self.assertEqual(bundle.validation_capabilities.poc_commands, [poc])

    def test_django_source_checkout_prefers_focused_runtests_command(self):
        sources = [
            SourceFile("django/__init__.py", "VERSION = (5, 0, 6)\n"),
            SourceFile("django/db/models/sql/query.py", "def set_values(fields):\n    pass\n"),
            SourceFile("tests/runtests.py", "def main():\n    pass\n"),
            SourceFile(
                "tests/query/test_query.py",
                "def test_set_values_alias():\n    assert True\n",
            ),
            SourceFile("pyproject.toml", "[project]\nname = 'Django'\n"),
        ]
        bundle = EvidenceCollector().collect(
            finding(
                affected_file="django/db/models/sql/query.py",
                affected_function="set_values",
                line=1,
            ),
            sources,
            engineering=EngineeringContext(language="Python", framework="Django"),
        )

        commands = bundle.validation_capabilities.test_commands
        self.assertIn("python tests/runtests.py query.test_query", commands)
        self.assertNotIn("python -m pytest", commands)
        self.assertIn(
            "django-runtests",
            bundle.validation_capabilities.detected_tools,
        )

    def test_django_python_finding_does_not_add_frontend_npm_tests(self):
        sources = [
            SourceFile("django/__init__.py", "VERSION = (5, 0, 6)\n"),
            SourceFile(
                "django/db/models/sql/query.py",
                "class Query:\n    def set_values(self, fields):\n        pass\n",
            ),
            SourceFile("tests/runtests.py", "def main():\n    pass\n"),
            SourceFile("package.json", '{"scripts": {"test": "grunt test"}}\n'),
        ]

        bundle = EvidenceCollector().collect(
            finding(
                affected_file="django/db/models/sql/query.py",
                affected_function="set_values",
            ),
            sources,
            engineering=EngineeringContext(
                language="Python",
                framework="Django",
            ),
        )

        self.assertNotIn("npm test", bundle.validation_capabilities.test_commands)
        self.assertNotIn("npm", bundle.validation_capabilities.detected_tools)

    def test_explicit_build_and_scanner_commands_are_preserved(self):
        bundle = EvidenceCollector().collect(
            finding(),
            [SourceFile("src/api/users.py", "def find_user():\n    pass\n")],
            engineering=EngineeringContext(
                available_build_commands=["python -m py_compile src/api/users.py"],
                available_scanner_commands=["semgrep scan --config sql ."],
            ),
        )

        self.assertEqual(
            bundle.validation_capabilities.build_commands,
            ["python -m py_compile src/api/users.py"],
        )
        self.assertEqual(
            bundle.validation_capabilities.scanner_commands,
            ["semgrep scan --config sql ."],
        )

    def test_django_identifier_finding_collects_check_alias_peer_control(self):
        root = Path(__file__).resolve().parents[1]
        query_path = (
            root
            / "validation-coverage"
            / "sql-injection"
            / "django-5.0.6"
            / "django"
            / "db"
            / "models"
            / "sql"
            / "query.py"
        )
        source = query_path.read_text(encoding="utf-8")

        bundle = EvidenceCollector().collect(
            finding(
                affected_file="django/db/models/sql/query.py",
                affected_function="set_values",
                line=2442,
                evidence=(
                    "values() accepts attacker-controlled JSONField column "
                    "aliases without enforcing the alias safety invariant"
                ),
            ),
            [SourceFile("django/db/models/sql/query.py", source)],
            engineering=EngineeringContext(
                language="Python",
                framework="Django",
            ),
        )

        peer_reasons = [
            item.reason
            for item in bundle.code_slices
            if item.reason.startswith("peer identifier security control:")
        ]
        self.assertEqual(
            peer_reasons,
            ["peer identifier security control: self.check_alias"],
        )

    def test_collection_is_stable_and_target_files_are_scanned_first(self):
        noisy = "\n".join(f"value_{index} = input()" for index in range(50))
        sources = [
            SourceFile("aaa/noise.py", noisy),
            SourceFile("src/api/users.py", "def find_user():\n    return db.execute(request.args['q'])\n"),
        ]
        collector = EvidenceCollector(max_candidates_per_kind=2)
        first = collector.collect(finding(line=2), sources)
        second = collector.collect(finding(line=2), list(reversed(sources)))

        self.assertEqual(first.bundle_hash, second.bundle_hash)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.source_candidates[0].path, "src/api/users.py")
        self.assertEqual(first.sink_candidates[0].path, "src/api/users.py")

    def test_dependency_and_manifest_evidence_are_collected(self):
        dep_finding = finding(
            vulnerability_type="dependency",
            affected_file="package.json",
            component="jsonwebtoken",
            current_version="8.0.0",
            fixed_versions=["9.0.0"],
            line=3,
        )
        sources = [
            SourceFile(
                "package.json",
                '{\n  "scripts": {"test": "jest"},\n  "dependencies": {"jsonwebtoken": "8.0.0"}\n}\n',
            ),
            SourceFile("src/auth.test.js", "test('auth', () => expect(true).toBe(true));\n"),
        ]
        bundle = EvidenceCollector().collect(dep_finding, sources)

        self.assertTrue(any(item.path == "package.json" for item in bundle.dependency_evidence))
        self.assertIn("npm test", bundle.validation_capabilities.test_commands)
        self.assertIn("package.json", bundle.repository_summary.manifests)

    def test_dependency_scanner_is_required_only_when_executable_is_available(self):
        dep_finding = finding(
            vulnerability_type="dependency",
            affected_file="requirements.txt",
            component="django",
            current_version="5.0.6",
            fixed_versions=["5.0.8"],
        )
        with patch(
            "vuln_agent.evidence.shutil.which",
            side_effect=lambda name: "C:/tools/osv-scanner.exe"
            if name == "osv-scanner" else None,
        ):
            bundle = EvidenceCollector().collect(
                dep_finding,
                [SourceFile("requirements.txt", "Django==5.0.6\n")],
            )
        self.assertIn(
            "osv-scanner --recursive .",
            bundle.validation_capabilities.scanner_commands,
        )
        self.assertIn(
            "osv-scanner",
            bundle.validation_capabilities.detected_tools,
        )

    def test_environment_values_are_never_exposed(self):
        secret = "super-secret-value"
        access_key = "AKIAABCDEFGHIJKLMNOP"
        sources = [
            SourceFile(".env", f"API_TOKEN={secret}\nNORMAL_FLAG=true\n"),
            SourceFile(
                "src/api/users.py",
                "PRIVATE_KEY = '''-----BEGIN PRIVATE KEY-----\n"
                "private-material\n"
                "-----END PRIVATE KEY-----'''\n"
                f"ACCESS_KEY = '{access_key}'\n"
                "def find_user():\n    return execute('safe')\n",
            ),
        ]
        bundle = EvidenceCollector().collect(finding(line=5), sources)
        serialized = json.dumps(bundle.to_dict(), ensure_ascii=False)

        self.assertNotIn(secret, serialized)
        self.assertNotIn("private-material", serialized)
        self.assertNotIn(access_key, serialized)
        self.assertTrue(any(item.path == ".env" and item.value == "<redacted>" for item in bundle.config_evidence))
        self.assertNotIn(secret, format_evidence_bundle(bundle))

    def test_prompt_view_is_bounded(self):
        source = SourceFile("src/api/users.py", "x = request.args['x']\n" * 500)
        bundle = EvidenceCollector(max_total_chars=20_000).collect(finding(line=250), [source])
        prompt = format_evidence_bundle(bundle, max_chars=2_000)

        self.assertLessEqual(len(prompt), 2_100)
        self.assertIn("bundle_hash", prompt)

    def test_descriptive_location_resolves_every_real_candidate(self):
        item = finding(
            vulnerability_type="JWT algorithm confusion",
            affected_file="authlib/jose/rfc7519/claims.py or jwt.py — decode path",
            affected_function=None,
            line=None,
        )
        sources = [
            SourceFile("authlib/jose/rfc7519/claims.py", "class JWTClaims(dict):\n    pass\n"),
            SourceFile("authlib/jose/rfc7519/jwt.py", "class JsonWebToken:\n    def decode(self, s, key):\n        pass\n"),
        ]

        bundle = EvidenceCollector().collect(item, sources)

        self.assertEqual(
            [target.path for target in bundle.target_files],
            [
                "authlib/jose/rfc7519/claims.py",
                "authlib/jose/rfc7519/jwt.py",
            ],
        )
        self.assertEqual(
            {code_slice.path for code_slice in bundle.code_slices},
            {
                "authlib/jose/rfc7519/claims.py",
                "authlib/jose/rfc7519/jwt.py",
            },
        )

    def test_tests_examples_and_ci_files_do_not_become_production_impact(self):
        sources = [
            SourceFile(
                "src/api/users.py",
                "@app.get('/users')\ndef find_user():\n    return db.execute(request.args['q'])\n",
            ),
            SourceFile(
                "tests/test_fake_routes.py",
                "@app.post('/fixture/admin')\ndef fake():\n    return execute(request.args['q'])\n",
            ),
            SourceFile(
                "examples/demo.py",
                "@app.delete('/demo')\ndef demo():\n    return execute(input())\n",
            ),
            SourceFile(
                ".github/workflows/security.yml",
                "steps:\n  - run: curl https://example.invalid?q=user_input\n",
            ),
        ]

        bundle = EvidenceCollector().collect(finding(line=2), sources)

        self.assertEqual(
            [(entry.route, entry.path) for entry in bundle.entry_points],
            [("/users", "src/api/users.py")],
        )
        production_candidate_paths = {
            item.path for item in [*bundle.source_candidates, *bundle.sink_candidates]
        }
        self.assertEqual(production_candidate_paths, {"src/api/users.py"})


if __name__ == "__main__":
    unittest.main()
