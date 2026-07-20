from __future__ import annotations

import unittest

from vuln_agent.runner import _build_engineering


class RunnerConfigurationTests(unittest.TestCase):
    def test_validation_commands_feed_engineering_context(self):
        raw = {
            "language": "Python",
            "framework": "Django",
            "validation_commands": {
                "build": ["python -m compileall -q target.py"],
                "business_regression": ["python tests/runtests.py queries"],
                "security_regression": ["python tests/runtests.py expressions"],
                "poc": "python poc.py",
                "scanner_rescan": ["semgrep scan ."],
            },
        }

        context = _build_engineering(None, raw, False, {})

        self.assertEqual(
            context.available_build_commands,
            ["python -m compileall -q target.py"],
        )
        self.assertEqual(
            context.available_test_commands,
            ["python tests/runtests.py queries"],
        )
        self.assertEqual(
            context.available_security_commands,
            ["python tests/runtests.py expressions"],
        )
        self.assertEqual(context.available_poc_commands, ["python poc.py"])
        self.assertEqual(
            context.available_scanner_commands,
            ["semgrep scan ."],
        )

    def test_direct_overrides_are_merged_first_and_deduplicated(self):
        raw = {
            "validation_commands": {
                "business_regression": ["python -m unittest"],
            },
        }

        context = _build_engineering(
            None,
            raw,
            False,
            {
                "available_test_commands": [
                    "python tests/runtests.py queries",
                    "python -m unittest",
                ],
            },
        )

        self.assertEqual(
            context.available_test_commands,
            [
                "python tests/runtests.py queries",
                "python -m unittest",
            ],
        )


if __name__ == "__main__":
    unittest.main()
