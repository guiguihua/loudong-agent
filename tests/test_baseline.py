from __future__ import annotations

import unittest

from vuln_agent.baseline import (
    build_verified_patch_baseline,
    count_prompt_contamination,
)


class VerifiedPatchBaselineTests(unittest.TestCase):
    def test_release_gate_uses_verified_semantics_not_pipeline_label(self):
        verified = {
            "status": "succeeded",
            "repair_route": {"family": "sast_code"},
            "patch_candidate": {"status": "generated"},
            "patch_validation": {"status": "passed"},
            "patch_quality": {
                "executable_artifact_rate": 1.0,
                "validation_layer_pass_rate": 1.0,
                "generated_test_contract_valid": True,
                "ready_for_automated_delivery": True,
            },
        }
        false_success = {
            "status": "succeeded",
            "repair_route": {"family": "sast_code"},
            "patch_candidate": {"status": "blocked"},
            "patch_validation": {"status": "failed"},
            "patch_quality": {
                "executable_artifact_rate": 0.0,
                "validation_layer_pass_rate": 0.0,
                "generated_test_contract_valid": False,
                "ready_for_automated_delivery": False,
            },
        }
        baseline = build_verified_patch_baseline([verified, false_success])
        self.assertEqual(baseline["metrics"]["verified_patch_rate"], 0.5)
        self.assertEqual(baseline["metrics"]["false_success_rate"], 0.5)
        self.assertFalse(baseline["release_ready"])

    def test_prompt_contamination_gate(self):
        self.assertEqual(
            count_prompt_contamination(["generic prompt", "OctKey.import_key rule"]),
            1,
        )

    def test_current_generic_prompts_have_no_case_specific_contamination(self):
        from vuln_agent.patching import PATCH_AGENT_PROMPT
        from vuln_agent.remediation import REMEDIATION_AGENT_PROMPT

        self.assertEqual(
            count_prompt_contamination([
                PATCH_AGENT_PROMPT,
                REMEDIATION_AGENT_PROMPT,
            ]),
            0,
        )


if __name__ == "__main__":
    unittest.main()
