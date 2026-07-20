from __future__ import annotations

import unittest
from types import SimpleNamespace

from vuln_agent.failure_analysis import FailureAnalysisAgent
from vuln_agent.models import (
    FailureCategory,
    RemediationFeedbackTarget,
)


class FailureRoutePolicyTests(unittest.TestCase):
    def test_each_failure_category_returns_to_its_owning_node(self):
        cases = [
            (
                FailureCategory.SECURITY_NOT_FIXED,
                RemediationFeedbackTarget.ROOT_CAUSE_AGENT,
            ),
            (
                FailureCategory.SCANNER_STILL_REPORTS,
                RemediationFeedbackTarget.ROOT_CAUSE_AGENT,
            ),
            (
                FailureCategory.BUSINESS_REGRESSION,
                RemediationFeedbackTarget.REMEDIATION_PLAN_AGENT,
            ),
            (
                FailureCategory.BUILD_FAILURE,
                RemediationFeedbackTarget.PATCH_GENERATION_AGENT,
            ),
            (
                FailureCategory.DIFFERENTIAL_RISK,
                RemediationFeedbackTarget.PATCH_GENERATION_AGENT,
            ),
            (
                FailureCategory.PATCH_POLICY_VIOLATION,
                RemediationFeedbackTarget.PATCH_GENERATION_AGENT,
            ),
            (
                FailureCategory.TEST_HARNESS_FAILURE,
                RemediationFeedbackTarget.PATCH_GENERATION_AGENT,
            ),
            (
                FailureCategory.TOOLING_GAP,
                RemediationFeedbackTarget.VALIDATION_TOOLCHAIN,
            ),
            (
                FailureCategory.UNKNOWN,
                RemediationFeedbackTarget.HUMAN_REVIEW,
            ),
        ]
        for category, expected in cases:
            with self.subTest(category=category.value):
                actual = FailureAnalysisAgent._route_for_findings([
                    SimpleNamespace(category=category)
                ])
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
