"""Tests for json_repair — robust JSON repair for truncated LLM outputs."""

from __future__ import annotations

import json
import unittest

from vuln_agent.json_repair import (
    extract_largest_json_object,
    repair_json,
)


class JsonRepairTests(unittest.TestCase):
    """Unit tests for repair_json."""

    def test_valid_json_passes_through(self):
        result = repair_json('{"status": "confirmed", "score": 0.9}')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["score"], 0.9)

    def test_truncated_mid_string(self):
        result = repair_json('{"summary": "JsonWebToken.decode() in v1.3.0 does not accept')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("summary", result)
        self.assertIsInstance(result["summary"], str)

    def test_missing_closing_brace_simple(self):
        result = repair_json('{"key": "value"')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["key"], "value")

    def test_missing_closing_brackets_nested(self):
        result = repair_json('{"a": {"b": [1, 2')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["a"]["b"], [1, 2])

    def test_trailing_comma_in_object(self):
        result = repair_json('{"a": 1, "b": 2,}')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["a"], 1)
        self.assertEqual(result["b"], 2)

    def test_trailing_comma_in_array(self):
        result = repair_json('{"items": [1, 2, 3,]}')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["items"], [1, 2, 3])

    def test_non_json_prefix_skipped(self):
        result = repair_json('Here is my analysis: {"status": "ok", "value": 42}')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["value"], 42)

    def test_empty_string_returns_none(self):
        result = repair_json("")
        self.assertIsNone(result)

    def test_no_braces_returns_none(self):
        result = repair_json("this is just text, no json here")
        self.assertIsNone(result)

    def test_unicode_content_preserved(self):
        result = repair_json('{"message": "你好世界')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("你好世界", result["message"])

    def test_escaped_quotes_inside_string(self):
        result = repair_json('{"key": "value with \\"escaped\\" quotes"')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn('escaped', result["key"])

    def test_deepseek_production_truncation_pattern(self):
        """Simulate actual DeepSeek truncation: JSON containing escaped JSON strings."""
        raw = (
            '{"finding_id": "CVE-2024-37568",'
            '"status": "confirmed",'
            '"summary": "JsonWebToken.decode() does not accept algorithms param'
        )
        result = repair_json(raw)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["finding_id"], "CVE-2024-37568")
        self.assertEqual(result["status"], "confirmed")
        self.assertIn("summary", result)
        self.assertIsInstance(result["summary"], str)
        self.assertIn("JsonWebToken.decode", result["summary"])

    def test_partial_field_value_dropped(self):
        """When a field value is incomplete, drop it to allow structural repair."""
        result = repair_json('{"finding_id": "F-001", "status": "pro')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["finding_id"], "F-001")
        # The incomplete "status" field should have been handled gracefully.
        self.assertIn("status", result)

    def test_boolean_and_null_values(self):
        result = repair_json('{"a": true, "b": false, "c": nul')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["a"], True)
        self.assertEqual(result["b"], False)

    def test_array_with_objects(self):
        result = repair_json('{"items": [{"id": 1}, {"id": 2')
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(len(result["items"]), 2)
        self.assertEqual(result["items"][0]["id"], 1)

    def test_truncated_number(self):
        result = repair_json('{"confidence_score": 0.')
        self.assertIsNotNone(result)
        assert result is not None

    def test_only_opening_brace(self):
        result = repair_json("{")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIsInstance(result, dict)

    def test_multiline_json(self):
        raw = """{
            "status": "confirmed",
            "items": [
                "one",
                "two"
        """
        result = repair_json(raw)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["items"], ["one", "two"])


class ExtractLargestJsonObjectTests(unittest.TestCase):
    """Unit tests for extract_largest_json_object."""

    def test_single_json_object_in_prose(self):
        text = """Some analysis text before the JSON.
        {"finding_id": "F-001", "status": "probable", "score": 0.55}
        And some more text after."""
        result = extract_largest_json_object(text)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["finding_id"], "F-001")

    def test_multiple_json_objects_picks_largest(self):
        text = """First: {"a": 1}
        Second: {"finding_id": "CVE-2024", "status": "confirmed", "score": 0.9, "services": ["auth", "api"]}
        Third: {"b": 2}"""
        result = extract_largest_json_object(text)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["finding_id"], "CVE-2024")
        self.assertIn("services", result)

    def test_no_json_object_returns_none(self):
        result = extract_largest_json_object("no json here at all")
        self.assertIsNone(result)

    def test_broken_json_object_repaired(self):
        text = """The root cause is: {"summary": "algorithm confusion in JWT", "status": "confirme"""
        result = extract_largest_json_object(text)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["summary"], "algorithm confusion in JWT")

    def test_nested_objects_handled(self):
        text = """Result: {"outer": {"inner": {"key": "value"}}, "flag": true}"""
        result = extract_largest_json_object(text)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["outer"]["inner"]["key"], "value")
        self.assertEqual(result["flag"], True)


if __name__ == "__main__":
    unittest.main()
