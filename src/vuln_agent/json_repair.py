"""Robust JSON repair for truncated / malformed LLM outputs.

When DeepSeek reasoning models produce ``submit_final_result`` tool calls whose
JSON arguments are truncated by ``max_tokens``, the system must recover as much
structured data as possible rather than falling through to regex-based extraction
that produces unusable garbage.

Public API
----------
* ``repair_json(raw)`` — attempt to repair a broken JSON string and return the
  parsed dict.  Returns ``None`` when the input contains no recoverable JSON.
* ``extract_largest_json_object(text)`` — scan arbitrary text for the largest
  valid (or reparable) JSON *object* and return it.
"""

from __future__ import annotations

import json
import re
from typing import Any


# ── public entry points ────────────────────────────────────────────────────


def repair_json(raw: str) -> dict[str, Any] | None:
    """Attempt to repair truncated / malformed JSON and return the parsed dict.

    Returns ``None`` when no structurally recoverable JSON could be found.
    Never raises.
    """
    if not raw or not isinstance(raw, str):
        return None

    # Strip leading non-JSON noise (prose that starts before the first brace).
    start = _find_json_start(raw)
    if start is None:
        return None

    body = raw[start:]

    # Pass 1: direct parse — the common fast path.
    try:
        result = json.loads(body)
        if isinstance(result, dict):
            return result
        return None
    except json.JSONDecodeError:
        pass

    # Pass 2: state-machine structural repair (close strings, balance brackets).
    repaired = _structural_repair(body)
    if repaired is not None:
        return repaired

    # Pass 3: progressive trim — find the last valid parse position.
    trimmed = _progressive_trim(body)
    if trimmed is not None:
        return trimmed

    return None


def extract_largest_json_object(text: str) -> dict[str, Any] | None:
    """Find the largest valid (or reparable) JSON *object* in arbitrary text.

    Unlike a naive ``first-{`` / ``last-}`` range, this scans for every
    balanced ``{…}`` span, attempts to repair each one, and returns the
    one with the most top-level keys.
    """
    if not text or not isinstance(text, str):
        return None

    spans = _find_json_object_spans(text)
    if not spans:
        # Fall back to treating the whole text as one candidate.
        return repair_json(text)

    best: dict[str, Any] | None = None
    best_keys = -1

    for span in spans:
        candidate = repair_json(span)
        if isinstance(candidate, dict):
            n_keys = len(candidate)
            if n_keys > best_keys:
                best = candidate
                best_keys = n_keys

    return best


# ── internal helpers ───────────────────────────────────────────────────────


def _find_json_start(raw: str) -> int | None:
    """Return the index of the first ``{`` or ``[``, or None."""
    for i, ch in enumerate(raw):
        if ch in "{[":
            return i
    return None


def _structural_repair(body: str) -> dict[str, Any] | None:
    """State-machine repair: close truncated strings then balance brackets.

    This handles the common DeepSeek truncation patterns:
    * ``{"key": "val`` → missing ``"}``
    * ``{"a": {"b": [1, 2`` → missing ``]}}``
    * ``{"k": "incomplete`` → string left open
    """
    output: list[str] = []
    bracket_stack: list[str] = []
    in_string = False
    escape_next = False

    for ch in body:
        if escape_next:
            output.append(ch)
            escape_next = False
            continue

        if ch == "\\" and in_string:
            output.append(ch)
            escape_next = True
            continue

        if ch == '"' and not escape_next:
            in_string = not in_string
            output.append(ch)
            continue

        if in_string:
            output.append(ch)
            continue

        if ch in "{[":
            bracket_stack.append(ch)
            output.append(ch)
        elif ch == "}":
            if bracket_stack and bracket_stack[-1] == "{":
                bracket_stack.pop()
            output.append(ch)
        elif ch == "]":
            if bracket_stack and bracket_stack[-1] == "[":
                bracket_stack.pop()
            output.append(ch)
        else:
            output.append(ch)

    repaired = "".join(output)

    # Close truncated string.
    if in_string:
        repaired += '"'

    # Remove trailing commas inside objects/arrays (e.g. ",]" → "]", ",}" → "}")
    # before balancing brackets.
    repaired = _remove_trailing_commas(repaired)

    # Balance remaining brackets.
    while bracket_stack:
        top = bracket_stack.pop()
        repaired += "}" if top == "{" else "]"

    # Try the repaired result.
    try:
        result = json.loads(repaired)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    # If bracket-balanced repair failed, try trimming the last incomplete field
    # value and re-balancing.
    trimmed = _trim_trailing_partial_field(repaired)
    if trimmed != repaired:
        # Re-balance after trimming.
        trimmed_stack = _count_bracket_imbalance(trimmed)
        while trimmed_stack:
            top = trimmed_stack.pop()
            trimmed += "}" if top == "{" else "]"
        # Remove any trailing commas that were exposed by balancing.
        trimmed = _remove_trailing_commas(trimmed)
        try:
            result = json.loads(trimmed)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    return None


def _trim_trailing_partial_field(text: str) -> str:
    """If *text* ends with a clearly incomplete scalar field value (truncated
    string, partial literal, broken number), drop that field so the rest of the
    JSON can be closed cleanly.

    Complex values (objects/arrays) are NOT trimmed — bracket balancing in
    ``_structural_repair`` already handles those.
    """
    depth = 0
    in_str = False
    escaped = False
    last_colon = -1
    last_comma = -1

    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_str:
            escaped = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        elif ch == ":" and depth == 1:
            last_colon = i
        elif ch == "," and depth == 1:
            last_comma = i

    if last_colon <= 0:
        return text

    # Value starts after last_colon.
    after = text[last_colon + 1:].strip()
    if not after:
        return text[:last_colon] if text.rstrip().endswith(",") else text[:last_colon + 1] + ' null'

    # Complex values (objects/arrays) — keep them; bracket balancing handles these.
    if after[0] in "{[":
        return text

    # Complete scalar — keep it.
    if _looks_complete(after):
        return text

    # Incomplete scalar (truncated string, partial literal, broken number).
    # Drop the entire key:value pair, including the preceding comma if any.
    if last_comma > last_colon:
        # Comma is AFTER this field — the field is not the last one.
        return text[:last_colon + 1] + " null, " + text[last_comma + 1:]

    # This is the last field.  Cut back to the preceding comma (or opening brace).
    if last_comma > 0:
        return text[:last_comma].rstrip()
    # First and only field — cut after opening brace.
    brace_pos = text.find("{")
    return text[:brace_pos + 1] if brace_pos >= 0 else text[:1]


def _looks_complete(value: str) -> bool:
    """Quick heuristic: does *value* look like a complete JSON token?"""
    value = value.strip()
    if not value:
        return False
    # String
    if value.startswith('"') and value.endswith('"'):
        return True
    # Number
    if re.match(r"^-?\d+(\.\d+)?([eE][+-]?\d+)?$", value):
        return True
    # Literals
    if value in ("true", "false", "null"):
        return True
    # Object or array — check bracket balance
    if value[0] in "{[":
        depth = 0
        in_str = False
        escaped = False
        for ch in value:
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_str:
                escaped = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
        return depth == 0
    return False


def _remove_trailing_commas(text: str) -> str:
    """Remove trailing commas inside objects and arrays (``,"}`` → ``"}``, ``,]`` → ``]``).

    Repeated until no more replacements are made.
    """
    prev = None
    while prev != text:
        prev = text
        text = text.replace(",]", "]").replace(",}", "}")
        # Also handle whitespace: ",  ]" → "  ]"
        text = re.sub(r",\s*\]", lambda m: m.group(0)[1:], text)
        text = re.sub(r",\s*\}", lambda m: m.group(0)[1:], text)
    return text


def _count_bracket_imbalance(text: str) -> list[str]:
    """Return the stack of unclosed brackets in *text* (e.g. ``['{', '[']``).

    Only counts brackets outside of strings.
    """
    stack: list[str] = []
    in_str = False
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_str:
            escaped = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch in "{[":
            stack.append(ch)
        elif ch == "}":
            if stack and stack[-1] == "{":
                stack.pop()
        elif ch == "]":
            if stack and stack[-1] == "[":
                stack.pop()
    return stack


def _progressive_trim(body: str, max_attempts: int = 5) -> dict[str, Any] | None:
    """Try progressively trimming the body from the end and re-parsing.

    Some LLMs append incomplete text after a structurally sound JSON object.
    """
    for trim_len in range(len(body), max(0, len(body) - 2000), -1):
        candidate = body[:trim_len]
        # Try as-is first
        try:
            result = json.loads(candidate)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass
        # Try structural repair on the trimmed candidate
        repaired = _structural_repair(candidate)
        if repaired is not None:
            return repaired
    return None


def _find_json_object_spans(text: str) -> list[str]:
    """Find every balanced ``{…}`` span in *text*.

    Returns spans in order of appearance (not length).
    """
    spans: list[str] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False

    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_string:
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                spans.append(text[start:i + 1])
                start = None
        elif depth < 0:
            depth = 0  # stray closing brace — reset

    return spans
