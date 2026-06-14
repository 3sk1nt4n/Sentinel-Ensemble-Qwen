"""Tests for tolerant JSON extractor.

Some backends return valid JSON followed by trailing prose or a second
object ("Extra data: line X column Y" from json.loads). Others wrap
output in markdown fences. The extractor handles all three forms.

Run 4 of v2.2 lost 6920 chars of Inv4 report because json.loads raised
on trailing text. These tests lock that fix in place.
"""
from __future__ import annotations

import json

import pytest

from sift_sentinel.tools.common import _extract_first_json_object


def test_extract_strips_json_fence():
    raw = '```json\n{"a": 1}\n```'
    assert _extract_first_json_object(raw) == '{"a": 1}'


def test_extract_strips_plain_fence():
    raw = '```\n{"a": 1}\n```'
    assert _extract_first_json_object(raw) == '{"a": 1}'


def test_extract_strips_trailing_prose():
    raw = '{"a":1}\n\nthanks!'
    out = _extract_first_json_object(raw)
    assert out == '{"a":1}'
    assert json.loads(out) == {"a": 1}


def test_extract_strips_trailing_json():
    """GPT sometimes emits {"findings":[...]}{"explanation":"..."}."""
    raw = '{"a":1}{"b":2}'
    out = _extract_first_json_object(raw)
    assert out == '{"a":1}'
    assert json.loads(out) == {"a": 1}


def test_extract_handles_nested():
    raw = '{"a":{"b":[1,2]}, "c":3} extra'
    out = _extract_first_json_object(raw)
    assert out == '{"a":{"b":[1,2]}, "c":3}'
    assert json.loads(out) == {"a": {"b": [1, 2]}, "c": 3}


def test_extract_handles_string_with_braces():
    """Braces inside string literals must not confuse the depth counter."""
    raw = '{"a":"x}y"} trailing'
    out = _extract_first_json_object(raw)
    assert out == '{"a":"x}y"}'
    assert json.loads(out) == {"a": "x}y"}


def test_extract_handles_escaped_quote_in_string():
    """An escaped quote inside a string must not toggle in_string off."""
    raw = r'{"a":"she said \"hi\" here"} trailing'
    out = _extract_first_json_object(raw)
    assert json.loads(out) == {"a": 'she said "hi" here'}


def test_extract_handles_preamble():
    """Sometimes AI adds 'Here is the JSON:' before the object."""
    raw = 'Here is the JSON: {"a":1}'
    out = _extract_first_json_object(raw)
    assert json.loads(out) == {"a": 1}


def test_extract_handles_real_gpt_report_with_trailing_text():
    """Real shape that broke Run 4: valid report JSON + closing remark."""
    raw = (
        '{"executive_summary": "attack detected", '
        '"timeline": [{"ts":"2018-01-01","event":"x"}], '
        '"limitations": "none"}\n\n'
        "Let me know if you need additional analysis."
    )
    out = _extract_first_json_object(raw)
    parsed = json.loads(out)
    assert parsed["executive_summary"] == "attack detected"
    assert parsed["timeline"][0]["event"] == "x"


def test_extract_empty_input():
    assert _extract_first_json_object("") == ""


def test_extract_no_json_returns_original():
    """If no object found, return original so json.loads raises a real error."""
    raw = "no json here at all"
    out = _extract_first_json_object(raw)
    # Should not raise here; json.loads downstream will raise normally.
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_extract_json_fence_with_trailing_prose():
    """Combined: fence + trailing prose."""
    raw = '```json\n{"x": 7}\n```\n\nThat concludes my analysis.'
    out = _extract_first_json_object(raw)
    assert json.loads(out) == {"x": 7}
