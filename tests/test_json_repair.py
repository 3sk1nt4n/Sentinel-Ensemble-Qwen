"""Shared lenient JSON load used by every AI call (_live_call). An unescaped Windows
path in a model string must not drop the whole reply; well-formed JSON is never altered.
"""
import json

import pytest

from sift_sentinel.json_repair import repair_json_escapes, loads_lenient


def test_unescaped_windows_path_recovered():
    # single-backslash path (what the model emits) -> invalid JSON -> repaired & parsed
    s = '{"reason":"key at HKLM\\System\\ControlSet001\\Control\\SafeBoot"}'
    obj = loads_lenient(s)
    assert "HKLM" in obj["reason"]


def test_wellformed_json_unaltered():
    s = '{"a":"line1\\nline2","b":"quote \\" ok","c":"esc\\\\path"}'
    # valid escapes -> parses on the FIRST try, repair never runs
    assert loads_lenient(s) == json.loads(s)


def test_repair_doubles_only_bad_escapes():
    assert repair_json_escapes(r"a\Wb") == r"a\\Wb"   # \W invalid -> doubled
    assert repair_json_escapes(r"a\nb") == r"a\nb"     # \n valid -> kept
    assert repair_json_escapes(r"a\"b") == r"a\"b"     # \" valid -> kept
    assert repair_json_escapes("a\\u0041b") == "a\\u0041b"   # \uXXXX valid -> kept


def test_both_attempts_fail_reraises_original():
    with pytest.raises(json.JSONDecodeError):
        loads_lenient("{not json at all")
