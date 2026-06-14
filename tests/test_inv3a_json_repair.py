"""inv3a robustness: a model that writes an UNESCAPED Windows path inside a JSON string
(``"...HKLM\\System\\ControlSet001..."`` -> \\S \\C are invalid JSON escapes) must not
drop every verdict. Observed live: inv3a moved 0/21 on this exact error. The parser now
repairs stray backslashes. Universal, structural, no case data.
"""
from sift_sentinel.analysis.inv3a_finalize import (
    parse_inv3a_verdicts,
    _extract_json_blob,
    _repair_json_escapes,
)


def test_unescaped_windows_path_in_reason_is_recovered():
    # NOTE: in this Python literal, "C:\\Windows" is ONE backslash -> mirrors the API text
    payload = ('{"verdicts":[{"finding_id":"F1","disposition":"false_positive",'
               '"reason":"baseline at C:\\Windows\\System32\\cmd.exe"}]}')
    v = parse_inv3a_verdicts(payload)
    assert "F1" in v
    assert v["F1"]["disposition"] == "false_positive"
    assert "Windows" in v["F1"]["reason"]


def test_multiple_verdicts_with_registry_paths_recovered():
    payload = ('{"verdicts":['
               '{"finding_id":"F027","disposition":"confirmed",'
               '"reason":"SafeBoot at HKLM\\System\\ControlSet001\\Control\\SafeBoot"},'
               '{"finding_id":"F006","disposition":"false_positive",'
               '"reason":"baseline cmd.exe in C:\\Windows\\System32"}]}')
    v = parse_inv3a_verdicts(payload)
    assert set(v) == {"F027", "F006"}


def test_wellformed_json_with_valid_escapes_still_parses():
    # \n and \" are valid JSON escapes -> the ORIGINAL parse succeeds, repair never runs
    payload = ('{"verdicts":[{"finding_id":"F2","disposition":"confirmed",'
               '"reason":"line1\\nline2 with a quote \\" inside"}]}')
    v = parse_inv3a_verdicts(payload)
    assert v.get("F2", {}).get("disposition") == "confirmed"


def test_already_escaped_backslashes_not_overcorrected():
    # a correctly-escaped path parses on the first try -> not touched by the repair
    payload = ('{"verdicts":[{"finding_id":"F3","disposition":"false_positive",'
               '"reason":"C:\\\\Windows\\\\System32"}]}')
    v = parse_inv3a_verdicts(payload)
    assert "F3" in v


def test_garbage_returns_empty_no_crash():
    assert parse_inv3a_verdicts("not json { ] [ }") == {}
    assert parse_inv3a_verdicts("") == {}
    assert _extract_json_blob("nope") is None


def test_repair_doubles_bad_backslash_keeps_valid():
    assert _repair_json_escapes(r"a\Wb") == r"a\\Wb"     # \W invalid -> doubled
    assert _repair_json_escapes(r"a\nb") == r"a\nb"       # \n valid -> kept
    assert _repair_json_escapes(r"a\"b") == r"a\"b"       # \" valid -> kept
    assert _repair_json_escapes("a\\u0041b") == "a\\u0041b"   # \uXXXX valid -> kept
