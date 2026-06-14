"""Token-cap/escape rescue for inv3a verdict payloads (universal, structural).

Live failure: the 13AA finalize response hit the 4096 output cap AND carried
unescaped Windows backslashes; strict parse failed, and the truncation rescue
only knew the "findings" array shape -- so all 50 verdicts were discarded
(moved=0/50). The rescue must (a) salvage ANY top-level array key (verdicts
included), (b) repair invalid escapes per object, (c) skip one bad object and
keep salvaging instead of stopping. Purely structural JSON token scanning --
no domain logic, no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.tools.json_rescue import (  # noqa: E402
    rescue_truncated_findings_json,
    rescue_truncated_verdicts_json,
)

_V = ('{"finding_id": "F00%d", "disposition": "confirmed", '
      '"reason": "multi source corroboration"}')


def test_truncated_verdicts_salvages_complete_objects():
    text = ('```json\n{\n  "verdicts": [' + _V % 1 + "," + _V % 2 + ","
            + '{"finding_id": "F003", "disposition": "needs')   # cut mid-object
    out = rescue_truncated_verdicts_json(text)
    assert out and [v["finding_id"] for v in out["verdicts"]] == ["F001", "F002"]


def test_invalid_windows_escape_inside_verdict_is_repaired_not_dropped():
    bad = ('{"finding_id": "F001", "disposition": "false_positive", '
           '"reason": "key HKLM\\Software\\Microsoft default value"}')
    text = '{"verdicts": [' + bad + "," + _V % 2 + "]}"
    out = rescue_truncated_verdicts_json(text)
    assert out and len(out["verdicts"]) == 2
    assert "HKLM" in out["verdicts"][0]["reason"]


def test_one_unparseable_object_is_skipped_not_fatal():
    # middle object irreparably broken (unbalanced quote junk) -- later
    # complete verdicts must still be salvaged
    broken = '{"finding_id": "F002", "disposition": confirmed_unquoted}'
    text = '{"verdicts": [' + _V % 1 + "," + broken + "," + _V % 3 + "]}"
    out = rescue_truncated_verdicts_json(text)
    ids = [v["finding_id"] for v in out["verdicts"]]
    assert "F001" in ids and "F003" in ids


def test_findings_wrapper_unchanged():
    text = ('{"findings": [{"finding_id": "F001", "title": "x"},'
            ' {"finding_id": "F002", "title": "y"')   # truncated
    out = rescue_truncated_findings_json(text)
    assert out and [f["finding_id"] for f in out["findings"]] == ["F001"]


def test_no_array_key_returns_none():
    assert rescue_truncated_verdicts_json("no json here") is None
    assert rescue_truncated_verdicts_json("") is None
