"""The summary 'AI self-corrected' headline count must equal what the Self-Correction
Ledger lists -- both key on the SAME predicate (inv3a-moved OR ReAct-flipped-to-benign).
Previously the count used the narrow self_corrected flag (0 when inv3a didn't run) while
the ledger counted ReAct flag->benign (2), so the top said 0 and the bottom showed 2.
Universal: structural markers only, no case data.
"""
import re

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal, _is_ai_self_corrected,
)


def _react_benign(fid):
    return {"finding_id": fid, "title": "thing %s" % fid,
            "react_conclusion": {"is_false_positive": True, "verdict": "benign",
                                 "reasoning": "cross-check cleared it"},
            "claims": [{"type": "pid", "pid": 1, "process": "x.exe"}]}


def _buckets(benign):
    return {"confirmed_malicious_atomic": [], "suspicious_needs_review": [],
            "benign_or_false_positive": list(benign), "inconclusive_unresolved": [],
            "synthesis_narrative": []}


def test_predicate_matches_react_flip_and_inv3a_flag():
    assert _is_ai_self_corrected(_react_benign("F1")) is True
    assert _is_ai_self_corrected({"finding_id": "F2", "self_corrected": True}) is True
    assert _is_ai_self_corrected({"finding_id": "F3"}) is False


def test_headline_count_equals_ledger_count():
    out = render_findings_terminal(_buckets([_react_benign("F15"), _react_benign("F22")]),
                                   summary={})
    # Operator request removed the printed SELF-CORRECTION LEDGER; the headline banner
    # count must STILL be correct (the cyan IDs + this count are now the SC signal).
    assert "SELF-CORRECTION LEDGER" not in out          # ledger no longer printed
    assert "F15" in out and "F22" in out                # the two react-benign show as FP rows
    # the summary '(N AI self-corrected)' count is 2 (both ReAct-flipped), not 0
    m = re.search(r"\(?(\d+) AI self-corrected", out)
    assert m and int(m.group(1)) == 2


def test_partition_unchanged_findings_plus_fps_equals_total():
    out = render_findings_terminal(_buckets([_react_benign("F15"), _react_benign("F22")]),
                                   summary={})
    m = re.search(r"(\d+) total\s+·\s+(\d+) findings\s+·\s+(\d+) AI-detected FPs", out)
    assert m
    total, findings, fps = int(m.group(1)), int(m.group(2)), int(m.group(3))
    assert findings + fps == total          # partition still holds
    assert fps == 2                          # the two react-benign are the FPs


def test_no_self_correction_when_none():
    out = render_findings_terminal(
        {"confirmed_malicious_atomic": [{"finding_id": "C1", "title": "real",
                                         "claims": [{"type": "pid", "pid": 9}]}],
         "suspicious_needs_review": [], "benign_or_false_positive": [],
         "inconclusive_unresolved": [], "synthesis_narrative": []},
        summary={})
    m = re.search(r"(\d+) AI self-corrected", out)
    assert m and int(m.group(1)) == 0
    assert "SELF-CORRECTION LEDGER" not in out
