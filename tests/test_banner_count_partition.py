"""Defect B: the summary banner 'N findings · M AI-detected FPs' must equal what the
two tables actually render. A finding that self-corrected INTO the benign bucket was
counted as a 'finding' in the banner (via the broad self_corr set) but rendered under
FPs in the table -- live mismatch banner 7/13 vs table 6/14. Universal: structural
buckets only, no case data.
"""
import re

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def _sc_benign(fid):
    # self-corrected AND landed benign (ReAct flip to benign) -> belongs with FPs
    return {"finding_id": fid, "title": "t%s" % fid, "self_corrected": True,
            "react_conclusion": {"is_false_positive": True, "verdict": "benign",
                                 "reasoning": "cleared on cross-check"},
            "claims": [{"type": "pid", "pid": 1, "process": "x.exe"}]}


def _confirmed(fid):
    return {"finding_id": fid, "title": "c%s" % fid,
            "claims": [{"type": "pid", "pid": 2, "process": "y.exe"}]}


def _buckets():
    return {"confirmed_malicious_atomic": [_confirmed("F1")],
            "suspicious_needs_review": [], "inconclusive_unresolved": [],
            "benign_or_false_positive": [_sc_benign("F9")],
            "synthesis_narrative": []}


def test_banner_findings_fp_split_matches_buckets():
    out = render_findings_terminal(_buckets(), summary={})
    m = re.search(r"(\d+) total\s+·\s+(\d+) findings\s+·\s+(\d+) AI-detected FPs", out)
    assert m
    total, findings, fps = int(m.group(1)), int(m.group(2)), int(m.group(3))
    assert total == 2
    # F1 confirmed -> 1 finding ; F9 self-corrected-to-benign -> 1 FP (NOT a finding)
    assert findings == 1
    assert fps == 1
    assert findings + fps == total
