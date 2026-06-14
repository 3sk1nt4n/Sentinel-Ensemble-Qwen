"""SC-blocked (held-out) findings render at the BOTTOM of the main FINDINGS table
-- never discarded, never parked in a standalone 'UNRESOLVED' row, and no longer
split off into the FP section. Universal: keyed on the held_out marker, no case
value.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def _f(fid, title):
    return {"finding_id": fid, "title": title,
            "claims": [{"type": "pid", "pid": 1, "process": "p.exe"}]}


def _holdout():
    return [_f("F010", "held one"), _f("F020", "held two"), _f("F030", "held three")]


def test_all_holdout_render_under_findings_bottom():
    buckets = {"confirmed_malicious_atomic": [_f("F001", "real confirmed")]}
    out = render_findings_terminal(buckets, summary={"sc_unresolved_holdout": _holdout()})
    assert "held for transparency" not in out
    fp_hdr = out.index("AI-DETECTED FP/Benign")
    for fid in ("F010", "F020", "F030"):
        assert fid in out, fid
        # under FINDINGS (above the FP header) ...
        assert out.index(fid) < fp_hdr, fid
        # ... and below the real confirmed finding (bottom of FINDINGS)
        assert out.index(fid) > out.index("F001"), fid


def test_empty_holdout_leaves_report_unchanged():
    buckets = {"confirmed_malicious_atomic": [_f("F001", "real")]}
    out = render_findings_terminal(buckets, summary={"sc_unresolved_holdout": []})
    assert "held for transparency" not in out
