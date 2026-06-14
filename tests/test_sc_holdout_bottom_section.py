"""SC-dropped findings must not be silently discarded -- they render at the BOTTOM
of the main FINDINGS table (not a separate UNRESOLVED limbo, not the FP section).
Universal: keys on the held_out_unresolved marker, no case data.

The held-out list is threaded through `summary` (not the disposition buckets), so
the partition/consistency gates are unaffected.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def _f(fid, title, claims):
    return {"finding_id": fid, "title": title, "claims": claims}


def test_held_out_sc_findings_render_at_findings_bottom():
    buckets = {"confirmed_malicious_atomic": [
        _f("F001", "real confirmed thing", [{"type": "pid", "pid": 1, "process": "x.exe"}])]}
    holdout = [
        _f("F099", "unresolved SC thing", []),
        _f("F098", "another unresolved", []),
    ]
    for h in holdout:
        h["held_out_unresolved"] = True
    out = render_findings_terminal(buckets, summary={"sc_unresolved_holdout": holdout})
    # both held-out findings are still shown (never discarded)...
    assert "F099" in out and "F098" in out
    # ...not parked in a separate UNRESOLVED limbo row...
    assert "held for transparency" not in out
    # ...and under FINDINGS (above the FP header), below the real finding.
    fp_hdr = out.index("AI-DETECTED FP/Benign")
    assert out.index("F099") < fp_hdr and out.index("F098") < fp_hdr
    assert out.index("F099") > out.index("F001")


def test_no_holdout_section_when_empty():
    buckets = {"confirmed_malicious_atomic": [
        _f("F001", "real", [{"type": "pid", "pid": 1, "process": "x.exe"}])]}
    out = render_findings_terminal(buckets, summary={"sc_unresolved_holdout": []})
    # no empty section header when there is nothing held out
    assert "held for transparency" not in out
