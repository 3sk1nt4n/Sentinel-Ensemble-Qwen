"""The customer findings table must NOT inline a verbose AI-Self-Corrected badge
on every row.

inv3a (Step 13AA) moves most ambiguous findings to needs-review, so a per-row
"[AI-Self-Corrected -> needs review]" badge ended up on ~every row -- pure noise,
and the long wrapping text broke the table's box borders. The self-correction is
now signalled subtly by the cyan finding-ID only; the full per-finding moves live
in inv3a_finalize_ledger.json. Universal: structural, no case data.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def _inv3a_finding(fid, disposition, dest):
    return {
        "finding_id": fid,
        "description": "structural evidence digest",
        "self_corrected": True,
        "_ai_finalize_to": dest,
        "self_correction": {
            "applied": True, "status": "finalized", "by": "inv3a",
            "disposition": disposition, "to": dest,
        },
    }


def _buckets():
    return {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            _inv3a_finding("F9", "needs_review", "suspicious_needs_review")
        ],
        "benign_or_false_positive": [
            _inv3a_finding("F8", "false_positive", "benign_or_false_positive")
        ],
        "inconclusive_unresolved": [
            _inv3a_finding("F7", "inconclusive", "inconclusive_unresolved")
        ],
        "synthesis_narrative": [],
    }


def test_no_inline_ai_self_corrected_badge_clutters_rows():
    out = render_findings_terminal(_buckets())
    # the verbose per-row badge must be gone (it was on ~every row and broke borders)
    assert "AI-Self-Corrected" not in out
    assert "→ needs review" not in out and "-> needs review" not in out
    # the findings themselves still render
    assert "F9" in out and "F8" in out


def test_self_corrected_finding_still_renders():
    out = render_findings_terminal(_buckets())
    # a self-corrected finding is not dropped -- it appears with its detail text
    assert "structural evidence digest" in out


def test_no_bluf_verdict_or_inv3a_summary_or_ioc_appendix():
    # These preamble/appendix sections were removed universally; the findings table
    # and the Self-Correction Ledger carry the signal instead.
    out = render_findings_terminal(_buckets())
    assert "VERDICT" not in out
    assert "AI finalization (Step 13AA)" not in out
    assert "IOCs  (copy-pasteable)" not in out
