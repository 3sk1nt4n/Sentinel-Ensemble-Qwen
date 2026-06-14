"""Fix C — a self-corrected finding must keep its REAL name; the renderer must never
stamp the blanket "AI self-corrected -> false positive" as a title (it overwrote the
name AND mislabelled findings corrected INTO needs-review, which are still suspicious).
Fix E — the summary-box legend renames the green dot to 'ReAct AI-Cross-Check' and
drops the always-empty 'inconclusive' entry.

Universal: keyed on the self_corrected flag + description shape, no case literal.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def _buckets(extra_review=None):
    return {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": list(extra_review or []),
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def test_self_corrected_needs_review_keeps_real_title_not_false_positive():
    # A self-corrected finding with NO title (only a description) in needs-review:
    # it was corrected inconclusive -> needs-review (still suspicious), NOT to an FP.
    f = {"finding_id": "F023", "self_corrected": True,
         "description": "Multiple rundll32.exe with null command lines spawned from staging",
         "claims": [{"type": "pid", "pid": 7552, "process": "rundll32.exe"}]}
    out = render_findings_terminal(_buckets([f]), summary={})
    # the mislabel is gone entirely ...
    assert "false positive" not in out.lower()
    assert "self-corrected → false positive" not in out
    assert "self-corrected -> false positive" not in out
    # ... and the row shows the finding's real subject derived from its own text
    assert "rundll32" in out


def test_legend_renames_green_and_drops_inconclusive():
    out = render_findings_terminal(_buckets(), summary={})
    legend_line = next((ln for ln in out.splitlines() if "Legend" in ln), "")
    assert legend_line, "legend line should render when a summary dict is given"
    assert "ReAct AI-Cross-Check" in legend_line
    assert "benign/FP" not in legend_line          # renamed
    assert "inconclusive" not in legend_line.lower()  # dropped (always-empty tier)
    # the kept tiers are still explained
    assert "confirmed" in legend_line
    assert "needs-review" in legend_line
    assert "AI self-corrected" in legend_line
