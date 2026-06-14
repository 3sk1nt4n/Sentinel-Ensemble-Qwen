"""inv3a (Step 13AA) per-finding reasoning must be surfaced like the ReAct cross-check, so
a judge can see the agent's final self-correction reasoning. Two layers: the verdicts_sink
on finalize_dispositions captures every adjudication, and render_inv3a_reasoning formats it.
"""
import re

from sift_sentinel.reporting.inv3a_reasoning import render_inv3a_reasoning
from sift_sentinel.analysis.inv3a_finalize import finalize_dispositions

_ANSI = re.compile(r"\033\[[0-9;]*m")

VERDICTS = [
    {"finding_id": "F002", "from": "inconclusive_unresolved", "to": "suspicious_needs_review",
     "disposition": "confirmed", "reason": "WinRM lateral movement corroborated by netscan, event logs, and amcache.", "moved": True},
    {"finding_id": "F047", "from": "suspicious_needs_review", "to": "suspicious_needs_review",
     "disposition": "needs_review", "reason": "Single-source SRUM outlier; suggestive of exfil but uncorroborated.", "moved": False},
]


def test_render_shows_header_counts_and_each_finding_with_reason():
    out = render_inv3a_reasoning(VERDICTS, color=False)
    assert "inv3a" in out
    assert "2" in out and "1" in out  # adjudicated 2, reclassified 1
    for v in VERDICTS:
        assert v["finding_id"] in out
        assert v["reason"][:30] in out
        assert v["disposition"] in out


def test_moved_shows_transition_unchanged_shows_kept():
    out = render_inv3a_reasoning(VERDICTS, color=False)
    assert "→" in out                 # the moved one shows a transition
    assert "kept" in out              # the unchanged one is marked kept
    # humanized bucket labels (not raw bucket keys)
    assert "needs-review" in out and "inconclusive" in out


def test_color_false_has_no_ansi():
    assert "\033[" not in render_inv3a_reasoning(VERDICTS, color=False)


def test_empty_is_empty_string():
    assert render_inv3a_reasoning([]) == ""
    assert render_inv3a_reasoning(None) == ""


# ---- verdicts_sink integration: finalize_dispositions populates ALL adjudications ----
def _buckets():
    return {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [{"finding_id": "F047", "title": "srum outlier",
                                     "claims": [{"type": "pid", "pid": 1}]}],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [{"finding_id": "F002", "title": "winrm",
                                     "claims": [{"type": "pid", "pid": 2}]}],
        "synthesis_narrative": [],
    }


def test_verdicts_sink_captures_moved_and_unchanged():
    def _adj(_prompt):
        return ('{"verdicts": ['
                '{"finding_id": "F002", "disposition": "needs_review", "reason": "corroborated lateral movement"},'
                '{"finding_id": "F047", "disposition": "needs_review", "reason": "single source, kept"}]}')
    sink = []
    finalize_dispositions(_buckets(), _adj, verdicts_sink=sink)
    ids = {v["finding_id"] for v in sink}
    assert ids == {"F002", "F047"}
    by = {v["finding_id"]: v for v in sink}
    assert by["F002"]["moved"] is True           # inconclusive -> needs-review
    assert by["F047"]["moved"] is False           # already needs-review
    assert by["F002"]["reason"] == "corroborated lateral movement"
    # the renderer accepts the sink shape directly
    out = render_inv3a_reasoning(sink, color=False)
    assert "F002" in out and "F047" in out
