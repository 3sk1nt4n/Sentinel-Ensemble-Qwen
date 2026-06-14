"""Live terminal findings table (render_findings_terminal):

(a) the event time/date surfaces in the Details cell -- derived purely from
    finding structure (a timestamp claim field, else an ISO-date shape in the
    evidence text), UTC-labelled, blank when nothing is present.
(c) rows are ordered most-tool-hits-first ("Result table shows the highest
    number of tool-hits at the top, always") -- counted exactly as the Tools
    Hit cell displays (deduped source tools + ReAct cross-check tools).

Both universal / dataset-agnostic: structure + tool identity only, no case data.
"""

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    _event_when,
    _tool_hit_count,
    _sort_by_tool_hits,
    render_findings_terminal,
)


# --- (a) event time/date -----------------------------------------------------

def test_event_when_from_timestamp_claim():
    f = {"claims": [{"type": "process", "timestamp": "2026-06-01 14:22:05"}]}
    assert _event_when(f) == "2026-06-01 14:22:05"


def test_event_when_from_iso_date_in_text():
    f = {"description": "first observed at 2026-06-03T08:00 UTC", "claims": []}
    assert "2026-06-03" in _event_when(f)


def test_event_when_blank_when_absent():
    assert _event_when({"claims": [{"type": "pid", "pid": 5}]}) == ""


# --- (c) sort by tool-hits ---------------------------------------------------

def test_tool_hit_count_counts_distinct_source_and_react():
    f = {"finding_id": "F1", "source_tools": ["vol_malfind", "vol_pstree"]}
    assert _tool_hit_count(f) == 2
    # ReAct adds a new tool; the duplicate vol_pstree is not double-counted.
    assert _tool_hit_count(f, {"F1": ["vol_ldrmodules", "vol_pstree"]}) == 3


def test_sort_by_tool_hits_desc_is_stable_on_ties():
    a = {"finding_id": "A", "source_tools": ["t1"]}
    b = {"finding_id": "B", "source_tools": ["t1", "t2", "t3"]}
    c = {"finding_id": "C", "source_tools": ["t1", "t2"]}
    d = {"finding_id": "D", "source_tools": ["t9"]}  # ties A -> keeps input order
    out = _sort_by_tool_hits([a, b, c, d])
    assert [f["finding_id"] for f in out] == ["B", "C", "A", "D"]


# --- integration: both behaviours in the rendered table ----------------------

def test_render_orders_findings_by_tool_hits_and_shows_when():
    buckets = {
        "suspicious_needs_review": [
            {"finding_id": "F_LOW", "title": "low-corroboration",
             "source_tools": ["t1"], "claims": [{"type": "path", "value": "x"}]},
            {"finding_id": "F_HIGH", "title": "high-corroboration",
             "source_tools": ["t1", "t2", "t3", "t4"],
             "claims": [{"type": "process", "timestamp": "2026-06-02 09:10:11"}]},
        ],
    }
    out = render_findings_terminal(buckets)
    # F_HIGH (4 tools) renders above F_LOW (1 tool).
    assert out.index("F_HIGH") < out.index("F_LOW")
    # the event time/date surfaces in the table body.
    assert "2026-06-02" in out
