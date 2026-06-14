"""A3: within the confirmed tier, order by SEVERITY first (CRITICAL>HIGH>MEDIUM>
LOW), then by tool-hit count. A live run surfaced a MEDIUM confirmed above a
HIGH confirmed because ordering ignored severity. SAFETY: findings with no
severity get the lowest rank, so existing severity-less fixtures keep their
tool-hit order. Confirmed still always outranks non-confirmed. Universal:
severity label + bucket membership, no case data. Kill-switch
SIFT_CONFIRMED_SEVERITY_SORT=0.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.reporting import customer_findings_table_bucket_faithful as t  # noqa: E402


def _f(fid, sev=None, tools=None):
    f = {"finding_id": fid, "source_tools": tools or []}
    if sev is not None:
        f["severity"] = sev
    return f


def test_high_confirmed_outranks_medium_confirmed_even_with_fewer_tools():
    high = _f("F_HIGH", "HIGH", tools=["a"])               # 1 tool
    med = _f("F_MED", "MEDIUM", tools=["a", "b", "c"])     # 3 tools
    out = t._sort_confirmed_first([med, high], {"F_HIGH", "F_MED"})
    assert out[0]["finding_id"] == "F_HIGH", "HIGH confirmed must lead MEDIUM confirmed"


def test_confirmed_still_outranks_nonconfirmed_regardless_of_severity():
    conf_med = _f("C", "MEDIUM", tools=["a"])
    nonconf_crit = _f("N", "CRITICAL", tools=["a", "b", "c", "d"])
    out = t._sort_confirmed_first([nonconf_crit, conf_med], {"C"})
    assert out[0]["finding_id"] == "C", "any confirmed outranks any non-confirmed"


def test_severityless_fixtures_keep_tool_hit_order():
    a = _f("A", tools=["x", "y", "z"])     # 3
    b = _f("B", tools=["x"])               # 1
    out = t._sort_confirmed_first([b, a], {"A", "B"})
    assert [f["finding_id"] for f in out] == ["A", "B"]


def test_kill_switch_restores_tool_hits_only(monkeypatch):
    monkeypatch.setenv("SIFT_CONFIRMED_SEVERITY_SORT", "0")
    high1 = _f("H", "HIGH", tools=["a"])
    med3 = _f("M", "MEDIUM", tools=["a", "b", "c"])
    out = t._sort_confirmed_first([high1, med3], {"H", "M"})
    assert out[0]["finding_id"] == "M", "with sort off, more-tool-hits leads"
