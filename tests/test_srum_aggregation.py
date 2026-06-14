"""TDD (regression fix): SRUM parser must AGGREGATE per (app,user,table).

D1b's pyesedb parser emitted one fact per raw SRUM row (42,972 on real evidence)
when the meaningful granularity is the per-(app,user,table) group (777 on the
same evidence -- a 55x inflation). That flood crowded the candidate set
(5,047 -> 13,596) and diluted the Inv2 prompt, dropping findings 45 -> 16.

Aggregating sums bytes per group: far fewer facts, and the per-app egress TOTAL
is exactly the right unit for the self-relative exfil-outlier signal.
Dataset-agnostic: group key is (table, app, user) only.
"""
from sift_sentinel.tools import generic as g


def _row(app, sent, recv, ts, table="T", sid="S-1-5-18"):
    return {"_srum_table": table, "ApplicationName": app, "UserSid": sid,
            "BytesSent": sent, "BytesReceived": recv, "TimeStamp": ts,
            "SourceFile": "x"}


def test_accumulate_sums_bytes_by_group():
    agg = {}
    g._srum_accumulate(agg, _row("a.exe", 100, 50, "2020-01-01T00:00:00"))
    g._srum_accumulate(agg, _row("a.exe", 900, 50, "2020-01-02T00:00:00"))
    g._srum_accumulate(agg, _row("b.exe", 5, 5, "2020-01-01T00:00:00"))
    assert len(agg) == 2
    by_app = {r["ApplicationName"]: r for r in agg.values()}
    assert by_app["a.exe"]["BytesSent"] == 1000
    assert by_app["a.exe"]["BytesReceived"] == 100
    assert by_app["a.exe"]["event_count"] == 2
    assert by_app["a.exe"]["TimeStamp"] == "2020-01-02T00:00:00"  # latest kept
    assert by_app["b.exe"]["event_count"] == 1


def test_accumulate_separates_distinct_users_and_tables():
    agg = {}
    g._srum_accumulate(agg, _row("a.exe", 10, 0, "t", sid="S-1-5-18"))
    g._srum_accumulate(agg, _row("a.exe", 10, 0, "t", sid="S-1-5-21-1-2-3-1001"))
    g._srum_accumulate(agg, _row("a.exe", 10, 0, "t", table="OTHER"))
    assert len(agg) == 3  # same app, different user/table -> distinct groups
