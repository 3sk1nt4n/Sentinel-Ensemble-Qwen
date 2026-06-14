"""A1: cross-bucket + within-bucket dedup by event identity.

A live run left the SAME log-clearing event (Event 1102 at one timestamp) as
THREE separate confirmed findings + one needs-review finding -- inflating the
confirmed bucket and contradicting itself. The existing dedup keyed only on
hash/exe-path, so event-only findings never collapsed.

Universal identity for an event finding: (event_id, timestamp-to-the-second,
IP-discriminator). Requiring a timestamp is the safety rail -- two share-access
events with the same Event ID but DIFFERENT target IPs (or no timestamp) must
stay separate. Neutral fixtures (RFC-5737 IPs, synthetic ids); no case data.
Kill-switch SIFT_DEDUP_EVENT_KEYS=0.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis import confirmed_dedup as cd  # noqa: E402

TS = "2020-01-01T08:00:00.123456+00:00"


def _evt(fid, event_id, ts=TS, ip=None, primary=None):
    f = {"finding_id": fid,
         "claims": [{"type": "event_log", "event_id": event_id}]}
    if ts is not None:
        f["timestamp"] = ts
    if primary is not None:
        f["primary_artifact"] = primary
    elif ip is not None:
        f["primary_artifact"] = ip
    return f


def test_same_event_same_time_shares_key():
    a = _evt("F1", 1102)
    b = _evt("F2", "1102", primary=["1102", "channel", "2020-01-01 08:00:00.123456+00:00"])
    assert cd.entity_keys(a) & cd.entity_keys(b), "same event+time must share a key"


def test_diff_ip_same_event_do_not_share_key():
    # Two share-access (same Event ID) to DIFFERENT targets must NOT merge.
    a = _evt("F1", 5140, ts=None, ip="203.0.113.10")
    b = _evt("F2", 5140, ts=None, ip="203.0.113.20")
    assert not (cd.entity_keys(a) & cd.entity_keys(b)), "different IP targets must stay separate"


def test_no_timestamp_no_event_merge():
    # event_id alone (no timestamp, no IP) must NOT create a merge key.
    a = _evt("F1", 1102, ts=None)
    b = _evt("F2", 1102, ts=None)
    assert not (cd.entity_keys(a) & cd.entity_keys(b))


def test_cross_bucket_merges_event_duplicate():
    buckets = {
        "confirmed_malicious_atomic": [_evt("F1", 1102)],
        "suspicious_needs_review": [
            _evt("F2", "1102", primary=["1102", "ch", "2020-01-01 08:00:00.999+00:00"]),
            _evt("F9", 5140, ts=None, ip="203.0.113.50"),  # distinct -> stays
        ],
    }
    new, ledger = cd.dedup_cross_bucket(buckets)
    rev_ids = {(f.get("finding_id")) for f in new["suspicious_needs_review"]}
    assert "F2" not in rev_ids, "F2 (same event as confirmed F1) should be merged out of review"
    assert "F9" in rev_ids, "distinct share-access finding must be preserved"


def test_kill_switch_disables_event_keys(monkeypatch):
    monkeypatch.setenv("SIFT_DEDUP_EVENT_KEYS", "0")
    a = _evt("F1", 1102)
    b = _evt("F2", 1102)
    assert not (cd.entity_keys(a) & cd.entity_keys(b))
