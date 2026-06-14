"""EvidenceDB dedup-merge must be linear-time with bounded provenance.

Live regression: Step 7 took ~230s (target <60s) and wrote a 248MB
evidence_db.json. Probe of the real artifact showed the biggest single fact
carrying 51KB of record_refs + 17KB of source_record_indices, and the merge
path rebuilding ``sorted(set(refs) | {new})`` on EVERY merge -- O(k log k) per
merge, O(k^2 log k) for a fact merged k times. Heavily-deduped facts (handles,
events) hit thousands of merges each => accidentally-quadratic build + an
unbounded provenance payload that bloats serialization.

Universal fixes under test:
  * merge is linear: membership via a sidecar set, append + ONE final sort
    (deterministic output identical to the old path when under the cap);
  * provenance refs are CAPPED (SIFT_PROVENANCE_REF_CAP, default 64, 0=uncap)
    -- merge_count still carries the TRUE count and a provenance_truncated
    flag makes the cap honest (raw_excerpts cap=3 is the existing precedent);
  * 20k duplicate records build in seconds, not minutes.

Synthetic records only; no case data.
"""
import os
import sys
import time

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.evidence_db import build_typed_evidence_db  # noqa: E402


def _dupes(n):
    # n identical process records -> 1 fact + (n-1) merges with distinct rec refs
    rec = {"PID": 500, "PPID": 4, "ImageFileName": "evil.exe",
           "CreateTime": "2018-09-01T01:02:03+00:00",
           "Path": "C:\\Temp\\evil.exe"}
    return {"vol_pstree": {"record_count": n, "output": [dict(rec) for _ in range(n)]}}


def _the_fact(db):
    for facts in db["typed_facts"].values():
        for f in facts:
            if f.get("merge_count", 1) > 1:
                return f
    raise AssertionError("no merged fact produced")


def test_merge_count_is_true_count_and_refs_sorted():
    db = build_typed_evidence_db(_dupes(10))
    f = _the_fact(db)
    assert f["merge_count"] == 10
    assert f["record_refs"] == sorted(f["record_refs"])
    assert f["source_record_indices"] == sorted(f["source_record_indices"])
    assert len(set(f["record_refs"])) == len(f["record_refs"])    # unique


def test_provenance_refs_are_capped_with_honest_flag(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_REF_CAP", "16")
    db = build_typed_evidence_db(_dupes(200))
    f = _the_fact(db)
    assert f["merge_count"] == 200                  # the TRUE count survives
    assert len(f["record_refs"]) <= 16
    assert len(f["source_record_indices"]) <= 16
    assert f.get("provenance_truncated") is True    # the cap is honest


def test_cap_zero_keeps_everything(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_REF_CAP", "0")
    db = build_typed_evidence_db(_dupes(120))
    f = _the_fact(db)
    assert len(f["record_refs"]) == 120
    assert "provenance_truncated" not in f


def test_under_cap_output_identical_to_legacy_contract(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_REF_CAP", "64")
    db = build_typed_evidence_db(_dupes(5))
    f = _the_fact(db)
    # legacy contract: every unique ref present, sorted
    assert f["record_refs"] == sorted(f"vol_pstree#{i}" for i in range(5))
    assert "provenance_truncated" not in f


def test_heavy_dedup_build_is_linear_time():
    # 20k duplicate records: quadratic merge needs minutes; linear takes seconds.
    t0 = time.monotonic()
    db = build_typed_evidence_db(_dupes(20_000))
    elapsed = time.monotonic() - t0
    f = _the_fact(db)
    assert f["merge_count"] == 20_000
    assert elapsed < 10.0, f"merge path is not linear: {elapsed:.1f}s for 20k dupes"
