"""SIFT_EGRESS_OUTLIER_PROMOTE_V1 (Fix A).

A self-relative SRUM egress outlier (egress > the image's OWN mean+2sigma) is
self-validating: the deviation from the image's own baseline IS the evidence, so
it surfaces for review even though SRUM is the only artifact that measures bytes
(single-source, which otherwise fails the multi-source validation-ready gate).

Root cause this fixes: on the insider-theft image the 193 MB RDP / cloud-upload
egress was collected (777 SRUM rows) but, being single-source, landed in the
thin_single_source_or_type bin and never reached Inv2 as a finding -> 0 exfil
surfaced. Bounded: promotion is hard-capped at the top-K outliers so it can never
flood the candidate set. Self-relative: mean+2sigma over the image's own SRUM
corpus -- no fixed byte constant, no host/app/path literal.
"""
from __future__ import annotations

from sift_sentinel.analysis.candidate_observations import build_candidate_observations


def _srum(fid, path, bytes_total):
    return {
        "fact_id": fid,
        "fact_type": "srum_usage_fact",
        "source_tool": "run_srumecmd",
        "normalized_path": path,
        "application_path": path,
        "table": "network_usage",
        "bytes_total": bytes_total,
    }


def _db(facts):
    typed: dict = {}
    for f in facts:
        typed.setdefault(f["fact_type"], []).append(f)
    return {"typed_facts": typed}


def test_egress_outlier_becomes_validation_ready_single_source():
    # 8 baseline apps (small egress) establish the distribution; one clear outlier.
    baselines = [_srum(f"srum_usage_fact-{i}", f"c:/dir/app{i}.exe", 1_000_000)
                 for i in range(8)]
    outlier = _srum("srum_usage_fact-OUT", "c:/dir/exfil.exe", 500_000_000)
    payload = build_candidate_observations(_db(baselines + [outlier]))
    cands = payload["candidates"]

    promoted = [c for c in cands
                if "srum_egress_self_relative_outlier" in (c.get("signals") or [])]
    assert len(promoted) == 1, [c["entity_key"] for c in promoted]
    assert promoted[0]["validation_ready"] is True
    assert promoted[0]["candidate_type"] == "data_exfiltration_egress_outlier"
    # single-source: SRUM only -- proves the multi-source gate was bypassed.
    assert promoted[0]["source_tools"] == ["run_srumecmd"]

    # A baseline (sub-threshold, single-source) is NOT promoted by this path.
    base = [c for c in cands if c.get("validation_ready")
            and "srum_egress_self_relative_outlier" not in (c.get("signals") or [])]
    assert base == [], [c["entity_key"] for c in base]


def test_promotion_is_hard_bounded_top_k():
    # Many large senders -> promotion is capped, never a flood.
    facts = [_srum(f"srum_usage_fact-s{i}", f"c:/dir/s{i}.exe", 1_000_000)
             for i in range(20)]
    facts += [_srum(f"srum_usage_fact-big{i}", f"c:/dir/big{i}.exe",
                    900_000_000 + i) for i in range(12)]
    payload = build_candidate_observations(_db(facts))
    promoted = [c for c in payload["candidates"]
                if "srum_egress_self_relative_outlier" in (c.get("signals") or [])]
    assert len(promoted) <= 5, len(promoted)


def test_small_corpus_does_not_promote():
    # Fewer than 8 egress samples -> threshold is undefined -> nothing promoted
    # (no guessing on a corpus too small to define an outlier).
    facts = [_srum(f"srum_usage_fact-{i}", f"c:/dir/a{i}.exe", 10_000_000 * (i + 1))
             for i in range(4)]
    payload = build_candidate_observations(_db(facts))
    promoted = [c for c in payload["candidates"]
                if "srum_egress_self_relative_outlier" in (c.get("signals") or [])]
    assert promoted == []
