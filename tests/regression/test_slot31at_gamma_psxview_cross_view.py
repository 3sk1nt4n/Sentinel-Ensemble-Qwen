"""slot31AT-gamma regression: psxview cross-view inconsistency candidate.

Random-token property-based tests. NO hardcoded process names/PIDs from
any dataset; every assertion is structural.
"""
import secrets
from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
)


def _db(*facts):
    typed = {}
    for f in facts:
        typed.setdefault(f["fact_type"], []).append(f)
    return {"typed_facts": typed}


def _psxview_fact(pid, name, views):
    """Build psxview_fact mirroring runtime storage shape.
    Production: typed fields are stripped at storage; raw_excerpt
    preserves the verbatim Vol3 record JSON. Candidate observations
    read from raw_excerpt. Missing view keys -> absent from JSON
    (handled defensively by candidate observation)."""
    import json
    raw_record = {"Name": name, "PID": pid, "Exit Time": ""}
    for k in ("pslist", "psscan", "thrdproc", "thrdscan",
              "csrss", "session", "deskthrd"):
        if k in views:
            raw_record[k] = views[k]
    return {
        "fact_id": f"psxview_fact-{pid}",
        "fact_type": "psxview_fact",
        "entity_id": f"psxview:pid:{pid}",
        "source_tool": "vol_psxview",
        "record_ref": f"vol_psxview#{pid}",
        "raw_excerpt": json.dumps(raw_record),
        "artifact": [name],
    }


def test_cross_view_disagreement_emits_candidate():
    name = "p" + secrets.token_hex(3) + ".exe"
    pid = 1000 + secrets.randbelow(50000)
    fact = _psxview_fact(pid, name, {
        "pslist": False, "psscan": True, "thrdproc": True,
        "csrss": True, "session": True, "deskthrd": True,
    })
    payload = build_candidate_observations(_db(fact))
    matches = [c for c in payload["candidates"]
               if "process_view_inconsistency" in c.get("signals", [])]
    assert len(matches) >= 1
    cand = matches[0]
    assert cand["candidate_type"] == "process_hiding_indicator"
    assert cand["validation_ready"] is True


def test_all_views_true_no_signal():
    name = "p" + secrets.token_hex(3) + ".exe"
    pid = 1000 + secrets.randbelow(50000)
    fact = _psxview_fact(pid, name, {
        "pslist": True, "psscan": True, "thrdproc": True,
        "csrss": True, "session": True, "deskthrd": True,
    })
    payload = build_candidate_observations(_db(fact))
    has_signal = any("process_view_inconsistency" in c.get("signals", [])
                     for c in payload["candidates"])
    assert not has_signal


def test_all_views_false_no_signal():
    name = "p" + secrets.token_hex(3) + ".exe"
    pid = 1000 + secrets.randbelow(50000)
    fact = _psxview_fact(pid, name, {
        "pslist": False, "psscan": False, "thrdproc": False,
        "csrss": False, "session": False, "deskthrd": False,
    })
    payload = build_candidate_observations(_db(fact))
    has_signal = any("process_view_inconsistency" in c.get("signals", [])
                     for c in payload["candidates"])
    assert not has_signal


def test_all_views_none_no_signal():
    name = "p" + secrets.token_hex(3) + ".exe"
    pid = 1000 + secrets.randbelow(50000)
    fact = _psxview_fact(pid, name, {})
    payload = build_candidate_observations(_db(fact))
    has_signal = any("process_view_inconsistency" in c.get("signals", [])
                     for c in payload["candidates"])
    assert not has_signal


def test_partial_with_none_fields():
    """Partial view data with the REVERSE of the DKOM signature
    (pslist=True, psscan=False) is a benign view disagreement — pool
    tag overwritten / transient — not active-but-unlinked DKOM, so
    process_view_inconsistency must NOT fire and no process-hiding
    candidate must be created. slot31AV-narrow.
    """
    name = "p" + secrets.token_hex(3) + ".exe"
    pid = 1000 + secrets.randbelow(50000)
    fact = _psxview_fact(pid, name, {
        "pslist": True,
        "psscan": False,
    })
    payload = build_candidate_observations(_db(fact))
    matches = [c for c in payload["candidates"]
               if "process_view_inconsistency" in c.get("signals", [])]
    assert matches == [], (
        "process_view_inconsistency fired for the reverse direction "
        "(pslist=True, psscan=False) — that is benign, not DKOM"
    )


def test_dataset_agnostic_random_tokens():
    facts = [
        _psxview_fact(
            10000 + secrets.randbelow(50000),
            secrets.token_hex(4) + ".exe",
            {"pslist": False, "psscan": True, "thrdproc": True,
             "csrss": True, "session": True, "deskthrd": True},
        )
        for _ in range(3)
    ]
    payload = build_candidate_observations(_db(*facts))
    matches = [c for c in payload["candidates"]
               if "process_view_inconsistency" in c.get("signals", [])]
    # Each fact may emit multiple candidates: build_candidate_observations
    # groups by entity_key and a fact can have multiple entity_keys
    # (e.g., process:pid + process:name). All share the signal.
    assert len(matches) >= 3
    for cand in matches:
        assert cand["candidate_type"] == "process_hiding_indicator"
        assert cand["validation_ready"] is True
