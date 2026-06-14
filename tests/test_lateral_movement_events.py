"""High-value lateral-movement Security events: 5140/5145 admin-share access +
4648 explicit-credential logon.

Universal Windows Event IDs mapped to MITRE techniques (T1021.002 admin shares;
T1078/T1550 alternate creds). admin_share_access is non-weak (strong lateral-
movement signal, FP-low: access to C$/ADMIN$/IPC$). explicit_credential_logon is
CORROBORATING (weak-alone) -- noisy on its own (legit RunAs), so it strengthens a
finding rather than surfacing standalone. Dataset-agnostic: universal Event IDs +
universal admin-share names, no host/IP/case data.
"""
from __future__ import annotations

from sift_sentinel.analysis.malicious_semantics import (
    MALICIOUS_SEMANTIC_SIGNALS,
    match_admin_share_access,
    match_explicit_credential_logon,
)
from sift_sentinel.analysis.candidate_observations import _candidate_type, _score_fact
from sift_sentinel.analysis.disposition import _WEAK_ALONE_SEMANTIC_SIGNALS


def _evt(eid, message):
    return {"fact_type": "event_log_fact", "type": "event_log_fact",
            "event_id": str(eid), "entity_id": str(eid), "message": message}


def test_admin_share_access_matcher():
    assert match_admin_share_access(_evt(5140, r"Share Name: \\*\C$ Source: 10.0.0.5"))
    assert match_admin_share_access(_evt(5145, "Share Name: \\\\srv\\ADMIN$ relative ..."))
    assert match_admin_share_access(_evt(5140, "Share Name: \\\\*\\IPC$"))


def test_admin_share_access_ignores_normal_share_and_other_eids():
    assert not match_admin_share_access(_evt(5140, r"Share Name: \\fileserver\Public"))
    assert not match_admin_share_access(_evt(4624, r"Share Name: \\*\C$"))  # wrong EID


def test_explicit_credential_logon_matcher():
    assert match_explicit_credential_logon(_evt(4648, "explicit credentials ... Target: DC01"))
    assert not match_explicit_credential_logon(_evt(4624, "normal logon"))


def test_both_registered():
    for name in ("admin_share_access", "explicit_credential_logon"):
        spec = MALICIOUS_SEMANTIC_SIGNALS.get(name)
        assert spec and callable(spec.get("matcher")) and spec.get("required_fact_types")


def test_4648_is_corroborating_not_standalone():
    # FP-bound: explicit_credential_logon is weak-alone -> won't surface a lone 4648.
    assert "explicit_credential_logon" in _WEAK_ALONE_SEMANTIC_SIGNALS
    # admin_share_access is NOT weak-alone (it's a strong standalone signal).
    assert "admin_share_access" not in _WEAK_ALONE_SEMANTIC_SIGNALS


def test_score_fact_emits_admin_share_signal_and_type():
    score, signals, _ = _score_fact(
        _evt(5140, r"A network share object was accessed. Share Name: \\*\C$"))
    assert "admin_share_access" in signals
    assert _candidate_type(set(signals)) == "lateral_movement_admin_share"


def test_score_fact_emits_4648():
    _, signals, _ = _score_fact(_evt(4648, "explicit credentials Target Server: DC01"))
    assert "explicit_credential_logon" in signals


# ── Event findings validate by their Event ID (the robust universal entity) ──
# An event has no path/pid/hash, and a bare source-IP yields a connection claim
# that can't MATCH (the checker needs PID+foreign_addr). The recognized, typed-
# checked entity for ANY Windows event is its Event ID -> validator _t_event_log
# matches it against the by_event_id index. The gen-fix must emit that claim so
# admin_share_access (and any future event-derived signal) validates, universally.

def _edb_5140():
    return {
        "typed_facts": {"event_log_fact": [
            {"fact_id": "ev-1", "fact_type": "event_log_fact", "event_id": "5140",
             "raw_excerpt": r'{"EventID":5140,"Message":"share C$ Source Address: 10.0.0.5"}'}]},
        "indexes": {"by_event_id": {"5140": ["ev-1"]}},
    }


def test_genfix_emits_event_log_claim_from_event_fact():
    from sift_sentinel.analysis.candidate_findings import build_candidate_semantic_findings
    cand = {
        "candidate_id": "c-1", "candidate_type": "lateral_movement_admin_share",
        "entity_key": "ip:10.0.0.5", "validation_ready": True,
        "signals": ["admin_share_access"], "score": 90,
        "source_tools": ["parse_event_logs"], "fact_ids": ["ev-1"],
    }
    out = build_candidate_semantic_findings({"candidates": [cand]},
                                            existing_findings=[], evidence_db=_edb_5140())
    assert len(out) == 1, out
    types = [cl["type"] for cl in out[0]["claims"]]
    assert "event_log" in types, types
    ev = next(cl for cl in out[0]["claims"] if cl["type"] == "event_log")
    assert str(ev.get("event_id")) == "5140", ev


def test_admin_share_event_finding_validates_MATCH():
    # The end-to-end fix: admin_share_access -> MATCH (was MISMATCH on the bare
    # connection claim), because the event_log claim hits the by_event_id index.
    from sift_sentinel.analysis.candidate_findings import build_candidate_semantic_findings
    from sift_sentinel.validation.validator import validate_finding
    edb = _edb_5140()
    cand = {
        "candidate_id": "c-1", "candidate_type": "lateral_movement_admin_share",
        "entity_key": "ip:10.0.0.5", "validation_ready": True,
        "signals": ["admin_share_access"], "score": 90,
        "source_tools": ["parse_event_logs"], "fact_ids": ["ev-1"],
    }
    out = build_candidate_semantic_findings({"candidates": [cand]},
                                            existing_findings=[], evidence_db=edb)
    res = validate_finding(out[0], {}, evidence_db=edb)
    assert res.get("status") == "MATCH", (res.get("status"), res.get("detail"))
