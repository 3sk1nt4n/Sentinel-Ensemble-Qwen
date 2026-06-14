"""High-value bullseye: privileged group modification (T1098 account manipulation).

EID 4732 (member added to a security-enabled LOCAL group), 4728 (GLOBAL group),
4756 (UNIVERSAL group) -- scoped to PRIVILEGED groups only (Administrators /
Domain Admins / Enterprise Admins / Backup/Account/Server/Print Operators /
Schema Admins). Adding an account to one of these is a classic persistence /
privilege-escalation TTP. FP-bound by well-known group RID (S-1-5-32-544,
domain -512/-519/-518/...) -- a 4732 adding to non-privileged "Users"
(S-1-5-32-545) or "Remote Desktop Users" does NOT fire.

Non-weak: rides the gen-fix + the validatable event_log claim path. Dataset-
agnostic: universal Event IDs + universal well-known group RIDs, no case data.
"""
from __future__ import annotations

import json
from pathlib import Path

from sift_sentinel.analysis.malicious_semantics import (
    MALICIOUS_SEMANTIC_SIGNALS,
    match_privileged_group_modification,
)
from sift_sentinel.analysis.candidate_observations import _candidate_type, _score_fact
from sift_sentinel.analysis.disposition import _BEHAVIORAL_ANOMALY_SEMANTIC_SIGNALS
from sift_sentinel.analysis.candidate_findings import _EMIT_ELIGIBLE


def _evt(eid, message):
    return {"fact_type": "event_log_fact", "type": "event_log_fact",
            "event_id": str(eid), "entity_id": str(eid),
            "message": message, "raw_excerpt": message}


def test_matcher_fires_local_administrators_by_rid():
    m = (r"A member was added to a security-enabled local group. "
         r"Group: Security ID: S-1-5-32-544 Group Name: Administrators "
         r"Member: Security ID: S-1-5-21-1-2-3-1105")
    assert match_privileged_group_modification(_evt(4732, m)) is True


def test_matcher_fires_domain_admins_by_rid():
    m = (r"A member was added to a security-enabled global group. "
         r"Group: Security ID: S-1-5-21-111-222-333-512 Group Name: Domain Admins")
    assert match_privileged_group_modification(_evt(4728, m)) is True


def test_matcher_fires_enterprise_admins_universal():
    m = "Group: Security ID: S-1-5-21-9-8-7-519 Group Name: Enterprise Admins"
    assert match_privileged_group_modification(_evt(4756, m)) is True


def test_matcher_does_not_fire_non_privileged_group():
    # 4732 adding to the non-privileged Users group (RID 545) must NOT fire.
    m = "Group: Security ID: S-1-5-32-545 Group Name: Users Member: ..."
    assert match_privileged_group_modification(_evt(4732, m)) is False


def test_matcher_does_not_fire_wrong_eid():
    m = "Group: Security ID: S-1-5-32-544 Group Name: Administrators"
    assert match_privileged_group_modification(_evt(4624, m)) is False


def test_score_fact_emits_signal_and_candidate_type():
    m = ("A member was added to a security-enabled local group. "
         "Group: Security ID: S-1-5-32-544 Group Name: Administrators")
    score, signals, _ = _score_fact(_evt(4732, m))
    assert "privileged_group_modification" in signals
    assert score > 0
    assert _candidate_type(set(signals)) == "privilege_escalation_group_modification"


def test_score_fact_quiet_on_non_privileged_group():
    m = "Group: Security ID: S-1-5-32-545 Group Name: Users"
    _, signals, _ = _score_fact(_evt(4732, m))
    assert "privileged_group_modification" not in signals


def test_registered_non_weak_with_matcher_and_fact_types():
    spec = MALICIOUS_SEMANTIC_SIGNALS.get("privileged_group_modification")
    assert spec is not None
    assert callable(spec.get("matcher"))
    assert spec.get("required_fact_types")


def test_in_behavioral_anomaly_and_emit_eligible():
    # Fix B (ReAct-benign can't bury it) + gen-fix emission.
    assert "privileged_group_modification" in _BEHAVIORAL_ANOMALY_SEMANTIC_SIGNALS
    assert "privileged_group_modification" in _EMIT_ELIGIBLE.values()


def test_not_weak_alone():
    # Strong standalone signal: must NOT be in the weak-alone (corroborating) set.
    from sift_sentinel.analysis.disposition import _WEAK_ALONE_SEMANTIC_SIGNALS
    assert "privileged_group_modification" not in _WEAK_ALONE_SEMANTIC_SIGNALS


def test_positive_fixture_exists_and_fires():
    p = (Path(__file__).parent / "fixtures" / "malicious_semantic"
         / "privileged_group_modification_positive.json")
    assert p.exists(), p
    payload = json.loads(p.read_text())
    assert match_privileged_group_modification(
        payload["fact"], evidence_db=payload.get("evidence_db")) is True
