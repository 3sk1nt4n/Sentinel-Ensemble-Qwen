"""Account-context anomaly: built-in service account owning an interactive shell.

LOCAL SERVICE / NETWORK SERVICE (well-known SIDs S-1-5-19 / S-1-5-20) run specific
non-interactive services -- never cmd/powershell. A service account holding an
interactive shell is the signature of service abuse / lateral movement
(T1078/T1569). Complements the existing privileged-LOGON scoring (4672) in
user_account_synthesizer with a role-vs-behavior anomaly. Dataset-agnostic: keys
on well-known SID RIDs + a universal shell vocabulary -- no account-name lists,
no case data. Rides the gen-fix -> needs_review.
"""
from __future__ import annotations

from sift_sentinel.analysis.malicious_semantics import (
    MALICIOUS_SEMANTIC_SIGNALS,
    match_service_account_interactive,
)
from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
    _candidate_type,
    _score_fact,
)


def _sid(pid, proc, sid):
    return {"fact_type": "sid_fact", "type": "sid_fact",
            "fact_id": "sid_fact-%d" % pid,
            "pid": pid, "process_name": proc, "sid": sid}


def _db(facts):
    typed: dict = {}
    for f in facts:
        typed.setdefault(f["fact_type"], []).append(f)
    return {"typed_facts": typed}


def test_matcher_fires_service_account_shell():
    assert match_service_account_interactive(_sid(1, "cmd.exe", "S-1-5-19"))
    assert match_service_account_interactive(_sid(2, "powershell.exe", "S-1-5-20"))


def test_matcher_ignores_legit_combinations():
    # service account running its OWN (non-shell) service -> not anomalous
    assert not match_service_account_interactive(_sid(3, "svchost.exe", "S-1-5-19"))
    # a normal USER (not a built-in service SID) running cmd -> not this signal
    assert not match_service_account_interactive(
        _sid(4, "cmd.exe", "S-1-5-21-111-222-333-1001"))
    # SYSTEM running cmd -> NOT keyed here (too common; deliberately scoped to 19/20)
    assert not match_service_account_interactive(_sid(5, "cmd.exe", "S-1-5-18"))


def test_registered_non_weak():
    spec = MALICIOUS_SEMANTIC_SIGNALS.get("service_account_interactive_execution")
    assert spec and callable(spec.get("matcher")) and spec.get("required_fact_types")


def test_score_fact_emits_signal_and_type():
    score, signals, _ = _score_fact(_sid(4123, "cmd.exe", "S-1-5-19"))
    assert "service_account_interactive_execution" in signals
    assert _candidate_type(set(signals)) == "account_context_anomaly"


def test_score_fact_clean_on_legit():
    _, signals, _ = _score_fact(_sid(4124, "svchost.exe", "S-1-5-19"))
    assert "service_account_interactive_execution" not in signals
