"""R1a/R1b: entity-key fallback claim builders + widened deterministic emission.

R1b: the fallback `_claim_from_entity_key` recognized only pid/process/path/
service/ip/peer prefixes; task: and hash: entity keys (both produced by
candidate_observations._entity_keys) fell through to None, so a task- or
hash-anchored candidate emitted a finding with NO claims -> blocked at
validation. registry:/url:/socket: stay None deliberately (no validator
checker can bind them from a bare entity key; socket: carries the SOURCE
side which the connection checker cannot match).

R1a: pid/path-anchored non-weak strong signals join _EMIT_ELIGIBLE so their
validation-ready candidates emit deterministically. SIFT_EMIT_DISABLE gives
a per-signal operational kill-switch.

Synthetic values only; keyed on prefix/signal structure, no case data.
"""
from __future__ import annotations

from sift_sentinel.analysis.candidate_findings import (
    _EMIT_ELIGIBLE,
    _claim_from_entity_key,
    build_candidate_semantic_findings,
)


# ── R1b: new fallback claim builders ─────────────────────────────────────

def test_task_entity_key_builds_scheduled_task_claim():
    c = _claim_from_entity_key(r"task:\microsoft\windows\updcheck")
    assert c is not None
    assert c["type"] == "scheduled_task"
    assert c["task_name"] == r"\microsoft\windows\updcheck"


def test_hash_sha1_entity_key_builds_hash_claim():
    sha1 = "a" * 40
    c = _claim_from_entity_key("hash:" + sha1)
    assert c is not None
    assert c["type"] == "hash"
    assert c["sha1"] == sha1


def test_hash_non_sha1_lengths_stay_none():
    # _t_hash binds by_hash on SHA1 keys; md5/sha256 fallbacks would emit a
    # claim that can never MATCH -- conservative None instead.
    assert _claim_from_entity_key("hash:" + "b" * 32) is None
    assert _claim_from_entity_key("hash:" + "c" * 64) is None


def test_unbindable_prefixes_stay_none():
    assert _claim_from_entity_key("registry:hklm/system/x/services/y") is None
    assert _claim_from_entity_key("url:http://203.0.113.7/p") is None
    assert _claim_from_entity_key("socket:203.0.113.7:49152") is None


def test_metamorphic_task_claim_relabel():
    a = _claim_from_entity_key("task:alpha")
    b = _claim_from_entity_key("task:beta")
    assert a["type"] == b["type"] == "scheduled_task"
    assert (a["task_name"], b["task_name"]) == ("alpha", "beta")


def test_task_anchored_candidate_emits_finding_with_claims():
    # end-to-end through the public builder: a task-anchored validation-ready
    # candidate must no longer emit a claimless (auto-blocked) finding.
    c = {
        "entity_key": "task:updcheck",
        "candidate_type": "persistence",
        "validation_ready": True,
        "supporting": True,
        "score": 200,
        "malicious_semantic_signals": ["anti_forensics_execution"],
        "signals": ["anti_forensics_execution"],
        "source_tools": ["parse_scheduled_tasks_disk"],
        "fact_ids": ["does-not-resolve"],
    }
    out = build_candidate_semantic_findings(
        {"candidates": [c]}, existing_findings=[])
    assert len(out) == 1
    claims = out[0]["claims"]
    assert claims and claims[0]["type"] == "scheduled_task"


# ── R1a: widened deterministic emission ──────────────────────────────────

_R1A_EXPECTED = {
    "injected_pe_image_in_executable_memory",
    "process_hollowing_indicators",
    "appcompatcache_execution_from_staging",
    "lnk_execution_from_staging",
    "jumplist_access_to_staging",
    "registry_run_key_pointing_to_temp",
    "ifeo_debugger_hijack",
    "safeboot_alternateshell_persistence",
    "scheduled_task_with_hidden_action",
    "spawned_by_lolbin_with_suspicious_chain",
}


def test_r1a_strong_signals_are_emit_eligible():
    missing = _R1A_EXPECTED - set(_EMIT_ELIGIBLE)
    assert not missing, missing


def test_r1a_values_are_registered_and_non_weak():
    from sift_sentinel.analysis.disposition import _WEAK_ALONE_SEMANTIC_SIGNALS
    from sift_sentinel.analysis.malicious_semantics import (
        MALICIOUS_SEMANTIC_SIGNALS,
    )
    for s in _R1A_EXPECTED:
        assert _EMIT_ELIGIBLE[s] in MALICIOUS_SEMANTIC_SIGNALS
        assert _EMIT_ELIGIBLE[s] not in _WEAK_ALONE_SEMANTIC_SIGNALS


def test_emit_disable_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_EMIT_DISABLE", "ifeo_debugger_hijack")
    c = {
        "entity_key": "path:c:/x/subject.exe",
        "candidate_type": "persistence",
        "validation_ready": True,
        "supporting": True,
        "score": 200,
        "malicious_semantic_signals": ["ifeo_debugger_hijack"],
        "signals": ["ifeo_debugger_hijack"],
        "source_tools": ["parse_registry_persistence"],
        "fact_ids": ["x"],
    }
    out = build_candidate_semantic_findings(
        {"candidates": [c]}, existing_findings=[])
    assert out == []
    monkeypatch.delenv("SIFT_EMIT_DISABLE")
    out2 = build_candidate_semantic_findings(
        {"candidates": [c]}, existing_findings=[])
    assert len(out2) == 1
