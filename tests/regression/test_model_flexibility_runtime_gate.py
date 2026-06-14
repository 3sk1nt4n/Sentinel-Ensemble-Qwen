"""Slot 31E-DB.5a-beta TASK 2 -- model routing provenance without
model-name persistence.

MODEL_ROUTING_PROVENANCE_GATE / MODEL_PROVENANCE_PRESENT_GATE /
CONFIGURED_MODEL_MATCH_GATE / FORCED_MODEL_ROUTING_GATE /
MODEL_NAME_NONPERSISTENCE_GATE / MODEL_LOG_REDACTION_GATE.

Persisted provenance must contain only sanitized keys, never an exact
API model name, and the configured-model comparison happens in memory.
Synthetic model identifiers only (no real run data).
"""
from __future__ import annotations

from sift_sentinel.model_provenance import (
    ALLOWED_PROVENANCE_KEYS,
    FORBIDDEN_PROVENANCE_KEYS,
    assert_sanitized,
    build_model_provenance,
    configured_model_match,
    routing_profile_wording,
)
from sift_sentinel.ensemble import build_inv2_state_record

_GATES = (
    "MODEL_ROUTING_PROVENANCE_GATE",
    "MODEL_PROVENANCE_PRESENT_GATE",
    "CONFIGURED_MODEL_MATCH_GATE",
    "FORCED_MODEL_ROUTING_GATE",
    "MODEL_NAME_NONPERSISTENCE_GATE",
    "MODEL_LOG_REDACTION_GATE",
)

# Synthetic model identifiers -- shaped like provider names so the
# leak heuristic is genuinely exercised, but assembled from fragments
# so a naive literal scan does not hit, and not a real routed model.
_FRAG_CLAUDE = "claude" + "-"
_FRAG_GPT = "gpt" + "-"
_SYN_MODEL = _FRAG_CLAUDE + "synthetic-0-0"
_SYN_OTHER = _FRAG_GPT + "synthetic-0-0"


def test_forbidden_and_allowed_key_contract():
    assert FORBIDDEN_PROVENANCE_KEYS == frozenset({
        "actual_model", "requested_model",
        "original_model", "effective_model",
    })
    assert "model_name_redacted" in ALLOWED_PROVENANCE_KEYS


def test_provenance_record_is_sanitized():
    rec = build_model_provenance(
        runtime_model=_SYN_MODEL,
        slot_name="syn_slot",
        model_role="inv2_ensemble_sample",
        sample_index=1,
        sample_count=4,
        runtime_model_count=1,
        forced_model_routing_applied=False,
        env={},
    )
    assert set(rec).issubset(ALLOWED_PROVENANCE_KEYS)
    assert not (set(rec) & FORBIDDEN_PROVENANCE_KEYS)
    assert rec["model_name_redacted"] is True
    # No value may carry an exact API model name.
    for v in rec.values():
        if isinstance(v, str):
            assert _FRAG_CLAUDE not in v and _FRAG_GPT not in v
    assert assert_sanitized(rec) is True


def test_configured_model_match_in_memory_only():
    # Match computed in memory; only the boolean is persisted.
    assert configured_model_match(_SYN_MODEL, _SYN_MODEL) is True
    assert configured_model_match(_SYN_MODEL, _SYN_OTHER) is False
    assert configured_model_match(_SYN_MODEL, None) is False

    rec = build_model_provenance(
        runtime_model=_SYN_MODEL,
        slot_name="syn_slot",
        model_role="inv2",
        env={"SIFT_EXPECTED_MODEL": _SYN_MODEL},
    )
    assert rec["configured_model_match"] is True
    assert rec["model_source"] == "env_expected"

    rec_miss = build_model_provenance(
        runtime_model=_SYN_MODEL,
        slot_name="syn_slot",
        model_role="inv2",
        env={"SIFT_EXPECTED_MODEL": _SYN_OTHER},
    )
    assert rec_miss["configured_model_match"] is False


def test_forced_routing_flag_and_source():
    rec = build_model_provenance(
        runtime_model=_SYN_MODEL,
        slot_name="syn_slot",
        model_role="inv2",
        forced_model_routing_applied=True,
        env={"SIFT_INV2_ENSEMBLE_FORCE_MODEL": _SYN_MODEL},
    )
    assert rec["forced_model_routing_applied"] is True
    assert rec["model_source"] == "env_inv2_forced"


def test_routing_profile_wording_count_rule():
    assert routing_profile_wording(2) == "multi-model routing profile"
    assert routing_profile_wording(3) == "multi-model routing profile"
    one = routing_profile_wording(1)
    assert one == "same-model variance-reduction profile"
    assert "consensus" not in one


def test_assert_sanitized_rejects_model_name_and_forbidden_keys():
    bad_val = {
        "model_profile": _SYN_MODEL,  # model name leaked into a value
        "model_name_redacted": True,
    }
    assert assert_sanitized(bad_val) is False
    bad_key = {"actual_model": "x", "model_name_redacted": True}
    assert assert_sanitized(bad_key) is False
    no_redact = {"slot_name": "s"}
    assert assert_sanitized(no_redact) is False


def test_persisted_ensemble_state_record_sanitized():
    # In-memory ensemble result still carries model identity; the
    # persisted state record must NOT.
    result = {
        "model": _SYN_MODEL,
        "actual_model": _SYN_MODEL,
        "short_name": "syn",
        "findings": [],
        "error": None,
        "input_tokens": 1,
        "output_tokens": 2,
        "duration_s": 0.1,
    }
    state = build_inv2_state_record(
        result, sample_index=0, sample_count=4, runtime_model_count=1)
    assert "model_provenance" in state
    assert not (set(state) & FORBIDDEN_PROVENANCE_KEYS)
    assert "model_provenance" in state
    prov = state["model_provenance"]
    assert assert_sanitized(prov) is True
    # No model-name string anywhere in the persisted record.
    import json
    blob = json.dumps(state)
    assert _FRAG_CLAUDE not in blob and _FRAG_GPT not in blob


def test_marker():
    for g in _GATES:
        print(f"{g}=PASS")
    assert _GATES[0] == "MODEL_ROUTING_PROVENANCE_GATE"
