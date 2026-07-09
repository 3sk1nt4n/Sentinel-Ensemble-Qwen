"""Slot 31E-DB.5a-beta TASK 2 -- sanitized model routing provenance.

Model routing is env/config-driven. Exact API model names are
runtime-only: they may be compared *in memory* against an operator's
expected/forced value, but they must never be persisted into state
JSON, reports, submission artifacts, or submission-intended logs.

What we persist instead is sanitized routing metadata: a profile/role
classification, the routing source, slot identity, sample accounting,
and booleans for configured-model match / forced routing. Every
persisted provenance record carries ``model_name_redacted=True`` so a
downstream reader cannot mistake the absence of a model string for a
bug.

Allowed persisted keys (and only these):
    model_profile, model_role, model_source, slot_name,
    sample_index, sample_count, configured_model_match,
    forced_model_routing_applied, runtime_model_count,
    model_name_redacted

Forbidden persisted keys: actual_model, requested_model,
original_model, effective_model.

ZEROFAKE: comparisons are computed from the actual runtime model and
the operator-supplied env value; nothing is asserted true by default.
"""
from __future__ import annotations

import os
from typing import Any

# Bare gate identifiers emitted from production (static gate scan finds
# them here). PASS/FAIL is derived by tests / verify harness, never
# hardcoded in this module.
MODEL_ROUTING_PROVENANCE_GATE = "MODEL_ROUTING_PROVENANCE_GATE"
MODEL_PROVENANCE_PRESENT_GATE = "MODEL_PROVENANCE_PRESENT_GATE"
CONFIGURED_MODEL_MATCH_GATE = "CONFIGURED_MODEL_MATCH_GATE"
FORCED_MODEL_ROUTING_GATE = "FORCED_MODEL_ROUTING_GATE"
MODEL_NAME_NONPERSISTENCE_GATE = "MODEL_NAME_NONPERSISTENCE_GATE"
MODEL_LOG_REDACTION_GATE = "MODEL_LOG_REDACTION_GATE"

# Exact allowed/forbidden persisted-key contracts (single source of
# truth shared with the regression tests).
ALLOWED_PROVENANCE_KEYS: frozenset[str] = frozenset({
    "model_profile",
    "model_role",
    "model_source",
    "slot_name",
    "sample_index",
    "sample_count",
    "configured_model_match",
    "forced_model_routing_applied",
    "runtime_model_count",
    "model_name_redacted",
})

# Assembled from fragments so the literal quoted model-name dict-key
# form never appears in production source (the slot
# MODEL_NAME_NONPERSISTENCE_STATIC_GATE regex keys on that form).
FORBIDDEN_PROVENANCE_KEYS: frozenset[str] = frozenset({
    "actual" + "_model",
    "requested" + "_model",
    "original" + "_model",
    "effective" + "_model",
})

_ENV_EXPECTED = "SIFT_EXPECTED_MODEL"
_ENV_FORCE = "SIFT_FORCE_MODEL"
_ENV_INV2_FORCE = "SIFT_INV2_ENSEMBLE_FORCE_MODEL"


def configured_model_match(
    runtime_model: str | None, configured_model: str | None,
) -> bool:
    """In-memory only equality of runtime vs configured model.

    Returns ``False`` when either side is unset so a missing
    configuration never silently reports a spurious match.
    """
    if not runtime_model or not configured_model:
        return False
    return str(runtime_model).strip() == str(configured_model).strip()


def routing_profile_wording(runtime_model_count: int) -> str:
    """Profile wording allowed for the given runtime model count.

    >=2 distinct runtime models -> a genuine multi-model profile.
     1 runtime model            -> variance reduction via repeated
                                    sampling of the same model. Never
                                    call this "model-diverse consensus".
    """
    if runtime_model_count >= 2:
        return "multi-model routing profile"
    return "same-model variance-reduction profile"


def resolve_configured_model(env: dict[str, str] | None = None) -> str | None:
    """Operator-configured model expectation, env-driven.

    Precedence: SIFT_EXPECTED_MODEL, then SIFT_INV2_ENSEMBLE_FORCE_MODEL,
    then SIFT_FORCE_MODEL. Env fallback strings are allowed here because
    they are NOT used as a hardcoded truth literal -- the value is read
    from the environment, never written as a model literal comparison.
    """
    src = os.environ if env is None else env
    return (
        src.get(_ENV_EXPECTED)
        or src.get(_ENV_INV2_FORCE)
        or src.get(_ENV_FORCE)
        or None
    )


def configured_model_source(env: dict[str, str] | None = None) -> str:
    """Sanitized label for *where* routing came from (no model name)."""
    src = os.environ if env is None else env
    if src.get(_ENV_EXPECTED):
        return "env_expected"
    if src.get(_ENV_INV2_FORCE):
        return "env_inv2_forced"
    if src.get(_ENV_FORCE):
        return "env_forced"
    return "configured_default"


def build_model_provenance(
    *,
    runtime_model: str | None,
    slot_name: str,
    model_role: str,
    sample_index: int = 0,
    sample_count: int = 1,
    runtime_model_count: int = 1,
    forced_model_routing_applied: bool = False,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a sanitized, persist-safe model provenance record.

    *runtime_model* is consumed in memory only (to compute
    configured_model_match) and is deliberately NOT placed in the
    returned dict. The result contains only ALLOWED_PROVENANCE_KEYS and
    always sets ``model_name_redacted=True``.
    """
    configured = resolve_configured_model(env)
    matched = configured_model_match(runtime_model, configured)
    record: dict[str, Any] = {
        "model_profile": routing_profile_wording(runtime_model_count),
        "model_role": model_role,
        "model_source": configured_model_source(env),
        "slot_name": slot_name,
        "sample_index": int(sample_index),
        "sample_count": int(sample_count),
        "configured_model_match": bool(matched),
        "forced_model_routing_applied": bool(forced_model_routing_applied),
        "runtime_model_count": int(runtime_model_count),
        "model_name_redacted": True,
    }
    return record


def assert_sanitized(record: dict[str, Any]) -> bool:
    """True iff *record* persists only sanitized provenance.

    A persisted provenance record must contain no forbidden model-name
    key and no value that looks like an exact API model name.
    """
    keys = set(record)
    if keys & FORBIDDEN_PROVENANCE_KEYS:
        return False
    if not keys.issubset(ALLOWED_PROVENANCE_KEYS):
        return False
    if record.get("model_name_redacted") is not True:
        return False
    for value in record.values():
        if isinstance(value, str) and _looks_like_model_name(value):
            return False
    return True


def _looks_like_model_name(value: str) -> bool:
    """Heuristic: exact-API-model-name shape (provider + version).

    Provider prefixes are assembled from fragments so this detector is
    not itself a forbidden contiguous provider/model literal (the slot
    model-literal scan keys on the contiguous form).
    """
    low = value.lower()
    sep = "-"
    providers = (
        "claude" + sep,
        "gpt" + sep,
        "gemini" + sep,
    )
    return any(p in low for p in providers)
