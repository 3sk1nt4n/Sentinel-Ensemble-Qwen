"""Self-correction terminal result classification.

Dataset-agnostic policy:
- corrected: SC produced a validator-backed correction.
- rejected: SC tried but validator/logic rejected it; not infrastructure failure.
- dropped_honest: SC honestly refused to fabricate or could not preserve the
  original unsupported subject; not infrastructure failure and not promoted.
- failed_with_reason: infrastructure/parser/API/schema failure.

No evidence literals, no answer keys.
"""

from __future__ import annotations

import json
from typing import Any


_HONEST_DROP_TOKENS = {
    "dropped_honest",
    "dropped_unsupported",
    "drop_finding",
    "declared_unfixable",
    "unfixable",
    "error_only",          # legacy replay: old self_correct terminal label
    "dropped",
}

_HONEST_DROP_MARKERS = (
    "declined to rewrite",
    "finding=null",
    "honest inconclusive",
    "kept as unresolved",
    "not promoted",
    "unsupported claim rejected",
    "cannot be salvaged",
    "cannot be verified",
    "no valid claim can be constructed",
)

_INFRA_FAILURE_TOKENS = {
    "failed_with_reason",
    "error",
    "exception",
    "infrastructure_failure",
    "parser_error",
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _serialized_lower(result: dict[str, Any]) -> str:
    try:
        return json.dumps(result, sort_keys=True, default=str).lower()
    except Exception:
        return str(result).lower()


def _status_tokens(result: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in (
        "status",
        "outcome",
        "outcome_kind",
        "kind",
        "terminal_status",
        "validator_result",
        "action",
    ):
        value = result.get(key)
        if value is not None:
            tokens.add(_norm(value))
    return {t for t in tokens if t}


def classify_self_correction_terminal_result(
    raw_result: Any,
    finding_id: str | None = None,
) -> tuple[dict[str, Any], str, str]:
    """Normalize an SC result into (result, terminal_status, reason).

    terminal_status is one of:
      corrected, rejected, dropped_honest, failed_with_reason
    """
    if not isinstance(raw_result, dict):
        return (
            {
                "finding_id": finding_id,
                "status": "failed_with_reason",
                "error": "self_correction_result_not_dict",
            },
            "failed_with_reason",
            "self_correction_result_not_dict",
        )

    result = dict(raw_result)
    if finding_id:
        result.setdefault("finding_id", finding_id)

    tokens = _status_tokens(result)
    text = _serialized_lower(result)
    reason = str(
        result.get("reason")
        or result.get("error")
        or result.get("status")
        or result.get("outcome")
        or result.get("validator_result")
        or ""
    ).strip()

    # Explicit infrastructure errors stay failures. This guard intentionally
    # comes before honest-drop handling.
    if result.get("error") or (tokens & _INFRA_FAILURE_TOKENS):
        result["status"] = "failed_with_reason"
        return result, "failed_with_reason", str(result.get("error") or reason or "error")

    # Positive correction wins when explicitly asserted.
    if result.get("corrected") is True or result.get("self_corrected") is True:
        result["status"] = "corrected"
        return result, "corrected", str(result.get("reason") or "corrected")

    if tokens & _HONEST_DROP_TOKENS or any(marker in text for marker in _HONEST_DROP_MARKERS):
        result["status"] = "dropped_honest"
        result["honest_drop"] = True
        return result, "dropped_honest", str(
            result.get("reason")
            or result.get("validator_result")
            or "unsupported finding honestly dropped"
        )

    # Explicit false correction is a normal rejected terminal state.
    if "corrected" in result and result.get("corrected") is False:
        result["status"] = "rejected"
        return result, "rejected", str(result.get("reason") or "not_corrected")

    if tokens & {"corrected", "accepted", "success"}:
        result["status"] = "corrected"
        return result, "corrected", str(result.get("reason") or "corrected")

    if tokens & {
        "rejected",
        "blocked",
        "inconclusive",
        "unsupported",
        "revalidation_failed",
        "failed",
        "not_corrected",
        "uncorrected",
        "exhausted",
        "validator_rejected",
    }:
        result["status"] = "rejected"
        return result, "rejected", str(result.get("reason") or reason or "not_corrected")

    # Unknown schema is fail-closed.
    result["status"] = "failed_with_reason"
    result["error"] = "unrecognized_self_correction_result_schema"
    return result, "failed_with_reason", "unrecognized_result_schema"
