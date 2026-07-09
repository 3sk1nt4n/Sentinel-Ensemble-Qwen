"""Sentinel Qwen Ensemble -- canonical validation telemetry (Slot 31E-DB.5.1).

Backend Step 10 validator telemetry is the single source of truth for
evidence-validation counters. report_truth.json,
report_validation.json, pipeline_summary.json and the rendered report
text must all consume the *same* normalized object -- never a stale
default-zero recomputation.

Two public helpers:

  * ``normalize_validation_telemetry`` -- coerce an arbitrary dict onto
    the canonical four-field shape, preserving *absence* (``None``) so a
    missing field is detectable rather than silently zeroed.
  * ``validate_telemetry_consistency`` -- prove backend and report
    telemetry agree; any missing field or value drift FAILS.

Reverting Slot 31E-DB.5.1 deletes this module and its run_pipeline
import; telemetry then degrades to the prior recomputed-from-findings
behaviour with no schema migration required.
"""

from __future__ import annotations

CANONICAL_TELEMETRY_FIELDS = (
    "typed_evidence_db_used",
    "typed_fact_matches",
    "reference_set_fallback_matches",
    "unsupported_claim_type_count",
)

_BOOL_FIELDS = frozenset({"typed_evidence_db_used"})


def normalize_validation_telemetry(obj: dict | None) -> dict:
    """Return the canonical four-field telemetry object.

    Present fields are coerced (bool for ``typed_evidence_db_used``,
    int for the counters). A field that is genuinely absent stays
    ``None`` -- this is deliberate so ``validate_telemetry_consistency``
    can distinguish "missing" from "zero". No stale default zeros are
    fabricated here.
    """
    out: dict = {}
    src = obj if isinstance(obj, dict) else {}
    for field in CANONICAL_TELEMETRY_FIELDS:
        if field not in src or src[field] is None:
            out[field] = None
            continue
        val = src[field]
        if field in _BOOL_FIELDS:
            out[field] = bool(val)
        else:
            try:
                out[field] = int(val)
            except (TypeError, ValueError):
                out[field] = None
    return out


def validate_telemetry_consistency(
    backend: dict | None,
    report: dict | None,
) -> tuple[bool, list[str]]:
    """Return ``(ok, errors)``.

    FAILS when:
      * any canonical field is missing/None in either side, or
      * backend and report disagree on any canonical field.

    The backend object is canonical; the report side must mirror it
    exactly. Bool fields compare by truth value, counters by int
    equality.
    """
    errors: list[str] = []
    nb = normalize_validation_telemetry(backend)
    nr = normalize_validation_telemetry(report)

    for field in CANONICAL_TELEMETRY_FIELDS:
        b = nb.get(field)
        r = nr.get(field)
        if b is None:
            errors.append("backend_missing_field:%s" % field)
        if r is None:
            errors.append("report_missing_field:%s" % field)
        if b is None or r is None:
            continue
        if b != r:
            errors.append(
                "telemetry_mismatch:%s backend=%r report=%r"
                % (field, b, r)
            )

    return (len(errors) == 0), errors
