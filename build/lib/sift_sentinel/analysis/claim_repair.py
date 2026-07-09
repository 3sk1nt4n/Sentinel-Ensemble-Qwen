"""Deterministic claim-repair / bind pass (BUILD 1) -- runs BEFORE Step 12 SC.

Why: Step 10 validation is all-or-nothing. One UNRESOLVED claim (the model put a
technique description in a path claim, or left a network claim empty) blocks the
WHOLE finding and discards the proof of the claims that DID bind. So a finding the
existing universal matchers (IFEO debugger-hijack, SafeBoot non-default, ...) would
confirm dies at Bind before Step 13 ever runs. ~46% of findings die here, and it
recurs on every sample because it is model-output-shape.

What: for a finding blocked at validation -- but NOT on a fact CONTRADICTION
(MISMATCH stays blocked; that is Handler A / a real disagreement) -- re-bind each
claim on the EXISTING typed indexes (exact match only, via the SHARED
``tf_bind_attempts`` the validator's own checker uses -- never a parallel lookup).
On >=1 exact hit, attach the matched typed fact(s) to
``validator_metadata.typed_fact_refs`` and mark the finding validated. That single
attachment satisfies every downstream bind gate (durable_fact_refs,
typed-or-validated support) AND lets ``has_malicious_semantic`` fire on the real
fact -- so a conclusive structural finding reaches confirmed WITHOUT the ~22 KB
self-correction round-trip. Repair-then-skip-SC: only findings still lacking any
bindable subject fall through to (or past) SC.

Contract (zero-fake, no answer keys):
  * Bind via the EXISTING indexes only (``tf_bind_attempts`` -> ``facts_by_index``).
  * EXACT index match or drop. No fuzzy / approximate binding, ever.
  * No concrete bindable subject -> leave blocked (drop honestly).
  * A real fact disagreement (validation_status == MISMATCH) is never repaired.
Universal / dataset-agnostic: keys on claim STRUCTURE + the by_* indexes, never on
a tool / case / path / hash / IP value.
"""
from __future__ import annotations

from typing import Any

from sift_sentinel.validation.typed_validator import tf_bind_attempts

try:  # single source of truth for claim-type -> fact family
    from sift_sentinel.validation.validator import _CLAIM_TYPE_TO_FACT_TYPE
except Exception:  # pragma: no cover - import guard
    _CLAIM_TYPE_TO_FACT_TYPE = {}


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _fact_type_for_claim(claim: dict) -> str | None:
    """The fact family a claim targets, if known -- else None (then bind unfiltered,
    accepting whatever real typed fact sits at the exact entity key)."""
    ct = _norm(claim.get("type"))
    return _CLAIM_TYPE_TO_FACT_TYPE.get(ct) or (claim.get("fact_type") or None)


def _bind_claim_exact(claim: dict, tdb) -> list[dict]:
    """Typed facts that EXACTLY bind this claim's named entities, else []. Reuses
    the validator's own ``tf_bind_attempts`` so it can never drift. When the claim
    declares no known fact family, binds unfiltered (fact_type=None) -- still an
    exact key match, just family-agnostic, which is how a registry/persistence claim
    binds without a per-type mapping."""
    ft = _fact_type_for_claim(claim)
    probe = dict(claim)
    # carry a registry-path-shaped subject into the value slot the binder reads.
    if all(probe.get(k) in (None, "") for k in ("value", "path", "artifact")):
        rp = (claim.get("registry_path") or claim.get("registry_key")
              or claim.get("normalized_registry_path") or claim.get("key"))
        if rp not in (None, ""):
            probe["value"] = rp
    for index_name, key in tf_bind_attempts(probe):
        facts = tdb.facts_by_index(index_name, key, ft)
        if facts:
            return facts
    return []


def repair_finding_binding(finding: dict, tdb) -> bool:
    """Repair ONE finding in place. Returns True iff it was rescued (>=1 exact bind).
    Leaves passed findings and MISMATCH (fact-disagreement) findings untouched."""
    if not isinstance(finding, dict):
        return False
    if _norm(finding.get("deterministic_check")) == "passed":
        return False
    if _norm(finding.get("validation_status")) == "mismatch":
        return False  # real fact disagreement -> stays blocked (Handler A integrity)

    matched: list[dict] = []
    seen: set = set()
    for claim in finding.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        for fact in _bind_claim_exact(claim, tdb):
            fid = fact.get("fact_id") or id(fact)
            if fid in seen:
                continue
            seen.add(fid)
            matched.append(fact)
    if not matched:
        return False

    vm = finding.get("validator_metadata")
    if not isinstance(vm, dict):
        vm = {}
        finding["validator_metadata"] = vm
    vm["typed_fact_refs"] = list(vm.get("typed_fact_refs") or []) + matched
    finding["validation_status"] = "match"
    finding["deterministic_check"] = "passed"
    finding["binding_repaired"] = True
    return True


def repair_blocked_findings(findings, tdb) -> dict:
    """Repair every blocked finding in place. Returns {repaired, examined}.
    ``tdb`` is a typed_validator.TypedEvidenceDB (exact-index accessor)."""
    repaired = 0
    examined = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        if _norm(f.get("deterministic_check")) == "passed":
            continue
        examined += 1
        if repair_finding_binding(f, tdb):
            repaired += 1
    return {"repaired": repaired, "examined": examined}
