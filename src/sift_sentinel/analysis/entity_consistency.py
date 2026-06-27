"""Entity-disposition consistency: the SAME entity must land in ONE table.

The judge-visible defect is a finding and its twin about the SAME entity (a process
PID, a registry key, an event) landing in *different* tables -- one in the
findings/confirmed table, the other in the benign table. That is automatically wrong:
one of them is mis-placed, and which one varies run-to-run (the verdict is an LLM
sample), so it is also non-reproducible across machines.

This pass runs AFTER inv3a finalizes the verdicts and resolves each entity that is
SPLIT across the surfaced (findings) and benign tables to ONE table, using the
existing downgrade-only philosophy extended symmetrically:

  STRONG MALICE  (explicit ReAct malicious verdict OR own non-weak malicious-semantic
                  signal)  -> the findings table; a weak benign sibling can NEVER bury
                  it (this is the adversarial false-benign guard).
  STRONG BENIGN  (ReAct is_false_positive / adjudicated FP, no strong-malice sibling)
                  -> the benign table; pull the surfaced siblings that carry no own
                  malice there (fixes the legit-DFIR-tool-as-a-finding leak).
  otherwise      (both weak / conflicting) -> the findings table as needs-review
                  (honest unknown is a finding, never a dismissal).

Universal by construction: keys ONLY on the run's own verdict strength + entity shape
(PID / registry key / event id), never on finding-IDs (non-deterministic) or case
names (an answer key). Deterministic given the findings, so the SAME evidence places
the SAME way on every PC. Downgrade-only in the dangerous direction (a confirmed
finding is never demoted out of the findings table; real malice is never pulled to
benign). Kill-switch SIFT_ENTITY_DISPOSITION_CONSISTENCY.
"""
from __future__ import annotations

import os

from sift_sentinel.analysis.fp_routing import (
    _entity_pids,
    _malicious_verdict,
    has_independent_malice,
)
from sift_sentinel.analysis.signature_reconcile import _is_adjudicated_benign

try:
    from sift_sentinel.analysis.confirmed_dedup import (
        _registry_keys,
        _event_identity_keys,
    )
except Exception:                       # pragma: no cover - keep the pass resilient
    def _registry_keys(_f):
        return set()

    def _event_identity_keys(_f):
        return set()

CONFIRMED = "confirmed_malicious_atomic"
REVIEW = "suspicious_needs_review"
BENIGN = "benign_or_false_positive"
INCONCLUSIVE = "inconclusive_unresolved"

# the four buckets this pass reasons over; the findings table = CONFIRMED + REVIEW
_SCANNED = (CONFIRMED, REVIEW, BENIGN, INCONCLUSIVE)
_FINDINGS_TABLE = frozenset({CONFIRMED, REVIEW})


def enabled() -> bool:
    return os.environ.get(
        "SIFT_ENTITY_DISPOSITION_CONSISTENCY", "").strip().lower() in (
        "1", "true", "yes", "on")


def _finding_id(f) -> str:
    return str((f or {}).get("finding_id") or (f or {}).get("id") or "")


def _binary_ids(f) -> set:
    """Strong, UNIQUE binary identities -- the file hash (sha1/sha256/md5) and a
    fully-qualified exe path -- so two findings about the SAME binary reconcile even
    when one is keyed by PID and the other only by hash/path (a finding cited the
    binary by PID while its twin cited it by path+hash, so they shared no identity and
    ended up in different tables). Only these unique keys are used -- never a bare
    basename or a title token, which could
    over-link unrelated findings in a table-moving pass. Reuses confirmed_dedup's
    exact hash/path extractors so identity stays consistent with the dedup layer."""
    ids: set = set()
    try:
        from sift_sentinel.analysis.confirmed_dedup import _HASH_RE, _EXE_RE, _norm_path
    except Exception:                       # pragma: no cover - keep the pass resilient
        return ids
    for c in (f.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for hk in ("sha1", "sha256", "md5", "hash"):
            v = c.get(hk)
            if isinstance(v, str) and _HASH_RE.match(v.strip()):
                ids.add("h:" + v.strip().lower())
        for pk in ("value", "path", "artifact", "file"):
            v = c.get(pk)
            if isinstance(v, str) and _EXE_RE.search(v.strip()):
                np = _norm_path(v)
                if "/" in np:                  # a real path, never a bare basename
                    ids.add("p:" + np)
    return ids


def _entity_ids(f) -> set:
    """The stable identity set for a finding: every subject PID (claim.pid + the
    'PID <n>' tokens in the title/detail, so a finding keyed on the PARENT pid still
    recovers the subject), plus registry-key, event, and same-binary (hash / full
    path) identities."""
    ids = {"proc:" + p for p in _entity_pids(f)}
    ids |= _registry_keys(f)
    ids |= _event_identity_keys(f)
    ids |= _binary_ids(f)            # same-binary reconcile by hash / fully-qualified path
    return ids


def _has_own_malice(f, evidence_db) -> bool:
    """The finding carries its OWN authoritative malice -- an explicit ReAct
    malicious verdict or a non-weak-alone malicious-semantic signal. (Severity is
    deliberately NOT used: it is the pre-ReAct heuristic that fires on legit tools.)"""
    try:
        return bool(_malicious_verdict(f) or has_independent_malice(f, evidence_db))
    except Exception:
        return False


def _is_strong_benign(f) -> bool:
    try:
        return bool(_is_adjudicated_benign(f))
    except Exception:
        return False


def apply_entity_disposition_consistency(buckets, evidence_db=None):
    """In-place-safe: returns (new_buckets, ledger). Resolves every entity that is
    SPLIT across the findings table and the benign table to one table. Never demotes
    a confirmed finding; never pulls a finding with its own malice to benign."""
    if not isinstance(buckets, dict):
        return buckets, []

    out = {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}

    # entity -> list of (bucket, finding)
    ent2items: dict = {}
    for bk in _SCANNED:
        for f in (out.get(bk) or []):
            if not isinstance(f, dict):
                continue
            for ent in _entity_ids(f):
                ent2items.setdefault(ent, []).append((bk, f))

    # decide a target bucket per finding-id (a finding may touch several entities;
    # benign-win is the strongest pull, then review; confirmed is never demoted).
    fid_target: dict = {}
    fid_reason: dict = {}

    def _propose(fid, target, reason):
        # precedence so multi-entity findings resolve deterministically:
        # BENIGN only sticks if nothing later asks for the findings table.
        prev = fid_target.get(fid)
        if prev is None or prev == BENIGN:   # REVIEW overrides a prior BENIGN proposal
            if prev != target:
                fid_target[fid] = target
                fid_reason[fid] = reason

    for ent, items in ent2items.items():
        present = {bk for bk, _ in items}
        # only act on a genuine SPLIT between the benign table and a findings-table row
        if not (BENIGN in present and (present & _FINDINGS_TABLE)):
            continue
        strong_malice = any(_has_own_malice(f, evidence_db) for _, f in items)
        strong_benign = any(_is_strong_benign(f) for _, f in items)

        if strong_benign and not strong_malice:
            # benign wins: pull surfaced siblings WITHOUT own malice into benign
            for bk, f in items:
                if bk in _FINDINGS_TABLE and bk != CONFIRMED and not _has_own_malice(f, evidence_db):
                    _propose(_finding_id(f), BENIGN,
                             "consistency:entity_strong_benign_wins[%s]" % ent)
                elif bk == CONFIRMED and not _has_own_malice(f, evidence_db):
                    # a confirmed twin of a strong-benign entity with no own malice
                    # is an over-confirm; route to review, never silently to benign
                    _propose(_finding_id(f), REVIEW,
                             "consistency:confirmed_over_strong_benign_to_review[%s]" % ent)
        else:
            # strong malice present, OR both weak: the entity belongs in the findings
            # table. Pull weak benign siblings UP to review (recall-safe; never benign,
            # never confirmed). Strong-benign and confirmed members are left untouched.
            for bk, f in items:
                if bk in (BENIGN, INCONCLUSIVE) and not _is_strong_benign(f):
                    _propose(_finding_id(f), REVIEW,
                             "consistency:entity_findings_table_pulls_weak_benign[%s]" % ent)

    if not fid_target:
        return out, []

    # apply moves
    ledger = []
    for bk in _SCANNED:
        kept = []
        for f in (out.get(bk) or []):
            if not isinstance(f, dict):
                kept.append(f)
                continue
            fid = _finding_id(f)
            tgt = fid_target.get(fid)
            if tgt is None or tgt == bk:
                kept.append(f)
                continue
            f.setdefault("disposition_reasons", []).append(fid_reason.get(fid, ""))
            f["_entity_consistency_moved"] = {"from": bk, "to": tgt}
            f["final_disposition"] = tgt
            out.setdefault(tgt, []).append(f)
            ledger.append({"finding_id": fid, "from": bk, "to": tgt,
                           "reason": fid_reason.get(fid, "")})
        out[bk] = kept
    return out, ledger


__all__ = ["apply_entity_disposition_consistency", "enabled"]
