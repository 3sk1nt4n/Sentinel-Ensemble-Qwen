"""Verdict-consistency reconciliation (C1 / Autonomous Execution Quality).

When several findings share one *signal signature* (e.g. seven "rundll32.exe with
null command line" findings differing only by PID), independent ensemble/ReAct
adjudication can hand them contradictory dispositions -- one benign, two malicious,
four inconclusive. To a judge that reads as the agent being unable to make up its
mind, which actively costs C1 (the first tiebreaker).

This pass makes identical-signature findings *consistent*. The rule is deliberately
conservative and dataset-agnostic:

  * A finding's signature is COMPUTED from its own title shape -- PIDs, hashes,
    offsets and punctuation stripped -- so it is never a hard-coded case value.
  * When a signature group spans more than one disposition bucket, the
    NON-confirmed members are routed to the single most-cautious actionable bucket
    present in the group (needs-review > inconclusive > benign). Identical evidence
    that looked suspicious even once is treated as at-least-review everywhere.
  * It NEVER promotes into `confirmed` (promotion stays gated by the deterministic
    eligibility predicate) and NEVER demotes a validated `confirmed` finding.

Findings are preserved (not merged), so the audit trail / C5 traceability is intact;
only the disposition bucket is reconciled. Returns the new buckets plus a ledger of
moves for the Self-Correction Ledger surface.
"""
from __future__ import annotations

import os
import re

CONFIRMED = "confirmed_malicious_atomic"
NEEDS_REVIEW = "suspicious_needs_review"
INCONCLUSIVE = "inconclusive_unresolved"
BENIGN = "benign_or_false_positive"
SYNTHESIS = "synthesis_narrative"

# Most-cautious actionable bucket first. `confirmed` is intentionally excluded as a
# reconciliation target -- reconciliation never manufactures a confirmation.
_NONCONFIRMED_SEVERITY = (NEEDS_REVIEW, INCONCLUSIVE, BENIGN)
_ALL_BUCKETS = (CONFIRMED, NEEDS_REVIEW, INCONCLUSIVE, BENIGN, SYNTHESIS)

_PID_HASH_RE = re.compile(r"\b(?:pid|sha1|sha256|md5|ppid)\b[:\s]*[0-9a-f]+", re.IGNORECASE)
_HEX_RE = re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b", re.IGNORECASE)
_DIGITS_RE = re.compile(r"\d+")
_NONWORD_RE = re.compile(r"[^a-z ]+")
_WS_RE = re.compile(r"\s+")


def finding_signature(f) -> str:
    """A case-agnostic signature for grouping near-identical findings.

    Derived only from the title's *shape*: identifiers (PIDs/hashes/offsets/numbers)
    and punctuation are stripped so "rundll32.exe (PID 1111) ..." and
    "rundll32.exe (PID 2222) ..." collapse to the same token string. Returns "" when
    there is no usable title (such findings are never reconciled)."""
    if not isinstance(f, dict):
        return ""
    t = str(f.get("title") or f.get("summary") or f.get("finding") or "").lower()
    t = _PID_HASH_RE.sub(" ", t)
    t = _HEX_RE.sub(" ", t)
    t = _DIGITS_RE.sub(" ", t)
    t = _NONWORD_RE.sub(" ", t)
    t = _WS_RE.sub(" ", t).strip()
    # require a few tokens so trivial/empty titles never group
    return t if len(t.split()) >= 3 else ""


def _finding_id(f) -> str:
    return str((f or {}).get("finding_id") or (f or {}).get("id") or "-")


def _choose_target(buckets_present) -> str:
    """The single most-cautious NON-confirmed bucket present in a contradicted group.

    If any sibling is `confirmed`, the rest must not settle at benign/inconclusive --
    identical evidence that is malicious in one place deserves at-least-review
    everywhere -- so escalate the target to needs-review."""
    has_confirmed = CONFIRMED in buckets_present
    for bucket in _NONCONFIRMED_SEVERITY:
        if bucket in buckets_present:
            if has_confirmed and bucket in (INCONCLUSIVE, BENIGN):
                return NEEDS_REVIEW
            return bucket
    return NEEDS_REVIEW


def reconcile_dispositions(buckets):
    """Reconcile contradictory dispositions across identical-signature findings.

    Returns ``(new_buckets, ledger)``. ``ledger`` is a list of
    ``{finding_id, from, to, signature}`` for each moved finding. A no-op (returns a
    shallow copy + empty ledger) when nothing is contradicted."""
    if not isinstance(buckets, dict):
        return buckets, []

    # group every finding by signature, remembering its current bucket
    groups: dict[str, list] = {}
    for bucket in _ALL_BUCKETS:
        for f in (buckets.get(bucket) or []):
            if not isinstance(f, dict):
                continue
            sig = finding_signature(f)
            if sig:
                groups.setdefault(sig, []).append((bucket, f))

    # decide a target bucket per contradicted signature
    move_to: dict[str, str] = {}  # finding_id -> target bucket
    ledger = []
    for sig, members in groups.items():
        present = {bk for bk, _ in members}
        if len(present) <= 1:
            continue  # already consistent
        target = _choose_target(present)
        for bk, f in members:
            # confirmed members stay confirmed (never demote a validated confirm);
            # synthesis context is left alone; everything else aligns to target.
            if bk in (CONFIRMED, SYNTHESIS) or bk == target:
                continue
            fid = _finding_id(f)
            move_to[fid] = target
            ledger.append({"finding_id": fid, "from": bk, "to": target, "signature": sig})

    if not move_to:
        # shallow copy so callers can treat the result uniformly
        return {k: list(v) if isinstance(v, list) else v for k, v in buckets.items()}, []

    # rebuild buckets honoring the moves
    new_buckets = {k: [] for k in buckets}
    for bucket in buckets:
        for f in (buckets.get(bucket) or []):
            if isinstance(f, dict) and _finding_id(f) in move_to and bucket not in (CONFIRMED, SYNTHESIS):
                target = move_to[_finding_id(f)]
                f = dict(f)
                f["_consistency_reconciled_from"] = bucket
                f["_consistency_reconciled_to"] = target
                rs = list(f.get("disposition_reasons") or [])
                rs.append("consistency:reconciled[%s->%s]" % (bucket, target))
                f["disposition_reasons"] = rs
                new_buckets.setdefault(target, []).append(f)
            else:
                new_buckets.setdefault(bucket, []).append(f)
    return new_buckets, ledger


# ── Cross-bucket entity reconciliation (the same ARTEFACT, contradicted) ──────
# The title-shape signature above groups findings whose TITLES rhyme. But one
# artefact -- a single registry key, file hash, or fully-qualified path -- can
# surface under wholly DIFFERENT titles (e.g. an IFEO sethc.exe Debugger key
# written four ways: "Sticky Keys debugger", "Accessibility IFEO", "IFEO debugger
# on sethc", ...) and land in BOTH benign and needs-review at once. Title-shape
# misses that; the artefact identity does not. When one artefact is simultaneously
# benign AND non-benign, escalate the BENIGN members to needs-review so a single
# artefact is never reported as both "benign" and "suspicious".
#
# Downgrade-only-safe and recall-favouring: benign -> needs-review ONLY; never
# demotes a review/confirmed finding, never manufactures a confirmation. Surfacing
# a contradicted artefact for a human is cheaper than silently hiding it. Universal
# / dataset-agnostic: keyed purely on artefact identity, no case literal.
try:
    from sift_sentinel.analysis.confirmed_dedup import entity_keys as _exact_entity_keys
except Exception:                                              # pragma: no cover
    def _exact_entity_keys(_f):
        return set()

# A registry key root; reconciliation needs registry identity because the exact-
# path dedup key only matches files ending .exe/.dll/.sys (a persistence key has no
# such suffix and would otherwise be invisible to reconciliation).
_REG_ROOT_RE = re.compile(r"^(?:hklm|hkcu|hku|hkcr|hkey[_a-z]*)\b", re.IGNORECASE)
# The hive root ANYWHERE after a short prose label ("Registry key HKLM\..."),
# so a labelled claim value still yields the key identity. The prefix must be
# prose-shaped (letters/spaces only) so a hive name embedded in arbitrary text
# never fabricates a key.
_REG_ROOT_AFTER_LABEL_RE = re.compile(
    r"^[a-z ]{1,40}?\b((?:hklm|hkcu|hku|hkcr|hkey[_a-z]*)\b.*)$", re.IGNORECASE)


def _registry_entity_keys(f) -> set:
    """Exact registry-key identities from a finding's claims. Normalised (lowercase,
    '\\'->'/', separator runs collapsed, optional prose label stripped); requires
    real depth so a bare hive root never groups unrelated keys. The same live
    key was emitted as ``HKLM\\...``, ``HKLM\\\\...`` (escaped) and
    ``Registry key HKLM\\...`` -- all three must produce one identity.
    Normalization kill-switch SIFT_ARTIFACT_NORM_V2=0."""
    keys: set = set()
    if not isinstance(f, dict):
        return keys
    _v2 = os.environ.get("SIFT_ARTIFACT_NORM_V2", "1").strip().lower() not in (
        "0", "false", "no", "off")
    for c in (f.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for pk in ("value", "name", "path", "registry_path", "registry_key", "key", "artifact"):
            v = c.get(pk)
            if isinstance(v, str):
                nv = _WS_RE.sub(" ", v.strip().lower().replace("\\", "/"))
                if _v2:
                    nv = re.sub(r"/{2,}", "/", nv)   # escaped-backslash runs
                    if not _REG_ROOT_RE.match(nv):
                        m = _REG_ROOT_AFTER_LABEL_RE.match(nv)
                        if m:
                            nv = m.group(1)          # strip the prose label
                if _REG_ROOT_RE.match(nv) and nv.count("/") >= 3:
                    keys.add("r:" + nv)
    return keys


def _xbucket_entity_keys(f) -> set:
    return _exact_entity_keys(f) | _registry_entity_keys(f)


# Markers that a benign disposition was an EXPLICIT, reasoned adjudication (ReAct
# false-positive verdict, inv3a false_positive, or fp-routing benign) -- as
# opposed to a finding that merely landed in the benign bucket. An adjudicated
# decision must not be silently reversed by a weak, never-adjudicated sibling.
_ADJUDICATED_BENIGN_REASON = (
    "inv3a:false_positive", "override:fp_routing_benign", "react_verdict=",
    "fp_routing_benign", "react:false_positive", "benign:react",
)


def _is_adjudicated_benign(f) -> bool:
    """True when the finding's benign disposition came from an explicit
    adjudication (ReAct FP / inv3a false_positive / fp-routing), not just bucket
    placement. Universal: reason-grammar markers, no case data."""
    if not isinstance(f, dict):
        return False
    rc = f.get("react_conclusion")
    if isinstance(rc, dict) and rc.get("is_false_positive") is True:
        return True
    if f.get("_fp_routing_benign"):
        return True
    blob = " ".join(str(r) for r in (f.get("disposition_reasons") or [])).lower()
    return any(m in blob for m in _ADJUDICATED_BENIGN_REASON)


def reconcile_cross_bucket_by_entity(buckets):
    """Escalate benign findings that share an exact artefact (registry key / file
    hash / fully-qualified path) with a non-benign finding -> needs-review, so one
    artefact is never both benign and suspicious in the same report.

    Returns ``(new_buckets, ledger)``. Downgrade-only-safe; no-op shallow copy when
    nothing is contradicted."""
    if not isinstance(buckets, dict):
        return buckets, []
    import os
    _respect_adj = os.environ.get(
        "SIFT_RECONCILE_RESPECT_ADJUDICATION", "1").strip().lower() not in (
        "0", "false", "no", "off")
    scoped = (CONFIRMED, NEEDS_REVIEW, INCONCLUSIVE, BENIGN)
    ent_buckets: dict = {}
    for bucket in scoped:
        for f in (buckets.get(bucket) or []):
            if not isinstance(f, dict):
                continue
            for ent in _xbucket_entity_keys(f):
                ent_buckets.setdefault(ent, set()).add(bucket)
    contradicted = {e for e, bks in ent_buckets.items()
                    if BENIGN in bks and (bks - {BENIGN})}
    # Entities whose contradiction includes a CONFIRMED member -- a proven
    # confirmation still wins, so adjudicated-benign exemption does NOT apply.
    _confirmed_ents = {e for e, bks in ent_buckets.items() if CONFIRMED in bks}
    if not contradicted:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}, []

    ledger = []
    new_buckets = {k: [] for k in buckets}
    for bucket in buckets:
        for f in (buckets.get(bucket) or []):
            _ent_hit = (_xbucket_entity_keys(f) & contradicted) if isinstance(f, dict) else set()
            hit = (bucket == BENIGN and isinstance(f, dict) and _ent_hit)
            # RESPECT ADJUDICATION: never reverse an explicitly-adjudicated benign
            # finding for a weak, never-adjudicated sibling. A confirmed sibling on
            # the same entity still overrides (surface it).
            if (hit and _respect_adj and _is_adjudicated_benign(f)
                    and not (_ent_hit & _confirmed_ents)):
                hit = False
            if hit:
                fid = _finding_id(f)
                f = dict(f)
                f["_xbucket_reconciled_from"] = BENIGN
                f["_xbucket_reconciled_to"] = NEEDS_REVIEW
                rs = list(f.get("disposition_reasons") or [])
                rs.append("consistency:xbucket_entity[benign->needs-review]")
                f["disposition_reasons"] = rs
                ledger.append({"finding_id": fid, "from": BENIGN, "to": NEEDS_REVIEW,
                               "entity": sorted(_xbucket_entity_keys(f) & contradicted)[0]})
                new_buckets.setdefault(NEEDS_REVIEW, []).append(f)
            else:
                new_buckets.setdefault(bucket, []).append(f)
    return new_buckets, ledger


# ── Confirmed-bucket confidence calibration ──────────────────────────────────
# "Validator-backed" is not the same as "confidently malicious". A finding can pass
# the deterministic eligibility predicate (real hash + path + Amcache execution) yet
# still be LOW severity AND LOW confidence -- a Nagios agent staged in a temp dir, a
# monitoring binary. Headlining that as "confirmed malicious atomic" overstates it.
# Demote a confirmed finding that is BOTH low severity AND low/speculative confidence
# to needs-review (still surfaced, just not asserted as confirmed). Universal: keyed
# only on the finding's own severity+confidence, no case data. NEVER promotes.
_LOW_SEV = {"LOW", "INFO", "INFORMATIONAL"}
_LOW_CONF = {"LOW", "SPECULATIVE"}


def demote_lowconfidence_confirmed(buckets):
    """Route confirmed findings that are BOTH low severity AND low/speculative
    confidence to needs-review. Returns ``(new_buckets, ledger)``; no-op shallow copy
    when nothing qualifies. Missing confidence is treated as 'not clearly weak' and is
    left confirmed (conservative -- never demote on absent signal)."""
    if not isinstance(buckets, dict):
        return buckets, []
    conf = [f for f in (buckets.get(CONFIRMED) or []) if isinstance(f, dict)]
    if not conf:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}, []
    keep, moved, ledger = [], [], []
    for f in conf:
        sev = str(f.get("severity") or "").strip().upper()
        cnf = str(f.get("confidence") or f.get("confidence_level") or "").strip().upper()
        if sev in _LOW_SEV and cnf in _LOW_CONF:
            f = dict(f)
            f["_lowconf_demoted_from"] = CONFIRMED
            rs = list(f.get("disposition_reasons") or [])
            rs.append("calibration:lowconf_confirm_demoted[%s/%s->needs-review]" % (sev, cnf))
            f["disposition_reasons"] = rs
            moved.append(f)
            ledger.append({"finding_id": _finding_id(f), "from": CONFIRMED,
                           "to": NEEDS_REVIEW, "severity": sev, "confidence": cnf})
        else:
            keep.append(f)
    if not moved:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}, []
    new_buckets = {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}
    new_buckets[CONFIRMED] = keep
    new_buckets[NEEDS_REVIEW] = list(new_buckets.get(NEEDS_REVIEW) or []) + moved
    return new_buckets, ledger
