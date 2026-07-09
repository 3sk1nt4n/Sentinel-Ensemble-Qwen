"""Inv3a finalization pass - Step 13AA, the consolidated replacement for the
per-finding self-correction (SC) loop.

WHY this exists
---------------
Measured on a real run (2026-06-07): the generative SC loop spent ~285K input
tokens across 12 calls (~45% of the whole run's input) and produced
``corrected=0``. The recoverable cases are already handled deterministically
upstream (claim re-bind, ReAct settle, the JIT-RWX gate), so SC is left burning
tokens on unfixable junk that it then contains anyway.

Inv3a swaps that for ONE discriminative triage call over the AMBIGUOUS findings,
run just before Inv4 so the customer table is FP-swept and finalized.

SAFETY CONTRACT (preserves defense-layer 7 "code checks AI, not AI checks AI")
-----------------------------------------------------------------------------
  * Adjudicates ONLY ``suspicious_needs_review`` + ``inconclusive_unresolved``.
    ``confirmed_malicious_atomic`` and clear benign are never re-judged.
  * Downgrade / reclassify / escalate-to-review only.  Promotion INTO
    ``confirmed_malicious_atomic`` requires the finding to be ALREADY
    deterministically eligible (``eligibility_fn``) - the AI only breaks ties
    among code-permitted buckets; it never manufactures a confirmation.  With no
    ``eligibility_fn`` promotion is impossible (fully fail-closed).
  * Fail-closed: an unparseable / missing / out-of-vocabulary verdict keeps the
    finding in its ORIGINAL bucket.
  * Pure: the AI call is injected (``adjudicator_fn``), so the whole pass is unit
    testable with a fake.  Input buckets are never mutated.

UNIVERSAL: keys on bucket names + the four OS-agnostic disposition tokens + an
eligibility predicate.  No case data - works on any evidence set.
"""
from __future__ import annotations

import copy
import json

# Canonical disposition buckets (mirror analysis.disposition.BUCKET_*; the names
# are locked by the project's disposition taxonomy).
BUCKET_CONFIRMED = "confirmed_malicious_atomic"
BUCKET_SUSPICIOUS = "suspicious_needs_review"
BUCKET_BENIGN = "benign_or_false_positive"
BUCKET_INCONCLUSIVE = "inconclusive_unresolved"
BUCKET_SYNTHESIS = "synthesis_narrative"

# The NON-TERMINAL tiers inv3a may re-judge: needs-review, inconclusive, and the
# synthesis/context tier (real behavioural findings parked as narrative -- egress,
# staging, anti-forensic download -- that should get a recovery look toward
# needs-review/confirmed). The TERMINAL tiers are deliberately excluded: confirmed
# (already proven) and benign_or_false_positive (evidence-cleared FPs -- re-judging
# them would undo the ReAct FP discipline). Promotion into confirmed stays gated by
# the eligibility predicate, so widening the sweep never manufactures a confirmation.
AMBIGUOUS_BUCKETS = (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE, BUCKET_SYNTHESIS)

# R1C floored-benign sweep: a LOW/info finding buried by an AUTOMATED weakness
# floor (disposition reason prefix ``benign:`` -- one_claim_weak /
# uncorroborated_weak) was never seen by ANY adjudicator -- no ReAct verdict,
# no validated zero-FP gate. inv3a re-judges those too, so a silently buried
# true positive gets a second look. ``override:``-class burials (ReAct benign,
# JIT-RWX, tool-status noise, fp-routing) WERE adjudicated/validated and stay
# terminal, as do CRITICAL/HIGH rows (operator rule -- those classes never
# floor-bury in practice). Keyed on the pipeline's own reason grammar +
# severity rank only. Kill-switch: SIFT_INV3A_SWEEP_FLOORED=0.
_FLOOR_BENIGN_PREFIX = "benign:"
_CLEARED_OVERRIDE_PREFIX = "override:"
_FLOOR_SWEEP_EXCLUDED_SEVERITIES = ("CRITICAL", "HIGH")


def _floored_sweep_enabled() -> bool:
    import os
    return os.environ.get("SIFT_INV3A_SWEEP_FLOORED", "1").strip().lower() \
        not in ("0", "false", "no", "off")


def _is_floor_buried_benign(f) -> bool:
    if not isinstance(f, dict):
        return False
    if str(f.get("severity") or "").upper() in _FLOOR_SWEEP_EXCLUDED_SEVERITIES:
        return False
    reasons = [str(r) for r in (f.get("disposition_reasons") or [])]
    if any(r.startswith(_CLEARED_OVERRIDE_PREFIX) for r in reasons):
        return False
    return any(r.startswith(_FLOOR_BENIGN_PREFIX) for r in reasons)

# The four verdict tokens the adjudicator may emit, and where each routes.
_DISP_TO_BUCKET = {
    "false_positive": BUCKET_BENIGN,
    "needs_review": BUCKET_SUSPICIOUS,
    "confirmed": BUCKET_CONFIRMED,
    "inconclusive": BUCKET_INCONCLUSIVE,
}
_DISPOSITION_TOKENS = frozenset(_DISP_TO_BUCKET)


def _finding_id(f) -> str:
    if isinstance(f, dict):
        for k in ("finding_id", "id", "fid"):
            v = f.get(k)
            if v:
                return str(v)
    return ""


def _review_all_enabled() -> bool:
    import os
    return os.environ.get("SIFT_INV3A_REVIEW_ALL", "").strip().lower() in (
        "1", "true", "yes", "on")


def select_ambiguous(buckets: dict) -> list:
    """The findings inv3a may adjudicate. By default the non-terminal tiers
    (needs-review, inconclusive, synthesis/context); confirmed (proven) and benign
    (cleared FPs) are excluded so the pass can only RECOVER, never re-litigate.

    SIFT_INV3A_REVIEW_ALL=1 -> inv3a SEES every finding (confirmed + benign too), so
    one AI pass gives a final TP/FP verdict on ALL of them. Proven evil is still
    protected: a deterministic-confirm finding cannot be DEMOTED out of confirmed by
    the model (the floor in finalize_dispositions), and promotion stays
    eligibility-gated -- so 'review all' widens visibility without letting a bad
    sample bury a confirmed detection (keeps it reproducible across PCs)."""
    out = []
    scan = AMBIGUOUS_BUCKETS
    if _review_all_enabled():
        scan = (BUCKET_CONFIRMED, BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE,
                BUCKET_SYNTHESIS, BUCKET_BENIGN)
    for bucket in scan:
        for f in (buckets.get(bucket) or []):
            if isinstance(f, dict):
                out.append(f)
    # R1C: floor-buried benign rows (never adjudicated) get the second look
    # (covered already when review-all includes BUCKET_BENIGN).
    if not _review_all_enabled() and _floored_sweep_enabled():
        for f in (buckets.get(BUCKET_BENIGN) or []):
            if _is_floor_buried_benign(f):
                out.append(f)
    return out


def prepare_blocked_for_review(blocked, existing_ids=()) -> list:
    """Normalize validator-blocked / rejected findings into inconclusive-bucket
    entries so inv3a's final sweep gives them a CROSS-CHECK instead of letting
    them be silently dropped (honest failure > wrong answer).

    ``blocked`` may be a list of finding dicts OR (finding_dict, error_str)
    tuples (the Step-10 validator shape). Entries already present in a bucket
    (``existing_ids`` -- e.g. a ReAct-settled finding) are skipped. A
    ``gate:validation_blocked`` reason is stamped so disposition/render know the
    origin. Promotion stays gated downstream by eligibility_fn -- a claimless
    finding can never be fabricated into confirmed. Universal: structural, no
    case data. Kill-switch SIFT_INV3A_REVIEW_BLOCKED=0 -> [] (legacy drop)."""
    import os
    if os.environ.get("SIFT_INV3A_REVIEW_BLOCKED", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return []
    seen = {str(i) for i in (existing_ids or ())}
    out: list = []
    for item in (blocked or []):
        f = item[0] if isinstance(item, (list, tuple)) and item else item
        if not isinstance(f, dict):
            continue
        fid = _finding_id(f)
        if not fid or fid in seen:
            continue
        seen.add(fid)
        g = dict(f)
        rs = list(g.get("disposition_reasons") or [])
        rs.append("gate:validation_blocked_deferred_to_inv3a")
        g["disposition_reasons"] = rs
        g["_inv3a_blocked_review"] = True
        out.append(g)
    return out


def build_xref_profiles(findings: list, evidence_db=None, _resolver=None) -> dict:
    """D8-A: deterministic cross-reference profile per finding, for the prompt.

    CASE-NEUTRAL BY CONSTRUCTION: only integer counts, an artifact-domain count,
    a weak/strong signal split and the parked-reason GRAMMAR PREFIX -- never a
    filename, path, tool name or any case value. Reuses the confidence module's
    tool->artifact-type map and the disposition weak-alone taxonomy.
    Returns {finding_id: {tools, domains, weak, strong, parked}}."""
    try:
        from sift_sentinel.analysis.confidence import count_artifact_types
    except Exception:
        def count_artifact_types(_t):
            return 0
    if _resolver is None:
        try:
            from sift_sentinel.analysis.malicious_semantics import (
                has_malicious_semantic as _resolver)
        except Exception:
            _resolver = None
    try:
        from sift_sentinel.analysis.disposition import (
            _WEAK_ALONE_SEMANTIC_SIGNALS as _WEAK)
    except Exception:
        _WEAK = frozenset()
    out: dict = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fid = _finding_id(f)
        tools = [str(t) for t in (f.get("source_tools") or []) if isinstance(t, str)]
        weak = strong = 0
        if _resolver is not None:
            try:
                _has, _signals = _resolver(f, evidence_db)
                fired = {str(s) for s in (_signals or [])} if _has else set()
                weak = len(fired & _WEAK)
                strong = len(fired - _WEAK)
            except Exception:
                pass
        parked = ""
        for r in (f.get("disposition_reasons") or []):
            r = str(r)
            if r.startswith(("gate:", "benign:", "override:")):
                parked = r.split("[", 1)[0].split("=", 1)[0][:60]
                break
        out[fid] = {"tools": len(tools),
                    "domains": count_artifact_types(tools),
                    "weak": weak, "strong": strong, "parked": parked}
    return out


def build_inv3a_prompt(findings: list, profiles=None) -> str:
    """Case-neutral adjudication prompt: lists the ambiguous findings with a
    compact evidence digest and asks for one JSON verdict each. No case data.
    With ``profiles`` (build_xref_profiles), each finding also carries its
    deterministic cross-reference so the model breaks ties WITH evidence."""
    lines = [
        "You are finalizing a forensic findings table before the incident report.",
        "These findings are currently in the REVIEW / INCONCLUSIVE tiers. For EACH",
        "one, output its final disposition based ONLY on the evidence shown below.",
        "",
        "Dispositions:",
        "  false_positive - benign / expected OS behavior, or a single uncorroborated",
        "                   weak signal (e.g. JIT/.NET RWX memory, signed-binary noise,",
        "                   a baseline registry value).",
        "  needs_review   - suspicious but not proven; a human analyst should examine it.",
        "  confirmed      - strong, corroborated, multi-source malicious evidence.",
        "  inconclusive   - insufficient evidence either way.",
        "",
        "Be conservative: choose 'confirmed' ONLY when the evidence is corroborated",
        "across multiple independent sources. When unsure, prefer needs_review.",
    ]
    if profiles:
        lines += [
            "",
            "Each finding carries a deterministic cross-reference (xref): tools = how",
            "many independent tools cite it, domains = distinct artifact classes",
            "(memory/disk/logs...), weak/strong = its signal split, parked = why the",
            "pipeline left it here. Use it: multi-tool multi-domain corroboration with",
            "a strong signal supports escalation; a single weak uncorroborated signal",
            "supports false_positive; identical xref + same entity suggests a duplicate.",
        ]
    lines += [
        "",
        "Return ONLY a JSON object, exactly one verdict per finding:",
        '  {"verdicts": [{"finding_id": "<id>", "disposition": "<one of the four>",',
        '                 "reason": "<max 15 words>"}]}',
        "Keep every reason under 15 words and escape backslashes in JSON",
        "strings (write \\\\ for a Windows path separator).",
        "",
        "Findings:",
    ]
    for f in findings:
        desc = str(f.get("description") or f.get("artifact") or "").strip().replace("\n", " ")[:300]
        tools = f.get("source_tools") or f.get("tools") or f.get("tool_hits") or []
        if isinstance(tools, str):
            tools = [tools]
        tline = ", ".join(str(t) for t in list(tools)[:8]) if tools else "-"
        row = '- finding_id=%s | tools=[%s] | evidence="%s"' % (_finding_id(f), tline, desc)
        prof = (profiles or {}).get(_finding_id(f)) if profiles else None
        if prof:
            row += " | xref: tools=%d domains=%d weak=%d strong=%d parked=%s" % (
                prof.get("tools", 0), prof.get("domains", 0),
                prof.get("weak", 0), prof.get("strong", 0),
                prof.get("parked") or "-")
        lines.append(row)
    return "\n".join(lines)


# Stray-backslash repair (an unescaped Windows path in a model string) lives in the
# shared json_repair module so EVERY AI call uses the same logic. Kept under the local
# name for this module's tests.
from sift_sentinel.json_repair import repair_json_escapes as _repair_json_escapes


def _extract_json_blob(text: str):
    """Tolerant JSON extraction: whole string first, else the widest [...] span, else the
    widest {...} span (handles code fences / surrounding prose). Each candidate is tried
    as-is AND with stray backslashes repaired -- so an unescaped Windows path in a
    model-written ``reason`` can no longer drop every verdict."""
    candidates = [text]
    for open_c, close_c in (("[", "]"), ("{", "}")):
        start = text.find(open_c)
        end = text.rfind(close_c)
        if start != -1 and end != -1 and end > start:
            candidates.append(text[start:end + 1])
    for cand in candidates:
        try:
            return json.loads(cand)
        except Exception:
            try:
                return json.loads(_repair_json_escapes(cand))
            except Exception:
                continue
    return None


def _coerce_to_list(data):
    """Accept a bare verdict array, an object wrapping one (verdicts/results/...),
    or a single verdict object. Returns the verdict list, or None."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("verdicts", "results", "dispositions", "findings", "items"):
            v = data.get(key)
            if isinstance(v, list):
                return v
        if data.get("finding_id") and data.get("disposition"):
            return [data]
    return None


def parse_inv3a_verdicts(text) -> dict:
    """Parse the adjudicator's reply into {finding_id: {disposition, reason}}.
    Accepts a bare array, an object-wrapped array, or a single verdict object.
    Out-of-vocabulary dispositions are DROPPED (never coerced)."""
    out: dict = {}
    if not isinstance(text, str) or not text.strip():
        return out
    data = _coerce_to_list(_extract_json_blob(text))
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        fid = item.get("finding_id") or item.get("id")
        disp = item.get("disposition") or item.get("verdict")
        if not fid or not isinstance(disp, str):
            continue
        disp = disp.strip().lower()
        if disp not in _DISPOSITION_TOKENS:
            continue
        out[str(fid)] = {"disposition": disp, "reason": str(item.get("reason") or "").strip()}
    return out


# D7: bucket severity rank -- a move to a HIGHER rank is a promotion the
# optional guard may veto; downgrades are never blocked.
_BUCKET_RANK = {
    BUCKET_BENIGN: 0,
    BUCKET_INCONCLUSIVE: 1,
    BUCKET_SYNTHESIS: 1,
    BUCKET_SUSPICIOUS: 2,
    BUCKET_CONFIRMED: 3,
}


def build_jit_rwx_promotion_guard(evidence_db, _resolver=None):
    """D7: promotion guard for the classic JIT/.NET RWX false positive -- a
    finding whose ONLY malicious signal is a single uncorroborated RWX/injection
    must not be PROMOTED by the finalize sweep (downgrade to FP stays allowed).

    Adversarially-adjusted contract:
      * semantics are RE-RESOLVED via disposition.has_malicious_semantic --
        the persisted signal field exists only on confirmed findings, so
        reading it here would be vacuously empty on the ambiguous buckets;
      * fires ONLY when: resolved set non-empty AND weak-alone-only AND exactly
        ONE injection-class source tool AND a weak/uncorroborated floor reason;
      * fail-closed: env flag off / no evidence_db / resolver error => None or
        False (guard inert, finding stays promotable).

    Returns guard_fn(finding) -> bool, or None when disabled/unavailable.
    Universal: signal taxonomy + tool-class + reason grammar, no process-name
    allowlist. Kill-switch SIFT_INV3A_JIT_RWX_GUARD=0.

    DEFAULT ON: live-validated -- a default-flag run on a fresh sample showed
    the exact failure mode this prevents (the finalize sweep promoted four
    single-signal RWX findings in AV/system service processes out of
    inconclusive with verdict 'confirmed'); the synthetic negative tests prove
    a real multi-tool + network injection still promotes."""
    import os
    if os.environ.get("SIFT_INV3A_JIT_RWX_GUARD", "1").strip().lower() not in (
            "1", "true", "yes", "on"):
        return None
    if not evidence_db:
        return None                       # no cross-reference => never block
    if _resolver is None:
        try:
            from sift_sentinel.analysis.malicious_semantics import (
                has_malicious_semantic as _resolver)
        except Exception:
            return None
    try:
        from sift_sentinel.analysis.disposition import (
            _WEAK_ALONE_SEMANTIC_SIGNALS as _WEAK,
            _INJECTION_MEMORY_TOOLS as _INJ)
    except Exception:
        return None

    def _guard(finding) -> bool:
        try:
            has_sem, signals = _resolver(finding, evidence_db)
            fired = {str(s) for s in (signals or [])}
            if not has_sem or not fired:
                return False              # empty set => inert, never vacuously true
            if not fired <= _WEAK:
                return False              # a strong signal is present
            tools = {str(t).strip().lower()
                     for t in (finding.get("source_tools") or [])
                     if isinstance(t, str)}
            if len(tools & _INJ) != 1:
                return False              # multi-tool corroboration (or none)
            reasons = " ".join(
                str(r) for r in (finding.get("disposition_reasons") or [])).lower()
            return ("uncorroborated" in reasons
                    or "rwx_requires_corroboration" in reasons
                    or "weak" in reasons)
        except Exception:
            return False                  # fail-closed: never block on error
    return _guard


def _badge(f: dict, src: str, dest: str, disposition: str, reason: str) -> None:
    """Stamp the AI-Self-Corrected markers the customer table renders."""
    f["self_corrected"] = True
    f["_ai_finalize_from"] = src
    f["_ai_finalize_to"] = dest
    # Keep the disposition field consistent with the bucket the finding is moved
    # INTO. Without this, a finding 13AA moves OUT of benign (e.g. benign ->
    # needs-review) keeps its stale pre-move final_disposition, and downstream
    # consumers (the FP/benign display) re-read that stale benign marker and
    # mis-render an escalated finding as a false positive. Universal: keyed on the
    # move's destination bucket, never case data.
    f["final_disposition"] = dest
    f["self_correction"] = {
        "applied": True,
        "status": "finalized",
        "by": "inv3a",
        "disposition": disposition,
        "from": src,
        "to": dest,
        "reason": reason,
    }
    rs = list(f.get("disposition_reasons") or [])
    rs.append("inv3a:%s:%s" % (disposition, (reason or "")[:120]))
    f["disposition_reasons"] = rs


def finalize_dispositions(
    buckets: dict,
    adjudicator_fn,
    *,
    eligibility_fn=None,
    max_findings: int = 80,
    verdicts_sink=None,
    promotion_guard_fn=None,
    xref_profiles_fn=None,
):
    """Run the inv3a finalization pass.

    Args:
        buckets:        the disposition buckets dict (NOT mutated).
        adjudicator_fn: callable(prompt: str) -> str, the injected AI call.
        eligibility_fn: optional callable(finding) -> bool gating promotion into
                        confirmed_malicious_atomic. Absent => no promotion.
        max_findings:   adjudicate at most this many ambiguous findings; any
                        beyond stay in place (fail-closed).
        promotion_guard_fn: optional callable(finding) -> bool; True vetoes any
                        move to a HIGHER-rank bucket (D7 JIT-RWX guard).
                        Downgrades are never blocked. None => legacy behavior.
        xref_profiles_fn: optional callable(findings) -> {fid: profile} (D8-A,
                        build_xref_profiles); enriches the prompt with the
                        deterministic cross-reference. None => legacy prompt.

    Returns:
        (new_buckets, ledger) where ledger is a list of
        {finding_id, from, to, disposition, reason} for each MOVED finding.
    """
    new = copy.deepcopy(buckets)
    ledger: list = []
    ambiguous = select_ambiguous(new)
    if not ambiguous:
        return new, ledger
    # The per-call adjudication budget is env-tunable, and a truncation is NEVER
    # silent: if more non-terminal findings need a final cross-check than the cap
    # allows, the dropped tail (the lowest-priority floored rows, appended last by
    # select_ambiguous) stays in its original bucket and the drop is announced --
    # so no SPECULATIVE/LOW finding can be quietly skipped. Universal: a count cap
    # + a log, no case data.
    import os as _os
    _env_cap = _os.environ.get("SIFT_INV3A_MAX_FINDINGS", "").strip()
    if _env_cap.isdigit() and int(_env_cap) > 0:
        max_findings = int(_env_cap)
    if len(ambiguous) > max_findings:
        try:
            print("INV3A_FINALIZE_TRUNCATED considered=%d cap=%d dropped=%d "
                  "(raise SIFT_INV3A_MAX_FINDINGS to review all)"
                  % (len(ambiguous), max_findings, len(ambiguous) - max_findings),
                  flush=True)
        except Exception:
            pass

    _profiles = None
    if xref_profiles_fn is not None:
        try:
            _profiles = xref_profiles_fn(ambiguous[:max_findings])
        except Exception:
            _profiles = None              # enrichment failure => legacy prompt
    prompt = build_inv3a_prompt(ambiguous[:max_findings], profiles=_profiles)
    try:
        text = adjudicator_fn(prompt)
    except Exception:
        return new, ledger  # adjudicator failure => everything stays put
    verdicts = parse_inv3a_verdicts(text or "")
    if not verdicts:
        return new, ledger

    # Decide moves (only for findings that actually change bucket).
    # R1C: the scan must include benign when the floored sweep is on, or a
    # swept floor-buried finding's verdict could never be applied. Safe:
    # verdicts exist only for adjudicated_ids, so untouched benign rows
    # (ReAct-cleared, gate-cleared) are never re-routed.
    if _review_all_enabled():
        # inv3a SEES every finding; the confirmed-demotion floor below keeps proven
        # evil in the findings table regardless of the model's verdict.
        _scan_buckets = (BUCKET_CONFIRMED, BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE,
                         BUCKET_SYNTHESIS, BUCKET_BENIGN)
    else:
        _scan_buckets = AMBIGUOUS_BUCKETS + (
            (BUCKET_BENIGN,) if _floored_sweep_enabled() else ())
    moves: dict = {}  # fid -> (src, dest, disposition, reason, finding_ref)
    adjudicated_ids = {_finding_id(f) for f in ambiguous[:max_findings]}
    for src in _scan_buckets:
        for f in (new.get(src) or []):
            if not isinstance(f, dict):
                continue
            fid = _finding_id(f)
            if fid not in adjudicated_ids:
                continue
            v = verdicts.get(fid)
            if not v:
                continue
            disp = v["disposition"]
            dest = _DISP_TO_BUCKET.get(disp)
            if dest is None:
                continue
            if disp == "confirmed" and not (eligibility_fn and eligibility_fn(f)):
                dest = BUCKET_SUSPICIOUS  # clamp: never fabricate a confirmation
            # FLOOR (review-all): a proven CONFIRMED finding is NEVER demoted out of
            # the findings table by the model -- protects real evil from a bad LLM
            # sample and keeps the confirmed set reproducible across PCs. inv3a still
            # SEES it for context; it just cannot bury it.
            if (src == BUCKET_CONFIRMED
                    and _BUCKET_RANK.get(dest, 0) < _BUCKET_RANK.get(src, 0)):
                continue
            if dest == src:
                continue  # no-op reclassify => not a correction, not badged
            # D7: a guard veto blocks PROMOTION only (higher rank); downgrades
            # (e.g. -> false_positive) always pass through.
            if (promotion_guard_fn is not None
                    and _BUCKET_RANK.get(dest, 0) > _BUCKET_RANK.get(src, 0)
                    and promotion_guard_fn(f)):
                continue
            moves[fid] = (src, dest, disp, v.get("reason", ""), f)

    # Optional sink: surface EVERY adjudicated verdict (moved AND unchanged) with its
    # reason, so the run can show inv3a's full per-finding reasoning to the analyst/judge.
    if isinstance(verdicts_sink, list):
        _cur_bucket: dict = {}
        for _b in _scan_buckets:
            for _x in (new.get(_b) or []):
                if isinstance(_x, dict):
                    _cur_bucket[_finding_id(_x)] = _b
        for _fid in adjudicated_ids:
            _v = verdicts.get(_fid)
            if not _v:
                continue
            if _fid in moves:
                _src, _dest, _disp, _reason, _f = moves[_fid]
                verdicts_sink.append({"finding_id": _fid, "from": _src, "to": _dest,
                                      "disposition": _disp, "reason": _reason, "moved": True})
            else:
                _b = _cur_bucket.get(_fid, "")
                verdicts_sink.append({"finding_id": _fid, "from": _b, "to": _b,
                                      "disposition": _v.get("disposition", ""),
                                      "reason": _v.get("reason", ""), "moved": False})

    if not moves:
        return new, ledger

    # Apply: remove moved findings from their source bucket, badge, re-home.
    moved_ids_by_src: dict = {}
    for fid, (src, _dest, _disp, _r, _f) in moves.items():
        moved_ids_by_src.setdefault(src, set()).add(fid)
    for src, ids in moved_ids_by_src.items():
        new[src] = [
            x for x in (new.get(src) or [])
            if not (isinstance(x, dict) and _finding_id(x) in ids)
        ]

    moved_to: dict = {}
    for fid, (src, dest, disp, reason, f) in moves.items():
        _badge(f, src, dest, disp, reason)
        moved_to.setdefault(dest, []).append(f)
        ledger.append({"finding_id": fid, "from": src, "to": dest,
                       "disposition": disp, "reason": reason})

    for dest, items in moved_to.items():
        new.setdefault(dest, []).extend(items)

    return new, ledger


def annotate_promotion_denials(verdicts, denials):
    """Attach eligibility blocking reasons to denied model-confirmed verdicts.

    When the model says ``confirmed`` but the deterministic eligibility gate
    keeps the finding out of ``confirmed_malicious_atomic``, the verdict entry
    gets ``promotion_denied_by`` (capped) so the run self-explains a
    confirmed=0 outcome instead of silently discarding the gate result.
    Returns a reason histogram for one console line. Pure telemetry -- never
    changes routing. Universal: structural ids only, no case data.
    """
    hist: dict = {}
    for e in verdicts or []:
        if not isinstance(e, dict):
            continue
        if e.get("disposition") != "confirmed" or e.get("to") == BUCKET_CONFIRMED:
            continue
        reasons = (denials or {}).get(e.get("finding_id"))
        if not reasons:
            continue
        e["promotion_denied_by"] = list(reasons)[:6]
        for r in e["promotion_denied_by"]:
            hist[r] = hist.get(r, 0) + 1
    return hist
