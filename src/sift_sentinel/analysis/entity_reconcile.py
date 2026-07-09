"""Sentinel Qwen Ensemble -- Entity contradiction reconciliation audit (Slot 31G-E2a).

INERT: describes what reconciliation WOULD do. Mutates no bucket; the only
side effect is write_audit(), and only when the caller asks. Routing (E2b)
and the postrun gate (E2c) are separate slots.

Rule A (decided after the E2 probe disproved evidence-strength tiebreak B):
  If an entity carries contradictory verdicts, no finding on that entity may
  remain in confirmed_malicious_atomic; its confirmed findings are recommended
  for demotion to suspicious_needs_review. Downgrade-only. No promotion.

DATASET-AGNOSTIC: only the run's own entity keys + bucket vocabulary appear
here. No process names, PIDs, finding IDs, paths, or source-doc strings.
Strength fields are recorded for transparency ONLY and never drive routing --
the E2 probe showed run-local strength measures evidence volume, not truth
direction (a ReAct-FP'd finding is forced LOW yet is a confident benign).
"""
from __future__ import annotations

SCHEMA_VERSION = 1
CONFIRMED = "confirmed_malicious_atomic"
REVIEW = "suspicious_needs_review"
BENIGN = "benign_or_false_positive"
RULE = "A_demote_confirmed_under_entity_contradiction"
REASON = "entity_verdict_conflict_confirmed_demoted_to_review"
STRENGTH_NOT_USED = "evidence_quantity_not_truth_direction"
_CONF_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _fid(f):
    return f.get("finding_id") or f.get("id")


def _bucket_index(buckets):
    idx = {}
    if isinstance(buckets, dict):
        for name, items in buckets.items():
            for it in (items or []):
                if isinstance(it, dict) and _fid(it):
                    idx[_fid(it)] = name
    return idx


def _observe_strength(fids, by_id):
    """Transparency only -- NEVER used for a routing decision."""
    best = tools = vrefs = 0
    for fid in fids:
        f = by_id.get(fid) or {}
        best = max(best, _CONF_RANK.get(str(f.get("confidence_level")), 0))
        tools = max(tools, len(f.get("source_tools") or []))
        vrefs = max(vrefs, len(f.get("validator_fact_refs") or []))
    return {"max_confidence_rank": best, "max_source_tools": tools,
            "max_validator_fact_refs": vrefs}


def build_reconciliation_audit(buckets, conflicts, findings):
    """Pure: (buckets, conflicts, findings) -> audit dict. No I/O, no mutation."""
    F = findings if isinstance(findings, list) else (
        findings.get("findings", []) if isinstance(findings, dict) else [])
    by_id = {_fid(f): f for f in F if isinstance(f, dict) and _fid(f)}
    bidx = _bucket_index(buckets)

    per_entity, at_risk = [], 0
    uncertainty_conflicts_skipped = 0
    for c in (conflicts or []):
        if not isinstance(c, dict):
            continue
        _vlabels = {str(v.get("verdict") or "").lower()
                    for v in c.get("conflicting_verdicts", [])}
        if not ("malicious" in _vlabels and any(
                ("benign" in x) or x == "false_positive" for x in _vlabels)):
            # slot 31G-E2b-refine: Rule A routes ONLY genuine malicious-vs-
            # benign truth conflicts. malicious-vs-inconclusive is uncertainty,
            # not a contradiction; demoting it would strip true positives
            # (e.g. a download-cradle finding) from confirmed. Recorded only.
            uncertainty_conflicts_skipped += 1
            continue
        ent_ids = sorted({fid for v in c.get("conflicting_verdicts", [])
                          for fid in (v.get("source_finding_ids") or [])})
        cur_conf = [i for i in ent_ids if bidx.get(i) == CONFIRMED]
        cur_ben = [i for i in ent_ids if bidx.get(i) == BENIGN]
        cur_rev = [i for i in ent_ids if bidx.get(i) == REVIEW]
        at_risk += len(cur_conf)
        per_entity.append({
            "entity_key": c.get("entity_key"),
            "conflict_type": c.get("conflict_type"),
            "conflicting_verdicts": [
                {"verdict": v.get("verdict"),
                 "source_finding_ids": v.get("source_finding_ids")}
                for v in c.get("conflicting_verdicts", [])],
            "current_confirmed_finding_ids": cur_conf,
            "current_benign_finding_ids": cur_ben,
            "current_review_finding_ids": cur_rev,
            "recommended_action": "demote_confirmed_to_review",
            "recommended_target_bucket": REVIEW,
            "would_move_finding_ids": list(cur_conf),   # downgrade-only
            "no_promotion": True,
            "reason": REASON,
            "confirmed_strength_observed": _observe_strength(cur_conf, by_id),
            "benign_strength_observed": _observe_strength(cur_ben, by_id),
            "strength_not_used_reason": STRENGTH_NOT_USED,
        })

    would_move = sorted({i for e in per_entity for i in e["would_move_finding_ids"]})
    return {
        "schema_version": SCHEMA_VERSION,
        "rule": RULE,
        "applied": False,
        "raw_conflict_count": len(conflicts or []),
        "conflicted_entity_count": len(per_entity),
        "uncertainty_conflicts_skipped": uncertainty_conflicts_skipped,
        "confirmed_at_risk_count": at_risk,
        "recommended_moves": len(would_move),
        "would_move_finding_ids": would_move,
        "strength_not_used_reason": STRENGTH_NOT_USED,
        "per_entity": per_entity,
    }


def write_audit(path, audit):
    """The ONLY side effect in this module."""
    import json, os
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(audit, fh, indent=2, default=str)
    return path


def evaluate_reconciliation_gates(audit, buckets):
    """Pure Step-13A gate evaluator. Returns ordered list of
    (gate_name, status, extra) asserting downgrade-only invariants against the
    POST-reconcile audit + buckets. No I/O, no dataset literals."""
    audit = audit or {}
    buckets = buckets or {}
    moved = (set(audit.get("would_move_finding_ids") or [])
             | set(audit.get("benign_only_moved_finding_ids") or []))
    at_risk = int(audit.get("confirmed_at_risk_count") or 0)
    raw = int(audit.get("raw_conflict_count") or 0)
    before = int(audit.get("confirmed_before") or 0)
    after = int(audit.get("confirmed_after") or 0)
    conf_ids = {(f.get("finding_id") or f.get("id"))
                for f in (buckets.get(CONFIRMED) or [])}
    still = moved & conf_ids
    return [
        ("ENTITY_RECONCILIATION_AUDIT_GATE", "PASS",
         "conflicts=%d confirmed_at_risk=%d" % (raw, at_risk)),
        ("ENTITY_RECONCILIATION_ROUTE_GATE",
         "PASS" if (at_risk == 0 or len(moved) > 0) else "FAIL",
         "moved_to_review=%d confirmed_before=%d confirmed_after=%d"
         % (len(moved), before, after)),
        ("ENTITY_RECONCILIATION_DOWNGRADE_ONLY_GATE",
         "PASS" if after <= before else "FAIL",
         "confirmed_before=%d confirmed_after=%d" % (before, after)),
        ("NO_CONFLICTED_ENTITY_CONFIRMED_GATE",
         "PASS" if not still else "FAIL",
         "moved=%d still_confirmed=%d" % (len(moved), len(still))),
    ]


def find_benign_only_demotions(buckets, ledger):
    """A'-benign-only: a confirmed finding whose PROCESS entity was concluded
    BENIGN by ReAct and NEVER malicious is a calibration-vs-ReAct contradiction
    -> demote to review (downgrade-only). Skips findings also touching a
    malicious entity (avoids chain over-demotion). Process-scope; no literals."""
    ledger = ledger or {}
    def _v(k): return set((ledger.get(k) or {}).get("verdicts") or [])
    benign_only = {k for k in ledger if "benign" in _v(k) and "malicious" not in _v(k)}
    malicious = {k for k in ledger if "malicious" in _v(k)}
    moved, per = [], []
    for f in ((buckets or {}).get(CONFIRMED) or []):
        if not isinstance(f, dict):
            continue
        fidv = f.get("finding_id") or f.get("id")
        keys = {"process:%s" % c.get("pid") for c in (f.get("claims") or [])
                if isinstance(c, dict) and c.get("type") == "pid"
                and c.get("pid") not in (None, "")}
        if fidv and (keys & benign_only) and not (keys & malicious):
            ek = sorted(keys & benign_only)[0]
            moved.append(fidv)
            per.append({"entity_key": ek, "confirmed_finding_id": fidv,
                        "react_verdicts": sorted(_v(ek)),
                        "recommended_action": "demote_confirmed_to_review",
                        "reason": "react_benign_only_vs_calibration_confirm_demoted_to_review"})
    return {"moved_finding_ids": sorted(set(moved)), "per_entity": per}


def find_synthesis_dependency_demotions(buckets, moved_finding_ids):
    """If a synthesis/user finding (identified by _user_synth_signals) cites a
    moved confirmed finding as malicious support, flag it for demotion to review
    and display-text rewrite. Returns moved_finding_ids + per_finding."""
    import re
    moved = set(moved_finding_ids or [])
    out_ids, per = [], []
    if not moved:
        return {"moved_finding_ids": [], "per_finding": []}
    for bname, items in (buckets or {}).items():
        for f in (items or []):
            if not isinstance(f, dict):
                continue
            sig = f.get("_user_synth_signals")
            if sig is None:
                continue
            cited = set(re.findall(r"F\d{2,4}", " ".join(map(str, sig))))
            hit = sorted(cited & moved)
            if hit:
                fidv = f.get("finding_id") or f.get("id")
                out_ids.append(fidv)
                per.append({"finding_id": fidv, "from_bucket": bname,
                            "cited_moved_support": hit,
                            "recommended_action": "demote_to_review_and_flag_display",
                            "reason": "support_finding_reconciled_requires_review"})
    return {"moved_finding_ids": sorted(set(out_ids)), "per_finding": per}


# ── A+ entity contradiction propagation ────────────────────────────────
# Dataset-agnostic policy:
#   * ReAct-confirmed benign/false-positive for an entity refutes ordinary
#     suspicious/confirmed findings on the same entity unless the finding
#     explicitly carries a future split-justification flag.
#   * If an entity has both benign and malicious ReAct labels, route the
#     shared-entity findings to review rather than keeping contradictory
#     truth buckets.
#   * If an entity has only malicious labels, preserve it.
#
# Pure function: no I/O, no mutation of input buckets.

def _a_plus_fid(finding):
    return str(
        (finding or {}).get("finding_id")
        or (finding or {}).get("id")
        or (finding or {}).get("fid")
        or ""
    ).strip()


def _a_plus_norm_entity(kind, value):
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    low = s.lower()
    if kind == "pid":
        return "pid:%s" % low
    if kind == "hash":
        return "hash:%s" % low
    if kind == "path":
        return "path:%s" % low
    if kind == "process":
        return "process:%s" % low
    return "%s:%s" % (kind, low)


def _a_plus_norm_ledger_key(key):
    """Return a broad but deterministic set of comparable entity keys."""
    if key is None:
        return set()
    s = str(key).strip()
    if not s:
        return set()
    low = s.lower()
    out = {s, low}
    if low.isdigit():
        out.add("pid:%s" % low)
    if low.startswith(("pid:", "hash:", "path:", "process:")):
        out.add(low)
    if "\\" in s or "/" in s:
        out.add("path:%s" % low)
    return out


def _a_plus_finding_entity_keys(finding):
    """Best-effort entity extraction, using legacy extractor when present."""
    keys = set()

    legacy = globals().get("_finding_entity_keys")
    if callable(legacy):
        try:
            keys.update(str(k).strip() for k in (legacy(finding) or []) if str(k).strip())
        except Exception:
            pass

    finding = finding or {}
    claims = finding.get("claims") or finding.get("validated_claims") or []
    if isinstance(claims, dict):
        claims = list(claims.values())

    for claim in claims or []:
        if not isinstance(claim, dict):
            continue
        ctype = str(claim.get("type") or "").lower()

        pid = (
            claim.get("pid")
            or claim.get("process_id")
            or claim.get("ProcessId")
            or claim.get("PID")
        )
        if pid is not None:
            k = _a_plus_norm_entity("pid", pid)
            if k:
                keys.add(k)

        process = (
            claim.get("process")
            or claim.get("process_name")
            or claim.get("image")
            or claim.get("ImageFileName")
        )
        if process:
            k = _a_plus_norm_entity("process", process)
            if k:
                keys.add(k)

        path = (
            claim.get("path")
            or claim.get("value")
            or claim.get("artifact")
            or claim.get("filename")
            or claim.get("application_path")
        )
        if path and ctype in {"path", "artifact", "appcompatcache", "srum_usage", "raw"}:
            k = _a_plus_norm_entity("path", path)
            if k:
                keys.add(k)

        for hk in ("hash", "sha1", "sha256", "md5"):
            hv = claim.get(hk)
            if hv:
                k = _a_plus_norm_entity("hash", hv)
                if k:
                    keys.add(k)

    for tk, kind in (
        ("pid", "pid"),
        ("process_id", "pid"),
        ("process", "process"),
        ("process_name", "process"),
        ("path", "path"),
        ("artifact", "path"),
        ("hash", "hash"),
        ("sha1", "hash"),
        ("sha256", "hash"),
        ("md5", "hash"),
    ):
        if finding.get(tk):
            k = _a_plus_norm_entity(kind, finding.get(tk))
            if k:
                keys.add(k)

    return keys


def _a_plus_verdict_labels(raw):
    """Classify ledger value into benign/malicious/inconclusive labels."""
    import json

    try:
        text = json.dumps(raw, sort_keys=True, default=str).lower()
    except Exception:
        text = str(raw).lower()

    collapsed = text.replace("-", "_").replace(" ", "_")

    labels = set()
    if (
        "false_positive" in collapsed
        or "confirmed_benign" in collapsed
        or '"benign"' in collapsed
        or "'benign'" in collapsed
        or collapsed.endswith(":benign")
        or collapsed == "benign"
    ):
        labels.add("benign")

    # Avoid treating explicit negative phrases as malicious labels.
    negative_mal = (
        "not_malicious" in collapsed
        or "non_malicious" in collapsed
        or "benign_not_malicious" in collapsed
    )
    if (
        "confirmed_malicious" in collapsed
        or (
            "malicious" in collapsed
            and not negative_mal
            and "confirmed_benign" not in collapsed
            and "false_positive" not in collapsed
        )
    ):
        labels.add("malicious")

    if "inconclusive" in collapsed or "unresolved" in collapsed:
        labels.add("inconclusive")

    return labels


def _a_plus_split_justified(finding):
    """Future-compatible escape hatch for explicit distinct-evidence-family split."""
    finding = finding or {}
    return bool(
        finding.get("entity_conflict_split_justification")
        or finding.get("distinct_evidence_family_justified")
        or finding.get("same_entity_conflict_justified")
    )


def find_entity_contradiction_routes(buckets, ledger):
    """Return route recommendations for same-entity contradictory verdicts.

    The helper is intentionally conservative:
      - benign-only entity -> route non-benign same-entity findings to benign/FP;
      - mixed benign+malicious entity -> route same-entity findings to review;
      - malicious-only entity -> preserve.

    It does not mutate buckets.
    """
    buckets = buckets or {}
    ledger = ledger or {}

    entity_labels = {}
    for raw_key, raw_value in ledger.items():
        labels = _a_plus_verdict_labels(raw_value)
        if not labels:
            continue
        for key in _a_plus_norm_ledger_key(raw_key):
            entity_labels.setdefault(key, set()).update(labels)

    benign_only = {
        key for key, labels in entity_labels.items()
        if "benign" in labels and "malicious" not in labels
    }
    mixed = {
        key for key, labels in entity_labels.items()
        if "benign" in labels and "malicious" in labels
    }
    malicious_only = {
        key for key, labels in entity_labels.items()
        if "malicious" in labels and "benign" not in labels
    }
    all_labeled = benign_only | mixed | malicious_only

    move_to_benign = []
    move_to_review = []
    already_review = []
    skipped_split_justified = []
    pure_malicious_preserved = []
    per_finding = []

    movable_buckets = {
        "confirmed_malicious_atomic",
        "suspicious_needs_review",
        "benign_or_false_positive",
    }

    for bucket_name, items in buckets.items():
        if bucket_name not in movable_buckets:
            continue

        for finding in items or []:
            fid = _a_plus_fid(finding)
            if not fid:
                continue

            keys = _a_plus_finding_entity_keys(finding)
            relevant = keys & all_labeled
            if not relevant:
                continue

            if _a_plus_split_justified(finding):
                skipped_split_justified.append(fid)
                per_finding.append({
                    "finding_id": fid,
                    "bucket": bucket_name,
                    "action": "preserve_split_justified",
                    "entities": sorted(relevant),
                })
                continue

            has_mixed = bool(relevant & mixed)
            has_benign = bool(relevant & benign_only)
            has_malicious = bool(relevant & malicious_only)

            if has_mixed:
                if bucket_name == "suspicious_needs_review":
                    already_review.append(fid)
                    action = "already_review_mixed_entity"
                else:
                    move_to_review.append(fid)
                    action = "move_to_review_mixed_entity"
            elif has_benign:
                # A finding that touches only benign-only labeled entities can
                # collapse to benign/FP. If it also touches a malicious-only
                # entity, do not call it benign; route to review.
                if has_malicious:
                    if bucket_name == "suspicious_needs_review":
                        already_review.append(fid)
                        action = "already_review_refuted_subset"
                    else:
                        move_to_review.append(fid)
                        action = "move_to_review_refuted_subset"
                else:
                    if bucket_name == "benign_or_false_positive":
                        action = "already_benign"
                    else:
                        move_to_benign.append(fid)
                        action = "move_to_benign_refuted_entity"
            elif has_malicious:
                pure_malicious_preserved.append(fid)
                action = "preserve_pure_malicious_entity"
            else:
                action = "preserve_no_route"

            per_finding.append({
                "finding_id": fid,
                "bucket": bucket_name,
                "action": action,
                "entities": sorted(relevant),
            })

    # Stable de-duplication.
    def uniq(seq):
        return sorted(set(seq))

    return {
        "schema_version": 1,
        "benign_only_entities": sorted(benign_only),
        "mixed_entities": sorted(mixed),
        "malicious_only_entities": sorted(malicious_only),
        "move_to_benign_ids": uniq(move_to_benign),
        "move_to_review_ids": uniq(move_to_review),
        "already_review_ids": uniq(already_review),
        "skipped_split_justified_ids": uniq(skipped_split_justified),
        "pure_malicious_preserved_ids": uniq(pure_malicious_preserved),
        "pure_malicious_preserved_count": len(set(pure_malicious_preserved)),
        "per_finding": per_finding,
    }

# ── A++ synthesis dependency propagation ──────────────────────────────
# Dataset-agnostic policy:
#   * Synthesis / narrative / attack-chain findings may not remain as
#     high-confidence malicious narrative when their entity support has
#     already been refuted by ReAct/FP routing.
#   * This is downgrade-only. It never promotes a finding.
#   * A future split-justification flag may preserve a synthesis finding
#     only when the author explicitly records an independent non-refuted
#     malicious anchor. The default is conservative review.
#   * No case literals, no oracle labels.

def _synth_ref_fid(finding):
    return str(
        (finding or {}).get("finding_id")
        or (finding or {}).get("id")
        or (finding or {}).get("fid")
        or ""
    ).strip()


def _synth_ref_as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    s = str(value).strip()
    return [s] if s else []


def _synth_ref_is_synthesis(bucket_name, finding):
    b = str(bucket_name or "").strip().lower()
    if b == "synthesis_narrative":
        return True

    f = finding or {}
    if f.get("_user_synth_signals") is not None:
        return True

    text = " ".join(
        str(f.get(k) or "")
        for k in (
            "finding_type",
            "category",
            "title",
            "name",
            "description",
            "summary",
        )
    ).lower()

    return any(
        token in text
        for token in (
            "synthesis",
            "narrative",
            "attack chain",
            "kill chain",
            "multi-stage",
            "multi stage",
            "campaign",
        )
    )


def _synth_ref_has_split_justification(finding):
    f = finding or {}
    return bool(
        f.get("allow_refuted_dependency")
        or f.get("refuted_dependency_split_justification")
        or f.get("independent_malicious_anchor")
        or f.get("independent_confirmed_anchor")
    )


def find_synthesis_refuted_entity_demotions(buckets, entity_context_map):
    """Return synthesis findings that depend on ReAct-refuted entities.

    Pure function: no I/O, no mutation of input buckets.

    Args:
        buckets: final disposition bucket mapping.
        entity_context_map: finding_id -> entity context built from final
            disposition buckets. Uses entity_react_refuted_by and
            entity_react_confirmed_by.

    Returns:
        {
          "moved_finding_ids": [...],
          "preserved_finding_ids": [...],
          "per_finding": [...]
        }
    """
    ctx = entity_context_map if isinstance(entity_context_map, dict) else {}
    moved_ids = []
    preserved_ids = []
    per = []

    for bucket_name, items in (buckets or {}).items():
        for finding in (items or []):
            if not isinstance(finding, dict):
                continue

            fid = _synth_ref_fid(finding)
            if not fid:
                continue
            if not _synth_ref_is_synthesis(bucket_name, finding):
                continue

            c = ctx.get(fid) if isinstance(ctx.get(fid), dict) else {}
            refuted_by = sorted(set(_synth_ref_as_list(
                c.get("entity_react_refuted_by")
            )))
            confirmed_by = sorted(set(_synth_ref_as_list(
                c.get("entity_react_confirmed_by")
            )))

            if not refuted_by:
                preserved_ids.append(fid)
                per.append({
                    "finding_id": fid,
                    "from_bucket": bucket_name,
                    "refuted_by": [],
                    "confirmed_by": confirmed_by,
                    "recommended_action": "preserve_no_refuted_entity_dependency",
                    "reason": "no_refuted_entity_dependency",
                })
                continue

            if _synth_ref_has_split_justification(finding):
                preserved_ids.append(fid)
                per.append({
                    "finding_id": fid,
                    "from_bucket": bucket_name,
                    "refuted_by": refuted_by,
                    "confirmed_by": confirmed_by,
                    "recommended_action": "preserve_with_explicit_split_justification",
                    "reason": "explicit_independent_anchor_or_split_justification",
                })
                continue

            moved_ids.append(fid)
            per.append({
                "finding_id": fid,
                "from_bucket": bucket_name,
                "refuted_by": refuted_by,
                "confirmed_by": confirmed_by,
                "recommended_action": "demote_to_review_and_cap_severity",
                "reason": "synthesis_depends_on_refuted_entity",
            })

    def uniq(seq):
        out = []
        seen = set()
        for x in seq:
            if x and x not in seen:
                out.append(x)
                seen.add(x)
        return out

    return {
        "moved_finding_ids": sorted(set(moved_ids)),
        "preserved_finding_ids": uniq(preserved_ids),
        "per_finding": per,
    }

