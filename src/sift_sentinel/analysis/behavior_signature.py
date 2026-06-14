"""Behavior-signature grouping for the final report (31G-B).

Groups findings into report sections by a structural fold over the fields the
analysis pipeline itself emitted on each finding's claims -- never over prose,
never over hardcoded tokens. The fold names no process, address, port, or TTP
value; it collects whatever the upstream stages classified.

Why this is dataset-agnostic and cannot over-collapse:
  * The signature is a pure function of a finding's own claim classifications
    (ttp_tag / process / type), case-folded. Run-specific noise (PIDs, ports,
    locator strings) lives in claim.pid / claim.artifact, which are
    deliberately NOT folded -- so duplicates are not fragmented by an incidental
    port and the signature itself contains no run-specific value.
  * Grouping is render-only: each group is a header plus its enumerated member
    findings, every one keeping its own finding_id. Nothing is merged. The
    partition invariant (assert_partition) proves mechanically that members form
    an exact, disjoint cover of the input -- closing the only two ways
    "grouped, not merged" can fail: a finding dropped, or a finding duplicated
    across groups while another is dropped (which count-equality alone misses).
"""
from __future__ import annotations

import re

from typing import Any


def _norm(value: Any) -> str:
    """Case-fold a categorical token. No digit masking: the folded fields are
    categorical labels the pipeline assigned and carry no PID/port noise -- that
    noise lives in unfolded fields, so masking would only risk merging genuinely
    distinct labels."""
    return str(value).strip().lower()


def behavior_signature(finding: dict) -> tuple:
    """Structural fold over a finding's own claim classifications.

    Returns a hashable ``(ttp_tags, processes, claim_types)`` of frozensets,
    built only from values the upstream pipeline emitted. This module hardcodes
    no process name, address, port, or TTP string.
    """
    if not isinstance(finding, dict):
        return (frozenset(), frozenset(), frozenset())
    ttp: set = set()
    proc: set = set()
    typ: set = set()
    for claim in finding.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        if claim.get("ttp_tag"):
            ttp.add(_norm(claim.get("ttp_tag")))
        if claim.get("process"):
            proc.add(_norm(claim.get("process")))
        if claim.get("type"):
            typ.add(_norm(claim.get("type")))
    return (frozenset(ttp), frozenset(proc), frozenset(typ))


def _finding_id(finding: dict) -> str:
    return str(finding.get("finding_id") or finding.get("id") or "")


def partition_findings(findings: list) -> dict:
    """Group findings by behavior_signature, preserving input order within each
    group. Pure render-grouping: no finding is merged or dropped."""
    groups: dict = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        groups.setdefault(behavior_signature(f), []).append(f)
    return groups


def build_dedup_map(findings: list) -> dict:
    """Reversible signature->finding_ids map plus its inverse. Loses nothing:
    every original finding_id is recoverable; raw findings stay source of truth."""
    groups = partition_findings(findings)
    sig_to_ids = {sig: [_finding_id(f) for f in members]
                  for sig, members in groups.items()}
    id_to_sig: dict = {}
    for sig, ids in sig_to_ids.items():
        for fid in ids:
            id_to_sig[fid] = sig
    return {"groups": sig_to_ids, "by_finding": id_to_sig,
            "group_count": len(groups)}


def assert_partition(findings: list) -> None:
    """Mechanical proof the grouping is a true partition (bijection):
      * input finding_ids are unique
      * union of all group members == the full input id set
      * groups are pairwise disjoint (each id in exactly one group)
    Raises AssertionError on any violation. Count-equality alone is rejected as
    insufficient by design."""
    ids = [_finding_id(f) for f in findings if isinstance(f, dict)]
    input_ids = set(ids)
    if len(ids) != len(input_ids):
        raise AssertionError("input finding_ids not unique: %d ids, %d unique"
                             % (len(ids), len(input_ids)))
    groups = partition_findings(findings)
    seen: set = set()
    for members in groups.values():
        for f in members:
            fid = _finding_id(f)
            if fid in seen:
                raise AssertionError("finding_id %r in more than one group" % fid)
            seen.add(fid)
    if seen != input_ids:
        raise AssertionError("partition mismatch: missing=%s extra=%s"
                             % (sorted(input_ids - seen)[:5],
                                sorted(seen - input_ids)[:5]))


def build_behavior_groups(findings: list, disposition_by_id: dict | None = None) -> list:
    """Freeze findings into report behavior-groups (31G-C). Render-only grouping.

    collapsible is True ONLY for ttp-defined groups (members share a ttp_tag set
    and carry no process token): provable behavior-duplicates safe to show as one
    canonical row. Entity-defined groups (process-defined, no ttp) mix distinct
    behaviors -- e.g. memory-injection and child-spawn of the same process -- so
    collapsible is False and the render must list each member. There is
    deliberately NO single representative_title: borrowing one member's behavior
    label for a mixed entity group would misrepresent the others.
    """
    disp = disposition_by_id or {}
    groups = partition_findings(findings)
    out: list = []
    for sig, members in groups.items():
        ttp, proc, types = sig
        member_ids = [_finding_id(f) for f in members]
        out.append({
            "behavior_signature": {"ttp_tags": sorted(ttp), "processes": sorted(proc),
                                   "claim_types": sorted(types)},
            "group_kind": ("ttp_defined" if (ttp and not proc)
                           else "entity_defined" if proc else "other"),
            "collapsible": bool(ttp and not proc),
            "group_size": len(members),
            "member_finding_ids": member_ids,
            "members": [
                {"finding_id": _finding_id(f), "title": f.get("title"),
                 "disposition": disp.get(_finding_id(f)),
                 "self_corrected": bool(f.get("self_corrected")),
                 "is_false_positive": bool(f.get("is_false_positive"))}
                for f in members],
            "source_tools_union": sorted(
                {t for f in members for t in (f.get("source_tools") or [])}),
            "disposition_set": sorted(
                {d for d in (disp.get(fid) for fid in member_ids) if d}),
            "fp_member_ids": [_finding_id(f) for f in members if f.get("is_false_positive")],
            "self_corrected_member_ids": [_finding_id(f) for f in members if f.get("self_corrected")],
        })
    return out


_CONFIRMED = "confirmed_malicious_atomic"
_BENIGN = "benign_or_false_positive"


def render_confirmed_md(behavior_groups: list, heading: str = "###") -> str:
    """Deterministic Confirmed Malicious Atomic Findings block (31G-D2a).

    collapsible (ttp-defined) group -> ONE canonical row enumerating member ids
    (safe: all members share the same agent ttp). Non-collapsible -> per-member
    rows with own titles (never a borrowed behavior label). Header count is the
    true confirmed total. ``heading`` is the markdown hash prefix so a section
    replace preserves the source report's heading level (## fallback vs ### LLM)."""
    groups = behavior_groups or []
    rows: list = []
    ids: list = []
    for g in groups:
        cm = [m for m in g.get("members", []) if m.get("disposition") == _CONFIRMED]
        if not cm:
            continue
        cids = [m["finding_id"] for m in cm]
        ids += cids
        if g.get("collapsible") and len(cm) > 1:
            title = cm[0].get("title") or ", ".join(
                g["behavior_signature"]["ttp_tags"]) or "behavior group"
            rows.append("- **%s** (%d instances): %s" % (title, len(cm), ", ".join(cids)))
        else:
            for m in cm:
                rows.append("- **%s**: %s" % (m["finding_id"], m.get("title") or "(untitled)"))
    out = ["%s Confirmed Malicious Atomic Findings (%d total)" % (heading, len(ids))]
    out += rows or ["- (none)"]
    return "\n".join(out)


def confirmed_finding_ids(behavior_groups: list) -> set:
    """IDs the confirmed-section render is responsible for. The D2c coverage gate
    asserts each appears in the final report (confirmed-only until FP/SC wired)."""
    return {m["finding_id"] for g in (behavior_groups or [])
            for m in g.get("members", []) if m.get("disposition") == _CONFIRMED}


def _render_simple_block(behavior_groups: list, header: str, pred) -> str:
    members = [m for g in (behavior_groups or []) for m in g.get("members", []) if pred(m)]
    out = ["### %s (%d)" % (header, len(members))]
    out += ["- **%s**: %s" % (m["finding_id"], m.get("title") or "(untitled)")
            for m in members] or ["- (none)"]
    return "\n".join(out)


def render_findings_tables_md(behavior_groups: list) -> str:
    """Combined deterministic findings tables (confirmed + FP + self-corrections).
    Backward-compatible: delegates to the split sub-renderers."""
    g = behavior_groups or []
    return "\n\n".join([
        render_confirmed_md(g),
        _render_simple_block(g, "Investigated and Dispositioned as Benign/False Positive",
                             lambda m: m.get("is_false_positive") or m.get("disposition") == _BENIGN),
        _render_simple_block(g, "Self-Corrections", lambda m: m.get("self_corrected")),
    ])


# Drift-tolerant: matches "## " OR "### " "Confirmed Malicious[ Atomic] Findings (...)".
# Matching both levels prevents a fallback "## Confirmed Malicious (atomic)" from
# being missed -> which would let the anchor chain insert a DUPLICATE block.
_CONFIRMED_HEADER_RE = re.compile(
    r"(^#{2,3}\s+Confirmed Malicious[^\n]*$)(.*?)(?=^##\s|\Z)",
    re.MULTILINE | re.DOTALL)


def replace_confirmed_findings_section(report_md: str, behavior_groups: list):
    """Replace the confirmed-findings section with the deterministic table so the
    prose layer cannot drop a confirmed id (31G-D2a).

    Modeled on insert_per_user_summary_into_report: structural ## anchors, never
    line numbers; idempotent (re-run yields byte-identical output); content built
    fresh each call; PRESERVES the matched heading level. Anchor chain when no
    confirmed header exists: after "## Key Findings" (as ###) -> before "##
    Requiring Further Investigation" (as ##) -> before "## MITRE" (as ##) -> else
    no-op (the coverage gate fails loud rather than splice at a wrong place).

    Returns (new_md, n_chars_replaced_or_inserted)."""
    if not isinstance(report_md, str):
        report_md = str(report_md or "")
    m = _CONFIRMED_HEADER_RE.search(report_md)
    if m:
        lvl = re.match(r"^(#+)", m.group(1)).group(1)   # preserve ## or ###
        block = render_confirmed_md(behavior_groups, heading=lvl).rstrip()
        return report_md[:m.start()] + block + "\n\n" + report_md[m.end():], len(block)
    for anchor, before, lvl in (
        (r"^##\s+Key Findings\s*$", False, "###"),
        (r"^##\s+Requiring Further Investigation\s*$", True, "##"),
        (r"^##\s+MITRE", True, "##"),
    ):
        a = re.search(anchor, report_md, re.MULTILINE)
        if a:
            block = render_confirmed_md(behavior_groups, heading=lvl).rstrip()
            if before:
                new = report_md[:a.start()].rstrip() + "\n\n" + block + "\n\n" + report_md[a.start():]
            else:
                new = report_md[:a.end()].rstrip() + "\n\n" + block + "\n\n" + report_md[a.end():].lstrip()
            return new, len(block)
    return report_md, 0


def reportable_finding_ids(behavior_groups: list) -> set:
    """Every finding_id the deterministic render must show (confirmed + benign/FP
    + self-corrected). The render-coverage gate (31G-D2) asserts each appears in
    the final report text."""
    ids: set = set()
    for g in behavior_groups or []:
        for m in g.get("members", []):
            if (m.get("disposition") in (_CONFIRMED, _BENIGN)
                    or m.get("is_false_positive") or m.get("self_corrected")):
                ids.add(m["finding_id"])
    return ids

# ── A+ deterministic confirmed section override ────────────────────────
# Appended intentionally so this definition supersedes older grouping-based
# renderers. Dataset-agnostic: source of truth is the final disposition bucket
# or any compatible finding list passed by the caller.
try:
    from sift_sentinel.reporting.deterministic_confirmed_section import (
        replace_confirmed_findings_section as _a_plus_replace_confirmed_findings_section,
    )

    def replace_confirmed_findings_section(report, confirmed_findings):  # noqa: F811
        return _a_plus_replace_confirmed_findings_section(report, confirmed_findings)
except Exception:  # pragma: no cover - fail closed to previous definition
    pass
