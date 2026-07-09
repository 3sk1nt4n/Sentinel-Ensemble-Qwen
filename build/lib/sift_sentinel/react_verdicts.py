"""Slot 31E-DB.5d GROUP B -- ReAct verdict ledger + entity convergence.

The Inv3 ReAct loop concludes one verdict per finding, but several
findings frequently touch the SAME underlying entity (a process, a
file, a network tuple, or an attack chain). If one finding's ReAct
concludes that process X is malicious while another concludes the same
process is benign, the system must NOT silently confirm X. This module
extracts only *final* ReAct conclusions, folds them into a per-entity
ledger, detects contradictions, and fails closed: a contradicted
process/file/network entity is routed out of confirmed_malicious_atomic
and a deterministic conflict artifact is written for a future
entity-level tiebreaker.

Strictness (B1): only genuine conclusion records count --
``action == "conclude"``, an explicit ``verdict`` field, a
``CONCLUDED -- ...`` line, or an explicit ReAct false-positive line.
Plain reasoning such as "this could indicate malicious activity" is NOT
a verdict and is ignored.

Scope (B2): a *chain* verdict carries ``chain_members`` and does NOT by
itself make any member process malicious -- only a separate
process-scope verdict can do that.

Dataset-agnostic and model-flexible: no provider/model name, no case
id, no evidence path is referenced. ZEROFAKE: every verdict is traced
back to a source finding id and a trimmed excerpt.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

__all__ = [
    "VERDICT_MALICIOUS",
    "VERDICT_BENIGN",
    "VERDICT_INCONCLUSIVE",
    "SCOPES",
    "extract_react_verdicts",
    "classify_react_verdict_scope",
    "canonical_entity_key",
    "build_react_entity_verdict_ledger",
    "detect_react_entity_contradictions",
    "write_react_entity_conflicts",
    "findings_blocked_by_react_conflicts",
    "is_finding_react_conflicted",
    "react_conflict_reasons",
    "verdict_records_from_findings",
    "summarize_react_contradictions_for_run",
    "REACT_VERDICT_EXTRACTION_GATE",
    "REACT_VERDICT_SCOPE_GATE",
    "REACT_CHAIN_ENTITY_SCOPE_GATE",
    "REACT_ENTITY_VERDICT_LEDGER_GATE",
    "REACT_ENTITY_VERDICT_CONFLICT_DETECTED_GATE",
    "REACT_CONTRADICTION_ROUTE_GATE",
    "REACT_ENTITY_TIEBREAKER_REQUIRED_GATE",
    "CONFLICT_ARTIFACT_NAME",
    "CONFLICT_SCHEMA_VERSION",
]

# ── Gate identifiers (names only; PASS/FAIL derived by tests) ───────────
REACT_VERDICT_EXTRACTION_GATE = "REACT_VERDICT_EXTRACTION_GATE"
REACT_VERDICT_SCOPE_GATE = "REACT_VERDICT_SCOPE_GATE"
REACT_CHAIN_ENTITY_SCOPE_GATE = "REACT_CHAIN_ENTITY_SCOPE_GATE"
REACT_ENTITY_VERDICT_LEDGER_GATE = "REACT_ENTITY_VERDICT_LEDGER_GATE"
REACT_ENTITY_VERDICT_CONFLICT_DETECTED_GATE = (
    "REACT_ENTITY_VERDICT_CONFLICT_DETECTED_GATE"
)
REACT_CONTRADICTION_ROUTE_GATE = "REACT_CONTRADICTION_ROUTE_GATE"
REACT_ENTITY_TIEBREAKER_REQUIRED_GATE = (
    "REACT_ENTITY_TIEBREAKER_REQUIRED_GATE"
)

CONFLICT_ARTIFACT_NAME = "react_entity_conflicts.json"
CONFLICT_SCHEMA_VERSION = "1.0"

# ── Normalized verdict vocabulary ──────────────────────────────────────
VERDICT_MALICIOUS = "malicious"
VERDICT_BENIGN = "benign"
VERDICT_INCONCLUSIVE = "inconclusive"

SCOPES = ("process", "file", "network", "chain", "finding", "unknown")

_EXCERPT_MAX = 200

# Conclusion-only signals. A plain reasoning line ("could indicate
# malicious", "may be benign") deliberately does NOT match.
_CONCLUDED_RE = re.compile(r"CONCLUDED\s*--\s*(.+)", re.IGNORECASE)
_FALSE_POSITIVE_RE = re.compile(
    r"\b(?:flagged\s+)?false\s*positive\b", re.IGNORECASE,
)
_VERDICT_LINE_RE = re.compile(
    r"\bverdict\s*[:=]\s*([A-Za-z_]+)", re.IGNORECASE,
)


def _trim(text: Any) -> str:
    s = "" if text is None else str(text)
    s = s.strip().replace("\n", " ")
    return s[:_EXCERPT_MAX]


def _norm(s: Any) -> str:
    return str(s).strip().lower() if s is not None else ""


def _normalize_verdict(raw: Any) -> str | None:
    """Map a raw verdict token onto malicious/benign/inconclusive.

    likely-FP / false-positive / confirmed_benign all normalize to
    ``benign`` -- they are non-malicious conclusions for conflict
    purposes. Returns ``None`` when there is no verdict signal.
    """
    v = _norm(raw)
    if not v:
        return None
    if v in ("malicious", "confirmed_malicious", "is_malicious"):
        return VERDICT_MALICIOUS
    if v in ("benign", "confirmed_benign", "confirmed_false_positive",
             "false_positive", "false positive", "likely_fp",
             "likely_false_positive", "not_malicious", "legitimate"):
        return VERDICT_BENIGN
    if v in ("inconclusive", "indeterminate", "ambiguous",
             "cannot_confirm", "insufficient_evidence", "unknown"):
        return VERDICT_INCONCLUSIVE
    return None


# ── Strict coordinator-conclusion line parsing ─────────────────────────
# Only two markers are a FINAL verdict: the coordinator "CONCLUDED -- "
# line and the explicit "ReAct flagged FALSE POSITIVE" line. Reasoning
# prose ("could indicate malicious", "strongly indicate compromise")
# and prompt-template lines (a literal ``"verdict": "..."`` inside an
# instruction block) deliberately do NOT match -- that is the 5d-alpha
# fix for reasoning-extraction contamination (TASK 2).
_CONCLUSION_MARKER_RE = re.compile(
    r"CONCLUDED\s*--\s*(.+)$", re.IGNORECASE,
)
_FP_FLAG_RE = re.compile(
    r"\b(?:ReAct\s+)?flagged\s+FALSE\s+POSITIVE\b", re.IGNORECASE,
)
_FINDING_ID_RE = re.compile(r"\b(F\d{2,4})\b")
# "PID NNNN (process.exe)" or "PID NNNN"
_PID_PAREN_RE = re.compile(
    r"\bPID\s+(\d+)\s*(?:\(\s*([^)]+?)\s*\))?", re.IGNORECASE,
)
# Example matched form: "EXAMPLE.EXE PID NNNN"
_NAME_PID_RE = re.compile(
    r"\b([A-Za-z0-9_.\-]+\.exe)\s+PID\s+(\d+)\b", re.IGNORECASE,
)
_CHAIN_SPLIT_RE = re.compile(r"→|->|=>")

_INCONCLUSIVE_TOKENS = (
    "not definitively malicious", "but not definitively",
    "suspicious but not", "inconclusive", "cannot be confirmed",
    "cannot confirm", "insufficient evidence", "indeterminate",
    "unable to determine", "not conclusive",
)
_BENIGN_TOKENS = (
    "false positive", "is benign", "are benign", "benign:",
    "is not malicious", "not malicious", "legitimate", "known-good",
    "known good", "no evidence of malicious", "no indicators",
)
_MALICIOUS_TOKENS = (
    "is malicious", "are malicious", "malicious:", "confirmed malicious",
    "represents confirmed malicious", "is a malicious",
    "actively malicious",
)


def _verdict_from_conclusion_text(text: str) -> str:
    """Classify a final-conclusion sentence.

    Precedence: inconclusive hedges first (so "not definitively
    malicious" is not read as malicious), then benign (so "is not
    malicious" / "false positive" win), then malicious, else
    inconclusive. This is applied ONLY to text already proven to be a
    final conclusion line -- never to reasoning prose.
    """
    low = _norm(text)
    if any(t in low for t in _INCONCLUSIVE_TOKENS):
        return VERDICT_INCONCLUSIVE
    if any(t in low for t in _BENIGN_TOKENS):
        return VERDICT_BENIGN
    if any(t in low for t in _MALICIOUS_TOKENS):
        return VERDICT_MALICIOUS
    return VERDICT_INCONCLUSIVE


def _parse_pid_name(text: str) -> tuple[int | None, str | None]:
    """Extract the first (pid, process_name) from a conclusion line.

    Handles both ``PID NNNN (process.exe)`` and ``PROCESS.EXE PID NNNN``.
    """
    m = _PID_PAREN_RE.search(text)
    if m:
        pid = int(m.group(1))
        name = (m.group(2) or "").strip() or None
        if name is None:
            n2 = _NAME_PID_RE.search(text)
            if n2 and int(n2.group(2)) == pid:
                name = n2.group(1).strip()
        return pid, name
    m2 = _NAME_PID_RE.search(text)
    if m2:
        return int(m2.group(2)), m2.group(1).strip()
    return None, None


def _looks_like_chain(text: str) -> bool:
    low = _norm(text)
    if "process chain" in low or "attack chain" in low:
        return True
    # Two or more arrow-joined segments and at least two PIDs.
    segs = _CHAIN_SPLIT_RE.split(text)
    pids = _PID_PAREN_RE.findall(text)
    return len(segs) >= 3 and len(pids) >= 2


def _chain_members_and_pids(text: str) -> tuple[list[str], list[int]]:
    segs = [s.strip() for s in _CHAIN_SPLIT_RE.split(text) if s.strip()]
    members: list[str] = []
    for s in segs:
        # Keep a compact member token (executable name if present).
        nm = re.search(r"([A-Za-z0-9_.\-]+\.exe)", s)
        members.append((nm.group(1) if nm else s)[:_EXCERPT_MAX])
    pids = sorted({int(p) for p, _ in _PID_PAREN_RE.findall(text)})
    return members, pids


def _parse_conclusion_line(
    line: str, finding_hint: str | None,
) -> dict | None:
    """Parse ONE coordinator log/text line into a verdict record.

    Returns ``None`` unless the line carries a genuine final-conclusion
    marker. PID-bearing lines become process-scope records keyed by
    ``process:<pid>``; chain narration becomes a chain-scope record
    carrying ``chain_members`` / ``chain_member_pids`` (and never a
    process verdict).
    """
    cm = _CONCLUSION_MARKER_RE.search(line)
    fp = _FP_FLAG_RE.search(line)
    if not (cm or fp):
        return None

    fid = finding_hint
    fmatch = _FINDING_ID_RE.search(line)
    if fmatch:
        fid = fmatch.group(1)

    base = {
        "scope": None, "pid": None, "process_name": None,
        "file": None, "network": None, "chain_members": None,
        "chain_member_pids": None,
        "source_finding_ids": [fid] if fid else [],
        "evidence_refs": [],
    }

    if cm and not fp:
        body = cm.group(1).strip()
        if _looks_like_chain(body):
            members, pids = _chain_members_and_pids(body)
            base.update({
                "verdict": _verdict_from_conclusion_text(body),
                "scope": "chain",
                "chain_members": members,
                "chain_member_pids": pids,
                "excerpt": _trim(body),
            })
            return base
        pid, name = _parse_pid_name(body)
        verdict = _verdict_from_conclusion_text(body)
        if pid is not None or name:
            base.update({
                "verdict": verdict, "scope": "process",
                "pid": pid, "process_name": name,
                "excerpt": _trim(body),
            })
            return base
        # Conclusion with no narrower entity (e.g. "The finding is a
        # false positive: ..."). Record at finding scope -- never block
        # a process from this (TASK 3).
        base.update({
            "verdict": verdict, "scope": "finding",
            "excerpt": _trim(body),
        })
        return base

    # Bare "Fxxx: ReAct flagged FALSE POSITIVE" line -> benign at
    # finding scope (the paired CONCLUDED line carries the PID).
    base.update({
        "verdict": VERDICT_BENIGN, "scope": "finding",
        "excerpt": _trim(line.strip()),
    })
    return base


# ── B1: schema-aware extraction (final conclusions only) ───────────────
def _record_from_dict(d: dict) -> dict | None:
    """Build one normalized verdict record from a structured dict, or
    None if the dict is not a genuine conclusion."""
    if not isinstance(d, dict):
        return None

    action = _norm(d.get("action"))
    rc = d.get("react_conclusion") if isinstance(
        d.get("react_conclusion"), dict) else None

    verdict = None
    is_fp = bool(d.get("is_false_positive"))
    if rc is not None:
        verdict = _normalize_verdict(rc.get("verdict"))
        is_fp = is_fp or bool(rc.get("is_false_positive"))
    if verdict is None:
        verdict = _normalize_verdict(d.get("verdict"))

    conclusion_text = (
        d.get("conclusion") or d.get("text")
        or (rc.get("text") if rc else "") or ""
    )
    concluded_match = _CONCLUDED_RE.search(str(conclusion_text))

    has_conclusion_signal = (
        action == "conclude"
        or verdict is not None
        or concluded_match is not None
        or is_fp
    )
    if not has_conclusion_signal:
        return None

    if verdict is None:
        if is_fp:
            verdict = VERDICT_BENIGN
        elif concluded_match:
            # Verdict embedded in the CONCLUDED line, else inconclusive.
            verdict = (
                _normalize_verdict(concluded_match.group(1).split()[0])
                or VERDICT_INCONCLUSIVE
            )
        else:
            verdict = VERDICT_INCONCLUSIVE

    fid = (d.get("finding_id") or d.get("fid")
           or (rc.get("finding_id") if rc else None))
    source_ids = [str(fid)] if fid else []

    chain_members = d.get("chain_members")
    if not isinstance(chain_members, list):
        chain_members = None

    text = str(conclusion_text or "")
    pid = d.get("pid")
    name = d.get("process") or d.get("process_name") or d.get("name")
    chain_member_pids = None
    scope = _norm(d.get("scope")) or None

    # The PID frequently lives in the conclusion text, not a field
    # (real coordinator react_conclusion shape). Recover it so the
    # entity collides on process:<pid> (TASK 1).
    if chain_members is None and scope != "chain" and _looks_like_chain(text):
        chain_members, chain_member_pids = _chain_members_and_pids(text)
        scope = "chain"
    elif scope == "chain" and chain_members:
        chain_member_pids = sorted(
            {int(p) for p, _ in _PID_PAREN_RE.findall(text)}) or None
    elif pid is None and not name:
        tpid, tname = _parse_pid_name(text)
        if tpid is not None:
            pid, name = tpid, tname

    rec = {
        "verdict": verdict,
        "scope": scope,
        "pid": pid,
        "process_name": name,
        "file": (d.get("file") or d.get("path") or d.get("filename")
                 or d.get("hash") or d.get("sha256")),
        "network": (d.get("network") or d.get("tuple")
                    or d.get("listener") or d.get("connection")),
        "chain_members": chain_members,
        "chain_member_pids": chain_member_pids,
        "source_finding_ids": source_ids,
        "evidence_refs": [
            r for r in (d.get("evidence_refs") or d.get("tool_refs") or [])
            if isinstance(r, (str, int))
        ],
        "excerpt": _trim(conclusion_text or d.get("verdict")),
    }
    return rec


def _records_from_text(text: str, finding_hint: str | None) -> list[dict]:
    """Extract FINAL-conclusion records from coordinator text/log/md.

    Strict (TASK 2): only genuine ``CONCLUDED -- ...`` lines and
    ``ReAct flagged FALSE POSITIVE`` lines yield a record. Prompt
    templates (which contain a literal ``"verdict": "..."`` and
    instruction bullets mentioning "false positive") and reasoning
    prose produce nothing.
    """
    recs: list[dict] = []
    for line in str(text).splitlines():
        rec = _parse_conclusion_line(line, finding_hint)
        if rec is not None:
            recs.append(rec)
    return recs


def _iter_structured(obj: Any):
    """Yield candidate dicts from investigation_threads / inv3 JSON."""
    if isinstance(obj, dict):
        for key in ("investigations", "threads", "findings", "records"):
            val = obj.get(key)
            if isinstance(val, list):
                yield from (x for x in val if isinstance(x, dict))
        # A single conclusion object.
        if any(k in obj for k in ("verdict", "action", "react_conclusion",
                                  "conclusion")):
            yield obj
    elif isinstance(obj, list):
        yield from (x for x in obj if isinstance(x, dict))


def extract_react_verdicts(paths_or_state_dir: Any) -> list[dict]:
    """Extract normalized final-conclusion verdict records.

    Accepts a state-dir path (str/Path) or an explicit list of file
    paths. Sources: ``investigation_threads.json``,
    ``inv3_response.json``, ``inv3_F*_turn*.md``. The live log is
    consulted only when explicitly passed (diagnostics).

    Returns a list of normalized records. Reasoning-only text never
    yields a record (REACT_VERDICT_EXTRACTION_GATE).
    """
    files: list[Path] = []
    if isinstance(paths_or_state_dir, (list, tuple)):
        files = [Path(p) for p in paths_or_state_dir]
    else:
        base = Path(paths_or_state_dir)
        if base.is_dir():
            # findings_*.json carry the real react_conclusion verdicts;
            # investigation_threads/inv3 carry structured threads. The
            # live coordinator log is intentionally NOT auto-added (it
            # is a diagnostics-only source -- pass it explicitly).
            for name in ("findings_revalidated.json", "findings_final.json",
                         "findings_validated.json",
                         "investigation_threads.json",
                         "inv3_response.json"):
                p = base / name
                if p.is_file():
                    files.append(p)
            files.extend(sorted(base.glob("inv3_*turn*.md")))
        elif base.is_file():
            files.append(base)

    records: list[dict] = []
    for fp in files:
        try:
            raw = fp.read_text(errors="ignore")
        except OSError:
            continue
        if fp.suffix == ".json":
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            for d in _iter_structured(data):
                rec = _record_from_dict(d)
                if rec is not None:
                    records.append(rec)
            continue
        # .md / .log / .txt and anything else: strict line scan only.
        hint = None
        m = re.search(r"inv3_(F[\w.-]+)_turn", fp.name)
        if m:
            hint = m.group(1)
        records.extend(_records_from_text(raw, hint))
    return records


# ── B2: scope classification ───────────────────────────────────────────
def classify_react_verdict_scope(record: dict) -> str:
    """Classify a verdict record's entity scope.

    A chain (>=2 ordered members or explicit chain scope) is ``chain``
    and never collapses into ``process`` -- only a separate
    process-scope record can mark a process malicious
    (REACT_CHAIN_ENTITY_SCOPE_GATE).
    """
    if not isinstance(record, dict):
        return "unknown"

    explicit = _norm(record.get("scope"))
    members = record.get("chain_members")
    is_chain = (
        explicit == "chain"
        or (isinstance(members, list) and len(members) >= 2)
    )
    if is_chain:
        return "chain"
    if explicit in SCOPES and explicit not in ("chain", "unknown"):
        return explicit

    if record.get("pid") is not None or record.get("process_name"):
        return "process"
    if record.get("file"):
        return "file"
    if record.get("network"):
        return "network"
    if record.get("source_finding_ids"):
        return "finding"
    return "unknown"


# ── B3: canonical entity key + ledger ──────────────────────────────────
def _norm_token(s: Any) -> str:
    return re.sub(r"\s+", "_", _norm(s))


def canonical_entity_key(record: dict) -> str:
    """Stable entity key for the ledger.

    process:<pid> (PID present -- the canonical identity; process
    names are aliases, NOT part of the key, so
    "PID NNNN" and "PID NNNN (process.exe)" collide) |
    process_name:<name> (PID absent) | file:<path-or-name> |
    network:<tuple> | chain:<a->b->c> | finding:<id> | unknown:<digest>.
    """
    scope = classify_react_verdict_scope(record)
    if scope == "process":
        pid = record.get("pid")
        if pid is not None and str(pid).strip() != "":
            return "process:%s" % pid
        return "process_name:%s" % _norm_token(record.get("process_name"))
    if scope == "file":
        return "file:%s" % _norm_token(record.get("file"))
    if scope == "network":
        return "network:%s" % _norm_token(record.get("network"))
    if scope == "chain":
        members = record.get("chain_members") or []
        sig = "->".join(_norm_token(m) for m in members)
        return "chain:%s" % sig
    if scope == "finding":
        sids = record.get("source_finding_ids") or ["?"]
        return "finding:%s" % _norm_token(sids[0])
    return "unknown:%s" % _norm_token(record.get("excerpt"))[:40]


def build_react_entity_verdict_ledger(records: list[dict]) -> dict:
    """Fold verdict records into a per-entity ledger.

    Each ledger value carries entity_key, scope, the set of distinct
    verdicts, source_finding_ids, evidence_refs and trimmed excerpts.
    """
    ledger: dict[str, dict] = {}
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        verdict = _normalize_verdict(rec.get("verdict"))
        if verdict is None:
            continue
        key = canonical_entity_key(rec)
        scope = classify_react_verdict_scope(rec)
        entry = ledger.get(key)
        if entry is None:
            entry = {
                "entity_key": key,
                "scope": scope,
                "verdicts": [],
                "source_finding_ids": [],
                "evidence_refs": [],
                "excerpts": [],
                "chain_members": rec.get("chain_members"),
                "chain_member_pids": [],
                "process_aliases": [],
                "pids": [],
                "display_name": None,
            }
            ledger[key] = entry
        if verdict not in entry["verdicts"]:
            entry["verdicts"].append(verdict)
        for fid in rec.get("source_finding_ids") or []:
            if fid and fid not in entry["source_finding_ids"]:
                entry["source_finding_ids"].append(str(fid))
        for ref in rec.get("evidence_refs") or []:
            if ref not in entry["evidence_refs"]:
                entry["evidence_refs"].append(ref)
        ex = _trim(rec.get("excerpt"))
        if ex and ex not in entry["excerpts"]:
            entry["excerpts"].append(ex)
        # TASK 1: names are aliases on the PID entity, not key parts.
        nm = rec.get("process_name")
        if nm:
            nm = str(nm).strip()
            if nm and nm not in entry["process_aliases"]:
                entry["process_aliases"].append(nm)
            if entry["display_name"] is None:
                entry["display_name"] = nm
        rp = rec.get("pid")
        if rp is not None and str(rp).strip() != "":
            try:
                rpi = int(rp)
                if rpi not in entry["pids"]:
                    entry["pids"].append(rpi)
            except (TypeError, ValueError):
                pass
        for cp in rec.get("chain_member_pids") or []:
            if cp not in entry["chain_member_pids"]:
                entry["chain_member_pids"].append(int(cp))
        if not entry.get("chain_members") and rec.get("chain_members"):
            entry["chain_members"] = rec.get("chain_members")
    for entry in ledger.values():
        entry["process_aliases"].sort()
        entry["pids"].sort()
        entry["chain_member_pids"].sort()
    return ledger


# ── B4/B5: contradiction detection (informational) + routing ───────────
# Process/file/network entities are the policy surface for fail-closed
# routing. A chain conflict is recorded informationally but does not by
# itself force member processes anywhere (scope discipline).
_ROUTABLE_SCOPES = ("process", "file", "network")


def detect_react_entity_contradictions(ledger: dict) -> list[dict]:
    """Return one conflict record per contradicted entity.

    A contradiction exists when an entity carries ``malicious`` AND at
    least one of ``benign`` / ``inconclusive``. Detection is
    informational (REACT_ENTITY_VERDICT_CONFLICT_DETECTED_GATE); routing
    is a separate decision (REACT_CONTRADICTION_ROUTE_GATE).
    """
    ledger = ledger or {}

    def _conflicting(entry: dict) -> list[dict]:
        out = []
        for v in sorted(set(entry.get("verdicts") or [])):
            out.append({
                "verdict": v,
                "source_finding_ids": list(
                    entry.get("source_finding_ids") or []),
                "excerpt": _trim("; ".join(entry.get("excerpts") or [])),
                "evidence_refs": list(entry.get("evidence_refs") or []),
            })
        return out

    by_key: dict[str, dict] = {}

    # TASK 3: direct contradiction -- malicious mixed with benign or
    # inconclusive on the SAME process/file/network/finding entity.
    for key, entry in ledger.items():
        verdicts = set(entry.get("verdicts") or [])
        if VERDICT_MALICIOUS in verdicts and (
            VERDICT_BENIGN in verdicts or VERDICT_INCONCLUSIVE in verdicts
        ):
            scope = entry.get("scope", "unknown")
            by_key[key] = {
                "entity_key": key,
                "scope": scope,
                "conflict_type": "direct_entity_verdict_conflict",
                "conflicting_verdicts": _conflicting(entry),
                "routing_decision": (
                    "blocked_from_confirmed_atomic"
                    if scope in _ROUTABLE_SCOPES else "flagged_for_review"
                ),
                "tiebreaker_required": True,
            }

    # TASK 4: chain-member tension -- a malicious chain whose member
    # process has a direct benign/inconclusive verdict. The member
    # process is NOT marked malicious (scope discipline); the tension
    # is recorded and the member process is blocked from confirmed.
    for entry in ledger.values():
        if entry.get("scope") != "chain":
            continue
        if VERDICT_MALICIOUS not in set(entry.get("verdicts") or []):
            continue
        for cp in entry.get("chain_member_pids") or []:
            pkey = "process:%s" % cp
            pentry = ledger.get(pkey)
            if not pentry:
                continue
            pv = set(pentry.get("verdicts") or [])
            if not (VERDICT_BENIGN in pv or VERDICT_INCONCLUSIVE in pv):
                continue
            if pkey in by_key:
                # Already a direct conflict; keep the stronger record.
                continue
            cv = _conflicting(pentry)
            cv.append({
                "verdict": VERDICT_MALICIOUS,
                "source_finding_ids": list(
                    entry.get("source_finding_ids") or []),
                "excerpt": _trim("chain: " + "; ".join(
                    entry.get("excerpts") or [])),
                "evidence_refs": list(entry.get("evidence_refs") or []),
            })
            by_key[pkey] = {
                "entity_key": pkey,
                "scope": "process",
                "conflict_type": "chain_member_tension",
                "conflicting_verdicts": cv,
                "routing_decision": "blocked_from_confirmed_atomic",
                "tiebreaker_required": True,
            }

    return list(by_key.values())


def write_react_entity_conflicts(
    state_dir: Any,
    conflicts: list[dict],
    head: str,
) -> Path:
    """Write the deterministic conflict artifact (B6 scaffold; no AI).

    Always writes a schema-valid file (possibly with an empty
    ``conflicts`` list) so a downstream entity-level tiebreaker has a
    stable input. Returns the artifact path.
    """
    out = {
        "schema_version": CONFLICT_SCHEMA_VERSION,
        "generated_at_epoch": int(time.time()),
        "head": str(head),
        "conflicts": list(conflicts or []),
    }
    base = Path(state_dir)
    base.mkdir(parents=True, exist_ok=True)
    path = base / CONFLICT_ARTIFACT_NAME
    path.write_text(json.dumps(out, indent=2, sort_keys=True))
    return path


def _entity_keys_for_finding(finding: dict) -> set[str]:
    """All entity keys a finding could depend on (pid/process/file/net)."""
    keys: set[str] = set()
    if not isinstance(finding, dict):
        return keys
    pid = finding.get("pid")
    name = (finding.get("process") or finding.get("process_name"))
    if pid is not None and str(pid).strip() != "":
        keys.add("process:%s" % pid)
    if name:
        keys.add("process_name:%s" % _norm_token(name))
    for claim in finding.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        cpid = claim.get("pid")
        cname = claim.get("process") or claim.get("process_name")
        if cpid is not None and str(cpid).strip() != "":
            keys.add("process:%s" % cpid)
        if cname:
            keys.add("process_name:%s" % _norm_token(cname))
        f = (claim.get("file") or claim.get("path")
             or claim.get("hash") or claim.get("sha256"))
        if f:
            keys.add("file:%s" % _norm_token(f))
        net = claim.get("network") or claim.get("tuple")
        if net:
            keys.add("network:%s" % _norm_token(net))
    return keys


def findings_blocked_by_react_conflicts(
    findings: list[dict],
    conflicts: list[dict],
) -> set[str]:
    """Finding ids that must be routed out of confirmed_malicious_atomic.

    A finding is blocked when it is named in a conflict's
    ``source_finding_ids`` OR it depends on a contradicted routable
    (process/file/network) entity.
    """
    blocked: set[str] = set()
    routable = [
        c for c in (conflicts or [])
        if c.get("scope") in _ROUTABLE_SCOPES
    ]
    conflicted_keys = {c.get("entity_key") for c in routable}
    conflicted_fids: set[str] = set()
    for c in routable:
        for cv in c.get("conflicting_verdicts") or []:
            conflicted_fids.update(
                str(x) for x in (cv.get("source_finding_ids") or []))
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("finding_id") or "")
        if fid and fid in conflicted_fids:
            blocked.add(fid)
            continue
        if _entity_keys_for_finding(f) & conflicted_keys:
            if fid:
                blocked.add(fid)
    return blocked


def is_finding_react_conflicted(
    finding: dict,
    conflicts: list[dict],
) -> bool:
    """True when this single finding depends on a contradicted entity."""
    if not isinstance(finding, dict):
        return False
    return bool(findings_blocked_by_react_conflicts([finding], conflicts))


def react_conflict_reasons(
    findings: list[dict],
    conflicts: list[dict],
) -> dict[str, str]:
    """Map blocked finding_id -> conflict_type reason (TASK 6).

    Reason is ``entity_verdict_conflict`` or ``chain_member_tension``
    so the routing record can name WHY confirmed_atomic was denied.
    """
    routable = [
        c for c in (conflicts or [])
        if c.get("scope") in _ROUTABLE_SCOPES
    ]
    key_reason = {
        c.get("entity_key"): c.get("conflict_type", "direct_entity_verdict_conflict")
        for c in routable
    }
    fid_reason: dict[str, str] = {}
    for c in routable:
        for cv in c.get("conflicting_verdicts") or []:
            for x in cv.get("source_finding_ids") or []:
                fid_reason.setdefault(
                    str(x), c.get("conflict_type",
                                  "direct_entity_verdict_conflict"))
    out: dict[str, str] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("finding_id") or "")
        if not fid:
            continue
        if fid in fid_reason:
            out[fid] = fid_reason[fid]
            continue
        hit = _entity_keys_for_finding(f) & set(key_reason)
        if hit:
            # Prefer a direct entity conflict over a chain tension.
            reasons = {key_reason[k] for k in hit}
            out[fid] = ("direct_entity_verdict_conflict"
                        if "direct_entity_verdict_conflict" in reasons
                        else sorted(reasons)[0])
    return out


def verdict_records_from_findings(findings: list[dict]) -> list[dict]:
    """Build verdict records from in-memory findings' react_conclusion.

    Used by the coordinator so production routing does not depend on
    re-reading state files (the verdicts already live on the findings).
    """
    recs: list[dict] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rec = _record_from_dict(f)
        if rec is not None:
            recs.append(rec)
    return recs


def summarize_react_contradictions_for_run(
    run_json: Any,
    live_log: Any = None,
) -> dict:
    """Mechanical diagnostic for an existing run (TASK 5).

    Accepts a run JSON path (or parsed dict) and an optional live log
    path. Returns counts only -- no production code path hardcodes a
    specific run. Dataset-agnostic.
    """
    if isinstance(run_json, (str, Path)):
        run = json.loads(Path(run_json).read_text(errors="ignore"))
    else:
        run = dict(run_json or {})
    state_dir = Path(run.get("state_dir", "."))
    paths: list[Path] = []
    for name in ("findings_revalidated.json", "findings_final.json",
                 "findings_validated.json", "investigation_threads.json",
                 "inv3_response.json"):
        p = state_dir / name
        if p.is_file():
            paths.append(p)
    paths.extend(sorted(state_dir.glob("inv3_F*_turn*.md")))
    if live_log and Path(live_log).exists():
        paths.append(Path(live_log))

    records = extract_react_verdicts(paths)
    ledger = build_react_entity_verdict_ledger(records)
    conflicts = detect_react_entity_contradictions(ledger)
    direct = [c for c in conflicts
              if c.get("conflict_type") == "direct_entity_verdict_conflict"]
    tension = [c for c in conflicts
               if c.get("conflict_type") == "chain_member_tension"]
    return {
        "verdict_records": len(records),
        "entity_count": len(ledger),
        "direct_conflicts": len(direct),
        "chain_member_tensions": len(tension),
        "total_conflicts": len(conflicts),
        "conflict_keys": [c.get("entity_key") for c in conflicts],
    }
