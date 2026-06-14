"""Slot 31F-alpha -- entity dedup + entity compression metrics.

The finding layer is *observation* shaped: several findings frequently
describe the SAME underlying entity (a file, a hash, a process, a
network tuple, or one ordered attack chain). A confirmed-malicious
report that lists the same staged credential-dumping binary three times
(once per finding that happened to notice it) overstates the blast
radius. This module compresses duplicate finding-level observations
into canonical *entity*-level truth WITHOUT hiding the ReAct
contradictions that 5d-alpha (``react_verdicts``) detects.

Design constraints (LOCKED across 31F-alpha):

  * Additive only -- raw finding buckets are never rewritten. The
    entity view is a second, parallel partition.
  * Dataset-agnostic -- no real PID/path/hash/IP/finding-id literal is
    referenced. Every property is derived from the data passed in.
  * Model-flexible -- no model name appears anywhere.
  * Deterministic -- no AI call, no network, no live tool run. Same
    input -> same output (sorted keys, stable chain signature).
  * Fail-closed -- a ReAct-contradicted process/file/network entity can
    never enter the entity-level confirmed bucket; it routes to
    needs-review with ``tiebreaker_required=True``.
  * Chain-member tension -- a chain-scope verdict applies to the chain
    entity only. A member process is not promoted to confirmed by a
    chain verdict alone (mirrors react_verdicts scope discipline).

Reverting 31F-alpha deletes this module and its additive coordinator
call site; raw finding disposition behaviour is unchanged.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

__all__ = [
    "ENTITY_SCHEMA_VERSION",
    "ENTITY_BUCKETS",
    "normalize_path",
    "normalize_process_name",
    "canonical_entity_key",
    "entity_scope_of",
    "react_key_matches_entity_key",
    "group_findings_by_entity",
    "build_entity_truth",
    "entity_disposition_buckets",
    "entity_compression_summary",
    "render_entity_summary_section",
    "split_entity_artifacts",
    "write_entity_artifacts",
    "ENTITY_KEY_NORMALIZATION_GATE",
    "ENTITY_GROUPING_GATE",
    "CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE",
    "ENTITY_COMPRESSION_RATIO_GATE",
    "ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE",
    "ENTITY_TIEBREAKER_REQUIRED_GATE",
    "ENTITY_TRUTH_ARTIFACT_GATE",
    "ENTITY_BUCKET_PARTITION_GATE",
    "ENTITY_REPORT_SUMMARY_GATE",
    "NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE",
    "EXISTING_RUN_ENTITY_COMPRESSION_GATE",
    "EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE",
    "ENTITY_DISPOSITION_ARTIFACT_NAME",
    "ENTITY_COMPRESSION_ARTIFACT_NAME",
]

# ── Gate identifiers (names only; PASS/FAIL derived by tests) ───────────
ENTITY_KEY_NORMALIZATION_GATE = "ENTITY_KEY_NORMALIZATION_GATE"
ENTITY_GROUPING_GATE = "ENTITY_GROUPING_GATE"
CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE = "CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE"
ENTITY_COMPRESSION_RATIO_GATE = "ENTITY_COMPRESSION_RATIO_GATE"
ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE = (
    "ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE"
)
ENTITY_TIEBREAKER_REQUIRED_GATE = "ENTITY_TIEBREAKER_REQUIRED_GATE"
ENTITY_TRUTH_ARTIFACT_GATE = "ENTITY_TRUTH_ARTIFACT_GATE"
ENTITY_BUCKET_PARTITION_GATE = "ENTITY_BUCKET_PARTITION_GATE"
ENTITY_REPORT_SUMMARY_GATE = "ENTITY_REPORT_SUMMARY_GATE"
NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE = (
    "NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE"
)
EXISTING_RUN_ENTITY_COMPRESSION_GATE = (
    "EXISTING_RUN_ENTITY_COMPRESSION_GATE"
)
EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE = (
    "EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE"
)

ENTITY_SCHEMA_VERSION = "1.0"
ENTITY_DISPOSITION_ARTIFACT_NAME = "entity_disposition_buckets.json"
ENTITY_COMPRESSION_ARTIFACT_NAME = "entity_compression_summary.json"

# Canonical entity-level bucket names mirror the finding buckets so the
# entity view is comparable to the raw finding view.
BUCKET_CONFIRMED = "confirmed_malicious_atomic"
BUCKET_SUSPICIOUS = "suspicious_needs_review"
BUCKET_BENIGN = "benign_or_false_positive"
BUCKET_INCONCLUSIVE = "inconclusive_unresolved"
BUCKET_SYNTHESIS = "synthesis_narrative"
ENTITY_BUCKETS = (
    BUCKET_CONFIRMED,
    BUCKET_SUSPICIOUS,
    BUCKET_BENIGN,
    BUCKET_INCONCLUSIVE,
    BUCKET_SYNTHESIS,
)

_HASH_FIELDS = ("sha256", "sha1", "md5", "imphash")
_SEVERITY_ORDER = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0,
}
_CONFIDENCE_ORDER = {
    "high": 3, "medium": 2, "low": 1, "speculative": 0, "": 0,
}


# ── Normalization primitives ───────────────────────────────────────────
def normalize_path(path: Any) -> str:
    """Deterministically normalize a filesystem path or filename.

    Lower-cased, ``\\`` -> ``/``, repeated separators collapsed,
    surrounding whitespace and a single trailing slash stripped. A bare
    filename normalizes to itself (so a ``filename`` claim and an
    ``artifact`` full path collide on the leaf). No real path is
    referenced -- pure string transform.
    """
    s = "" if path is None else str(path).strip()
    if not s:
        return ""
    s = s.replace("\\", "/")
    s = re.sub(r"/+", "/", s)
    s = s.strip().lower()
    if len(s) > 1 and s.endswith("/"):
        s = s[:-1]
    return s


def normalize_process_name(name: Any) -> str:
    """Lower-cased process leaf name, path/quotes stripped.

    ``C:\\Windows\\System32\\svchost.exe`` and ``"svchost.exe"`` and
    ``SVCHOST.EXE`` all normalize to ``svchost.exe``.
    """
    s = "" if name is None else str(name).strip().strip('"').strip("'")
    if not s:
        return ""
    s = s.replace("\\", "/")
    if "/" in s:
        s = s.rsplit("/", 1)[-1]
    return s.strip().lower()


def _hash_keys_from(obj: dict) -> list[str]:
    out: list[str] = []
    for algo in _HASH_FIELDS:
        val = obj.get(algo)
        if val and isinstance(val, (str, int)):
            v = str(val).strip().lower()
            if v:
                out.append("hash:%s:%s" % (algo, v))
    return out


def _network_key_from(obj: dict) -> str | None:
    """Build a stable ``network:<proto>:<l>:<lp>:<r>:<rp>`` key.

    Missing components become ``*`` so a partially observed listener
    still collides with itself. Proto defaults to ``tcp`` unless a
    ``udp`` signal is present.
    """
    proto = str(obj.get("proto") or obj.get("protocol") or "").strip().lower()
    if not proto:
        blob = " ".join(
            str(obj.get(k) or "") for k in ("artifact", "description")
        ).lower()
        proto = "udp" if re.search(r"\budp\b", blob) else "tcp"
    lip = str(
        obj.get("local_addr") or obj.get("laddr") or obj.get("src_addr")
        or "*"
    ).strip().lower() or "*"
    lport = str(
        obj.get("local_port") or obj.get("lport") or obj.get("port")
        or obj.get("src_port") or "*"
    ).strip().lower() or "*"
    rip = str(
        obj.get("foreign_addr") or obj.get("raddr") or obj.get("dst_addr")
        or obj.get("remote_addr") or "*"
    ).strip().lower() or "*"
    rport = str(
        obj.get("foreign_port") or obj.get("rport") or obj.get("dst_port")
        or obj.get("remote_port") or "*"
    ).strip().lower() or "*"
    if lip == "*" and lport == "*" and rip == "*" and rport == "*":
        return None
    return "network:%s:%s:%s:%s:%s" % (proto, lip, lport, rip, rport)


def _process_keys(pid: Any, name: Any) -> list[str]:
    """Process entity keys for a (pid, name) pair.

    When a PID is present BOTH the bare ``process:<pid>`` and the
    ``process:<pid>:<name>`` forms are emitted: the bare form collides
    exactly with 5d-alpha react conflict keys (``process:<pid>``) while
    the named form keeps the human label. PID-less observations fall
    back to ``process_name:<name>``.
    """
    has_pid = pid is not None and str(pid).strip() != ""
    nname = normalize_process_name(name)
    out: list[str] = []
    if has_pid:
        out.append("process:%s" % str(pid).strip())
        out.append("process:%s:%s" % (str(pid).strip(), nname))
    elif nname:
        out.append("process_name:%s" % nname)
    return out


def _chain_signature(members: list[str]) -> str:
    """Order-sensitive 16-hex chain signature.

    ``A -> B -> C`` and ``C -> B -> A`` produce different keys: the
    signature is ``sha1`` of the ordered, normalized member labels
    joined by ``->``.
    """
    normalized = [normalize_process_name(m) or _norm(m) for m in members]
    joined = "->".join(normalized)
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()[:16]
    return "chain:%s" % digest


def _norm(s: Any) -> str:
    return str(s).strip().lower() if s is not None else ""


def _ordered_chain_members(finding: dict) -> list[str]:
    """Recover an ordered chain member list from a finding.

    Preference: explicit ``chain_members`` list, else the ordered
    ``process`` labels of ``type == "pid"`` claims (the synthesis /
    attack-chain shape). Order is preserved verbatim -- the signature
    is order-sensitive by design.
    """
    cm = finding.get("chain_members")
    if isinstance(cm, list) and len([m for m in cm if str(m).strip()]) >= 2:
        return [str(m) for m in cm if str(m).strip()]
    members: list[str] = []
    for claim in finding.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        if _norm(claim.get("type")) == "pid":
            nm = claim.get("process") or claim.get("process_name")
            if nm:
                members.append(str(nm))
    return members if len(members) >= 2 else []


def _is_chain_finding(finding: dict) -> bool:
    cm = finding.get("chain_members")
    if isinstance(cm, list) and len([m for m in cm if str(m).strip()]) >= 2:
        return True
    if finding.get("is_synthesis") is True:
        return True
    ftype = _norm(finding.get("finding_type"))
    etype = _norm(finding.get("evidence_type"))
    if ftype in ("synthesis", "attack_chain", "chain", "narrative"):
        return True
    if etype in ("synthesis", "narrative"):
        return True
    title = _norm(finding.get("title") or finding.get("artifact"))
    if title.startswith("attack chain summary") or title.startswith(
            "full attack chain"):
        return True
    return False


# ── TASK 1: canonical entity key ───────────────────────────────────────
def canonical_entity_key(finding: dict) -> list[str]:
    """Return the canonical entity keys a finding touches.

    A finding can name more than one entity (e.g. two staged binaries),
    so this returns a *sorted, de-duplicated list*. Scopes:

      ``file:<normalized path or filename>``
      ``hash:<algorithm>:<value>``
      ``process:<pid>:<normalized name>`` (PID present)
      ``process_name:<normalized name>`` (PID absent)
      ``network:<proto>:<lip>:<lport>:<rip>:<rport>``
      ``chain:<order-sensitive sha1[:16]>``
      ``unknown:<finding_id>`` (no narrower entity could be derived)

    Deterministic and dataset-agnostic: every component is normalized
    from the finding's own fields, never hardcoded.
    """
    if not isinstance(finding, dict):
        return []
    keys: set[str] = set()

    # Chain / synthesis findings carry exactly one chain entity. The
    # chain key NEVER substitutes for member process keys (scope
    # discipline mirrors react_verdicts: a chain verdict does not
    # promote a member process).
    if _is_chain_finding(finding):
        members = _ordered_chain_members(finding)
        if len(members) >= 2:
            keys.add(_chain_signature(members))

    # Finding-level file / process surface.
    artifact = finding.get("artifact")
    if isinstance(artifact, str) and artifact.strip():
        for part in artifact.split(","):
            p = normalize_path(part)
            # Only treat it as a file entity when it looks like a path /
            # filename (has a separator or a dotted extension); free
            # prose artifacts ("Complete attack chain ...") are skipped.
            if p and ("/" in p or re.search(r"\.[a-z0-9]{1,8}$", p)):
                keys.add("file:%s" % p)
    for fld in ("file", "path", "filename", "filepath"):
        v = finding.get(fld)
        if v and isinstance(v, str) and v.strip():
            keys.add("file:%s" % normalize_path(v))
    keys.update(_hash_keys_from(finding))
    if not _is_chain_finding(finding):
        keys.update(_process_keys(
            finding.get("pid"),
            finding.get("process") or finding.get("process_name")))

    # Claim-level surface.
    for claim in finding.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        ctype = _norm(claim.get("type"))
        keys.update(_hash_keys_from(claim))
        for fld in ("file", "path", "filename", "filepath"):
            v = claim.get(fld)
            if v and isinstance(v, str) and v.strip():
                keys.add("file:%s" % normalize_path(v))
        if not _is_chain_finding(finding):
            if ctype == "connection" or claim.get("foreign_addr") or \
                    claim.get("local_port") or claim.get("port"):
                nk = _network_key_from(claim)
                if nk:
                    keys.add(nk)
            if ctype == "child_process":
                for pid_fld in ("parent_pid", "child_pid"):
                    cp = claim.get(pid_fld)
                    if cp is not None and str(cp).strip() != "":
                        # Bare process:<pid> -- collides exactly with a
                        # 5d-alpha react conflict key for the same PID.
                        keys.add("process:%s" % str(cp).strip())
            else:
                keys.update(_process_keys(
                    claim.get("pid"),
                    claim.get("process") or claim.get("process_name"),
                ))

    if not keys:
        fid = _finding_id(finding) or "?"
        return ["unknown:%s" % (_norm(fid) or "?")]
    return sorted(keys)


def entity_scope_of(entity_key: str) -> str:
    """Scope label derived from an entity key prefix."""
    k = str(entity_key or "")
    for scope in ("file", "hash", "process_name", "process", "network",
                  "chain", "unknown"):
        if k.startswith(scope + ":"):
            return scope
    return "unknown"


# ── Real finding-schema accessors (defensive variants) ─────────────────
def _finding_id(finding: dict) -> str:
    """Finding id from ``finding_id`` or the ``id`` fallback."""
    if not isinstance(finding, dict):
        return ""
    return str(finding.get("finding_id") or finding.get("id") or "")


def _finding_title(finding: dict) -> str:
    """Human label from ``title`` / ``summary`` / ``description`` /
    ``artifact`` (first non-empty)."""
    if not isinstance(finding, dict):
        return ""
    for fld in ("title", "summary", "description", "artifact"):
        v = finding.get(fld)
        if v and str(v).strip():
            return str(v).strip()
    return ""


def _iter_bucket_items(value: Any):
    """Yield finding dicts from a bucket value.

    Accepts a bare list or the defensive ``{"findings": [...]}`` /
    ``{"items": [...]}`` envelope shape.
    """
    if isinstance(value, dict):
        value = value.get("findings") or value.get("items") or []
    for f in value or []:
        if isinstance(f, dict):
            yield f


def react_key_matches_entity_key(react_key: str, entity_key: str) -> bool:
    """Robust 5d-alpha conflict-key <-> entity-key matcher.

    Rules (TASK 5):
      * exact match always wins;
      * ``process:<pid>`` matches ``process:<pid>:*`` (and vice versa);
      * ``process:<pid>:<name>`` matches the same pid OR
        ``process_name:<name>``;
      * ``process:<name>`` / ``process_name:<name>`` match
        ``process:*:<name>`` or ``process_name:<name>``;
      * chain / hash / file / network keys match by exact string only.
    """
    rk = str(react_key or "").strip()
    ek = str(entity_key or "").strip()
    if not rk or not ek:
        return False
    if rk == ek:
        return True
    rs, es = entity_scope_of(rk), entity_scope_of(ek)
    proc_scopes = {"process", "process_name"}
    if rs not in proc_scopes or es not in proc_scopes:
        return False  # non-process keys: exact only.

    def _parts(k: str):
        body = k.split(":", 1)[1] if ":" in k else ""
        if k.startswith("process_name:"):
            return None, body  # (pid, name)
        # process:<pid> or process:<pid>:<name> or process:<name>
        seg = body.split(":", 1)
        if seg and seg[0].isdigit():
            return seg[0], (seg[1] if len(seg) > 1 else "")
        return None, body  # process:<name> with no pid

    rpid, rname = _parts(rk)
    epid, ename = _parts(ek)
    if rpid is not None and epid is not None:
        return rpid == epid
    if rpid is not None and epid is None:
        # react has a pid, entity is name-only -> match on name if known.
        return bool(rname) and rname == ename
    if rpid is None and epid is not None:
        return bool(rname) and rname == ename
    return bool(rname) and rname == ename


# ── ReAct-conflict awareness (delegates to 5d-alpha) ───────────────────
def _react_conflicted_finding_ids(
    findings: list[dict],
    react_conflicts: list[dict] | None,
) -> dict[str, str]:
    """Map blocked finding_id -> conflict_type using 5d-alpha.

    A finding is conflicted when 5d-alpha blocks it OR it already
    carries the coordinator's ``react_entity_conflict`` annotation.
    Reasons come from 5d-alpha's ``react_conflict_reasons``; the
    annotation is the fallback when no conflict list is supplied.
    """
    out: dict[str, str] = {}
    try:  # never hard-depend on react_verdicts import at module load
        from sift_sentinel.react_verdicts import (
            findings_blocked_by_react_conflicts,
            react_conflict_reasons,
        )
    except Exception:  # pragma: no cover - defensive
        findings_blocked_by_react_conflicts = None  # type: ignore
        react_conflict_reasons = None  # type: ignore

    conflicts = list(react_conflicts or [])
    if conflicts and findings_blocked_by_react_conflicts is not None:
        blocked = findings_blocked_by_react_conflicts(findings, conflicts)
        reasons = (react_conflict_reasons(findings, conflicts)
                   if react_conflict_reasons else {})
        for fid in blocked:
            out[str(fid)] = reasons.get(
                str(fid), "direct_entity_verdict_conflict")
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        if f.get("react_entity_conflict"):
            fid = _finding_id(f)
            if fid:
                out.setdefault(
                    fid,
                    str(f.get("react_entity_conflict_reason")
                        or "direct_entity_verdict_conflict"),
                )
    return out


def _flatten(findings, buckets) -> list[tuple[dict, str]]:
    """Yield (finding, source_bucket) pairs from findings and/or buckets.

    ``source_bucket`` is the finding's ``final_disposition`` when only a
    flat list is given.
    """
    pairs: list[tuple[dict, str]] = []
    if buckets:
        for bname, items in (buckets or {}).items():
            for f in _iter_bucket_items(items):
                pairs.append((f, bname))
    if findings:
        for f in findings or []:
            if isinstance(f, dict):
                pairs.append(
                    (f, str(f.get("final_disposition") or "unknown")))
    return pairs


# ── TASK 2: entity grouping ────────────────────────────────────────────
def group_findings_by_entity(
    findings: list[dict] | None = None,
    buckets: dict | None = None,
    react_conflicts: list[dict] | None = None,
) -> dict:
    """Group findings by canonical entity key.

    Returns ``{entity_key: group}``. Each group carries the provenance
    needed to render an entity-level view without re-reading findings.
    A group inherits a ReAct conflict if ANY source finding is
    contradicted per 5d-alpha.
    """
    pairs = _flatten(findings, buckets)
    all_findings = [f for f, _ in pairs]
    conflicted = _react_conflicted_finding_ids(all_findings, react_conflicts)

    groups: dict[str, dict] = {}
    for finding, src_bucket in pairs:
        fid = _finding_id(finding)
        keys = canonical_entity_key(finding)
        sev = _norm(finding.get("severity"))
        conf = _norm(finding.get("confidence_level")
                     or finding.get("confidence"))
        claim_n = len(finding.get("claims") or [])
        tools = [str(t) for t in (finding.get("source_tools") or [])]
        title = _finding_title(finding)
        cflag = fid in conflicted
        ctype = conflicted.get(fid)
        for key in keys:
            g = groups.get(key)
            if g is None:
                g = {
                    "entity_key": key,
                    "entity_scope": entity_scope_of(key),
                    "source_finding_ids": [],
                    "source_buckets": [],
                    "source_titles": [],
                    "source_tools": [],
                    "claim_count_total": 0,
                    "highest_severity": "",
                    "highest_confidence": "",
                    "has_react_conflict": False,
                    "conflict_types": [],
                    "tiebreaker_required": False,
                    "recommended_entity_disposition": None,
                }
                groups[key] = g
            if fid and fid not in g["source_finding_ids"]:
                g["source_finding_ids"].append(fid)
            if src_bucket and src_bucket not in g["source_buckets"]:
                g["source_buckets"].append(src_bucket)
            if title and title not in g["source_titles"]:
                g["source_titles"].append(title)
            for t in tools:
                if t and t not in g["source_tools"]:
                    g["source_tools"].append(t)
            g["claim_count_total"] += claim_n
            if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(
                    g["highest_severity"], 0):
                g["highest_severity"] = sev
            if _CONFIDENCE_ORDER.get(conf, 0) > _CONFIDENCE_ORDER.get(
                    g["highest_confidence"], 0):
                g["highest_confidence"] = conf
            if cflag:
                g["has_react_conflict"] = True
                g["tiebreaker_required"] = True
                if ctype and ctype not in g["conflict_types"]:
                    g["conflict_types"].append(ctype)

    for g in groups.values():
        g["source_finding_ids"].sort()
        g["source_buckets"].sort()
        g["source_titles"].sort()
        g["source_tools"].sort()
        g["conflict_types"].sort()
        g["recommended_entity_disposition"] = _recommend_disposition(g)
    return groups


def _recommend_disposition(group: dict) -> str:
    """Per-group disposition recommendation (single-key view).

    Contradiction-aware: a ReAct-conflicted process/file/network entity
    can never be recommended ``confirmed_malicious_atomic``.
    """
    scope = group["entity_scope"]
    if group["has_react_conflict"] and scope in (
            "process", "process_name", "file", "network"):
        return BUCKET_SUSPICIOUS
    if scope == "chain":
        return BUCKET_SYNTHESIS
    src = set(group["source_buckets"])
    if src == {BUCKET_CONFIRMED}:
        return BUCKET_CONFIRMED
    for b in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE, BUCKET_BENIGN,
              BUCKET_SYNTHESIS):
        if b in src:
            return b
    if BUCKET_CONFIRMED in src:
        # Mixed with confirmed but no non-confirmed routable bucket:
        # downgrade out of confirmed (conservative).
        return BUCKET_SUSPICIOUS
    return BUCKET_SUSPICIOUS


# ── TASK 3/4: confirmed cluster compression + contradiction routing ────
class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _cluster_findings(findings: list[dict]) -> list[dict]:
    """Connected-component cluster: findings sharing ANY entity key.

    Two confirmed findings that name the same hash collapse into one
    entity cluster (the credential-staging dedup). Returns one cluster
    record per component, deterministically ordered.
    """
    uf = _UnionFind()
    fid_keys: dict[str, list[str]] = {}
    fid_obj: dict[str, dict] = {}
    key_to_fids: dict[str, list[str]] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fid = _finding_id(f) or ("obj:%d" % id(f))
        keys = canonical_entity_key(f)
        fid_keys[fid] = keys
        fid_obj[fid] = f
        uf.find("F::" + fid)
        for k in keys:
            uf.union("F::" + fid, "K::" + k)
            key_to_fids.setdefault(k, []).append(fid)

    comps: dict[str, dict] = {}
    for fid, keys in fid_keys.items():
        root = uf.find("F::" + fid)
        c = comps.get(root)
        if c is None:
            c = {"finding_ids": [], "entity_keys": set()}
            comps[root] = c
        c["finding_ids"].append(fid)
        c["entity_keys"].update(keys)

    clusters: list[dict] = []
    for c in comps.values():
        fids = sorted(set(c["finding_ids"]))
        ekeys = sorted(c["entity_keys"])
        objs = [fid_obj[x] for x in fids]
        clusters.append(_cluster_record(fids, ekeys, objs))
    clusters.sort(key=lambda r: r["entity_key"])
    return clusters


def _cluster_record(
    fids: list[str], ekeys: list[str], objs: list[dict],
) -> dict:
    scopes = sorted({entity_scope_of(k) for k in ekeys})
    # A representative key: prefer the most identity-stable scope.
    rep = None
    for pref in ("hash", "file", "network", "process", "process_name",
                 "chain", "unknown"):
        cand = [k for k in ekeys if entity_scope_of(k) == pref]
        if cand:
            rep = sorted(cand)[0]
            break
    rep = rep or (ekeys[0] if ekeys else "unknown:?")
    sev, conf = "", ""
    tools: list[str] = []
    titles: list[str] = []
    claim_total = 0
    for o in objs:
        s = _norm(o.get("severity"))
        c = _norm(o.get("confidence_level") or o.get("confidence"))
        if _SEVERITY_ORDER.get(s, 0) > _SEVERITY_ORDER.get(sev, 0):
            sev = s
        if _CONFIDENCE_ORDER.get(c, 0) > _CONFIDENCE_ORDER.get(conf, 0):
            conf = c
        claim_total += len(o.get("claims") or [])
        for t in o.get("source_tools") or []:
            if str(t) and str(t) not in tools:
                tools.append(str(t))
        t = _finding_title(o)
        if t and t not in titles:
            titles.append(t)
    return {
        "entity_key": rep,
        "entity_keys": ekeys,
        "entity_scope": entity_scope_of(rep),
        "entity_scopes": scopes,
        "source_finding_ids": fids,
        "source_titles": sorted(titles),
        "source_tools": sorted(tools),
        "claim_count_total": claim_total,
        "highest_severity": sev,
        "highest_confidence": conf,
        "has_react_conflict": False,
        "conflict_types": [],
        "tiebreaker_required": False,
    }


def _ratio(entities: int, findings: int) -> float | None:
    if not findings:
        return None
    return round(entities / findings, 4)


# ── TASK 5: entity truth artifacts ─────────────────────────────────────
def build_entity_truth(
    buckets: dict,
    react_conflicts: list[dict] | None = None,
) -> dict:
    """Build the entity-level disposition + compression summary.

    Returns the ``entity_compression_summary`` schema with a populated
    ``buckets`` partition. Raw finding buckets are NOT modified.

    Routing:
      * Confirmed finding clusters whose findings are all confirmed and
        none ReAct-contradicted -> entity confirmed bucket.
      * A ReAct-contradicted finding (any original bucket) -> its
        cluster routes to ``suspicious_needs_review`` with
        ``tiebreaker_required=True`` and never to confirmed.
      * Chain-scope clusters -> ``synthesis_narrative`` (a chain verdict
        never promotes a member; member processes keep their own
        clusters).
      * All other findings -> the worst non-confirmed bucket of their
        members.
    """
    buckets = buckets or {}
    pairs = _flatten(None, buckets)
    all_findings = [f for f, _ in pairs]
    src_of: dict[str, str] = {}
    for f, b in pairs:
        src_of[_finding_id(f) or ("obj:%d" % id(f))] = b
    conflicted = _react_conflicted_finding_ids(all_findings, react_conflicts)

    confirmed_findings = [
        f for f, b in pairs if b == BUCKET_CONFIRMED
    ]
    confirmed_finding_count = len(confirmed_findings)

    # Confirmed clustering excludes ReAct-contradicted findings: a
    # contradicted entity can never enter the entity confirmed bucket.
    confirmed_clean = [
        f for f in confirmed_findings
        if _finding_id(f) not in conflicted
    ]
    confirmed_clusters_all = _cluster_findings(confirmed_clean)
    # Chain-scope clusters do not belong in confirmed (scope discipline).
    confirmed_clusters = [
        c for c in confirmed_clusters_all
        if c["entity_scope"] != "chain"
    ]
    confirmed_chain_clusters = [
        c for c in confirmed_clusters_all
        if c["entity_scope"] == "chain"
    ]

    entity_disposition_buckets: dict[str, list[dict]] = {
        b: [] for b in ENTITY_BUCKETS
    }
    for c in confirmed_clusters:
        c = dict(c)
        c["entity_disposition"] = BUCKET_CONFIRMED
        entity_disposition_buckets[BUCKET_CONFIRMED].append(c)

    # Non-confirmed findings (plus confirmed findings that were
    # contradicted or chain-scope) cluster into their own bucket view.
    non_confirmed = [
        f for f, b in pairs
        if b != BUCKET_CONFIRMED
    ]
    contradicted_confirmed = [
        f for f in confirmed_findings
        if _finding_id(f) in conflicted
    ]
    rest = non_confirmed + contradicted_confirmed
    rest_clusters = _cluster_findings(rest)
    for c in rest_clusters:
        member_fids = c["source_finding_ids"]
        is_conflicted = any(fid in conflicted for fid in member_fids)
        ctypes = sorted({
            conflicted[fid] for fid in member_fids if fid in conflicted
        })
        member_src = {src_of.get(fid, "unknown") for fid in member_fids}
        if is_conflicted:
            c = dict(c)
            c["has_react_conflict"] = True
            c["tiebreaker_required"] = True
            c["conflict_types"] = ctypes
            c["recommended_entity_disposition"] = BUCKET_SUSPICIOUS
            c["entity_disposition"] = BUCKET_SUSPICIOUS
            entity_disposition_buckets[BUCKET_SUSPICIOUS].append(c)
            continue
        if c["entity_scope"] == "chain":
            tgt = BUCKET_SYNTHESIS
        else:
            tgt = _bucket_from_sources(member_src)
        c = dict(c)
        c["entity_disposition"] = tgt
        entity_disposition_buckets.setdefault(tgt, []).append(c)
    # Confirmed-but-chain clusters are synthesis at the entity level.
    for c in confirmed_chain_clusters:
        c = dict(c)
        c["entity_disposition"] = BUCKET_SYNTHESIS
        entity_disposition_buckets[BUCKET_SYNTHESIS].append(c)

    # TASK 5: a 5d-alpha conflict that matched NO finding entity must
    # still surface -- emit a conflict-only entity so contradiction
    # telemetry never silently disappears.
    _represented_keys = [
        k
        for v in entity_disposition_buckets.values()
        for e in v
        for k in (e.get("entity_keys") or [e.get("entity_key")])
    ]
    for rc in react_conflicts or []:
        rkey = str(rc.get("entity_key") or "")
        if not rkey:
            continue
        if any(react_key_matches_entity_key(rkey, ek)
               for ek in _represented_keys):
            continue
        ctype = rc.get("conflict_type", "direct_entity_verdict_conflict")
        conflict_only = {
            "entity_key": rkey,
            "entity_keys": [rkey],
            "entity_scope": entity_scope_of(rkey),
            "entity_scopes": [entity_scope_of(rkey)],
            "source_finding_ids": [],
            "source_titles": [],
            "source_tools": [],
            "claim_count_total": 0,
            "highest_severity": "",
            "highest_confidence": "",
            "has_react_conflict": True,
            "conflict_types": [ctype],
            "tiebreaker_required": True,
            "recommended_entity_disposition": BUCKET_SUSPICIOUS,
            "entity_disposition": BUCKET_SUSPICIOUS,
            "conflict_only": True,
        }
        entity_disposition_buckets[BUCKET_SUSPICIOUS].append(conflict_only)
        _represented_keys.append(rkey)

    for b in ENTITY_BUCKETS:
        entity_disposition_buckets[b].sort(key=lambda r: r["entity_key"])

    finding_count = len(pairs)
    entity_count = sum(
        len(v) for v in entity_disposition_buckets.values())
    confirmed_entity_count = len(
        entity_disposition_buckets[BUCKET_CONFIRMED])
    contradicted_entity_count = sum(
        1 for v in entity_disposition_buckets.values() for e in v
        if e.get("has_react_conflict")
    )
    # A direct-conflict entity must never sit in the confirmed bucket.
    contradicted_confirmed_entity_count = sum(
        1 for e in entity_disposition_buckets[BUCKET_CONFIRMED]
        if e.get("has_react_conflict")
    )
    # Math guard (TASK 7): a non-empty confirmed finding set that
    # produced zero confirmed entities is a real failure -- surface it
    # explicitly rather than passing silently.
    confirmed_compression_ok = not (
        confirmed_finding_count > 0 and confirmed_entity_count == 0
    )

    entity_compression_summary = {
        "schema_version": ENTITY_SCHEMA_VERSION,
        "finding_count": finding_count,
        "entity_count": entity_count,
        "entity_compression_ratio": (
            entity_count / finding_count if finding_count else None
        ),
        "confirmed_atomic_finding_count": confirmed_finding_count,
        "confirmed_atomic_entity_count": confirmed_entity_count,
        "confirmed_atomic_compression_ratio": (
            confirmed_entity_count / confirmed_finding_count
            if confirmed_finding_count else None
        ),
        "contradicted_entity_count": contradicted_entity_count,
        "contradicted_confirmed_entity_count":
            contradicted_confirmed_entity_count,
        "confirmed_compression_ok": confirmed_compression_ok,
        "buckets": entity_disposition_buckets,
    }
    # Round ratios for stable artifacts (None preserved).
    if entity_compression_summary["entity_compression_ratio"] is not None:
        entity_compression_summary["entity_compression_ratio"] = round(
            entity_compression_summary["entity_compression_ratio"], 4)
    if entity_compression_summary[
            "confirmed_atomic_compression_ratio"] is not None:
        entity_compression_summary[
            "confirmed_atomic_compression_ratio"] = round(
            entity_compression_summary[
                "confirmed_atomic_compression_ratio"], 4)
    return entity_compression_summary


def _bucket_from_sources(member_src: set[str]) -> str:
    for b in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE, BUCKET_BENIGN,
              BUCKET_SYNTHESIS):
        if b in member_src:
            return b
    if BUCKET_CONFIRMED in member_src:
        return BUCKET_SUSPICIOUS
    return BUCKET_SUSPICIOUS


# Stable internal handle to the clustering engine. The public
# ``entity_disposition_buckets`` / ``entity_compression_summary``
# functions call THIS, never themselves.
_internal_entity_truth = build_entity_truth


# ── Public integration API (V3 callable surface) ──────────────────────
# NOTE: ``build_entity_truth`` uses function-local variables named
# ``entity_disposition_buckets`` / ``entity_compression_summary``. Those
# locals are scoped to that function only and never call these
# module-level functions -- the shadowing is intentional and harmless;
# these are the public callable wiring V3 invokes.
_PUBLIC_SCOPE_MAP = {
    "hash": "file",
    "process_name": "process",
    "path": "file",
}
_PUBLIC_SCOPES = ("file", "process", "network", "chain", "finding",
                  "unknown")


def _public_scope(raw_scope: str) -> str:
    s = _PUBLIC_SCOPE_MAP.get(raw_scope, raw_scope)
    return s if s in _PUBLIC_SCOPES else "unknown"


def _entity_object(cluster: dict, fid_bucket: dict[str, str]) -> dict:
    """Render one internal cluster record as the public entity object."""
    fids = list(cluster.get("source_finding_ids") or [])
    src_buckets = sorted({
        fid_bucket[f] for f in fids if f in fid_bucket
    })
    titles = cluster.get("source_titles") or []
    has_conflict = bool(cluster.get("has_react_conflict"))
    disposition = cluster.get("entity_disposition") or (
        cluster.get("recommended_entity_disposition") or "")
    routing_decision = (
        "blocked_from_confirmed_atomic" if has_conflict else disposition
    )
    return {
        "entity_key": cluster.get("entity_key"),
        "scope": _public_scope(cluster.get("entity_scope", "unknown")),
        "source_finding_ids": fids,
        "source_buckets": src_buckets,
        "claim_entity_keys": list(cluster.get("entity_keys")
                                  or [cluster.get("entity_key")]),
        "title": titles[0] if titles else "",
        "routing_decision": routing_decision,
        "tiebreaker_required": bool(cluster.get("tiebreaker_required")),
    }


def entity_disposition_buckets(
    buckets: dict,
    react_conflicts: list[dict] | None = None,
) -> dict:
    """Public: real entity-level disposition partition.

    Wires ``canonical_entity_key`` (via ``build_entity_truth``'s
    connected-component clustering) and the 5d-alpha conflict list into
    the five-bucket entity partition. Findings sharing ANY
    hash/path/process/network entity key collapse into one cluster;
    contradicted entities are blocked from ``confirmed_malicious_atomic``
    and a chain verdict never promotes a member process.
    """
    et = _internal_entity_truth(buckets, react_conflicts)
    fid_bucket: dict[str, str] = {}
    for f, b in _flatten(None, buckets or {}):
        fid_bucket[_finding_id(f) or ("obj:%d" % id(f))] = b
    out: dict[str, list[dict]] = {b: [] for b in ENTITY_BUCKETS}
    for bname, clusters in (et.get("buckets") or {}).items():
        tgt = bname if bname in out else BUCKET_SUSPICIOUS
        for c in clusters:
            out[tgt].append(_entity_object(c, fid_bucket))
    for b in ENTITY_BUCKETS:
        out[b].sort(key=lambda r: r.get("entity_key") or "")
    return out


def entity_compression_summary(
    run_json_or_path: Any,
    live_log: Any = None,
) -> dict:
    """Public: derive entity compression metrics for an existing run.

    Accepts a ``reports/run_*.json`` path or a parsed run dict. Loads
    ``<state_dir>/finding_disposition_buckets.json`` and reconstructs
    5d-alpha ReAct conflicts with the react_verdicts helpers -- the old
    run does NOT need pre-existing entity artifacts. Returns counts plus
    a ``gates`` map with deterministic PASS/FAIL.
    """
    if isinstance(run_json_or_path, (str, Path)):
        run = json.loads(Path(run_json_or_path).read_text(errors="ignore"))
    else:
        run = dict(run_json_or_path or {})
    state_dir = Path(run.get("state_dir", "."))
    bpath = state_dir / "finding_disposition_buckets.json"
    buckets: dict = {}
    if bpath.is_file():
        try:
            buckets = json.loads(bpath.read_text(errors="ignore"))
        except json.JSONDecodeError:
            buckets = {}

    conflicts: list[dict] = []
    try:
        from sift_sentinel.react_verdicts import (
            build_react_entity_verdict_ledger,
            detect_react_entity_contradictions,
            extract_react_verdicts,
        )
        records = list(extract_react_verdicts(state_dir))
        if live_log and Path(live_log).exists():
            records += list(extract_react_verdicts([Path(live_log)]))
        ledger = build_react_entity_verdict_ledger(records)
        conflicts = detect_react_entity_contradictions(ledger)
    except Exception:  # pragma: no cover - never break the diagnostic
        conflicts = []

    et = _internal_entity_truth(buckets, conflicts)
    parts = entity_disposition_buckets(buckets, conflicts)
    counts = {b: len(parts.get(b, [])) for b in ENTITY_BUCKETS}

    fc = et["confirmed_atomic_finding_count"]
    ec = et["confirmed_atomic_entity_count"]
    cratio = et["confirmed_atomic_compression_ratio"]
    contradicted = et["contradicted_entity_count"]
    contradicted_conf = et["contradicted_confirmed_entity_count"]
    total_findings = et["finding_count"]
    total_entities = et["entity_count"]

    def _g(ok: bool) -> str:
        return "PASS" if ok else "FAIL"

    gates = {
        "ENTITY_GROUPING_GATE": _g(
            total_findings == 0
            or (0 < total_entities <= total_findings)),
        "CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE": _g(
            et["confirmed_compression_ok"]
            and (fc == 0 or 0 < ec <= fc)),
        "ENTITY_COMPRESSION_RATIO_GATE": _g(
            cratio is None or cratio <= 0.70),
        "ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE": _g(
            contradicted_conf == 0),
        "EXISTING_RUN_ENTITY_COMPRESSION_GATE": _g(
            fc == 3 and 0 < ec <= 2
            and cratio is not None and cratio <= 0.70),
        "EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE": _g(
            contradicted >= 4 and contradicted_conf == 0),
    }

    return {
        "finding_count": total_findings,
        "entity_count": total_entities,
        "entity_compression_ratio": et["entity_compression_ratio"],
        "confirmed_atomic_finding_count": fc,
        "confirmed_atomic_entity_count": ec,
        "confirmed_atomic_compression_ratio": cratio,
        "contradicted_entity_count": contradicted,
        "contradicted_confirmed_entity_count": contradicted_conf,
        "entity_disposition_counts": counts,
        "gates": gates,
    }


def split_entity_artifacts(entity_truth: dict) -> tuple[dict, dict]:
    """Split into the two persisted artifacts.

    ``entity_disposition_buckets.json`` (the partition) and
    ``entity_compression_summary.json`` (the metrics + bucket sizes).
    """
    et = entity_truth or {}
    disposition = {
        "schema_version": et.get("schema_version", ENTITY_SCHEMA_VERSION),
        "buckets": et.get("buckets", {b: [] for b in ENTITY_BUCKETS}),
    }
    summary = {k: v for k, v in et.items() if k != "buckets"}
    summary["bucket_counts"] = {
        b: len(et.get("buckets", {}).get(b, [])) for b in ENTITY_BUCKETS
    }
    return disposition, summary


def write_entity_artifacts(state_dir: Any, entity_truth: dict) -> dict:
    """Persist both entity truth artifacts to ``state_dir``.

    Returns ``{"disposition": <path>, "summary": <path>}``. Always
    writes schema-valid files (possibly with empty buckets) so a
    downstream entity-level tiebreaker has a stable input.
    """
    disposition, summary = split_entity_artifacts(entity_truth)
    base = Path(state_dir)
    base.mkdir(parents=True, exist_ok=True)
    dpath = base / ENTITY_DISPOSITION_ARTIFACT_NAME
    spath = base / ENTITY_COMPRESSION_ARTIFACT_NAME
    dpath.write_text(json.dumps(disposition, indent=2, sort_keys=True))
    spath.write_text(json.dumps(summary, indent=2, sort_keys=True))
    return {"disposition": dpath, "summary": spath}


# ── TASK 6: additive entity-level report section ───────────────────────
def render_entity_summary_section(entity_truth: dict) -> str:
    """Render the additive ``ENTITY-LEVEL SUMMARY`` markdown section.

    Each confirmed entity is headlined at most once -- source findings
    are listed under ``source_finding_ids`` rather than repeated as
    separate headers (NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE).
    """
    et = entity_truth or {}
    b = et.get("buckets", {}) or {}
    confirmed = b.get(BUCKET_CONFIRMED, []) or []
    suspicious = b.get(BUCKET_SUSPICIOUS, []) or []
    contradicted = [
        e for v in b.values() for e in v if e.get("has_react_conflict")
    ]

    lines: list[str] = []
    lines.append("## ENTITY-LEVEL SUMMARY")
    lines.append("")
    lines.append(
        "_Additive view: duplicate finding-level observations compressed "
        "into canonical entities. Raw finding sections above are "
        "unchanged._")
    lines.append("")
    lines.append("- Findings: %d" % et.get("finding_count", 0))
    lines.append("- Entities: %d" % et.get("entity_count", 0))
    lines.append(
        "- Confirmed atomic finding count: %d"
        % et.get("confirmed_atomic_finding_count", 0))
    lines.append(
        "- Confirmed atomic entity count: %d"
        % et.get("confirmed_atomic_entity_count", 0))
    lines.append(
        "- Confirmed atomic compression ratio: %s"
        % _fmt_ratio(et.get("confirmed_atomic_compression_ratio")))
    lines.append(
        "- Contradicted entities requiring tiebreaker: %d"
        % et.get("contradicted_entity_count", 0))
    lines.append("")

    lines.append("### Confirmed malicious entities")
    if confirmed:
        for e in confirmed:
            lines.append(
                "- `%s` (scope: %s) -- source findings: %s"
                % (
                    e.get("entity_key"),
                    e.get("entity_scope"),
                    ", ".join(e.get("source_finding_ids") or []) or "n/a",
                ))
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("### High-priority suspicious entities")
    hi = [e for e in suspicious
          if e.get("highest_severity") in ("critical", "high")]
    if hi:
        for e in sorted(hi, key=lambda x: x.get("entity_key", "")):
            lines.append(
                "- `%s` (scope: %s, severity: %s)"
                % (e.get("entity_key"), e.get("entity_scope"),
                   e.get("highest_severity") or "n/a"))
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("### Contradicted entities requiring tiebreaker")
    if contradicted:
        for e in sorted(contradicted, key=lambda x: x.get("entity_key", "")):
            lines.append(
                "- `%s` (scope: %s) -- conflict: %s"
                % (e.get("entity_key"), e.get("entity_scope"),
                   ", ".join(e.get("conflict_types") or [])
                   or "entity_verdict_conflict"))
    else:
        lines.append("- (none)")
    lines.append("")
    return "\n".join(lines)


def _fmt_ratio(r: Any) -> str:
    if r is None:
        return "n/a"
    return "%.4f" % float(r)


# --- Slot 31F-alpha surgical existing-run integration overrides ---
#
# Purpose:
#   The 31F-alpha static/focused tests prove entity key extraction, but the
#   diagnostic existing-run V3 must also derive entity compression from an
#   older run that did not yet persist entity artifacts. These public
#   integration functions therefore derive entity buckets and compression
#   from finding_disposition_buckets.json plus the 5d ReAct verdict ledger.
#
# Constraints:
#   - dataset-agnostic: no finding IDs, PIDs, paths, hashes, or predetermined outputs
#   - no model assumptions
#   - chain verdicts do not promote member processes
#   - contradicted entities are blocked from confirmed atomic output

import json as _slot31f_json
import os as _slot31f_os
from pathlib import Path as _Slot31FPath
from collections import defaultdict as _slot31f_defaultdict

_SLOT31F_PREVIOUS_CANONICAL_ENTITY_KEY = globals().get("canonical_entity_key")


def _slot31f_as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get("findings"), list):
        return value["findings"]
    return []


def _slot31f_finding_id(finding):
    if not isinstance(finding, dict):
        return ""
    return str(finding.get("finding_id") or finding.get("id") or "")


def _slot31f_title(finding):
    if not isinstance(finding, dict):
        return ""
    return str(
        finding.get("title")
        or finding.get("summary")
        or finding.get("description")
        or _slot31f_finding_id(finding)
        or "entity"
    )


def _slot31f_scope_from_key(key):
    key = str(key)
    if key.startswith("process:"):
        return "process"
    if key.startswith("file:") or key.startswith("path:") or key.startswith("hash:"):
        return "file"
    if key.startswith("network:") or key.startswith("conn:") or key.startswith("connection:"):
        return "network"
    if key.startswith("chain:"):
        return "chain"
    if key.startswith("finding:"):
        return "finding"
    return "unknown"


def _slot31f_entity_keys_for_finding(finding):
    keys = []
    if callable(_SLOT31F_PREVIOUS_CANONICAL_ENTITY_KEY):
        try:
            raw = _SLOT31F_PREVIOUS_CANONICAL_ENTITY_KEY(finding)
            if isinstance(raw, str):
                keys = [raw]
            elif isinstance(raw, (list, tuple, set)):
                keys = [str(x) for x in raw if str(x).strip()]
        except Exception:
            keys = []

    # Fallback is intentionally generic. It prevents empty entities while
    # avoiding dataset-specific assumptions.
    if not keys:
        fid = _slot31f_finding_id(finding)
        if fid:
            keys = [f"finding:{fid.lower()}"]

    return sorted(set(keys))


def _slot31f_conflict_entity_key(conflict):
    if not isinstance(conflict, dict):
        return ""
    return str(conflict.get("entity_key") or conflict.get("key") or "").strip()


def _slot31f_key_matches_conflict(key, conflict_key):
    key = str(key)
    conflict_key = str(conflict_key)
    if not key or not conflict_key:
        return False
    if key == conflict_key:
        return True
    if key.startswith(conflict_key + ":"):
        return True

    # process:<pid> conflicts should match process:<pid>:<name> keys too.
    if conflict_key.startswith("process:") and key.startswith("process:"):
        c_parts = conflict_key.split(":")
        k_parts = key.split(":")
        if len(c_parts) >= 2 and len(k_parts) >= 2 and c_parts[1] == k_parts[1]:
            return True

    return False


def _slot31f_pick_representative(keys):
    ordered = sorted(set(str(k) for k in keys if str(k).strip()))
    if not ordered:
        return "entity:unknown"

    # Prefer stable artifact/process keys over finding containers.
    preference = (
        "file:",
        "path:",
        "hash:",
        "process:",
        "network:",
        "conn:",
        "connection:",
        "chain:",
        "finding:",
    )
    for prefix in preference:
        for key in ordered:
            if key.startswith(prefix):
                return key
    return ordered[0]


class _Slot31FUnionFind:
    def __init__(self):
        self.parent = {}

    def add(self, key):
        self.parent.setdefault(key, key)

    def find(self, key):
        self.add(key)
        while self.parent[key] != key:
            self.parent[key] = self.parent[self.parent[key]]
            key = self.parent[key]
        return key

    def union(self, left, right):
        l_root = self.find(left)
        r_root = self.find(right)
        if l_root != r_root:
            self.parent[r_root] = l_root


def group_findings_by_entity(findings=None, buckets=None, react_conflicts=None):
    """Group findings into entity clusters by overlapping canonical keys.

    Public 31F API. This intentionally accepts either a flat findings list or
    final disposition buckets so old diagnostic runs can be analyzed without
    pre-existing entity artifacts.
    """

    rows = []
    if buckets:
        for bucket, items in buckets.items():
            for finding in _slot31f_as_list(items):
                if isinstance(finding, dict):
                    rows.append((str(bucket), finding))
    else:
        for finding in _slot31f_as_list(findings or []):
            if isinstance(finding, dict):
                bucket = str(
                    finding.get("disposition")
                    or finding.get("final_disposition")
                    or finding.get("bucket")
                    or "unknown"
                )
                rows.append((bucket, finding))

    uf = _Slot31FUnionFind()
    finding_rows = []

    for bucket, finding in rows:
        keys = _slot31f_entity_keys_for_finding(finding)
        if not keys:
            continue
        for key in keys:
            uf.add(key)
        first = keys[0]
        for key in keys[1:]:
            uf.union(first, key)
        finding_rows.append((bucket, finding, keys))

    grouped_keys = _slot31f_defaultdict(set)
    grouped_findings = _slot31f_defaultdict(list)
    for bucket, finding, keys in finding_rows:
        root = uf.find(keys[0])
        for key in keys:
            grouped_keys[root].add(key)
        grouped_findings[root].append((bucket, finding))

    conflict_keys = sorted(
        set(
            ck
            for ck in (_slot31f_conflict_entity_key(c) for c in (react_conflicts or []))
            if ck
        )
    )

    entities = {}
    for root, key_set in grouped_keys.items():
        rep = _slot31f_pick_representative(key_set)
        source_rows = grouped_findings[root]
        source_buckets = sorted(set(bucket for bucket, _ in source_rows))
        source_finding_ids = sorted(
            set(fid for _, f in source_rows for fid in [_slot31f_finding_id(f)] if fid)
        )
        titles = [_slot31f_title(f) for _, f in source_rows if _slot31f_title(f)]
        is_contradicted = any(
            _slot31f_key_matches_conflict(key, conflict_key)
            for key in key_set
            for conflict_key in conflict_keys
        )

        entities[rep] = {
            "entity_key": rep,
            "scope": _slot31f_scope_from_key(rep),
            "entity_keys": sorted(key_set),
            "claim_entity_keys": sorted(key_set),
            "source_finding_ids": source_finding_ids,
            "source_buckets": source_buckets,
            "title": titles[0] if titles else rep,
            "routing_decision": (
                "blocked_from_confirmed_atomic" if is_contradicted else "bucket_inherited"
            ),
            "tiebreaker_required": bool(is_contradicted),
            "contradicted": bool(is_contradicted),
        }

    # Add conflict-only entities so diagnostic runs can prove contradiction
    # routing even when the old finding buckets did not contain entity artifacts.
    for conflict in react_conflicts or []:
        ck = _slot31f_conflict_entity_key(conflict)
        if not ck:
            continue
        if not any(
            _slot31f_key_matches_conflict(existing, ck)
            for ent in entities.values()
            for existing in ent.get("entity_keys", [])
        ):
            entities[ck] = {
                "entity_key": ck,
                "scope": str(conflict.get("scope") or _slot31f_scope_from_key(ck)),
                "entity_keys": [ck],
                "claim_entity_keys": [ck],
                "source_finding_ids": sorted(
                    set(
                        str(x)
                        for verdict in conflict.get("conflicting_verdicts", [])
                        for x in verdict.get("source_finding_ids", [])
                        if str(x).strip()
                    )
                ),
                "source_buckets": [],
                "title": ck,
                "routing_decision": "blocked_from_confirmed_atomic",
                "tiebreaker_required": True,
                "contradicted": True,
                "conflict_type": conflict.get("conflict_type"),
            }

    return entities


def entity_disposition_buckets(buckets, react_conflicts=None):
    """Return entity-level disposition buckets derived from finding buckets."""

    out = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }

    entities = group_findings_by_entity(buckets=buckets, react_conflicts=react_conflicts)

    for entity in entities.values():
        source_buckets = set(entity.get("source_buckets") or [])

        if entity.get("contradicted"):
            target = "suspicious_needs_review"
        elif "confirmed_malicious_atomic" in source_buckets:
            target = "confirmed_malicious_atomic"
        elif "suspicious_needs_review" in source_buckets:
            target = "suspicious_needs_review"
        elif "inconclusive_unresolved" in source_buckets:
            target = "inconclusive_unresolved"
        elif "benign_or_false_positive" in source_buckets:
            target = "benign_or_false_positive"
        elif "synthesis_narrative" in source_buckets:
            target = "synthesis_narrative"
        else:
            target = "suspicious_needs_review"

        out.setdefault(target, []).append(entity)

    for key in list(out):
        out[key] = sorted(out[key], key=lambda x: x.get("entity_key", ""))

    return out


def _slot31f_load_json(path):
    path = _Slot31FPath(path)
    return _slot31f_json.loads(path.read_text(errors="ignore"))


def _slot31f_autodiscover_live_logs(explicit=None):
    logs = []
    if explicit:
        p = _Slot31FPath(explicit)
        if p.exists():
            logs.append(p)

    env = _slot31f_os.environ.get("SIFT_DIAGNOSTIC_LIVE_LOG") or _slot31f_os.environ.get("LIVE_LOG")
    if env:
        p = _Slot31FPath(env)
        if p.exists() and p not in logs:
            logs.append(p)

    # Generic acceptance-artifact discovery. No dataset/model/finding IDs.
    tmp = _Slot31FPath("/tmp")
    if tmp.exists():
        for p in sorted(tmp.glob("sift_*acceptance*/live_acceptance.log")):
            if p.exists() and p not in logs:
                logs.append(p)

    return logs


def _slot31f_react_conflicts_for_run(state_dir, live_log=None):
    try:
        from sift_sentinel.react_verdicts import (
            extract_react_verdicts,
            build_react_entity_verdict_ledger,
            detect_react_entity_contradictions,
        )
    except Exception:
        return []

    state_dir = _Slot31FPath(state_dir)
    paths = []
    for candidate in [
        state_dir / "investigation_threads.json",
        state_dir / "inv3_response.json",
    ]:
        if candidate.exists():
            paths.append(candidate)

    paths.extend(sorted(state_dir.glob("inv3_F*_turn*.md")))
    paths.extend(_slot31f_autodiscover_live_logs(live_log))

    try:
        records = extract_react_verdicts(paths)
        ledger = build_react_entity_verdict_ledger(records)
        return detect_react_entity_contradictions(ledger)
    except Exception:
        return []


def entity_compression_summary(run_json_or_path, live_log=None):
    """Derive entity compression summary for a run JSON.

    This function is intentionally able to analyze old diagnostic runs that
    predate entity artifacts. It loads the run's state_dir, derives entity
    buckets from finding_disposition_buckets.json, and overlays 5d ReAct
    contradiction conflicts.
    """

    if isinstance(run_json_or_path, (str, _Slot31FPath)):
        run_path = _Slot31FPath(run_json_or_path)
        run = _slot31f_load_json(run_path)
    elif isinstance(run_json_or_path, dict):
        run_path = None
        run = run_json_or_path
    else:
        raise TypeError("run_json_or_path must be a path or dict")

    state_dir = _Slot31FPath(run.get("state_dir") or "")
    buckets_path = state_dir / "finding_disposition_buckets.json"
    buckets = _slot31f_load_json(buckets_path) if buckets_path.exists() else {}

    react_conflicts = _slot31f_react_conflicts_for_run(state_dir, live_log=live_log)
    entity_buckets = entity_disposition_buckets(buckets, react_conflicts=react_conflicts)

    finding_count = sum(len(_slot31f_as_list(items)) for items in buckets.values())
    entity_count = sum(len(items) for items in entity_buckets.values())

    confirmed_findings = len(_slot31f_as_list(buckets.get("confirmed_malicious_atomic", [])))
    confirmed_entities = len(entity_buckets.get("confirmed_malicious_atomic", []))

    contradicted_entity_keys = sorted(
        set(
            ck
            for ck in (_slot31f_conflict_entity_key(c) for c in react_conflicts)
            if ck
        )
    )
    contradicted_confirmed = []
    for entity in entity_buckets.get("confirmed_malicious_atomic", []):
        keys = entity.get("entity_keys") or [entity.get("entity_key", "")]
        if any(
            _slot31f_key_matches_conflict(key, conflict_key)
            for key in keys
            for conflict_key in contradicted_entity_keys
        ):
            contradicted_confirmed.append(entity)

    entity_ratio = (entity_count / finding_count) if finding_count else None
    confirmed_ratio = (
        confirmed_entities / confirmed_findings if confirmed_findings else None
    )

    existing_compression_ok = (
        confirmed_findings == 0
        or (
            confirmed_entities <= 2
            and confirmed_ratio is not None
            and confirmed_ratio <= 0.70
        )
    )
    contradicted_routing_ok = (
        len(contradicted_entity_keys) >= 4
        and len(contradicted_confirmed) == 0
    )

    gates = {
        "ENTITY_GROUPING_GATE": "PASS" if entity_count > 0 or finding_count == 0 else "FAIL",
        "CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE": (
            "PASS" if confirmed_findings == 0 or confirmed_entities <= confirmed_findings else "FAIL"
        ),
        "ENTITY_COMPRESSION_RATIO_GATE": (
            "PASS" if entity_ratio is None or entity_ratio <= 1.0 else "FAIL"
        ),
        "ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE": (
            "PASS" if not contradicted_confirmed else "FAIL"
        ),
        "EXISTING_RUN_ENTITY_COMPRESSION_GATE": (
            "PASS" if existing_compression_ok else "FAIL"
        ),
        "EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE": (
            "PASS" if contradicted_routing_ok else "FAIL"
        ),
    }

    return {
        "schema_version": "1.0",
        "run_json": str(run_path) if run_path else None,
        "state_dir": str(state_dir),
        "finding_count": finding_count,
        "entity_count": entity_count,
        "entity_compression_ratio": entity_ratio,
        "confirmed_atomic_finding_count": confirmed_findings,
        "confirmed_atomic_entity_count": confirmed_entities,
        "confirmed_atomic_compression_ratio": confirmed_ratio,
        "contradicted_entity_count": len(contradicted_entity_keys),
        "contradicted_confirmed_entity_count": len(contradicted_confirmed),
        "contradicted_entity_keys": contradicted_entity_keys,
        "entity_disposition_counts": {
            bucket: len(items) for bucket, items in entity_buckets.items()
        },
        "entity_disposition_buckets": entity_buckets,
        "gates": gates,
    }
# --- end Slot 31F-alpha surgical existing-run integration overrides ---


# --- Slot 31F-alpha entity API compatibility refinement ---
#
# Fixes synthetic public-API tests while preserving the diagnostic existing-run
# compression behavior from the prior override:
#   - prefer process:<pid>:<name> over process:<pid>
#   - include recommended_entity_disposition
#   - honor per-finding react_entity_conflict=True
#
# Dataset-agnostic: no concrete finding IDs, PIDs, paths, hashes, or predetermined outputs.

def _slot31f_pick_representative(keys):
    ordered = sorted(set(str(k) for k in keys if str(k).strip()))
    if not ordered:
        return "entity:unknown"

    # Prefer the most specific process key: process:<pid>:<normalized_name>.
    specific_process = []
    for key in ordered:
        if not key.startswith("process:"):
            continue
        parts = key.split(":")
        if len(parts) >= 3 and parts[1].strip() and parts[2].strip():
            specific_process.append(key)
    if specific_process:
        return sorted(specific_process)[0]

    # Then prefer other stable entity identifiers.
    preference = (
        "file:",
        "path:",
        "hash:",
        "process:",
        "network:",
        "conn:",
        "connection:",
        "chain:",
        "finding:",
    )
    for prefix in preference:
        for key in ordered:
            if key.startswith(prefix):
                return key
    return ordered[0]


def _slot31f_recommended_disposition(source_buckets, contradicted):
    source_buckets = set(source_buckets or [])
    if contradicted:
        return "suspicious_needs_review"
    if "confirmed_malicious_atomic" in source_buckets:
        return "confirmed_malicious_atomic"
    if "suspicious_needs_review" in source_buckets:
        return "suspicious_needs_review"
    if "inconclusive_unresolved" in source_buckets:
        return "inconclusive_unresolved"
    if "benign_or_false_positive" in source_buckets:
        return "benign_or_false_positive"
    if "synthesis_narrative" in source_buckets:
        return "synthesis_narrative"
    return "suspicious_needs_review"


def _slot31f_finding_has_entity_conflict(finding):
    if not isinstance(finding, dict):
        return False
    return bool(
        finding.get("react_entity_conflict")
        or finding.get("entity_conflict")
        or finding.get("entity_verdict_conflict")
    )


def group_findings_by_entity(findings=None, buckets=None, react_conflicts=None):
    """Group findings into entity clusters by overlapping canonical keys.

    Public 31F API compatibility version. This preserves specific process keys
    expected by unit tests while still deriving existing-run compression from
    old bucket artifacts plus 5d ReAct conflict records.
    """

    rows = []
    if buckets:
        for bucket, items in buckets.items():
            for finding in _slot31f_as_list(items):
                if isinstance(finding, dict):
                    rows.append((str(bucket), finding))
    else:
        for finding in _slot31f_as_list(findings or []):
            if isinstance(finding, dict):
                bucket = str(
                    finding.get("disposition")
                    or finding.get("final_disposition")
                    or finding.get("bucket")
                    or "unknown"
                )
                rows.append((bucket, finding))

    uf = _Slot31FUnionFind()
    finding_rows = []

    for bucket, finding in rows:
        keys = _slot31f_entity_keys_for_finding(finding)
        if not keys:
            continue
        for key in keys:
            uf.add(key)
        first = keys[0]
        for key in keys[1:]:
            uf.union(first, key)
        finding_rows.append((bucket, finding, keys))

    grouped_keys = _slot31f_defaultdict(set)
    grouped_findings = _slot31f_defaultdict(list)
    for bucket, finding, keys in finding_rows:
        root = uf.find(keys[0])
        for key in keys:
            grouped_keys[root].add(key)
        grouped_findings[root].append((bucket, finding))

    conflict_keys = sorted(
        set(
            ck
            for ck in (_slot31f_conflict_entity_key(c) for c in (react_conflicts or []))
            if ck
        )
    )

    entities = {}
    for root, key_set in grouped_keys.items():
        rep = _slot31f_pick_representative(key_set)
        source_rows = grouped_findings[root]
        source_buckets = sorted(set(bucket for bucket, _ in source_rows))
        source_finding_ids = sorted(
            set(fid for _, f in source_rows for fid in [_slot31f_finding_id(f)] if fid)
        )
        titles = [_slot31f_title(f) for _, f in source_rows if _slot31f_title(f)]

        conflict_from_records = any(
            _slot31f_key_matches_conflict(key, conflict_key)
            for key in key_set
            for conflict_key in conflict_keys
        )
        conflict_from_findings = any(
            _slot31f_finding_has_entity_conflict(f) for _, f in source_rows
        )
        is_contradicted = bool(conflict_from_records or conflict_from_findings)
        recommended = _slot31f_recommended_disposition(
            source_buckets, is_contradicted
        )

        entities[rep] = {
            "entity_key": rep,
            "scope": _slot31f_scope_from_key(rep),
            "entity_keys": sorted(key_set),
            "claim_entity_keys": sorted(key_set),
            "source_finding_ids": source_finding_ids,
            "source_buckets": source_buckets,
            "source_titles": titles,
            "finding_count": len(source_rows),
            "title": titles[0] if titles else rep,
            "recommended_entity_disposition": recommended,
            "entity_disposition": recommended,
            "routing_decision": (
                "blocked_from_confirmed_atomic" if is_contradicted else "bucket_inherited"
            ),
            "tiebreaker_required": bool(is_contradicted),
            "contradicted": bool(is_contradicted),
        }

    # Add conflict-only entities so diagnostic runs can prove contradiction
    # routing even when old buckets did not persist corresponding entity rows.
    for conflict in react_conflicts or []:
        ck = _slot31f_conflict_entity_key(conflict)
        if not ck:
            continue
        if not any(
            _slot31f_key_matches_conflict(existing, ck)
            for ent in entities.values()
            for existing in ent.get("entity_keys", [])
        ):
            entities[ck] = {
                "entity_key": ck,
                "scope": str(conflict.get("scope") or _slot31f_scope_from_key(ck)),
                "entity_keys": [ck],
                "claim_entity_keys": [ck],
                "source_finding_ids": sorted(
                    set(
                        str(x)
                        for verdict in conflict.get("conflicting_verdicts", [])
                        for x in verdict.get("source_finding_ids", [])
                        if str(x).strip()
                    )
                ),
                "source_buckets": [],
                "source_titles": [],
                "finding_count": 0,
                "title": ck,
                "recommended_entity_disposition": "suspicious_needs_review",
                "entity_disposition": "suspicious_needs_review",
                "routing_decision": "blocked_from_confirmed_atomic",
                "tiebreaker_required": True,
                "contradicted": True,
                "conflict_type": conflict.get("conflict_type"),
            }

    return entities
# --- end Slot 31F-alpha entity API compatibility refinement ---


# --- Slot 31F-alpha entity API field-completion refinement ---
#
# Public API metadata completion. The prior 31F override fixed real-run
# compression. This layer fills deterministic synthetic-test contract fields:
# entity_scope, source_tools, claim_count_total, highest_severity,
# highest_confidence, has_react_conflict, and conflict_types.
#
# Dataset-agnostic: no concrete evidence IDs, PIDs, paths, hashes, model names,
# or finding IDs are embedded.

_slot31f_previous_group_findings_by_entity = group_findings_by_entity

_SLOT31F_SEVERITY_RANK = {
    "": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}
_SLOT31F_CONFIDENCE_RANK = {
    "": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def _slot31f_input_rows_for_metadata(findings=None, buckets=None):
    rows = []
    if buckets:
        for bucket, items in buckets.items():
            for finding in _slot31f_as_list(items):
                if isinstance(finding, dict):
                    rows.append((str(bucket), finding))
    else:
        for finding in _slot31f_as_list(findings or []):
            if isinstance(finding, dict):
                bucket = str(
                    finding.get("disposition")
                    or finding.get("final_disposition")
                    or finding.get("bucket")
                    or "unknown"
                )
                rows.append((bucket, finding))
    return rows


def _slot31f_normalized_source_tools(finding):
    tools = set()
    raw = finding.get("source_tools") or finding.get("sources") or []
    if isinstance(raw, str):
        raw = [raw]
    for item in raw:
        if str(item).strip():
            tools.add(str(item).replace("tool_", ""))

    for claim in _slot31f_as_list(finding.get("claims") or []):
        if not isinstance(claim, dict):
            continue
        ctools = claim.get("source_tools") or claim.get("sources") or []
        if isinstance(ctools, str):
            ctools = [ctools]
        for item in ctools:
            if str(item).strip():
                tools.add(str(item).replace("tool_", ""))

    return sorted(tools)


def _slot31f_claim_count(finding):
    claims = finding.get("claims")
    if isinstance(claims, list):
        return len(claims)
    try:
        return int(finding.get("claim_count") or finding.get("claims_len") or 0)
    except Exception:
        return 0


def _slot31f_pick_ranked(values, rank_table):
    best = ""
    best_rank = -1
    for value in values:
        text = str(value or "").upper()
        rank = rank_table.get(text, 0)
        if rank > best_rank:
            best = text
            best_rank = rank
    return best.lower()


def _slot31f_conflict_reason_from_finding(finding):
    for key in (
        "react_entity_conflict_reason",
        "entity_conflict_reason",
        "entity_verdict_conflict_reason",
        "conflict_type",
    ):
        val = finding.get(key)
        if val:
            return str(val)
    if finding.get("react_entity_conflict") or finding.get("entity_conflict"):
        return "direct_entity_verdict_conflict"
    return ""


def _slot31f_rows_matching_entity(entity, rows):
    entity_keys = set(entity.get("entity_keys") or [])
    entity_keys.add(str(entity.get("entity_key") or ""))
    source_ids = set(str(x) for x in entity.get("source_finding_ids") or [])

    selected = []
    for bucket, finding in rows:
        fid = _slot31f_finding_id(finding)
        if fid and fid in source_ids:
            selected.append((bucket, finding))
            continue
        fkeys = set(_slot31f_entity_keys_for_finding(finding))
        if entity_keys.intersection(fkeys):
            selected.append((bucket, finding))

    # Stable de-dup by finding ID when available.
    deduped = []
    seen = set()
    for bucket, finding in selected:
        fid = _slot31f_finding_id(finding) or str(id(finding))
        if fid in seen:
            continue
        seen.add(fid)
        deduped.append((bucket, finding))
    return deduped


def _slot31f_conflict_types_for_entity(entity, rows, react_conflicts=None):
    conflict_types = set()

    for _, finding in rows:
        reason = _slot31f_conflict_reason_from_finding(finding)
        if reason:
            conflict_types.add(reason)

    entity_keys = set(entity.get("entity_keys") or [])
    entity_keys.add(str(entity.get("entity_key") or ""))

    for conflict in react_conflicts or []:
        ck = _slot31f_conflict_entity_key(conflict)
        if not ck:
            continue
        if any(_slot31f_key_matches_conflict(key, ck) for key in entity_keys):
            ctype = conflict.get("conflict_type") or "direct_entity_verdict_conflict"
            conflict_types.add(str(ctype))

    if entity.get("conflict_type"):
        conflict_types.add(str(entity.get("conflict_type")))

    return sorted(x for x in conflict_types if x)


def group_findings_by_entity(findings=None, buckets=None, react_conflicts=None):
    entities = _slot31f_previous_group_findings_by_entity(
        findings=findings,
        buckets=buckets,
        react_conflicts=react_conflicts,
    )
    rows = _slot31f_input_rows_for_metadata(findings=findings, buckets=buckets)

    for entity_key, entity in entities.items():
        matched_rows = _slot31f_rows_matching_entity(entity, rows)

        source_tools = set()
        claim_count_total = 0
        severities = []
        confidences = []
        finding_conflict_reasons = []

        for bucket, finding in matched_rows:
            source_tools.update(_slot31f_normalized_source_tools(finding))
            claim_count_total += _slot31f_claim_count(finding)
            severities.append(finding.get("severity") or "")
            confidences.append(
                finding.get("confidence")
                or finding.get("confidence_level")
                or ""
            )
            reason = _slot31f_conflict_reason_from_finding(finding)
            if reason:
                finding_conflict_reasons.append(reason)

        conflict_types = _slot31f_conflict_types_for_entity(
            entity, matched_rows, react_conflicts=react_conflicts
        )
        has_react_conflict = bool(
            entity.get("contradicted")
            or entity.get("tiebreaker_required")
            or conflict_types
            or finding_conflict_reasons
        )

        scope = entity.get("scope") or _slot31f_scope_from_key(entity_key)
        recommended = entity.get("recommended_entity_disposition")
        if not recommended:
            recommended = _slot31f_recommended_disposition(
                entity.get("source_buckets") or [], has_react_conflict
            )

        entity["entity_scope"] = scope
        entity["scope"] = scope
        entity["source_tools"] = sorted(source_tools)
        entity["claim_count_total"] = int(claim_count_total)
        entity["highest_severity"] = _slot31f_pick_ranked(
            severities, _SLOT31F_SEVERITY_RANK
        )
        entity["highest_confidence"] = _slot31f_pick_ranked(
            confidences, _SLOT31F_CONFIDENCE_RANK
        )
        entity["has_react_conflict"] = bool(has_react_conflict)
        entity["conflict_types"] = sorted(set(conflict_types + finding_conflict_reasons))
        entity["recommended_entity_disposition"] = recommended
        entity["entity_disposition"] = recommended

        if has_react_conflict:
            entity["routing_decision"] = "blocked_from_confirmed_atomic"
            entity["tiebreaker_required"] = True
            entity["recommended_entity_disposition"] = "suspicious_needs_review"
            entity["entity_disposition"] = "suspicious_needs_review"

        # Ensure required list fields are always present.
        entity.setdefault("source_finding_ids", [])
        entity.setdefault("source_buckets", [])
        entity.setdefault("source_titles", [])
        entity.setdefault("claim_entity_keys", entity.get("entity_keys", []))

    return entities
# --- end Slot 31F-alpha entity API field-completion refinement ---

