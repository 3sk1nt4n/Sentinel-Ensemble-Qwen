"""Confirmed-bucket dedup (lever 1 / C2 + C1).

Independent ensemble/ReAct emission produced several confirmed findings about the
SAME artifact under different titles -- e.g. a credential-dump tool staged in one Temp directory
appeared as four confirmed findings ("credential dumping tools staged...",
"AppCompat cache evidence of...", "tool staged in temporary directory", ...).
That inflates the confirmed count and makes the bucket read as repetitive, which
costs C2 (overcount) and C1 (the report literally calls duplicates "second / third
independent validation").

This collapses confirmed findings that refer to the SAME artifact. The dedup key is
deliberately EXACT so it can never merge two different files:

  * an identical file hash (sha1/sha256/md5), or
  * an identical fully-qualified executable/dll/sys path.

Two confirmed findings whose key SETS intersect are the same artifact. The
representative kept is the one with the most corroborating source tools (then the
most claims); the others are removed from `confirmed` and recorded -- their ids are
attached to the representative (`_merged_duplicate_ids`) and returned in a ledger,
so the audit trail / C5 traceability is preserved (identical evidence traces through
the representative). Nothing is deleted from the run; only the confirmed bucket is
de-duplicated.
"""
from __future__ import annotations

import os
import re

# YYYY-MM-DD HH:MM:SS or ...THH:MM:SS, anywhere in a string -> normalize to second.
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
_BARE_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

CONFIRMED = "confirmed_malicious_atomic"

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?(?:[a-fA-F0-9]{24})?$")
_EXE_RE = re.compile(r"\.(?:exe|dll|sys|ps1|scr)$", re.IGNORECASE)


def _norm_path(p: str) -> str:
    """Canonical path spelling. SIFT_ARTIFACT_NORM_V2 (default ON) additionally
    collapses separator RUNS so an escaped-backslash claim (literal ``\\\\`` ->
    ``//`` after separator replacement) yields the same string as its plain
    sibling -- a universal JSON-escaping variance, not identity. Drive-letter
    handling is NOT done here (it would change every caller); the drive-agnostic
    MATCH key is emitted separately in entity_keys. Legacy form when off."""
    s = re.sub(r"\s+", " ", str(p or "").strip().lower().replace("\\", "/"))
    if os.environ.get("SIFT_ARTIFACT_NORM_V2", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return s
    return re.sub(r"/{2,}", "/", s)         # escaped-backslash runs -> one sep


def _v2_norm_on() -> bool:
    return os.environ.get("SIFT_ARTIFACT_NORM_V2", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _drive_stripped(np: str) -> str:
    """A leading ``<letter>:`` drive prefix is a mount artifact, not file
    identity -- the typed validator already matches paths drive-agnostically."""
    return re.sub(r"^[a-z]:", "", np).lstrip("/")


def _norm_ts19(s) -> str:
    """YYYY-MM-DDTHH:MM:SS from any ISO-ish timestamp; '' if none present."""
    m = _TS_RE.search(str(s or ""))
    return f"{m.group(1)}T{m.group(2)}" if m else ""


def _event_identity_keys(f) -> set:
    """A1: identity for an EVENT finding = (event_id, timestamp-to-the-second,
    IP-discriminator). The SAME event at the SAME time IS a duplicate even with
    no hash/path. SAFETY: a timestamp is REQUIRED (no coarse event-id-only
    merge), and the IP discriminator keeps two same-event-id findings to
    DIFFERENT targets (e.g. share-access to two hosts) separate. Universal:
    OS Event-ID + ISO timestamp + IPv4 shape. Kill-switch SIFT_DEDUP_EVENT_KEYS=0."""
    if os.environ.get("SIFT_DEDUP_EVENT_KEYS", "1") == "0":
        return set()
    eids = set()
    for c in (f.get("claims") or []):
        if isinstance(c, dict) and str(c.get("event_id") or "").strip():
            eids.add(str(c["event_id"]).strip())
    if not eids:
        return set()
    ts = _norm_ts19(f.get("timestamp"))
    pa = f.get("primary_artifact")
    if not ts and isinstance(pa, (list, tuple)):
        for x in pa:
            ts = _norm_ts19(x)
            if ts:
                break
    if not ts and isinstance(pa, str):
        ts = _norm_ts19(pa)
    if not ts:                                  # safety rail: no timestamp -> no merge key
        return set()
    ip = pa.strip() if isinstance(pa, str) and _BARE_IP_RE.match(pa.strip()) else ""
    return {f"evt:{eid}|{ts}|{ip}" for eid in eids}


_SVC_NAME_GRAMMAR_RE = re.compile(
    r"service\s*name\s*[:|]\s*([A-Za-z][\w.$-]{1,39})", re.IGNORECASE)
_SVC_REG_TAIL_RE = re.compile(r"/services/([a-z][\w.$-]{1,39})(?:/|$)")
_SVC_FIELD_RE = re.compile(r"^[A-Za-z][\w.$-]{1,39}$")


def _service_identity_keys(f) -> set:
    """svc: identity for a Windows service. The SAME service cited via its
    install event ('Service Name:' Event-7045 field grammar), its Services
    registry-key tail, or an explicit service_name claim field must intersect,
    so install-event + registry siblings merge/reconcile instead of shipping
    as duplicates. Universal: OS-primitive grammars only, no case data; a
    1-char or purely-numeric tail is never an identity.
    Kill-switch SIFT_DEDUP_SERVICE_KEYS=0."""
    if os.environ.get("SIFT_DEDUP_SERVICE_KEYS", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return set()
    names: set = set()
    if not isinstance(f, dict):
        return names
    texts = [str(f.get("raw_excerpt") or "")]
    for c in (f.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for sk in ("service_name", "service"):
            v = c.get(sk)
            if isinstance(v, str) and _SVC_FIELD_RE.match(v.strip()):
                names.add(v.strip().lower())
        for pk in ("value", "name", "path", "registry_path",
                   "registry_key", "key", "artifact"):
            v = c.get(pk)
            if isinstance(v, str):
                texts.append(v)
    for t in texts:
        m = _SVC_REG_TAIL_RE.search(_norm_path(t))
        if m:
            names.add(m.group(1))
        m2 = _SVC_NAME_GRAMMAR_RE.search(t)
        if m2:
            names.add(m2.group(1).strip().lower())
    return {"svc:" + n for n in names if len(n) >= 2 and not n.isdigit()}


def _proc_pid_keys(f) -> set:
    """D6: refined identity for memory/PID findings that today produce NO key at
    all (no file hash, basename-only path, no event-id) -- so duplicate findings
    about the same injected process could never merge.

    The key is deliberately COMPOSITE so process identity is never a standalone
    merge key (a single malicious PID legitimately hosts DISTINCT behaviors):

      proc:{process}|{pid} | behavior signature (the existing pure fold over the
      finding's own claim ttp_tags + claim types) | injection-detector presence
      (any _INJECTION_MEMORY_TOOLS source tool) | sorted PUBLIC peer-IP set.

    Two findings merge only when ALL components match: injection vs network vs
    ancestry on the same PID never merge (signature/detector differ), and two
    different external targets never merge (peer set differs). Loopback/private
    peers are excluded from the discriminator -- they are staging detail, not
    target identity. Universal: claim/tool/octet structure only, no case data.
    Kill-switch SIFT_DEDUP_PROC_KEYS=0."""
    if os.environ.get("SIFT_DEDUP_PROC_KEYS", "1") == "0":
        return set()
    if not isinstance(f, dict):
        return set()
    from sift_sentinel.analysis.behavior_signature import behavior_signature
    try:
        from sift_sentinel.analysis.disposition import (
            _INJECTION_MEMORY_TOOLS as _INJ, _ipv4_is_public as _pub)
    except Exception:
        return set()                       # fail-closed: no refiner, no merge
    ttp, _procs, types = behavior_signature(f)
    sig = "t:%s;c:%s" % (",".join(sorted(ttp)), ",".join(sorted(types)))
    tools = {str(t).strip().lower() for t in (f.get("source_tools") or [])
             if isinstance(t, str)}
    inj = "1" if tools & _INJ else "0"
    peers = sorted({str(c.get("dst_ip")).strip()
                    for c in (f.get("claims") or [])
                    if isinstance(c, dict) and str(c.get("dst_ip") or "").strip()
                    and _pub(str(c.get("dst_ip")).strip())})
    suffix = "%s|inj:%s|peers:%s" % (sig, inj, ",".join(peers))
    keys: set = set()
    for c in (f.get("claims") or []):
        if not isinstance(c, dict):
            continue
        pid = c.get("pid")
        proc = c.get("process") or c.get("process_name")
        if pid and isinstance(proc, str) and proc.strip():
            keys.add("proc:%s|%s|%s" % (proc.strip().lower(), pid, suffix))
    return keys


# Registry-key identity for the dedup passes. Same grammar as the cross-bucket
# reconciler: a hive root (optionally after a short prose label like "Registry
# key ..."), with REAL depth (>=3 separators) so a bare hive root never groups
# unrelated keys. Registry-only findings (no exe path, no hash) were otherwise
# invisible to dedup and survived as triplicated rows of one persistence key.
_REG_ROOT_RE = re.compile(r"^(?:hklm|hkcu|hku|hkcr|hkey[_a-z]*)\b", re.IGNORECASE)
_REG_ROOT_AFTER_LABEL_RE = re.compile(
    r"^[a-z ]{1,40}?\b((?:hklm|hkcu|hku|hkcr|hkey[_a-z]*)\b.*)$", re.IGNORECASE)


def _registry_keys(f) -> set:
    keys: set = set()
    if not isinstance(f, dict):
        return keys
    for c in (f.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for pk in ("value", "name", "path", "registry_path", "registry_key",
                   "key", "artifact"):
            v = c.get(pk)
            if isinstance(v, str):
                nv = _norm_path(v)
                if not _REG_ROOT_RE.match(nv):
                    m = _REG_ROOT_AFTER_LABEL_RE.match(nv)
                    if m:
                        nv = m.group(1)            # strip the prose label
                if _REG_ROOT_RE.match(nv) and nv.count("/") >= 3:
                    keys.add("r:" + nv)
    return keys


def entity_keys(f) -> set:
    """Exact identity keys for a finding: file hashes and fully-qualified exe paths,
    plus registry-key identity, plus event identity (event_id + timestamp + IP
    discriminator), plus the D6 composite process+pid+behavior+peers refiner for
    hash-less memory findings.

    A fully-qualified path must contain a directory separator -- a bare basename
    ('pwdumpx.exe') is NOT used as a path key (it could collide across directories);
    such findings still dedup via a shared hash if one exists."""
    keys: set = set()
    if not isinstance(f, dict):
        return keys
    for c in (f.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for hk in ("sha1", "sha256", "md5", "hash"):
            v = c.get(hk)
            if isinstance(v, str) and _HASH_RE.match(v.strip()):
                keys.add("h:" + v.strip().lower())
        for pk in ("value", "path", "artifact", "file"):
            v = c.get(pk)
            if isinstance(v, str) and _EXE_RE.search(v.strip()):
                np = _norm_path(v)
                if "/" in np:                      # require a real path, not a basename
                    keys.add("p:" + np)             # drive-ful (legacy, kept)
                    if _v2_norm_on():
                        ds = _drive_stripped(np)    # drive-agnostic MATCH key
                        if "/" in ds:
                            keys.add("p:" + ds)
    keys |= _registry_keys(f)
    keys |= _event_identity_keys(f)
    keys |= _proc_pid_keys(f)
    keys |= _service_identity_keys(f)
    return keys


def _tool_count(f) -> int:
    return len([t for t in (f.get("source_tools") or []) if t])


def _claim_count(f) -> int:
    return len(f.get("claims") or [])


def _finding_id(f) -> str:
    return str((f or {}).get("finding_id") or (f or {}).get("id") or "-")


NEEDS_REVIEW = "suspicious_needs_review"


def dedup_confirmed(buckets):
    """Collapse same-artifact duplicates inside the confirmed bucket."""
    return _dedup_in_bucket(buckets, CONFIRMED)


def dedup_review(buckets):
    """Collapse same-artifact duplicates inside the needs-review bucket. Same EXACT
    hash/path identity rule as the confirmed dedup, so different files never merge.
    (Pure memory/PID-only duplicates that share no hash or full path are left alone --
    that needs a riskier entity key and is intentionally out of scope here.)"""
    return _dedup_in_bucket(buckets, NEEDS_REVIEW)


def _dedup_in_bucket(buckets, bucket_key):
    """Collapse same-artifact duplicates inside ``bucket_key``. Returns
    ``(new_buckets, ledger)``; no-op shallow copy when there is nothing to merge."""
    if not isinstance(buckets, dict):
        return buckets, []
    confirmed = [f for f in (buckets.get(bucket_key) or []) if isinstance(f, dict)]
    if len(confirmed) < 2:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}, []

    # union-find over findings whose entity-key sets intersect
    keysets = [entity_keys(f) for f in confirmed]
    parent = list(range(len(confirmed)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        parent[find(i)] = find(j)

    key_owner: dict = {}
    for i, ks in enumerate(keysets):
        for k in ks:
            if k in key_owner:
                union(i, key_owner[k])
            else:
                key_owner[k] = i

    groups: dict = {}
    for i in range(len(confirmed)):
        groups.setdefault(find(i), []).append(i)

    ledger = []
    keep_idx = set()
    merged_into: dict = {}  # representative index -> [dup ids]
    for members in groups.values():
        if len(members) == 1:
            keep_idx.add(members[0])
            continue
        # representative = most tools, then most claims, then first
        rep = max(members, key=lambda i: (_tool_count(confirmed[i]), _claim_count(confirmed[i]), -i))
        keep_idx.add(rep)
        rep_id = _finding_id(confirmed[rep])
        for i in members:
            if i == rep:
                continue
            dup_id = _finding_id(confirmed[i])
            merged_into.setdefault(rep, []).append(dup_id)
            ledger.append({"finding_id": dup_id, "merged_into": rep_id,
                           "reason": "same artifact (shared hash/path) as " + rep_id})

    if not ledger:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}, []

    new_confirmed = []
    for i, f in enumerate(confirmed):
        if i not in keep_idx:
            continue
        if i in merged_into:
            f = dict(f)
            dups = sorted(set(merged_into[i]))
            f["_merged_duplicate_ids"] = dups
            rs = list(f.get("disposition_reasons") or [])
            rs.append("dedup:merged_same_artifact[%s]" % ",".join(dups))
            f["disposition_reasons"] = rs
        new_confirmed.append(f)

    new_buckets = {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}
    new_buckets[bucket_key] = new_confirmed
    return new_buckets, ledger


# Surfaced buckets, highest disposition first. A cross-bucket duplicate keeps
# its representative in the highest bucket it appears in. Benign / inconclusive
# / any other bucket are NOT considered: their membership is a deliberate
# suppression that cross-bucket dedup must never resurrect or bury.
_XBUCKET_PRIORITY = (CONFIRMED, NEEDS_REVIEW)


_BENIGN_BUCKET = "benign_or_false_positive"


def dedup_cross_bucket(buckets):
    """Collapse the SAME artifact when it appears in more than one surfaced
    bucket. Identity is the exact shared hash or fully-qualified exe/dll/sys
    path used by the within-bucket dedup, so different files never merge and
    theme-dupes (different binaries) are left alone. The representative is
    kept in the highest-priority bucket present; duplicates in lower buckets
    are removed, their ids attached to the representative
    (_merged_duplicate_ids) and recorded in a ledger.

    SIFT_XBUCKET_BENIGN_ABSORB (default ON): BENIGN joins the span as the
    LOWEST priority, so a benign DUPLICATE of a surfaced artifact is absorbed
    into the confirmed/needs-review representative instead of contradicting it
    in the report ("same evidence, two verdicts"). Most-severe wins --
    recall-favoring: a merge can only raise visibility, never demote or hide a
    detection; benign-only groups are untouched. Returns (new_buckets,
    ledger); a no-op shallow copy when nothing spans buckets."""
    if not isinstance(buckets, dict):
        return buckets, []

    span = _XBUCKET_PRIORITY
    if os.environ.get("SIFT_XBUCKET_BENIGN_ABSORB", "1").strip().lower() \
            not in ("0", "false", "no", "off"):
        span = _XBUCKET_PRIORITY + (_BENIGN_BUCKET,)

    # flat list of (bucket, finding) across the surfaced buckets only
    items: list[tuple[str, dict]] = []
    for bk in span:
        for f in (buckets.get(bk) or []):
            if isinstance(f, dict):
                items.append((bk, f))
    if len(items) < 2:
        return {k: (list(v) if isinstance(v, list) else v)
                for k, v in buckets.items()}, []

    keysets = [entity_keys(f) for _, f in items]
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        parent[find(i)] = find(j)

    key_owner: dict = {}
    for i, ks in enumerate(keysets):
        for k in ks:
            if k in key_owner:
                union(i, key_owner[k])
            else:
                key_owner[k] = i

    groups: dict = {}
    for i in range(len(items)):
        groups.setdefault(find(i), []).append(i)

    prio = {bk: r for r, bk in enumerate(span)}
    ledger = []
    removed: dict[str, set] = {bk: set() for bk in span}
    merged_into: dict[int, list] = {}

    for members in groups.values():
        buckets_spanned = {items[i][0] for i in members}
        if len(members) < 2 or len(buckets_spanned) < 2:
            continue          # single finding, or all in one bucket (that's
            #                   the within-bucket dedup's job, not ours)
        # representative = highest-priority bucket, then most tools, then claims
        rep = min(members, key=lambda i: (
            prio[items[i][0]], -_tool_count(items[i][1]),
            -_claim_count(items[i][1]), i))
        rep_bucket, rep_f = items[rep]
        rep_id = _finding_id(rep_f)
        for i in members:
            if i == rep:
                continue
            bk, f = items[i]
            dup_id = _finding_id(f)
            removed[bk].add(id(f))
            merged_into.setdefault(rep, []).append(dup_id)
            ledger.append({"finding_id": dup_id, "merged_into": rep_id,
                           "from_bucket": bk, "into_bucket": rep_bucket,
                           "reason": "same artifact (shared hash/path) as "
                                     + rep_id + " in " + rep_bucket})

    if not ledger:
        return {k: (list(v) if isinstance(v, list) else v)
                for k, v in buckets.items()}, []

    new_buckets = {k: (list(v) if isinstance(v, list) else v)
                   for k, v in buckets.items()}
    for bk in span:
        new_buckets[bk] = [f for f in (buckets.get(bk) or [])
                           if not (isinstance(f, dict)
                                   and id(f) in removed[bk])]
    # annotate representatives with the merged ids
    for rep, dups in merged_into.items():
        rep_f = items[rep][1]
        for f in new_buckets[items[rep][0]]:
            if f is rep_f:
                dups_sorted = sorted(set(dups))
                f["_merged_duplicate_ids"] = sorted(
                    set(f.get("_merged_duplicate_ids") or []) | set(dups_sorted))
                rs = list(f.get("disposition_reasons") or [])
                rs.append("dedup:cross_bucket_same_artifact[%s]"
                          % ",".join(dups_sorted))
                f["disposition_reasons"] = rs
                break
    return new_buckets, ledger
