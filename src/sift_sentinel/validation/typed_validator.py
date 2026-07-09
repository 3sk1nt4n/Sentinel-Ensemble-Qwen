"""Sentinel Qwen Ensemble - Typed EvidenceDB claim validator (Slot 31E-DB.2).

Step 10 prefers first-class typed forensic facts (compiled at Step 7 by
``analysis.evidence_db.build_typed_evidence_db``) for claim validation,
falling back to the legacy paired reference set when:

  * the typed EvidenceDB sidecar is absent / empty,
  * the claim type is not representable as a typed fact, or
  * the typed lookup cannot produce a *deterministic* answer.

This module never reads raw tool text. Every typed verdict is a
normalized-field comparison against compiled fact objects -- a string
appearing somewhere in a raw excerpt is NOT a match. It also never
fabricates: absence of a supporting fact yields a fall-back signal, not
a pass.

Verdict protocol -- each typed checker returns one of:

  ("MATCH", detail)        typed facts deterministically confirm the claim
  ("MISMATCH", detail)     typed facts deterministically refute the claim
  None                     typed facts cannot answer -> caller falls back

Reverting Slot 31E-DB.2 deletes this module and the optional
``evidence_db`` argument; Step 10 returns to reference_set-only
validation with no schema or state-dir change.
"""

from __future__ import annotations

import ntpath

from sift_sentinel.analysis.evidence_db import (
    normalize_cmdline,
    normalize_ip,
    normalize_path,
    normalize_registry,
)

# Claim types the typed layer is capable of representing. A claim whose
# type is outside this set is "unsupported by typed facts" -- it is
# counted for telemetry and always handled by the reference_set path.
TYPED_SUPPORTED_CLAIM_TYPES = frozenset({
    "pid",
    "process_exists",
    "child_process",
    "connection",
    "hash",
    "path",
    "artifact",
    "raw",
    "srum_usage",  # 31K-SRUM-TYPED-VALIDATOR
    "typed_fact",  # 31X-UNIVERSAL-ENTITY-KEYED-TYPED-CHECKER
})


def _names_match(a: str, b: str) -> bool:
    """Case-insensitive process-name match with Windows truncation
    tolerance. Mirrors validator._names_match so typed and reference_set
    verdicts agree on name equivalence (15-char ImageFileName cap)."""
    al, bl = (a or "").lower(), (b or "").lower()
    if al == bl:
        return True
    if not al or not bl:
        return False
    shorter, longer = (al, bl) if len(al) <= len(bl) else (bl, al)
    if not longer.startswith(shorter):
        return False
    # Kernel truncation: _EPROCESS.ImageFileName is a fixed 15-byte buffer, so a
    # memory-side name rendered at >=14 chars was CUT by the kernel -- any
    # remainder length is possible (a <=4 diff only covers a dropped ".exe").
    # Without this, long names false-MISMATCH against their full disk/event name
    # and the finding is blocked as "typed cross-contamination".
    if len(shorter) >= _EPROCESS_NAME_CAP:
        return True
    return len(shorter) >= 5 and len(longer) - len(shorter) <= 4


# _EPROCESS.ImageFileName: 16-byte buffer (15 chars + NUL); tools render 14-15
# visible chars. A prefix of >= this length means kernel truncation, not a
# different process.
_EPROCESS_NAME_CAP = 14


def _int_or_none(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def _basename(path: str) -> str:
    p = (path or "").replace("\\", "/").rstrip("/")
    return p.rsplit("/", 1)[-1] if p else ""


class TypedEvidenceDB:
    """Read-only accessor over a Step 7 ``evidence_db.json`` payload.

    Resolves index keys to compiled fact objects. Holds no global state;
    safe to share read-only across validator threads.
    """

    def __init__(self, evidence_db: dict | None):
        ed = evidence_db if isinstance(evidence_db, dict) else {}
        self.typed_facts: dict = ed.get("typed_facts") or {}
        self.indexes: dict = ed.get("indexes") or {}
        self._fid: dict[str, dict] = {}
        for facts in self.typed_facts.values():
            if isinstance(facts, list):
                for f in facts:
                    if isinstance(f, dict) and f.get("fact_id"):
                        self._fid[f["fact_id"]] = f

    def available(self) -> bool:
        """True when at least one typed fact was compiled."""
        return any(
            isinstance(v, list) and v for v in self.typed_facts.values()
        )

    def facts_by_index(
        self, index_name: str, key, fact_type: str | None = None,
    ) -> list[dict]:
        if key is None or key == "":
            return []
        ids = (self.indexes.get(index_name) or {}).get(str(key)) or []
        out = []
        for fid in ids:
            f = self._fid.get(fid)
            if f is None:
                continue
            if fact_type is not None and f.get("fact_type") != fact_type:
                continue
            out.append(f)
        return out

    def index_has(self, index_name: str, key) -> bool:
        if key is None or key == "":
            return False
        return bool((self.indexes.get(index_name) or {}).get(str(key)))


# ── Typed claim checkers ─────────────────────────────────────────────────
# Each returns ("MATCH"|"MISMATCH", detail) or None (fall back).

def _t_pid(claim: dict, tdb: TypedEvidenceDB):
    pid = claim.get("pid")
    claimed = claim.get("process") or ""
    names: set[str] = set()
    for f in tdb.facts_by_index("by_pid", pid, "process_fact"):
        for k in ("process_name", "image_name"):
            v = f.get(k)
            if v:
                names.add(str(v))
    for f in tdb.facts_by_index("by_pid", pid, "memory_injection_fact"):
        v = f.get("process_name")
        if v:
            names.add(str(v))
    for f in tdb.facts_by_index("by_pid", pid, "network_connection_fact"):
        v = f.get("owner")
        if v:
            names.add(str(v))
    if not names:
        return None  # no typed fact establishes this PID -> fall back
    if not claimed:
        return ("MATCH", "")
    for n in names:
        if _names_match(n, claimed):
            return ("MATCH", "")
    if len({n.lower() for n in names}) > 1:
        return ("MATCH", f"PID {pid} reuse detected "
                          f"({', '.join(sorted(names))}), accepting")
    return ("MISMATCH",
            f"PID {pid} is {sorted(names)[0]}, not {claimed} "
            f"(typed cross-contamination)")


def _t_process_exists(claim: dict, tdb: TypedEvidenceDB):
    pid = claim.get("pid")
    if tdb.facts_by_index("by_pid", pid, "process_fact"):
        return ("MATCH", "")
    if tdb.facts_by_index("by_pid", pid, "memory_injection_fact"):
        return ("MATCH", f"PID {pid} confirmed via memory injection fact")
    return None


def _t_child_process(claim: dict, tdb: TypedEvidenceDB):
    parent_pid = _int_or_none(claim.get("parent_pid"))
    child_pid = _int_or_none(claim.get("child_pid"))
    rels = [
        r for r in tdb.facts_by_index(
            "by_pid", child_pid, "process_relationship_fact")
        if _int_or_none(r.get("pid")) == child_pid
    ]
    if not rels:
        return None
    # Endpoint existence must also be typed-known; otherwise let the
    # reference_set path arbitrate the full relationship.
    if not tdb.facts_by_index("by_pid", child_pid, "process_fact"):
        return None
    for r in rels:
        if _int_or_none(r.get("parent_pid")) == parent_pid:
            return ("MATCH", "")
    actual = rels[0].get("parent_pid")
    return ("MISMATCH",
            f"PID {child_pid} parent is {actual}, not {parent_pid} "
            f"(typed relationship)")


def _t_connection(claim: dict, tdb: TypedEvidenceDB):
    # CONNFIX_BY_IP_V1 -- dataset-agnostic connection-EXISTENCE fallback.
    # by_pid stays authoritative when the claim names a pid (no behavior change).
    # When the claim has NO pid (CLOSED/scanned netscan sockets carry owner=None),
    # verify the connection exists via the generic by_ip index, keyed only on the
    # claim's own foreign endpoint. Confirms existence, never asserts an owning
    # process, never fabricates a MISMATCH. No literals -> universal.
    pid = claim.get("pid")
    raw_faddr = claim.get("foreign_addr") or claim.get("remote_addr") or ""
    faddr = normalize_ip(raw_faddr)
    if raw_faddr and faddr is None:
        return None
    fport = claim.get("foreign_port")
    if fport in (None, ""):
        fport = claim.get("remote_port")
    proc = claim.get("process") or ""
    pid_specified = pid not in (None, "", 0, "0")
    if pid_specified:
        facts = tdb.facts_by_index("by_pid", pid, "network_connection_fact")
    elif faddr:
        facts = tdb.facts_by_index("by_ip", faddr, "network_connection_fact")
    else:
        facts = []
    if not facts:
        return None
    for f in facts:
        if faddr and normalize_ip(f.get("dst_ip")) != faddr:
            continue
        if fport not in (None, "", 0, "0") and f.get("dst_port") is not None:
            if _int_or_none(fport) != _int_or_none(f.get("dst_port")):
                continue
        owner = f.get("owner") or ""
        if proc and owner and not _names_match(owner, proc):
            return ("MISMATCH",
                    f"connection from PID {pid} owned by {owner}, not {proc} (typed)")
        if owner:
            return ("MATCH", "")
        return ("MATCH", f"typed connection to {raw_faddr}:{fport} present (owner unattributed)")
    return ("MISMATCH", f"no typed connection to {raw_faddr}:{fport}")


def _t_hash(claim: dict, tdb: TypedEvidenceDB):
    sha1 = (claim.get("sha1") or "").lower()
    if not sha1:
        return None
    fname = claim.get("filename") or ""
    facts = tdb.facts_by_index("by_hash", sha1, "file_execution_fact")
    if not facts:
        return None
    bases = []
    for f in facts:
        base = _basename(f.get("normalized_path") or f.get("path") or "")
        if base:
            bases.append(base)
        if not fname or _names_match(base, ntpath.basename(fname)):
            return ("MATCH", "")
    actual = bases[0] if bases else "(unknown)"
    return ("MISMATCH",
            f"SHA1 {sha1} maps to {actual}, not {fname} "
            f"(typed cross-contamination)")


def _t_passthrough(claim: dict, tdb: TypedEvidenceDB):
    """Positive typed verification for path/artifact/raw claims.

    File/path values match on a drive-agnostic path tail (exact -> strong)
    or, when the value names a concrete file (has an extension), a basename
    fallback (weak), across the populated file-evidence families. Non-file
    values fall back to registry, scheduled-task, service, network-IOC and
    event-log index equality. Never returns MISMATCH: a passthrough claim
    the typed layer cannot place keeps legacy pass-through behavior and
    never becomes a new block. Dataset-agnostic: structural only.
    """
    val = (
        claim.get("value")
        or claim.get("artifact")
        or claim.get("path")
        or claim.get("filename")
    )
    if val in (None, ""):
        return None
    sval = str(val)

    def _da_tail(s):
        s = normalize_path(str(s or ""))
        if len(s) >= 2 and s[1] == ":" and s[0].isalpha():
            s = s[2:]
        return s.lstrip("/")

    cache = getattr(tdb, "_passthrough_fileidx", None)
    if cache is None:
        tails, bases = set(), set()
        for _ft in (
            "filesystem_listing_fact", "file_execution_fact",
            "appcompatcache_execution_fact", "lnk_execution_fact",
            "jumplist_fact", "string_artifact_fact",
        ):
            for _fact in (tdb.typed_facts or {}).get(_ft) or []:
                for _cand in _fs_path_candidates_v1(_fact):
                    _t = _da_tail(_cand)
                    if _t:
                        tails.add(_t)
                        bases.add(_t.rsplit("/", 1)[-1])
        cache = (tails, bases)
        try:
            tdb._passthrough_fileidx = cache
        except Exception:
            pass
    tails, bases = cache

    ctail = _da_tail(sval)
    if ctail:
        if ctail in tails:
            return ("MATCH", "typed file/path fact match (drive-agnostic path)")
        cbase = ctail.rsplit("/", 1)[-1]
        if "." in cbase:
            ext = cbase.rsplit(".", 1)[-1]
            if 1 <= len(ext) <= 8 and ext.isalnum() and cbase in bases:
                return ("MATCH", "typed file/path fact match (basename)")

    # registry persistence: match the claim against registry_persistence_fact at
    # key AND value granularity (reg: prefix stripped, standard hive roots
    # normalized). MATCH-only, dataset-agnostic.
    _REG_HIVES = {
        "hkey_local_machine": "hklm", "hkey_current_user": "hkcu",
        "hkey_users": "hku", "hkey_classes_root": "hkcr",
        "hkey_current_config": "hkcc",
    }

    def _reg_norm(s):
        s = str(s or "").strip().lower().replace("\\", "/")
        if s.startswith("reg:"):
            s = s[4:]
        parts = [p for p in s.strip("/").split("/") if p]
        if parts and parts[0] in _REG_HIVES:
            parts[0] = _REG_HIVES[parts[0]]
        return "/".join(parts)

    regset = getattr(tdb, "_passthrough_regidx", None)
    if regset is None:
        regset = set()
        for _rf in (tdb.typed_facts or {}).get("registry_persistence_fact") or []:
            for _fld in ("normalized_registry_path", "registry_path", "canonical_entity_id"):
                _n = _reg_norm(_rf.get(_fld))
                if _n:
                    regset.add(_n)
            _nrp = _reg_norm(_rf.get("normalized_registry_path"))
            if _nrp and "/" in _nrp:
                regset.add(_nrp.rsplit("/", 1)[0])
        try:
            tdb._passthrough_regidx = regset
        except Exception:
            pass
    rnorm = _reg_norm(sval)
    if rnorm and rnorm.count("/") + 1 >= 3 and rnorm in regset:
        return ("MATCH", "typed registry persistence fact match")
    nreg = normalize_registry(sval)
    if nreg and tdb.index_has("by_registry_path", nreg):
        return ("MATCH", "typed registry persistence fact match")

    low = sval.strip().lower()
    if tdb.index_has("by_task_name", low):
        return ("MATCH", "typed scheduled task fact match")
    if tdb.index_has("by_service_name", low):
        return ("MATCH", "typed service fact match")

    cip = normalize_ip(sval)
    if cip and tdb.index_has("by_ip", cip):
        return ("MATCH", "typed network IOC fact match")

    iv = _int_or_none(sval)
    if iv is not None and tdb.index_has("by_event_id", str(iv)):
        return ("MATCH", "typed event log fact match")

    return None

def _t_powershell_command(claim, tdb):
    """Validate a powershell_command claim against typed facts."""
    ttp_tag = claim.get("ttp_tag")
    user = claim.get("user")
    ip = claim.get("ip")
    url_host = claim.get("url_host")
    if not any([ttp_tag, user, ip, url_host]):
        return None
    if ttp_tag:
        facts = tdb.facts_by_index("by_ttp_tag", ttp_tag, "powershell_command_fact")
        if facts:
            return ("MATCH", "")
        return ("MISMATCH", "no powershell record with ttp_tag=" + str(ttp_tag))
    if user:
        facts = tdb.facts_by_index("by_user", user, "powershell_command_fact")
        if facts:
            return ("MATCH", "")
        return ("MISMATCH", "no powershell record for user=" + str(user))
    if ip:
        facts = tdb.facts_by_index("by_ip", ip, "powershell_command_fact")
        if facts:
            return ("MATCH", "")
        return ("MISMATCH", "no powershell record referencing ip=" + str(ip))
    if url_host:
        facts = tdb.facts_by_index("by_url_host", url_host, "powershell_command_fact")
        if facts:
            return ("MATCH", "")
        return ("MISMATCH", "no powershell record referencing url_host=" + str(url_host))
    return None



def _t_srum_usage(claim: dict, tdb: TypedEvidenceDB):
    """Validate a claim against compiled SRUM usage telemetry.

    MATCH means: a SRUM row exists matching the requested app/user/table/byte
    constraints. It does NOT mean process creation, command-line execution, or
    exact remote endpoint proof.
    """
    facts = []
    tf = getattr(tdb, "typed_facts", {}) or {}
    raw = tf.get("srum_usage_fact") or []
    if isinstance(raw, list):
        facts = [f for f in raw if isinstance(f, dict)]

    if not facts:
        return ("MISMATCH", "no typed SRUM usage facts available")

    app = (
        claim.get("application_path")
        or claim.get("path")
        or claim.get("application")
        or claim.get("value")
        or claim.get("artifact")
        or ""
    )
    app_norm = normalize_path(str(app)) if app not in (None, "") else ""
    app_base = _basename(app_norm) if app_norm else ""

    user = str(claim.get("user") or claim.get("username") or "").strip().lower()
    sid = str(claim.get("sid") or claim.get("user_sid") or "").strip().lower()
    table = str(claim.get("table") or "").strip().lower()

    raw_ip = str(
        claim.get("remote_ip")
        or claim.get("destination_ip")
        or claim.get("ip")
        or ""
    ).strip()
    remote_ip = normalize_ip(raw_ip) if raw_ip else None

    min_bytes = _int_or_none(
        claim.get("min_bytes_total")
        or claim.get("bytes_total_min")
        or claim.get("bytes_min")
        or 0
    ) or 0

    ts_raw = str(claim.get("timestamp") or claim.get("ts") or "").strip()
    ts_min = ""
    if ts_raw:
        try:
            from sift_sentinel.analysis.evidence_db import timestamp_minute as _ts_minute
            ts_min = _ts_minute(ts_raw)
        except Exception:
            ts_min = ts_raw[:16]

    for f in facts:
        if app_norm:
            vals = [
                f.get("normalized_path"),
                f.get("application_path"),
                f.get("application"),
            ]
            norm_vals = [normalize_path(str(v)) for v in vals if v not in (None, "")]
            norm_bases = [_basename(v) for v in norm_vals if v]
            if app_norm not in norm_vals and (not app_base or app_base not in norm_bases):
                continue

        if user and user != str(f.get("user") or "").strip().lower():
            continue
        if sid and sid != str(f.get("sid") or "").strip().lower():
            continue
        if table and table not in str(f.get("table") or "").strip().lower():
            continue

        if remote_ip:
            f_ip = normalize_ip(str(f.get("remote_ip") or ""))
            if f_ip != remote_ip:
                continue

        if ts_min and ts_min != str(f.get("timestamp_minute") or ""):
            continue

        f_bytes = _int_or_none(f.get("bytes_total")) or 0
        if min_bytes and f_bytes < min_bytes:
            continue

        return ("MATCH", "typed SRUM usage fact match")

    return ("MISMATCH", "no typed SRUM usage fact matched constraints")


def _tf_norm_ip(value):
    s = str(value or "").strip().strip("[]")
    if not s:
        return None
    if s.count(":") == 1 and "." in s:  # ipv4:port -> ipv4
        s = s.split(":", 1)[0]
    return s.lower() or None


def _tf_reg_variants(value):
    # Emit BOTH separator forms so a claim value -- in either slash style --
    # matches the by_registry_path index, whose keys are forward-slash, lowercase,
    # value-name-suffixed (e.g. 'hklm/.../safeboot/alternateshell'). The prior
    # version produced backslash-only variants and never matched -> registry
    # typed_fact claims could not bind. Universal: pure key normalization.
    s = str(value or "").strip()
    if not s:
        return []
    bs = s.replace("/", "\\")          # backslash form
    fs = s.replace("\\", "/")          # forward-slash form (index key style)
    out = []
    for v in (bs, bs.lower(), bs.lower().rstrip("\\"),
              fs, fs.lower(), fs.lower().rstrip("/")):
        if v and v not in out:
            out.append(v)
    return out


def tf_bind_attempts(claim):
    """The ordered (index_name, key) bind attempts a claim's named entities imply:
    pid / ip / port / hash / event_id / path+registry+task+service / fact_signature.

    SHARED by the typed checker (``_t_typed_fact``) and the deterministic
    claim-repair pass so BOTH bind via the SAME existing indexes -- never a parallel
    lookup. Pure function of the claim; dataset-agnostic (no product/path/PID/hash
    literals). Exact keys only -- the caller does the (exact) index membership test."""
    attempts = []
    for k in ("pid", "process_id"):
        v = claim.get(k)
        if v not in (None, ""):
            attempts.append(("by_pid", str(v).strip()))
    for k in ("foreign_addr", "ip", "local_addr", "remote_addr", "dst_ip", "src_ip"):
        v = claim.get(k)
        if v not in (None, ""):
            nip = _tf_norm_ip(v)
            if nip:
                attempts.append(("by_ip", nip))
    for k in ("port", "foreign_port", "local_port", "remote_port", "dst_port"):
        v = claim.get(k)
        if v not in (None, ""):
            attempts.append(("by_port", str(v).strip()))
    for k in ("hash", "sha1", "sha256", "sha256_hash"):
        v = claim.get(k)
        if v not in (None, ""):
            attempts.append(("by_hash", str(v).strip().lower()))
    eid = claim.get("event_id")
    if eid not in (None, ""):
        attempts.append(("by_event_id", str(eid).strip()))
    raw = claim.get("value")
    if raw in (None, ""):
        raw = claim.get("artifact")
    if raw in (None, ""):
        raw = claim.get("path")
    if raw not in (None, ""):
        s = str(raw)
        try:
            np = normalize_path(s)
        except Exception:
            np = None
        if np:
            attempts.append(("by_path", np))
        for rv in _tf_reg_variants(s):
            attempts.append(("by_registry_path", rv))
        low = s.strip().lower()
        if low:
            attempts.append(("by_task_name", low))
            attempts.append(("by_service_name", low))
        if s.strip().isdigit():
            attempts.append(("by_event_id", s.strip()))
    # Universal existence anchor: every fact carries a fact_signature and lives in
    # by_fact_signature, so a family with NO OS-primitive entity (e.g. a WMI
    # subscription keyed by consumer class) still confirms the cited artifact is
    # real (not hallucinated). Last resort -- entity indexes are tried first.
    sig = claim.get("fact_signature")
    if sig not in (None, ""):
        attempts.append(("by_fact_signature", str(sig)))
    return attempts


def _t_typed_fact(claim, tdb):
    """Universal entity-keyed typed checker -- the validation-side mirror of the
    entity corroboration pivot. Confirms >=1 typed fact of the claim's declared
    ``fact_type`` exists for an entity the claim itself names (pid / path /
    registry path / service / task / ip / port / hash / event_id) via whatever
    index already carries it. ONE checker for every present-or-future fact_type:
    no per-family code, keyed only on the claim's own normalized entities -> fully
    dataset-agnostic (no product / path / PID / hash literals). The declared
    fact_type filters every index lookup, so cross-index attempts are harmless.
    Conservative MATCH-or-None: returns ("MATCH", detail) only when the typed fact
    is present for a named entity; otherwise None (never a fabricated MISMATCH ->
    can let true evidence validate, never block a finding). Inert until synthesis
    emits ``typed_fact`` claims, so it cannot regress existing behavior."""
    ft = str(claim.get("fact_type") or "").strip()
    if not ft:
        return None
    for index_name, key in tf_bind_attempts(claim):
        if tdb.facts_by_index(index_name, key, ft):
            return ("MATCH", "typed " + ft + " present via " + index_name + "=" + str(key))
    return None


_TYPED_CHECKERS = {
    "pid": _t_pid,
    "process_exists": _t_process_exists,
    "child_process": _t_child_process,
    "connection": _t_connection,
    "hash": _t_hash,
    "path": _t_passthrough,
    "artifact": _t_passthrough,
    "raw": _t_passthrough,
    "srum_usage": _t_srum_usage,  # 31K-SRUM-TYPED-VALIDATOR
    "powershell_command": _t_powershell_command,
    "typed_fact": _t_typed_fact,  # 31X-UNIVERSAL-ENTITY-KEYED-TYPED-CHECKER
}


def typed_check_claim(claim: dict, tdb: TypedEvidenceDB):
    """Dispatch one claim to its typed checker.

    Returns ("MATCH"|"MISMATCH", detail) or None (fall back / no typed
    answer). Unsupported claim types always return None.
    """
    checker = _TYPED_CHECKERS.get(claim.get("type", ""))
    if checker is None:
        return None
    try:
        return checker(claim, tdb)
    except Exception:  # noqa: BLE001 - typed layer must never break Step 10
        return None

# 31K-PS-DECODED-COMMAND-WIRE:
# The typed checker for powershell_command already existed, but the claim type
# was not in TYPED_SUPPORTED_CLAIM_TYPES, and decoded base64 observations had
# no typed claim. Add both without weakening legacy pass-through behavior.
def _t_decoded_string(claim: dict, tdb: TypedEvidenceDB):
    """31K-DECODED-GENERIC-TAG-GUARD: validate decoded payload claims.

    `decoded_string` is a structural tag on every decoded row, including
    harmless text such as "hello world". It is not a TTP and must never be
    sufficient proof for a malicious finding.

    A decoded-string claim is validator-checkable only when it names a
    non-generic decoded TTP tag such as encoded_command, download_cradle,
    or long_base64_blob. Optional `contains` further narrows the match.
    """
    raw_tag = (
        claim.get("ttp_tag")
        or claim.get("tag")
        or claim.get("decoded_ttp_tag")
        or ""
    )
    tag = str(raw_tag).strip().lower()

    generic_tags = {"", "decoded_string"}
    if tag in generic_tags:
        return (
            "MISMATCH",
            "decoded_string claim requires a non-generic decoded TTP tag",
        )

    facts = tdb.facts_by_index("by_ttp_tag", tag, "decoded_string_fact")
    if not facts:
        return (
            "MISMATCH",
            f"no decoded_string_fact with TTP tag {tag!r}",
        )

    contains = str(
        claim.get("contains")
        or claim.get("decoded_contains")
        or claim.get("payload_contains")
        or ""
    ).strip()

    if contains:
        needle = contains.lower()
        narrowed = []
        for fact in facts:
            haystack = " ".join(
                str(fact.get(k) or "")
                for k in (
                    "decoded_preview",
                    "decoded",
                    "original",
                    "raw_excerpt",
                )
            ).lower()
            if needle in haystack:
                narrowed.append(fact)

        if not narrowed:
            return (
                "MISMATCH",
                "no decoded_string_fact matched TTP tag and contains constraint",
            )
        facts = narrowed

    return ("MATCH", "typed decoded string fact match")


TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"powershell_command", "decoded_string"}
)



# PROCESS_CMDLINE_TYPED_VALIDATOR_V1
#
# Dataset-agnostic command-line validation.
#
# Reads only compiled process_cmdline_fact rows from the current EvidenceDB.
# No product names, no paths, no PIDs, no hashes, no case-specific command
# strings. Indexes are used when present; typed_facts scanning is a fallback
# for import/replay states where the facts exist but indexes are incomplete.
def _claim_value(claim: dict, *keys):
    for key in keys:
        if key in claim and claim.get(key) is not None:
            return claim.get(key)
    return None


def _fact_value(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    for key in keys:
        if key in fact and fact.get(key) is not None:
            return fact.get(key)

    # Some EvidenceDB producers wrap payload fields. Support wrappers without
    # reading raw text or inventing data.
    for container_key in ("fields", "payload", "data", "attributes"):
        sub = fact.get(container_key)
        if not isinstance(sub, dict):
            continue
        for key in keys:
            if key in sub and sub.get(key) is not None:
                return sub.get(key)

    return None


def _claim_pid(claim: dict):
    return _int_or_none(
        _claim_value(claim, "pid", "PID", "process_id", "process_pid")
    )


def _claim_process_name(claim: dict) -> str:
    return str(
        _claim_value(
            claim,
            "process",
            "process_name",
            "image_name",
            "image",
            "owner",
        )
        or ""
    ).strip()


def _fact_process_name(fact: dict) -> str:
    return str(
        _fact_value(
            fact,
            "process_name",
            "image_name",
            "process",
            "owner",
        )
        or ""
    ).strip()


def _fact_cmdline(fact: dict):
    value = _fact_value(
        fact,
        "cmdline",
        "command_line",
        "command",
        "args",
        "Args",
    )
    if value is None:
        return None
    return normalize_cmdline(value)


def _fact_cmdline_is_empty(fact: dict) -> bool:
    flag = _fact_value(fact, "cmdline_is_empty", "is_empty", "empty")
    if isinstance(flag, bool):
        return flag
    if isinstance(flag, str):
        low = flag.strip().lower()
        if low in {"true", "yes", "1"}:
            return True
        if low in {"false", "no", "0"}:
            return False

    cmdline = _fact_cmdline(fact)
    return cmdline == "" if cmdline is not None else False


def _cmdline_facts_for_pid(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _int_or_none(pid)
    out: list[dict] = []
    seen: set[str] = set()

    def add(fact):
        if not isinstance(fact, dict):
            return
        if fact.get("fact_type") and fact.get("fact_type") != "process_cmdline_fact":
            return
        key = str(fact.get("fact_id") or id(fact))
        if key in seen:
            return
        seen.add(key)
        out.append(fact)

    if pid_i is not None:
        for fact in tdb.facts_by_index("by_pid", pid_i, "process_cmdline_fact"):
            add(fact)

    # Fallback scan: still typed facts only, never raw tool text.
    facts = (tdb.typed_facts or {}).get("process_cmdline_fact") or []
    for fact in facts:
        fact_pid = _int_or_none(_fact_value(fact, "pid", "PID"))
        if pid_i is None or fact_pid == pid_i:
            add(fact)

    return out


def _filter_cmdline_facts_by_process(facts: list[dict], process_name: str):
    wanted = (process_name or "").strip()
    if not wanted:
        return facts, False

    matched = []
    saw_named_fact = False
    for fact in facts:
        actual = _fact_process_name(fact)
        if actual:
            saw_named_fact = True
            if _names_match(actual, wanted):
                matched.append(fact)

    if matched:
        return matched, False
    if saw_named_fact:
        return [], True
    return facts, False


def _t_process_cmdline(claim: dict, tdb: TypedEvidenceDB):
    pid = _claim_pid(claim)
    facts = _cmdline_facts_for_pid(tdb, pid)
    if not facts:
        return None

    facts, process_mismatch = _filter_cmdline_facts_by_process(
        facts, _claim_process_name(claim)
    )
    if process_mismatch:
        return ("MISMATCH", "typed command-line fact process does not match claim")
    if not facts:
        return None

    expected_raw = _claim_value(
        claim,
        "cmdline",
        "command_line",
        "command",
        "args",
        "Args",
        "value",
    )
    if expected_raw is None:
        return ("MATCH", "typed command-line fact match")

    expected = normalize_cmdline(expected_raw)
    for fact in facts:
        actual = _fact_cmdline(fact)
        if actual is not None and actual == expected:
            return ("MATCH", "typed command-line exact match")

    return ("MISMATCH", "typed command line does not match expected value")


def _t_process_cmdline_contains(claim: dict, tdb: TypedEvidenceDB):
    pid = _claim_pid(claim)
    facts = _cmdline_facts_for_pid(tdb, pid)
    if not facts:
        return None

    facts, process_mismatch = _filter_cmdline_facts_by_process(
        facts, _claim_process_name(claim)
    )
    if process_mismatch:
        return ("MISMATCH", "typed command-line fact process does not match claim")
    if not facts:
        return None

    needle_raw = _claim_value(
        claim,
        "contains",
        "cmdline_contains",
        "argument_contains",
        "argument",
        "needle",
        "value",
    )
    if needle_raw is None or str(needle_raw).strip() == "":
        return None

    needle = normalize_cmdline(needle_raw)
    for fact in facts:
        actual = _fact_cmdline(fact)
        if actual is not None and needle in actual:
            return ("MATCH", "typed command-line contains match")

    return ("MISMATCH", "typed command line does not contain expected value")


def _t_process_cmdline_empty(claim: dict, tdb: TypedEvidenceDB):
    pid = _claim_pid(claim)
    facts = _cmdline_facts_for_pid(tdb, pid)
    if not facts:
        return None

    facts, process_mismatch = _filter_cmdline_facts_by_process(
        facts, _claim_process_name(claim)
    )
    if process_mismatch:
        return ("MISMATCH", "typed command-line fact process does not match claim")
    if not facts:
        return None

    for fact in facts:
        if _fact_cmdline_is_empty(fact):
            return ("MATCH", "typed empty command-line fact match")

    return ("MISMATCH", "typed command line is not empty")

def _t_event_log(claim, tdb):
    eid = claim.get("event_id")
    if eid in (None, ""):
        return None
    facts = tdb.facts_by_index("by_event_id", str(eid), "event_log_fact")
    if not facts:
        return ("MISMATCH", "no event_log record with event_id=" + str(eid))
    needle = str(claim.get("contains") or claim.get("image_path") or claim.get("service_name") or "").strip().lower()
    if not needle:
        return ("MATCH", "")
    for f in facts:
        hay = " ".join(str(f.get(k) or "") for k in ("raw_excerpt", "artifact")).lower()
        if needle in hay:
            return ("MATCH", "")
    return ("MISMATCH", "event_id present but contains not found")


def _t_appcompatcache(claim, tdb):
    path = claim.get("path") or claim.get("value") or claim.get("artifact")
    if path in (None, ""):
        return None
    npath = normalize_path(str(path))
    if not npath:
        return None
    facts = tdb.facts_by_index("by_path", npath, "appcompatcache_execution_fact")
    if not facts:
        return ("MISMATCH", "no AppCompatCache entry for path=" + npath)
    if str(claim.get("executed") or "").strip().lower() in ("yes", "true", "1"):
        if not any(bool(f.get("executed")) for f in facts):
            return ("MISMATCH", "Executed flag not set for " + npath)
    return ("MATCH", "")

_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS.setdefault("powershell_command", _t_powershell_command)
_TYPED_CHECKERS["decoded_string"] = _t_decoded_string
_TYPED_CHECKERS["event_log"] = _t_event_log
_TYPED_CHECKERS["appcompatcache"] = _t_appcompatcache
_TYPED_CHECKERS["process_cmdline"] = _t_process_cmdline
_TYPED_CHECKERS["process_cmdline_contains"] = _t_process_cmdline_contains
_TYPED_CHECKERS["process_cmdline_empty"] = _t_process_cmdline_empty
TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES) | {"event_log", "appcompatcache", "process_cmdline", "process_cmdline_contains", "process_cmdline_empty"})


# RUN17_PROCESS_HANDLE_TYPED_VALIDATOR_V1
#
# Typed validation for vol_handles -> handle_fact.
#
# Dataset-agnostic:
# - Reads only compiled handle_fact rows from the current EvidenceDB.
# - No handle names, PIDs, paths, users, hosts, hashes, or case constants.
# - Optional constraints narrow the match; absence of facts falls back.
def _handle_fact_value(fact: dict, *names):
    if not isinstance(fact, dict):
        return None
    fields = fact.get("fields") if isinstance(fact.get("fields"), dict) else {}
    for name in names:
        if name in fact and fact.get(name) is not None:
            return fact.get(name)
        if name in fields and fields.get(name) is not None:
            return fields.get(name)
    return None


def _handle_fact_text(fact: dict, *names) -> str:
    value = _handle_fact_value(fact, *names)
    return str(value).strip().lower() if value is not None else ""


def _handle_facts_for_pid(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _int_or_none(pid)
    if pid_i is None:
        return []

    facts = []
    try:
        facts = tdb.facts_by_index("by_pid", pid_i, "handle_fact")
    except Exception:
        facts = []

    if facts:
        return facts

    # Fallback for older EvidenceDBs whose phase1 compiler emitted facts but
    # did not register a by_pid index for handle_fact.
    out = []
    for fact in (tdb.typed_facts or {}).get("handle_fact") or []:
        if not isinstance(fact, dict):
            continue
        if _int_or_none(_handle_fact_value(fact, "pid", "PID")) == pid_i:
            out.append(fact)
    return out


def _filter_handle_facts_by_process(facts: list[dict], process_name: str):
    proc = str(process_name or "").strip()
    if not proc:
        return facts, False

    matched = []
    saw_named = False
    for fact in facts:
        actual = _handle_fact_text(fact, "process_name", "process", "Process", "image_name")
        if actual:
            saw_named = True
            if _names_match(actual, proc):
                matched.append(fact)

    if matched:
        return matched, False
    if saw_named:
        return [], True
    return facts, False


def _handle_matches_constraints(fact: dict, claim: dict) -> bool:
    expected_type = str(
        claim.get("handle_type")
        or claim.get("type_name")
        or claim.get("object_type")
        or ""
    ).strip().lower()

    if expected_type:
        actual_type = _handle_fact_text(fact, "handle_type", "type", "Type")
        if actual_type != expected_type:
            return False

    expected_name = str(
        claim.get("handle_name")
        or claim.get("name")
        or claim.get("object_name")
        or ""
    ).strip().lower()

    if expected_name:
        actual_name = _handle_fact_text(fact, "handle_name", "name", "Name")
        if actual_name != expected_name:
            return False

    contains = str(
        claim.get("contains")
        or claim.get("handle_contains")
        or claim.get("name_contains")
        or ""
    ).strip().lower()

    if contains:
        haystack = " ".join(
            _handle_fact_text(fact, *names)
            for names in (
                ("handle_name", "name", "Name"),
                ("handle_type", "type", "Type"),
                ("process_name", "process", "Process"),
            )
        )
        if contains not in haystack:
            return False

    granted = claim.get("granted_access")
    if granted not in (None, ""):
        actual = _int_or_none(_handle_fact_value(fact, "granted_access", "GrantedAccess"))
        wanted = _int_or_none(granted)
        if actual is None or wanted is None or actual != wanted:
            return False

    handle_value = claim.get("handle_value")
    if handle_value not in (None, ""):
        actual = _int_or_none(_handle_fact_value(fact, "handle_value", "HandleValue"))
        wanted = _int_or_none(handle_value)
        if actual is None or wanted is None or actual != wanted:
            return False

    return True


def _t_process_handle(claim: dict, tdb: TypedEvidenceDB):
    pid = claim.get("pid")
    facts = _handle_facts_for_pid(tdb, pid)
    if not facts:
        return None

    facts, process_mismatch = _filter_handle_facts_by_process(
        facts, str(claim.get("process") or claim.get("process_name") or "")
    )
    if process_mismatch:
        return ("MISMATCH", "typed handle fact process mismatch")
    if not facts:
        return None

    for fact in facts:
        if _handle_matches_constraints(fact, claim):
            return ("MATCH", "typed process handle fact match")

    return ("MISMATCH", "no typed handle fact matched constraints")


def _t_process_handle_type(claim: dict, tdb: TypedEvidenceDB):
    if not (
        claim.get("handle_type")
        or claim.get("type_name")
        or claim.get("object_type")
    ):
        return None
    return _t_process_handle(claim, tdb)


def _t_process_handle_contains(claim: dict, tdb: TypedEvidenceDB):
    if not (
        claim.get("contains")
        or claim.get("handle_contains")
        or claim.get("name_contains")
    ):
        return None
    return _t_process_handle(claim, tdb)


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["process_handle"] = _t_process_handle
_TYPED_CHECKERS["process_handle_type"] = _t_process_handle_type
_TYPED_CHECKERS["process_handle_contains"] = _t_process_handle_contains

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {
        "process_handle",
        "process_handle_type",
        "process_handle_contains",
    }
)

# PROCESS_DLL_TYPED_VALIDATOR_V1
#
# vol_dlllist -> dll_load_fact claim surface.
#
# Dataset-agnostic:
# - Reads only compiled dll_load_fact rows from the current EvidenceDB.
# - Does not encode any dataset path, hash, PID, IP, hostname, or answer label.
# - Supports both exact module-name and normalized-path checks.
def _dll_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    lowered = {str(k).strip().lower(): v for k, v in fact.items()}
    for key in keys:
        if key in fact and fact.get(key) not in (None, ""):
            return fact.get(key)
        lk = str(key).strip().lower()
        if lowered.get(lk) not in (None, ""):
            return lowered.get(lk)

    fields = fact.get("fields")
    if isinstance(fields, dict):
        lowered_fields = {str(k).strip().lower(): v for k, v in fields.items()}
        for key in keys:
            if key in fields and fields.get(key) not in (None, ""):
                return fields.get(key)
            lk = str(key).strip().lower()
            if lowered_fields.get(lk) not in (None, ""):
                return lowered_fields.get(lk)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            lowered_raw = {str(k).strip().lower(): v for k, v in decoded.items()}
            for key in keys:
                if key in decoded and decoded.get(key) not in (None, ""):
                    return decoded.get(key)
                lk = str(key).strip().lower()
                if lowered_raw.get(lk) not in (None, ""):
                    return lowered_raw.get(lk)

    return None


def _dll_norm_text_v1(value):
    return str(value or "").strip().lower()


def _dll_basename_v1(value):
    s = str(value or "").replace("\\", "/").rstrip("/")
    return s.rsplit("/", 1)[-1].strip().lower() if s else ""


def _dll_fact_pid_v1(fact: dict):
    return _int_or_none(_dll_fact_nested_value_v1(fact, "pid", "PID", "ProcessId"))


def _dll_fact_process_v1(fact: dict) -> str:
    return _dll_norm_text_v1(
        _dll_fact_nested_value_v1(
            fact,
            "process_name",
            "process",
            "image_name",
            "ImageFileName",
        )
    )


def _dll_fact_name_v1(fact: dict) -> str:
    name = _dll_fact_nested_value_v1(
        fact,
        "dll_name",
        "module_name",
        "name",
        "Name",
        "BaseDllName",
    )
    if name not in (None, ""):
        return _dll_basename_v1(name)

    path = _dll_fact_path_raw_v1(fact)
    return _dll_basename_v1(path)


def _dll_fact_path_raw_v1(fact: dict) -> str:
    value = _dll_fact_nested_value_v1(
        fact,
        "dll_path",
        "path",
        "normalized_path",
        "full_path",
        "Path",
        "MappedPath",
    )
    return str(value or "").strip()


def _dll_fact_path_norm_v1(fact: dict) -> str:
    path = _dll_fact_path_raw_v1(fact)
    return normalize_path(path) if path else ""


def _dll_claim_pid_v1(claim: dict):
    return _int_or_none(claim.get("pid") or claim.get("process_id"))


def _dll_claim_process_v1(claim: dict) -> str:
    return _dll_norm_text_v1(
        claim.get("process")
        or claim.get("process_name")
        or claim.get("image_name")
        or ""
    )


def _dll_claim_name_v1(claim: dict) -> str:
    value = (
        claim.get("dll_name")
        or claim.get("module")
        or claim.get("name")
        or claim.get("dll")
        or ""
    )
    return _dll_basename_v1(value)


def _dll_claim_path_norm_v1(claim: dict) -> str:
    value = (
        claim.get("dll_path")
        or claim.get("path")
        or claim.get("value")
        or claim.get("artifact")
        or ""
    )
    return normalize_path(str(value)) if value not in (None, "") else ""


def _dll_facts_for_pid_v1(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _int_or_none(pid)
    if pid_i is None:
        return []

    facts = list(tdb.facts_by_index("by_pid", pid_i, "dll_load_fact") or [])
    if facts:
        return facts

    # Defensive fallback for older EvidenceDB sidecars that compiled facts but
    # did not populate by_pid for this family.
    out = []
    for fact in (tdb.typed_facts or {}).get("dll_load_fact") or []:
        if isinstance(fact, dict) and _dll_fact_pid_v1(fact) == pid_i:
            out.append(fact)
    return out


def _dll_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("dll_load_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _dll_filter_process_v1(facts: list[dict], process_name: str):
    proc = _dll_norm_text_v1(process_name)
    if not proc:
        return facts, False

    matched = []
    saw_other_process = False

    for fact in facts:
        fproc = _dll_fact_process_v1(fact)
        if not fproc:
            matched.append(fact)
            continue

        if _names_match(fproc, proc):
            matched.append(fact)
        else:
            saw_other_process = True

    return matched, saw_other_process


def _dll_name_matches_v1(fact: dict, expected_name: str) -> bool:
    expected = _dll_basename_v1(expected_name)
    if not expected:
        return False

    actual_name = _dll_fact_name_v1(fact)
    if actual_name == expected:
        return True

    actual_path_base = _dll_basename_v1(_dll_fact_path_raw_v1(fact))
    return actual_path_base == expected


def _dll_path_matches_v1(fact: dict, expected_path_norm: str) -> bool:
    expected = normalize_path(expected_path_norm) if expected_path_norm else ""
    if not expected:
        return False

    actual = _dll_fact_path_norm_v1(fact)
    return bool(actual and actual == expected)


def _t_process_dll_loaded(claim: dict, tdb: TypedEvidenceDB):
    """Validate a DLL loaded by a specific process/PID.

    Required:
    - pid
    - either dll_name/module/name OR dll_path/path
    Optional:
    - process/process_name
    """
    pid = _dll_claim_pid_v1(claim)
    if pid is None:
        return None

    facts = _dll_facts_for_pid_v1(tdb, pid)
    if not facts:
        return None

    process = _dll_claim_process_v1(claim)
    facts, process_mismatch = _dll_filter_process_v1(facts, process)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "typed DLL facts exist for PID but process name differed")
        return None

    expected_name = _dll_claim_name_v1(claim)
    expected_path = _dll_claim_path_norm_v1(claim)

    if not expected_name and not expected_path:
        return None

    for fact in facts:
        if expected_name and _dll_name_matches_v1(fact, expected_name):
            return ("MATCH", "typed process DLL name match")
        if expected_path and _dll_path_matches_v1(fact, expected_path):
            return ("MATCH", "typed process DLL path match")

    return ("MISMATCH", "no typed dll_load_fact matched process DLL constraints")


def _t_dll_loaded(claim: dict, tdb: TypedEvidenceDB):
    """Validate a DLL/module name anywhere, optionally narrowed by PID/process."""
    pid = _dll_claim_pid_v1(claim)
    expected_name = _dll_claim_name_v1(claim)
    if not expected_name:
        return None

    facts = _dll_facts_for_pid_v1(tdb, pid) if pid is not None else _dll_all_facts_v1(tdb)
    if not facts:
        return None

    process = _dll_claim_process_v1(claim)
    facts, process_mismatch = _dll_filter_process_v1(facts, process)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "typed DLL facts exist but process name differed")
        return None

    for fact in facts:
        if _dll_name_matches_v1(fact, expected_name):
            return ("MATCH", "typed DLL name match")

    return ("MISMATCH", "no typed dll_load_fact matched DLL name")


def _t_dll_path_loaded(claim: dict, tdb: TypedEvidenceDB):
    """Validate a loaded DLL by normalized full path, optionally narrowed by PID/process."""
    pid = _dll_claim_pid_v1(claim)
    expected_path = _dll_claim_path_norm_v1(claim)
    if not expected_path:
        return None

    facts = _dll_facts_for_pid_v1(tdb, pid) if pid is not None else _dll_all_facts_v1(tdb)
    if not facts:
        return None

    process = _dll_claim_process_v1(claim)
    facts, process_mismatch = _dll_filter_process_v1(facts, process)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "typed DLL facts exist but process name differed")
        return None

    for fact in facts:
        if _dll_path_matches_v1(fact, expected_path):
            return ("MATCH", "typed DLL path match")

    return ("MISMATCH", "no typed dll_load_fact matched DLL path")


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["process_dll_loaded"] = _t_process_dll_loaded
_TYPED_CHECKERS["dll_loaded"] = _t_dll_loaded
_TYPED_CHECKERS["dll_path_loaded"] = _t_dll_path_loaded

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"process_dll_loaded", "dll_loaded", "dll_path_loaded"}
)

# PROCESS_PRIVILEGE_TYPED_VALIDATOR_V1
#
# vol_privileges -> privilege_fact claim surface.
#
# Dataset-agnostic:
# - Reads only compiled privilege_fact rows from the current EvidenceDB.
# - Does not hardcode sensitive privilege names or case artifacts.
# - Lets the model claim a concrete observed privilege and optional enabled state.
def _priv_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    lowered = {str(k).strip().lower(): v for k, v in fact.items()}
    for key in keys:
        if key in fact and fact.get(key) not in (None, ""):
            return fact.get(key)
        lk = str(key).strip().lower()
        if lowered.get(lk) not in (None, ""):
            return lowered.get(lk)

    fields = fact.get("fields")
    if isinstance(fields, dict):
        lowered_fields = {str(k).strip().lower(): v for k, v in fields.items()}
        for key in keys:
            if key in fields and fields.get(key) not in (None, ""):
                return fields.get(key)
            lk = str(key).strip().lower()
            if lowered_fields.get(lk) not in (None, ""):
                return lowered_fields.get(lk)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            lowered_raw = {str(k).strip().lower(): v for k, v in decoded.items()}
            for key in keys:
                if key in decoded and decoded.get(key) not in (None, ""):
                    return decoded.get(key)
                lk = str(key).strip().lower()
                if lowered_raw.get(lk) not in (None, ""):
                    return lowered_raw.get(lk)

    return None


def _priv_norm_text_v1(value) -> str:
    return str(value or "").strip().lower()


def _priv_canon_name_v1(value) -> str:
    """Canonical privilege name: lowercase with a trailing 'privilege' dropped, so
    the short form (SeImpersonate) and the full constant (SeImpersonatePrivilege)
    compare equal. Windows naming convention -> universal, no case data."""
    s = _priv_norm_text_v1(value)
    if s.endswith("privilege"):
        s = s[: -len("privilege")].rstrip()
    return s


def _priv_fact_pid_v1(fact: dict):
    return _int_or_none(
        _priv_fact_nested_value_v1(
            fact,
            "pid",
            "PID",
            "process_id",
            "ProcessId",
        )
    )


def _priv_fact_process_v1(fact: dict) -> str:
    return _priv_norm_text_v1(
        _priv_fact_nested_value_v1(
            fact,
            "process_name",
            "process",
            "image_name",
            "ImageFileName",
        )
    )


def _priv_fact_name_v1(fact: dict) -> str:
    return _priv_norm_text_v1(
        _priv_fact_nested_value_v1(
            fact,
            "privilege",
            "privilege_name",
            "name",
            "Name",
            "right",
            "Right",
        )
    )


def _priv_fact_attrs_v1(fact: dict) -> str:
    value = _priv_fact_nested_value_v1(
        fact,
        "attributes",
        "Attributes",
        "state",
        "State",
        "status",
        "Status",
        "flags",
        "Flags",
    )
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(x) for x in value).strip().lower()
    return str(value or "").strip().lower()


def _priv_fact_enabled_v1(fact: dict):
    explicit = _priv_fact_nested_value_v1(
        fact,
        "enabled",
        "is_enabled",
        "privilege_enabled",
        "present_and_enabled",
    )

    if isinstance(explicit, bool):
        return explicit

    if explicit not in (None, ""):
        s = str(explicit).strip().lower()
        if s in {"1", "true", "yes", "enabled", "enable"}:
            return True
        if s in {"0", "false", "no", "disabled", "disable"}:
            return False

    attrs = _priv_fact_attrs_v1(fact)
    if not attrs:
        return None

    # Windows privilege output commonly uses "Enabled", "Enabled by Default",
    # or "Disabled" in an Attributes/State field. These are OS vocabulary,
    # not dataset-specific values.
    if "disabled" in attrs:
        return False
    if "enabled" in attrs:
        return True

    return None


def _priv_claim_pid_v1(claim: dict):
    return _int_or_none(claim.get("pid") or claim.get("process_id"))


def _priv_claim_process_v1(claim: dict) -> str:
    return _priv_norm_text_v1(
        claim.get("process")
        or claim.get("process_name")
        or claim.get("image_name")
        or ""
    )


def _priv_claim_name_v1(claim: dict) -> str:
    return _priv_norm_text_v1(
        claim.get("privilege")
        or claim.get("privilege_name")
        or claim.get("name")
        or claim.get("right")
        or ""
    )


def _priv_claim_enabled_v1(claim: dict):
    value = claim.get("enabled")
    if value is None:
        value = claim.get("is_enabled")
    if value is None:
        value = claim.get("privilege_enabled")

    if isinstance(value, bool):
        return value

    if value not in (None, ""):
        s = str(value).strip().lower()
        if s in {"1", "true", "yes", "enabled", "enable"}:
            return True
        if s in {"0", "false", "no", "disabled", "disable"}:
            return False

    return None


def _priv_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("privilege_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _priv_facts_for_pid_v1(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _int_or_none(pid)
    if pid_i is None:
        return []

    facts = list(tdb.facts_by_index("by_pid", pid_i, "privilege_fact") or [])
    if facts:
        return facts

    # Defensive fallback for older EvidenceDB sidecars that compiled facts but
    # did not populate by_pid for this family.
    return [f for f in _priv_all_facts_v1(tdb) if _priv_fact_pid_v1(f) == pid_i]


def _priv_filter_process_v1(facts: list[dict], process_name: str):
    proc = _priv_norm_text_v1(process_name)
    if not proc:
        return facts, False

    matched = []
    saw_other_process = False

    for fact in facts:
        fproc = _priv_fact_process_v1(fact)
        if not fproc:
            matched.append(fact)
            continue

        if _names_match(fproc, proc):
            matched.append(fact)
        else:
            saw_other_process = True

    return matched, saw_other_process


def _priv_candidate_facts_v1(claim: dict, tdb: TypedEvidenceDB):
    pid = _priv_claim_pid_v1(claim)
    process = _priv_claim_process_v1(claim)

    if pid is not None:
        facts = _priv_facts_for_pid_v1(tdb, pid)
    else:
        facts = _priv_all_facts_v1(tdb)

    if not facts:
        return [], False

    facts, process_mismatch = _priv_filter_process_v1(facts, process)

    # If neither PID nor process was supplied, do not globally match arbitrary
    # privilege facts. A privilege claim must identify a process context.
    if pid is None and not process:
        return [], False

    return facts, process_mismatch


def _priv_match_core_v1(claim: dict, tdb: TypedEvidenceDB, require_enabled: bool = False):
    privilege = _priv_canon_name_v1(_priv_claim_name_v1(claim))
    if not privilege:
        return None

    facts, process_mismatch = _priv_candidate_facts_v1(claim, tdb)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "typed privilege facts exist but process name differed")
        return None

    expected_enabled = True if require_enabled else _priv_claim_enabled_v1(claim)

    privilege_seen = False
    saw_unknown_enabled = False
    saw_disabled = False

    for fact in facts:
        fact_priv = _priv_canon_name_v1(_priv_fact_name_v1(fact))
        if fact_priv != privilege:
            continue

        privilege_seen = True

        if expected_enabled is None:
            return ("MATCH", "typed process privilege match")

        actual_enabled = _priv_fact_enabled_v1(fact)
        if actual_enabled is None:
            saw_unknown_enabled = True
            continue

        if actual_enabled is expected_enabled:
            return ("MATCH", "typed process privilege state match")

        if actual_enabled is False:
            saw_disabled = True

    if privilege_seen and expected_enabled is True and saw_disabled:
        return ("MISMATCH", "typed privilege present but not enabled")

    if privilege_seen and saw_unknown_enabled:
        return None

    if privilege_seen:
        return ("MISMATCH", "typed privilege present but requested state did not match")

    return ("MISMATCH", "no typed privilege_fact matched process privilege constraints")


def _t_process_privilege(claim: dict, tdb: TypedEvidenceDB):
    """Validate an observed process privilege by PID/process and privilege name."""
    return _priv_match_core_v1(claim, tdb, require_enabled=False)


def _t_process_privilege_enabled(claim: dict, tdb: TypedEvidenceDB):
    """Validate an observed process privilege that is enabled."""
    return _priv_match_core_v1(claim, tdb, require_enabled=True)


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["process_privilege"] = _t_process_privilege
_TYPED_CHECKERS["process_privilege_enabled"] = _t_process_privilege_enabled

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"process_privilege", "process_privilege_enabled"}
)

# PROCESS_SID_TYPED_VALIDATOR_V1
#
# vol_getsids -> sid_fact claim surface.
#
# Dataset-agnostic:
# - Reads only compiled sid_fact rows from the current EvidenceDB.
# - Does not hardcode account names, domains, SIDs, users, hosts, paths, IPs,
#   hashes, or case labels.
# - Lets the model claim a concrete observed SID and/or account label for a
#   process context.
def _sid_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    lowered = {str(k).strip().lower(): v for k, v in fact.items()}
    for key in keys:
        if key in fact and fact.get(key) not in (None, ""):
            return fact.get(key)
        lk = str(key).strip().lower()
        if lowered.get(lk) not in (None, ""):
            return lowered.get(lk)

    fields = fact.get("fields")
    if isinstance(fields, dict):
        lowered_fields = {str(k).strip().lower(): v for k, v in fields.items()}
        for key in keys:
            if key in fields and fields.get(key) not in (None, ""):
                return fields.get(key)
            lk = str(key).strip().lower()
            if lowered_fields.get(lk) not in (None, ""):
                return lowered_fields.get(lk)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None

        if isinstance(decoded, dict):
            lowered_raw = {str(k).strip().lower(): v for k, v in decoded.items()}
            for key in keys:
                if key in decoded and decoded.get(key) not in (None, ""):
                    return decoded.get(key)
                lk = str(key).strip().lower()
                if lowered_raw.get(lk) not in (None, ""):
                    return lowered_raw.get(lk)

    return None


def _sid_norm_text_v1(value) -> str:
    return str(value or "").strip().lower()


def _sid_norm_sid_v1(value) -> str:
    return str(value or "").strip().upper()


def _sid_fact_pid_v1(fact: dict):
    return _int_or_none(
        _sid_fact_nested_value_v1(
            fact,
            "pid",
            "PID",
            "process_id",
            "ProcessId",
        )
    )


def _sid_fact_process_v1(fact: dict) -> str:
    return _sid_norm_text_v1(
        _sid_fact_nested_value_v1(
            fact,
            "process_name",
            "process",
            "image_name",
            "ImageFileName",
        )
    )


def _sid_fact_sid_v1(fact: dict) -> str:
    return _sid_norm_sid_v1(
        _sid_fact_nested_value_v1(
            fact,
            "sid",
            "SID",
            "security_identifier",
            "SecurityIdentifier",
            "sid_string",
            "Sid",
        )
    )


def _sid_fact_account_v1(fact: dict) -> str:
    return _sid_norm_text_v1(
        _sid_fact_nested_value_v1(
            fact,
            "account",
            "account_name",
            "sid_name",
            "name",
            "Name",
            "user",
            "username",
            "principal",
        )
    )


def _sid_claim_pid_v1(claim: dict):
    return _int_or_none(claim.get("pid") or claim.get("process_id"))


def _sid_claim_process_v1(claim: dict) -> str:
    return _sid_norm_text_v1(
        claim.get("process")
        or claim.get("process_name")
        or claim.get("image_name")
        or ""
    )


def _sid_claim_sid_v1(claim: dict) -> str:
    return _sid_norm_sid_v1(
        claim.get("sid")
        or claim.get("security_identifier")
        or claim.get("sid_string")
        or ""
    )


def _sid_claim_account_v1(claim: dict) -> str:
    return _sid_norm_text_v1(
        claim.get("account")
        or claim.get("account_name")
        or claim.get("sid_name")
        or claim.get("name")
        or claim.get("user")
        or claim.get("username")
        or ""
    )


def _sid_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("sid_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _sid_facts_for_pid_v1(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _int_or_none(pid)
    if pid_i is None:
        return []

    facts = list(tdb.facts_by_index("by_pid", pid_i, "sid_fact") or [])
    if facts:
        return facts

    # Defensive fallback for older EvidenceDB sidecars that compiled sid_fact
    # rows but did not populate by_pid for this family.
    return [f for f in _sid_all_facts_v1(tdb) if _sid_fact_pid_v1(f) == pid_i]


def _sid_filter_process_v1(facts: list[dict], process_name: str):
    proc = _sid_norm_text_v1(process_name)
    if not proc:
        return facts, False

    matched = []
    saw_other_process = False

    for fact in facts:
        fproc = _sid_fact_process_v1(fact)
        if not fproc:
            matched.append(fact)
            continue

        if _names_match(fproc, proc):
            matched.append(fact)
        else:
            saw_other_process = True

    return matched, saw_other_process


def _sid_account_match_v1(actual: str, expected: str) -> bool:
    actual = _sid_norm_text_v1(actual)
    expected = _sid_norm_text_v1(expected)

    if not actual or not expected:
        return False

    if actual == expected:
        return True

    actual_leaf = actual.replace("/", "\\").rsplit("\\", 1)[-1]
    expected_leaf = expected.replace("/", "\\").rsplit("\\", 1)[-1]

    return bool(actual_leaf and expected_leaf and actual_leaf == expected_leaf)


def _sid_candidate_facts_v1(claim: dict, tdb: TypedEvidenceDB):
    pid = _sid_claim_pid_v1(claim)
    process = _sid_claim_process_v1(claim)

    if pid is not None:
        facts = _sid_facts_for_pid_v1(tdb, pid)
    else:
        facts = _sid_all_facts_v1(tdb)

    if not facts:
        return [], False

    facts, process_mismatch = _sid_filter_process_v1(facts, process)

    # Do not globally match arbitrary SID rows. A SID claim must identify a
    # process context by PID or process name.
    if pid is None and not process:
        return [], False

    return facts, process_mismatch


def _t_process_sid(claim: dict, tdb: TypedEvidenceDB):
    """Validate an observed SID attached to a process."""
    sid = _sid_claim_sid_v1(claim)
    if not sid:
        return None

    facts, process_mismatch = _sid_candidate_facts_v1(claim, tdb)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "typed sid facts exist but process name differed")
        return None

    for fact in facts:
        if _sid_fact_sid_v1(fact) == sid:
            return ("MATCH", "typed process SID match")

    return ("MISMATCH", "no typed sid_fact matched process SID constraints")


def _t_process_account_sid(claim: dict, tdb: TypedEvidenceDB):
    """Validate an observed account/name SID mapping attached to a process."""
    sid = _sid_claim_sid_v1(claim)
    account = _sid_claim_account_v1(claim)

    if not sid and not account:
        return None

    facts, process_mismatch = _sid_candidate_facts_v1(claim, tdb)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "typed sid facts exist but process name differed")
        return None

    saw_sid = False
    saw_account = False

    for fact in facts:
        fact_sid = _sid_fact_sid_v1(fact)
        fact_account = _sid_fact_account_v1(fact)

        if sid and fact_sid == sid:
            saw_sid = True
        if account and _sid_account_match_v1(fact_account, account):
            saw_account = True

        if sid and fact_sid != sid:
            continue
        if account and not _sid_account_match_v1(fact_account, account):
            continue

        return ("MATCH", "typed process account SID match")

    if sid and saw_sid and account:
        return ("MISMATCH", "typed SID present but account label did not match")

    if account and saw_account and sid:
        return ("MISMATCH", "typed account label present but SID did not match")

    return ("MISMATCH", "no typed sid_fact matched account/SID constraints")


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["process_sid"] = _t_process_sid
_TYPED_CHECKERS["process_account_sid"] = _t_process_account_sid

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"process_sid", "process_account_sid"}
)

# SSDT_TYPED_VALIDATOR_V1
#
# Typed validation for vol_ssdt -> ssdt_integrity_fact.
#
# Dataset-agnostic contract:
# - Validates only current-run compiled SSDT rows.
# - Does not decide that an SSDT row is malicious.
# - Does not hardcode any module, syscall, symbol, PID, path, hash, IP, user,
#   hostname, finding id, or answer label.
# - Returns MATCH only for exact structural constraints from typed facts.
def _ssdt_fact_carriers_v1(fact: dict) -> list[dict]:
    out = []
    if isinstance(fact, dict):
        out.append(fact)
        for key in ("fields", "raw", "record", "source", "data"):
            val = fact.get(key)
            if isinstance(val, dict):
                out.append(val)

        raw_excerpt = fact.get("raw_excerpt")
        if isinstance(raw_excerpt, str) and raw_excerpt.strip():
            try:
                import json as _ssdt_json_v1
                decoded = _ssdt_json_v1.loads(raw_excerpt)
            except Exception:
                decoded = None
            if isinstance(decoded, dict):
                out.append(decoded)
    return out


def _ssdt_fact_value_v1(fact: dict, *names):
    wanted = {str(n).lower() for n in names}
    for carrier in _ssdt_fact_carriers_v1(fact):
        for key, value in carrier.items():
            if str(key).lower() in wanted:
                return value
    return None


def _ssdt_fact_artifact_value_v1(fact: dict, idx: int):
    artifact = fact.get("artifact")
    if isinstance(artifact, list) and len(artifact) > idx:
        return artifact[idx]
    return None


def _ssdt_text_v1(value) -> str:
    return str(value or "").strip().lower()


def _ssdt_leaf_v1(value) -> str:
    s = _ssdt_text_v1(value).replace("\\", "/").rstrip("/")
    return s.rsplit("/", 1)[-1] if s else ""


def _ssdt_int_v1(value):
    return _int_or_none(value)


def _ssdt_bool_v1(value):
    if isinstance(value, bool):
        return value
    s = _ssdt_text_v1(value)
    if s in ("true", "yes", "1", "enabled", "hooked"):
        return True
    if s in ("false", "no", "0", "disabled", "clean", "unhooked"):
        return False
    return None


def _ssdt_fact_index_v1(fact: dict):
    value = _ssdt_fact_value_v1(
        fact,
        "index", "idx", "ssdt_index", "entry", "entry_index",
        "ordinal", "number", "syscall_index",
    )
    if value is None:
        value = _ssdt_fact_artifact_value_v1(fact, 0)
    return _ssdt_int_v1(value)


def _ssdt_fact_module_v1(fact: dict) -> str:
    value = _ssdt_fact_value_v1(
        fact,
        "module", "driver", "owner", "handler_module", "target_module",
        "address_module",
    )
    if value is None:
        value = _ssdt_fact_artifact_value_v1(fact, 1)
    return _ssdt_text_v1(value)


def _ssdt_fact_symbol_v1(fact: dict) -> str:
    value = _ssdt_fact_value_v1(
        fact,
        "symbol", "function", "routine", "syscall", "name",
        "entry_name", "handler", "api",
    )
    if value is None:
        value = _ssdt_fact_artifact_value_v1(fact, 2)
    return _ssdt_text_v1(value)


def _ssdt_fact_status_v1(fact: dict) -> str:
    value = _ssdt_fact_value_v1(
        fact,
        "status", "verdict", "integrity", "state", "classification",
    )
    return _ssdt_text_v1(value)


def _ssdt_fact_hooked_v1(fact: dict):
    value = _ssdt_fact_value_v1(
        fact,
        "hooked", "is_hooked", "suspicious", "is_suspicious",
    )
    return _ssdt_bool_v1(value)


def _ssdt_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    return list((tdb.typed_facts or {}).get("ssdt_integrity_fact") or [])


def _ssdt_facts_for_index_v1(tdb: TypedEvidenceDB, index) -> list[dict]:
    idx = _ssdt_int_v1(index)
    if idx is None:
        return []

    facts = []
    for index_name in ("by_ssdt_index", "by_index", "by_entry", "by_ordinal"):
        facts.extend(tdb.facts_by_index(index_name, idx, "ssdt_integrity_fact"))

    if facts:
        seen = set()
        out = []
        for fact in facts:
            fid = fact.get("fact_id") or id(fact)
            if fid in seen:
                continue
            seen.add(fid)
            out.append(fact)
        return out

    return [f for f in _ssdt_all_facts_v1(tdb) if _ssdt_fact_index_v1(f) == idx]


def _ssdt_claim_constraints_v1(claim: dict) -> dict:
    return {
        "index": _ssdt_int_v1(
            claim.get("index")
            if claim.get("index") not in (None, "")
            else claim.get("ssdt_index")
            if claim.get("ssdt_index") not in (None, "")
            else claim.get("entry")
            if claim.get("entry") not in (None, "")
            else claim.get("entry_index")
        ),
        "module": _ssdt_text_v1(
            claim.get("module")
            or claim.get("driver")
            or claim.get("target_module")
            or ""
        ),
        "symbol": _ssdt_text_v1(
            claim.get("symbol")
            or claim.get("function")
            or claim.get("syscall")
            or claim.get("routine")
            or ""
        ),
        "status": _ssdt_text_v1(
            claim.get("status")
            or claim.get("verdict")
            or claim.get("state")
            or ""
        ),
        "hooked": _ssdt_bool_v1(claim.get("hooked")),
    }


def _ssdt_has_any_constraint_v1(cons: dict) -> bool:
    return any(
        cons.get(k) not in (None, "")
        for k in ("index", "module", "symbol", "status", "hooked")
    )


def _ssdt_module_matches_v1(actual: str, expected: str) -> bool:
    if not expected:
        return True
    if not actual:
        return False
    return (
        _ssdt_text_v1(actual) == _ssdt_text_v1(expected)
        or _ssdt_leaf_v1(actual) == _ssdt_leaf_v1(expected)
    )


def _ssdt_symbol_matches_v1(actual: str, expected: str) -> bool:
    if not expected:
        return True
    return bool(actual) and _ssdt_text_v1(actual) == _ssdt_text_v1(expected)


def _ssdt_status_matches_v1(actual: str, expected: str) -> bool:
    if not expected:
        return True
    if not actual:
        return False
    return _ssdt_text_v1(actual) == _ssdt_text_v1(expected)


def _ssdt_fact_matches_constraints_v1(fact: dict, cons: dict) -> bool:
    if cons.get("index") is not None:
        if _ssdt_fact_index_v1(fact) != cons["index"]:
            return False

    if cons.get("module"):
        if not _ssdt_module_matches_v1(_ssdt_fact_module_v1(fact), cons["module"]):
            return False

    if cons.get("symbol"):
        if not _ssdt_symbol_matches_v1(_ssdt_fact_symbol_v1(fact), cons["symbol"]):
            return False

    if cons.get("status"):
        if not _ssdt_status_matches_v1(_ssdt_fact_status_v1(fact), cons["status"]):
            return False

    if cons.get("hooked") is not None:
        actual = _ssdt_fact_hooked_v1(fact)
        if actual is not None and actual != cons["hooked"]:
            return False

    return True


def _t_ssdt_integrity(claim: dict, tdb: TypedEvidenceDB):
    cons = _ssdt_claim_constraints_v1(claim)
    if not _ssdt_has_any_constraint_v1(cons):
        return None

    facts = (
        _ssdt_facts_for_index_v1(tdb, cons["index"])
        if cons.get("index") is not None
        else _ssdt_all_facts_v1(tdb)
    )
    if not facts:
        return None

    for fact in facts:
        if _ssdt_fact_matches_constraints_v1(fact, cons):
            return ("MATCH", "typed SSDT integrity fact match")

    return ("MISMATCH", "no typed ssdt_integrity_fact matched SSDT constraints")


def _t_kernel_ssdt_entry(claim: dict, tdb: TypedEvidenceDB):
    cons = _ssdt_claim_constraints_v1(claim)
    # A kernel_ssdt_entry claim must name at least one row discriminator.
    # This prevents generic "SSDT exists" claims from becoming proof.
    if cons.get("index") is None and not cons.get("module") and not cons.get("symbol"):
        return None
    return _t_ssdt_integrity(claim, tdb)


_TYPED_CHECKERS["ssdt_integrity"] = _t_ssdt_integrity
_TYPED_CHECKERS["kernel_ssdt_entry"] = _t_kernel_ssdt_entry

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"ssdt_integrity", "kernel_ssdt_entry"}
)

# SERVICE_FACT_TYPED_VALIDATOR_V1
#
# Typed validation for vol_svcscan -> service_fact.
#
# Dataset-agnostic contract:
# - Validates only current-run compiled service_fact rows.
# - Does not decide that a service is malicious.
# - Does not hardcode service names, binary paths, PIDs, users, hashes, IPs,
#   hostnames, finding ids, or answer labels.
# - Generic "service exists" is not enough; a claim must name at least a
#   service name, display name, process id, or binary path.
def _service_fact_carriers_v1(fact: dict) -> list[dict]:
    out = []
    if isinstance(fact, dict):
        out.append(fact)
        for key in ("fields", "raw", "record", "source", "data"):
            val = fact.get(key)
            if isinstance(val, dict):
                out.append(val)

        raw_excerpt = fact.get("raw_excerpt")
        if isinstance(raw_excerpt, str) and raw_excerpt.strip():
            try:
                import json as _service_json_v1
                decoded = _service_json_v1.loads(raw_excerpt)
            except Exception:
                decoded = None
            if isinstance(decoded, dict):
                out.append(decoded)
    return out


def _service_fact_value_v1(fact: dict, *names):
    wanted = {str(n).lower() for n in names}
    for carrier in _service_fact_carriers_v1(fact):
        for key, value in carrier.items():
            if str(key).lower() in wanted:
                return value
    return None


def _service_fact_artifact_value_v1(fact: dict, idx: int):
    artifact = fact.get("artifact")
    if isinstance(artifact, list) and len(artifact) > idx:
        return artifact[idx]
    return None


def _service_text_v1(value) -> str:
    return str(value or "").strip().lower()


def _service_int_v1(value):
    return _int_or_none(value)


def _service_norm_path_v1(value) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    try:
        normalized = normalize_path(s)
    except Exception:
        normalized = s.replace("\\", "/").lower()
    return str(normalized or "").strip().lower()


def _service_basename_v1(value) -> str:
    s = _service_norm_path_v1(value).replace("\\", "/").rstrip("/")
    return s.rsplit("/", 1)[-1] if s else ""


def _service_fact_name_v1(fact: dict) -> str:
    value = _service_fact_value_v1(
        fact,
        "service_name", "name", "service", "servicekey", "service_key",
    )
    if value is None:
        value = _service_fact_artifact_value_v1(fact, 0)
    return _service_text_v1(value)


def _service_fact_display_name_v1(fact: dict) -> str:
    value = _service_fact_value_v1(
        fact,
        "display_name", "displayname", "display", "description",
    )
    return _service_text_v1(value)


def _service_fact_state_v1(fact: dict) -> str:
    value = _service_fact_value_v1(
        fact,
        "state", "service_state", "status", "current_state",
    )
    if value is None:
        value = _service_fact_artifact_value_v1(fact, 1)
    return _service_text_v1(value)


def _service_fact_binary_v1(fact: dict) -> str:
    value = _service_fact_value_v1(
        fact,
        "binary_path", "binary", "image_path", "path", "service_binary",
        "binpath", "command", "command_line", "image",
    )
    if value is None:
        value = _service_fact_artifact_value_v1(fact, 2)
    return _service_norm_path_v1(value)


def _service_fact_pid_v1(fact: dict):
    return _service_int_v1(
        _service_fact_value_v1(
            fact,
            "pid", "process_id", "service_pid", "ProcessId", "PID",
        )
    )


def _service_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    return list((tdb.typed_facts or {}).get("service_fact") or [])


def _service_facts_for_name_v1(tdb: TypedEvidenceDB, service_name: str) -> list[dict]:
    name = _service_text_v1(service_name)
    if not name:
        return []

    facts = []
    for index_name in ("by_service_name", "by_name", "by_service"):
        facts.extend(tdb.facts_by_index(index_name, name, "service_fact"))

    if facts:
        seen = set()
        out = []
        for fact in facts:
            fid = fact.get("fact_id") or id(fact)
            if fid in seen:
                continue
            seen.add(fid)
            out.append(fact)
        return out

    return [
        f for f in _service_all_facts_v1(tdb)
        if _service_fact_name_v1(f) == name
    ]


def _service_facts_for_pid_v1(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _service_int_v1(pid)
    if pid_i is None:
        return []

    facts = list(tdb.facts_by_index("by_pid", pid_i, "service_fact") or [])
    if facts:
        return facts

    return [
        f for f in _service_all_facts_v1(tdb)
        if _service_fact_pid_v1(f) == pid_i
    ]


def _service_claim_constraints_v1(claim: dict) -> dict:
    service_name = _service_text_v1(
        claim.get("service_name")
        or claim.get("name")
        or claim.get("service")
        or ""
    )
    display_name = _service_text_v1(
        claim.get("display_name")
        or claim.get("display")
        or ""
    )
    state = _service_text_v1(
        claim.get("state")
        or claim.get("service_state")
        or claim.get("status")
        or ""
    )
    binary = _service_norm_path_v1(
        claim.get("binary_path")
        or claim.get("binary")
        or claim.get("service_binary")
        or claim.get("image_path")
        or claim.get("path")
        or ""
    )
    pid = _service_int_v1(
        claim.get("pid")
        if claim.get("pid") not in (None, "")
        else claim.get("process_id")
    )
    return {
        "service_name": service_name,
        "display_name": display_name,
        "state": state,
        "binary": binary,
        "pid": pid,
    }


def _service_has_any_discriminator_v1(cons: dict) -> bool:
    return any(
        cons.get(k) not in (None, "")
        for k in ("service_name", "display_name", "binary", "pid")
    )


def _service_name_matches_v1(fact: dict, expected: str) -> bool:
    if not expected:
        return True
    return _service_fact_name_v1(fact) == _service_text_v1(expected)


def _service_display_matches_v1(fact: dict, expected: str) -> bool:
    if not expected:
        return True
    actual = _service_fact_display_name_v1(fact)
    return bool(actual) and actual == _service_text_v1(expected)


def _service_state_matches_v1(fact: dict, expected: str) -> bool:
    if not expected:
        return True
    actual = _service_fact_state_v1(fact)
    return bool(actual) and actual == _service_text_v1(expected)


def _service_binary_matches_v1(fact: dict, expected: str) -> bool:
    if not expected:
        return True

    actual = _service_fact_binary_v1(fact)
    if not actual:
        return False

    expected_norm = _service_norm_path_v1(expected)
    if not expected_norm:
        return True

    if actual == expected_norm:
        return True

    # If a claim supplies only a file name, allow basename equality.
    if "/" not in expected_norm and "\\" not in expected_norm:
        return _service_basename_v1(actual) == expected_norm

    return False


def _service_pid_matches_v1(fact: dict, expected_pid) -> bool:
    if expected_pid is None:
        return True
    actual = _service_fact_pid_v1(fact)
    return actual is not None and actual == expected_pid


def _service_fact_matches_constraints_v1(fact: dict, cons: dict) -> bool:
    return (
        _service_name_matches_v1(fact, cons.get("service_name") or "")
        and _service_display_matches_v1(fact, cons.get("display_name") or "")
        and _service_state_matches_v1(fact, cons.get("state") or "")
        and _service_binary_matches_v1(fact, cons.get("binary") or "")
        and _service_pid_matches_v1(fact, cons.get("pid"))
    )


def _service_candidate_facts_v1(tdb: TypedEvidenceDB, cons: dict) -> list[dict]:
    if cons.get("service_name"):
        return _service_facts_for_name_v1(tdb, cons["service_name"])

    if cons.get("pid") is not None:
        facts = _service_facts_for_pid_v1(tdb, cons["pid"])
        if facts:
            return facts

    return _service_all_facts_v1(tdb)


def _t_service(claim: dict, tdb: TypedEvidenceDB):
    cons = _service_claim_constraints_v1(claim)
    if not _service_has_any_discriminator_v1(cons):
        return None

    facts = _service_candidate_facts_v1(tdb, cons)
    if not facts:
        return None

    for fact in facts:
        if _service_fact_matches_constraints_v1(fact, cons):
            return ("MATCH", "typed service fact match")

    return ("MISMATCH", "no typed service_fact matched service constraints")


def _t_service_state(claim: dict, tdb: TypedEvidenceDB):
    cons = _service_claim_constraints_v1(claim)
    if not cons.get("state"):
        return None
    if not _service_has_any_discriminator_v1(cons):
        return None
    return _t_service(claim, tdb)


def _t_service_binary(claim: dict, tdb: TypedEvidenceDB):
    cons = _service_claim_constraints_v1(claim)
    if not cons.get("binary"):
        return None
    return _t_service(claim, tdb)


_TYPED_CHECKERS["service"] = _t_service
_TYPED_CHECKERS["service_state"] = _t_service_state
_TYPED_CHECKERS["service_binary"] = _t_service_binary

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"service", "service_state", "service_binary"}
)

# SERVICE_FACT_TYPED_VALIDATOR_SCHEMA_TOLERANCE_V2
#
# Repair: service_fact artifact shapes are not guaranteed to place service
# state and service binary in fixed slots. Some facts may carry only an
# artifact list, and an artifact value can be a binary path rather than a
# state. This override is dataset-agnostic:
# - No service names, paths, PIDs, hashes, users, IPs, hosts, or answer labels.
# - Explicit typed fields are preferred.
# - Artifact fallback is interpreted by value shape, not by case data.
# - Missing state/binary evidence returns None instead of false MISMATCH.
_SERVICE_STATE_TOKENS_V2 = frozenset({
    "running",
    "stopped",
    "start pending",
    "stop pending",
    "continue pending",
    "pause pending",
    "paused",
    "unknown",
    "disabled",
    "manual",
    "auto",
    "automatic",
    "boot",
    "system",
    "demand",
})


def _service_v2_carriers(fact: dict) -> list[dict]:
    carriers = []
    if isinstance(fact, dict):
        carriers.append(fact)
        for key in ("fields", "raw", "record", "source", "data"):
            value = fact.get(key)
            if isinstance(value, dict):
                carriers.append(value)

        raw_excerpt = fact.get("raw_excerpt")
        if isinstance(raw_excerpt, str) and raw_excerpt.strip():
            try:
                import json as _service_v2_json
                decoded = _service_v2_json.loads(raw_excerpt)
            except Exception:
                decoded = None
            if isinstance(decoded, dict):
                carriers.append(decoded)
    return carriers


def _service_v2_value(fact: dict, *names):
    wanted = {str(n).lower() for n in names}
    for carrier in _service_v2_carriers(fact):
        for key, value in carrier.items():
            if str(key).lower() in wanted:
                return value
    return None


def _service_v2_text(value) -> str:
    return str(value or "").strip().lower()


def _service_v2_int(value):
    return _int_or_none(value)


def _service_v2_norm_path(value) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    try:
        normalized = normalize_path(s)
    except Exception:
        normalized = s.replace("\\", "/").lower()
    return str(normalized or "").strip().lower()


def _service_v2_basename(value) -> str:
    s = _service_v2_norm_path(value).replace("\\", "/").rstrip("/")
    return s.rsplit("/", 1)[-1] if s else ""


def _service_v2_artifact_values(fact: dict) -> list[str]:
    artifact = fact.get("artifact")
    if isinstance(artifact, list):
        return [str(x or "").strip() for x in artifact if str(x or "").strip()]
    if isinstance(artifact, str) and artifact.strip():
        return [artifact.strip()]
    return []


def _service_v2_looks_path(value) -> bool:
    s = str(value or "").strip().lower().replace("\\", "/")
    if not s:
        return False
    return (
        "/" in s
        or s.endswith((".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".com"))
        or "systemroot" in s
        or "%systemroot%" in s
        or "%programfiles%" in s
    )


def _service_v2_looks_state(value) -> bool:
    s = _service_v2_text(value).replace("_", " ")
    if not s:
        return False
    if _service_v2_looks_path(s):
        return False
    return s in _SERVICE_STATE_TOKENS_V2


def _service_v2_name(fact: dict) -> str:
    value = _service_v2_value(
        fact,
        "service_name", "name", "service", "servicekey", "service_key",
    )
    if value not in (None, ""):
        return _service_v2_text(value)

    # Conservative artifact fallback: first non-path, non-state value.
    for item in _service_v2_artifact_values(fact):
        if not _service_v2_looks_path(item) and not _service_v2_looks_state(item):
            return _service_v2_text(item)
    return ""


def _service_v2_display_name(fact: dict) -> str:
    value = _service_v2_value(
        fact,
        "display_name", "displayname", "display", "description",
    )
    return _service_v2_text(value)


def _service_v2_state(fact: dict) -> str:
    value = _service_v2_value(
        fact,
        "state", "service_state", "status", "current_state",
    )
    if value not in (None, ""):
        return _service_v2_text(value)

    for item in _service_v2_artifact_values(fact):
        if _service_v2_looks_state(item):
            return _service_v2_text(item)
    return ""


def _service_v2_binary(fact: dict) -> str:
    value = _service_v2_value(
        fact,
        "binary_path", "binary", "image_path", "path", "service_binary",
        "binpath", "command", "command_line", "image",
    )
    if value not in (None, ""):
        return _service_v2_norm_path(value)

    for item in _service_v2_artifact_values(fact):
        if _service_v2_looks_path(item):
            return _service_v2_norm_path(item)
    return ""


def _service_v2_pid(fact: dict):
    return _service_v2_int(
        _service_v2_value(
            fact,
            "pid", "process_id", "service_pid", "ProcessId", "PID",
        )
    )


def _service_v2_all(tdb: TypedEvidenceDB) -> list[dict]:
    return list((tdb.typed_facts or {}).get("service_fact") or [])


def _service_v2_by_name(tdb: TypedEvidenceDB, service_name: str) -> list[dict]:
    name = _service_v2_text(service_name)
    if not name:
        return []

    facts = []
    for index_name in ("by_service_name", "by_name", "by_service"):
        facts.extend(tdb.facts_by_index(index_name, name, "service_fact"))

    if facts:
        seen = set()
        out = []
        for fact in facts:
            fid = fact.get("fact_id") or id(fact)
            if fid in seen:
                continue
            seen.add(fid)
            out.append(fact)
        return out

    return [f for f in _service_v2_all(tdb) if _service_v2_name(f) == name]


def _service_v2_by_pid(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _service_v2_int(pid)
    if pid_i is None:
        return []

    facts = list(tdb.facts_by_index("by_pid", pid_i, "service_fact") or [])
    if facts:
        return facts

    return [f for f in _service_v2_all(tdb) if _service_v2_pid(f) == pid_i]


def _service_v2_constraints(claim: dict) -> dict:
    return {
        "service_name": _service_v2_text(
            claim.get("service_name")
            or claim.get("name")
            or claim.get("service")
            or ""
        ),
        "display_name": _service_v2_text(
            claim.get("display_name")
            or claim.get("display")
            or ""
        ),
        "state": _service_v2_text(
            claim.get("state")
            or claim.get("service_state")
            or claim.get("status")
            or ""
        ),
        "binary": _service_v2_norm_path(
            claim.get("binary_path")
            or claim.get("binary")
            or claim.get("service_binary")
            or claim.get("image_path")
            or claim.get("path")
            or ""
        ),
        "pid": _service_v2_int(
            claim.get("pid")
            if claim.get("pid") not in (None, "")
            else claim.get("process_id")
        ),
    }


def _service_v2_has_discriminator(cons: dict) -> bool:
    return any(
        cons.get(k) not in (None, "")
        for k in ("service_name", "display_name", "binary", "pid")
    )


def _service_v2_candidate_facts(tdb: TypedEvidenceDB, cons: dict) -> list[dict]:
    if cons.get("service_name"):
        return _service_v2_by_name(tdb, cons["service_name"])

    if cons.get("pid") is not None:
        facts = _service_v2_by_pid(tdb, cons["pid"])
        if facts:
            return facts

    return _service_v2_all(tdb)


def _service_v2_name_ok(fact: dict, expected: str) -> bool:
    return not expected or _service_v2_name(fact) == _service_v2_text(expected)


def _service_v2_display_ok(fact: dict, expected: str) -> bool:
    return not expected or _service_v2_display_name(fact) == _service_v2_text(expected)


def _service_v2_state_known(fact: dict) -> bool:
    return bool(_service_v2_state(fact))


def _service_v2_binary_known(fact: dict) -> bool:
    return bool(_service_v2_binary(fact))


def _service_v2_state_ok(fact: dict, expected: str) -> bool:
    return not expected or _service_v2_state(fact) == _service_v2_text(expected)


def _service_v2_binary_ok(fact: dict, expected: str) -> bool:
    if not expected:
        return True
    actual = _service_v2_binary(fact)
    if not actual:
        return False
    expected_norm = _service_v2_norm_path(expected)
    if not expected_norm:
        return True
    if actual == expected_norm:
        return True
    if "/" not in expected_norm and "\\" not in expected_norm:
        return _service_v2_basename(actual) == expected_norm
    return False


def _service_v2_pid_ok(fact: dict, expected_pid) -> bool:
    if expected_pid is None:
        return True
    actual = _service_v2_pid(fact)
    return actual is not None and actual == expected_pid


def _service_v2_base_match(fact: dict, cons: dict) -> bool:
    return (
        _service_v2_name_ok(fact, cons.get("service_name") or "")
        and _service_v2_display_ok(fact, cons.get("display_name") or "")
        and _service_v2_pid_ok(fact, cons.get("pid"))
    )


def _service_v2_full_match(fact: dict, cons: dict) -> bool:
    return (
        _service_v2_base_match(fact, cons)
        and _service_v2_state_ok(fact, cons.get("state") or "")
        and _service_v2_binary_ok(fact, cons.get("binary") or "")
    )


def _t_service_v2(claim: dict, tdb: TypedEvidenceDB):
    cons = _service_v2_constraints(claim)
    if not _service_v2_has_discriminator(cons):
        return None

    facts = _service_v2_candidate_facts(tdb, cons)
    if not facts:
        return None

    # If a claim includes state/binary but the matched service facts do not
    # carry that field, typed evidence cannot answer the field. Fall back.
    base_matches = [f for f in facts if _service_v2_base_match(f, cons)]
    if not base_matches:
        return ("MISMATCH", "no typed service_fact matched service identity constraints")

    if cons.get("state") and not any(_service_v2_state_known(f) for f in base_matches):
        return None
    if cons.get("binary") and not any(_service_v2_binary_known(f) for f in base_matches):
        return None

    for fact in base_matches:
        if _service_v2_full_match(fact, cons):
            return ("MATCH", "typed service fact match")

    return ("MISMATCH", "no typed service_fact matched service constraints")


def _t_service_state_v2(claim: dict, tdb: TypedEvidenceDB):
    cons = _service_v2_constraints(claim)
    if not cons.get("state"):
        return None
    if not _service_v2_has_discriminator(cons):
        return None
    return _t_service_v2(claim, tdb)


def _t_service_binary_v2(claim: dict, tdb: TypedEvidenceDB):
    cons = _service_v2_constraints(claim)
    if not cons.get("binary"):
        return None
    return _t_service_v2(claim, tdb)


_TYPED_CHECKERS["service"] = _t_service_v2
_TYPED_CHECKERS["service_state"] = _t_service_state_v2
_TYPED_CHECKERS["service_binary"] = _t_service_binary_v2

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"service", "service_state", "service_binary"}
)


# FILESYSTEM_LISTING_TYPED_VALIDATOR_V1
#
# vol_filescan / file-object typed validation.
#
# Dataset-agnostic rules:
# - Reads only compiled filesystem_listing_fact rows from EvidenceDB.
# - Confirms exact normalized paths or explicit substring constraints.
# - Does not infer maliciousness.
# - Does not use case-specific paths, PIDs, hashes, IPs, usernames, or case keys.
# - If a claim asks process/PID ownership but the fact family lacks ownership
#   fields, typed validation falls back instead of over-verifying.

def _fs_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    containers = [fact]
    for ck in ("fields", "normalized", "data", "attributes", "extension"):
        cv = fact.get(ck)
        if isinstance(cv, dict):
            containers.append(cv)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            containers.append(decoded)

    lowered = {str(k).lower(): k for k in keys}
    for c in containers:
        direct = {}
        for k, v in c.items():
            direct[str(k).lower()] = v
        for lk in lowered:
            if lk in direct:
                return direct[lk]

    return None


def _fs_fact_text_v1(fact: dict) -> str:
    parts = []

    def ingest(value):
        if value is None:
            return
        if isinstance(value, (str, int, float, bool)):
            parts.append(str(value))
        elif isinstance(value, list):
            for item in value:
                ingest(item)
        elif isinstance(value, dict):
            for item in value.values():
                ingest(item)

    if isinstance(fact, dict):
        for key in (
            "path", "normalized_path", "file_path", "full_path", "name",
            "filename", "object_name", "source_file", "raw_excerpt",
            "artifact", "fields",
        ):
            ingest(fact.get(key))

    return " ".join(parts).lower()


def _fs_path_candidates_v1(fact: dict) -> list[str]:
    candidates = []
    for key in (
        "normalized_path",
        "path",
        "file_path",
        "full_path",
        "name",
        "filename",
        "object_name",
        "source_file",
        "target",
    ):
        value = _fs_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            candidates.append(str(value))

    artifact = fact.get("artifact") if isinstance(fact, dict) else None
    if isinstance(artifact, list):
        for value in artifact:
            if isinstance(value, str) and value.strip():
                candidates.append(value)

    out = []
    seen = set()
    for value in candidates:
        raw = str(value).strip()
        if not raw:
            continue
        normalized = normalize_path(raw)
        for item in (normalized, raw.lower().replace("\\", "/")):
            if item and item not in seen:
                seen.add(item)
                out.append(item)
    return out


def _fs_fact_pid_v1(fact: dict):
    return _int_or_none(_fs_fact_nested_value_v1(fact, "pid", "PID"))


def _fs_fact_process_v1(fact: dict) -> str:
    value = _fs_fact_nested_value_v1(
        fact,
        "process_name",
        "process",
        "image_name",
        "ImageFileName",
        "owner",
    )
    return str(value or "").strip().lower()


def _fs_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("filesystem_listing_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _fs_facts_for_path_v1(tdb: TypedEvidenceDB, path_value: str) -> list[dict]:
    npath = normalize_path(path_value)
    out = []
    if npath:
        out.extend(tdb.facts_by_index("by_path", npath, "filesystem_listing_fact") or [])

    if out:
        return out

    wanted = set()
    if npath:
        wanted.add(npath)
    raw_norm = str(path_value or "").strip().lower().replace("\\", "/")
    if raw_norm:
        wanted.add(raw_norm)

    for fact in _fs_all_facts_v1(tdb):
        if wanted.intersection(set(_fs_path_candidates_v1(fact))):
            out.append(fact)
    return out


def _fs_filter_context_v1(facts: list[dict], claim: dict):
    pid = _int_or_none(claim.get("pid"))
    process = str(
        claim.get("process")
        or claim.get("process_name")
        or claim.get("image_name")
        or ""
    ).strip()

    if pid is None and not process:
        return facts, None

    facts_with_context = []
    for fact in facts:
        has_context = _fs_fact_pid_v1(fact) is not None or bool(_fs_fact_process_v1(fact))
        if has_context:
            facts_with_context.append(fact)

    if not facts_with_context:
        return [], "filesystem_listing_fact does not carry process/PID ownership context"

    filtered = []
    for fact in facts_with_context:
        if pid is not None:
            fpid = _fs_fact_pid_v1(fact)
            if fpid is not None and fpid != pid:
                continue

        if process:
            fproc = _fs_fact_process_v1(fact)
            if fproc and not _names_match(fproc, process):
                continue

        filtered.append(fact)

    if filtered:
        return filtered, None

    return [], "no filesystem_listing_fact matched process/PID context"


def _fs_claim_path_v1(claim: dict) -> str:
    return str(
        claim.get("path")
        or claim.get("file_path")
        or claim.get("normalized_path")
        or claim.get("value")
        or claim.get("artifact")
        or claim.get("name")
        or claim.get("filename")
        or ""
    ).strip()


def _fs_claim_contains_v1(claim: dict) -> str:
    return str(
        claim.get("contains")
        or claim.get("path_contains")
        or claim.get("name_contains")
        or claim.get("file_contains")
        or ""
    ).strip()


def _t_filesystem_listing(claim: dict, tdb: TypedEvidenceDB):
    path_value = _fs_claim_path_v1(claim)
    contains = _fs_claim_contains_v1(claim)

    all_facts = _fs_all_facts_v1(tdb)
    if not all_facts:
        return None

    if path_value:
        facts = _fs_facts_for_path_v1(tdb, path_value)
        if not facts:
            return ("MISMATCH", "no typed filesystem_listing_fact matched path")
        facts, context_reason = _fs_filter_context_v1(facts, claim)
        if context_reason:
            return None
        if not facts:
            return ("MISMATCH", "filesystem_listing_fact path matched but context did not")
        return ("MATCH", "typed filesystem listing path match")

    if contains:
        needle = contains.lower()
        facts = [
            fact for fact in all_facts
            if needle in _fs_fact_text_v1(fact)
        ]
        if not facts:
            return ("MISMATCH", "no typed filesystem_listing_fact matched contains constraint")
        facts, context_reason = _fs_filter_context_v1(facts, claim)
        if context_reason:
            return None
        if not facts:
            return ("MISMATCH", "filesystem_listing_fact contains matched but context did not")
        return ("MATCH", "typed filesystem listing contains match")

    return None


def _t_file_object(claim: dict, tdb: TypedEvidenceDB):
    return _t_filesystem_listing(claim, tdb)


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["filesystem_listing"] = _t_filesystem_listing
_TYPED_CHECKERS["file_object"] = _t_file_object

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"filesystem_listing", "file_object"}
)


# SCHEDULED_TASK_TYPED_VALIDATOR_V1
#
# parse_scheduled_tasks_disk -> scheduled_task_fact typed validation.
#
# Dataset-agnostic rules:
# - Reads only compiled scheduled_task_fact rows from EvidenceDB.
# - Supports exact task name/path matching and action substring matching.
# - Optional hidden/enabled constraints are honored only when present in facts.
# - Does not infer maliciousness from scheduled task existence.
# - Does not use dataset names, hashes, IPs, PIDs, usernames, or case keys.

def _sched_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    containers = [fact]
    for ck in ("fields", "normalized", "data", "attributes", "extension"):
        cv = fact.get(ck)
        if isinstance(cv, dict):
            containers.append(cv)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            containers.append(decoded)

    wanted = {str(k).lower() for k in keys}
    for c in containers:
        direct = {str(k).lower(): v for k, v in c.items()}
        for key in wanted:
            if key in direct:
                return direct[key]

    return None


def _sched_s(value) -> str:
    return str(value or "").strip().lower()


def _sched_norm_name_v1(value) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    raw = raw.replace("/", "\\")
    raw = "\\".join(part for part in raw.split("\\") if part)
    return raw.lower()


def _sched_fact_text_v1(fact: dict) -> str:
    parts = []

    def ingest(value):
        if value is None:
            return
        if isinstance(value, (str, int, float, bool)):
            parts.append(str(value))
        elif isinstance(value, list):
            for item in value:
                ingest(item)
        elif isinstance(value, dict):
            for item in value.values():
                ingest(item)

    if isinstance(fact, dict):
        for key in (
            "task_name", "name", "task", "task_path", "path", "uri",
            "action", "actions", "command", "exec", "arguments",
            "raw_excerpt", "artifact", "fields",
        ):
            ingest(fact.get(key))

    return " ".join(parts).lower()


def _sched_action_text_v1(fact: dict) -> str:
    parts = []
    for key in (
        "action", "actions", "command", "exec", "arguments",
        "task_action", "raw_excerpt",
    ):
        value = _sched_fact_nested_value_v1(fact, key)
        if value is None:
            continue
        if isinstance(value, list):
            parts.extend(str(v) for v in value if v is not None)
        elif isinstance(value, dict):
            parts.extend(str(v) for v in value.values() if v is not None)
        else:
            parts.append(str(value))
    return " ".join(parts).lower()


def _sched_bool_v1(value):
    if isinstance(value, bool):
        return value
    s = str(value or "").strip().lower()
    if s in {"true", "yes", "1", "enabled", "hidden"}:
        return True
    if s in {"false", "no", "0", "disabled", "visible"}:
        return False
    return None


def _sched_fact_bool_v1(fact: dict, *keys):
    for key in keys:
        value = _sched_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            parsed = _sched_bool_v1(value)
            if parsed is not None:
                return parsed
    return None


def _sched_name_candidates_v1(fact: dict) -> list[str]:
    vals = []
    for key in (
        "task_name", "name", "task", "task_path", "path", "uri",
        "source_file",
    ):
        value = _sched_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            vals.append(str(value))

    artifact = fact.get("artifact") if isinstance(fact, dict) else None
    if isinstance(artifact, list):
        vals.extend(str(v) for v in artifact if isinstance(v, str) and v.strip())

    out = []
    seen = set()
    for value in vals:
        raw = str(value).strip()
        if not raw:
            continue
        for candidate in (
            _sched_norm_name_v1(raw),
            raw.strip().lower(),
            normalize_path(raw),
        ):
            if candidate and candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
    return out


def _sched_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("scheduled_task_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _sched_facts_for_name_v1(tdb: TypedEvidenceDB, name_value: str) -> list[dict]:
    raw = str(name_value or "").strip()
    if not raw:
        return []

    keys = {
        raw.lower(),
        _sched_norm_name_v1(raw),
        normalize_path(raw),
    }
    keys = {k for k in keys if k}

    out = []
    for key in keys:
        out.extend(tdb.facts_by_index("by_task_name", key, "scheduled_task_fact") or [])

    if out:
        seen = set()
        deduped = []
        for fact in out:
            fid = fact.get("fact_id")
            if fid and fid in seen:
                continue
            if fid:
                seen.add(fid)
            deduped.append(fact)
        return deduped

    for fact in _sched_all_facts_v1(tdb):
        if keys.intersection(set(_sched_name_candidates_v1(fact))):
            out.append(fact)

    return out


def _sched_claim_name_v1(claim: dict) -> str:
    return str(
        claim.get("task_name")
        or claim.get("name")
        or claim.get("task")
        or claim.get("task_path")
        or claim.get("path")
        or claim.get("value")
        or claim.get("artifact")
        or ""
    ).strip()


def _sched_claim_action_contains_v1(claim: dict) -> str:
    return str(
        claim.get("action_contains")
        or claim.get("action")
        or claim.get("contains")
        or claim.get("command")
        or claim.get("exec")
        or claim.get("arguments")
        or ""
    ).strip()


def _sched_apply_optional_constraints_v1(facts: list[dict], claim: dict):
    out = facts

    if "hidden" in claim:
        wanted = _sched_bool_v1(claim.get("hidden"))
        if wanted is not None:
            contextual = [
                f for f in out
                if _sched_fact_bool_v1(f, "hidden", "is_hidden") is not None
            ]
            if not contextual:
                return None, "scheduled_task_fact lacks hidden context"
            out = [
                f for f in contextual
                if _sched_fact_bool_v1(f, "hidden", "is_hidden") == wanted
            ]

    if "enabled" in claim:
        wanted = _sched_bool_v1(claim.get("enabled"))
        if wanted is not None:
            contextual = [
                f for f in out
                if _sched_fact_bool_v1(f, "enabled", "is_enabled", "disabled") is not None
            ]
            if not contextual:
                return None, "scheduled_task_fact lacks enabled context"
            tmp = []
            for f in contextual:
                enabled = _sched_fact_bool_v1(f, "enabled", "is_enabled")
                disabled = _sched_fact_bool_v1(f, "disabled")
                if enabled is None and disabled is not None:
                    enabled = not disabled
                if enabled == wanted:
                    tmp.append(f)
            out = tmp

    return out, None


def _t_scheduled_task(claim: dict, tdb: TypedEvidenceDB):
    all_facts = _sched_all_facts_v1(tdb)
    if not all_facts:
        return None

    name = _sched_claim_name_v1(claim)
    action_contains = _sched_claim_action_contains_v1(claim)

    if name:
        facts = _sched_facts_for_name_v1(tdb, name)
        if not facts:
            return ("MISMATCH", "no typed scheduled_task_fact matched task name/path")
    elif action_contains:
        needle = action_contains.lower()
        facts = [
            fact for fact in all_facts
            if needle in _sched_action_text_v1(fact)
            or needle in _sched_fact_text_v1(fact)
        ]
        if not facts:
            return ("MISMATCH", "no typed scheduled_task_fact matched action/contains constraint")
    else:
        return None

    if action_contains and name:
        needle = action_contains.lower()
        facts = [
            fact for fact in facts
            if needle in _sched_action_text_v1(fact)
            or needle in _sched_fact_text_v1(fact)
        ]
        if not facts:
            return ("MISMATCH", "scheduled_task_fact task matched but action/contains did not")

    facts, reason = _sched_apply_optional_constraints_v1(facts, claim)
    if reason:
        return None
    if not facts:
        return ("MISMATCH", "scheduled_task_fact matched primary constraint but optional constraints did not")

    return ("MATCH", "typed scheduled task fact match")


def _t_scheduled_task_action(claim: dict, tdb: TypedEvidenceDB):
    action_contains = _sched_claim_action_contains_v1(claim)
    if not action_contains:
        return None
    return _t_scheduled_task(claim, tdb)


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["scheduled_task"] = _t_scheduled_task
_TYPED_CHECKERS["scheduled_task_action"] = _t_scheduled_task_action

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"scheduled_task", "scheduled_task_action"}
)


# FILESYSTEM_TIMELINE_TYPED_VALIDATOR_V1
#
# extract_mft_timeline / run_mftecmd -> filesystem_timeline_fact validation.
#
# Dataset-agnostic rules:
# - Reads only compiled filesystem_timeline_fact rows from the current EvidenceDB.
# - Validates path/time/action claims by normalized fields, not raw tool text alone.
# - Requires at least a path or a non-trivial contains constraint; it never treats
#   generic timeline existence as proof.
# - Optional timestamp/action constraints narrow an already-checkable timeline claim.
# - No dataset names, fixed hashes, fixed IPs, fixed PIDs, or case-key values.

def _timeline_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    containers = [fact]
    for ck in ("fields", "normalized", "data", "attributes", "extension"):
        cv = fact.get(ck)
        if isinstance(cv, dict):
            containers.append(cv)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            containers.append(decoded)

    wanted = {str(k).lower() for k in keys}
    for c in containers:
        direct = {str(k).lower(): v for k, v in c.items()}
        for key in wanted:
            if key in direct:
                return direct[key]

    return None


def _timeline_s_v1(value) -> str:
    return str(value or "").strip().lower()


def _timeline_text_v1(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(_timeline_text_v1(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_timeline_text_v1(v) for v in value.values())
    return str(value)


def _timeline_fact_text_v1(fact: dict) -> str:
    if not isinstance(fact, dict):
        return ""

    parts = []
    for key in (
        "path", "file_path", "filename", "name", "normalized_path",
        "timestamp", "time", "datetime", "timestamp_minute",
        "created", "modified", "accessed", "changed",
        "event_type", "event", "action", "operation", "reason",
        "source_tool", "raw_excerpt", "artifact", "fields",
    ):
        parts.append(_timeline_text_v1(fact.get(key)))

    return " ".join(p for p in parts if p).lower()


def _timeline_path_candidates_v1(fact: dict) -> list[str]:
    vals = []
    for key in (
        "normalized_path", "path", "file_path", "filename", "name",
        "full_path", "source_file",
    ):
        value = _timeline_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            vals.append(str(value))

    artifact = fact.get("artifact") if isinstance(fact, dict) else None
    if isinstance(artifact, list):
        vals.extend(str(v) for v in artifact if isinstance(v, str) and v.strip())

    out = []
    seen = set()
    for value in vals:
        raw = str(value).strip()
        if not raw:
            continue

        for candidate in (
            normalize_path(raw),
            raw.replace("\\", "/").strip().lower(),
            raw.strip().lower(),
        ):
            if candidate and candidate not in seen:
                seen.add(candidate)
                out.append(candidate)

    return out


def _timeline_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("filesystem_timeline_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _timeline_claim_path_v1(claim: dict) -> str:
    return str(
        claim.get("path")
        or claim.get("file_path")
        or claim.get("filename")
        or claim.get("normalized_path")
        or claim.get("value")
        or claim.get("artifact")
        or ""
    ).strip()


def _timeline_claim_contains_v1(claim: dict) -> str:
    return str(
        claim.get("contains")
        or claim.get("path_contains")
        or claim.get("file_contains")
        or ""
    ).strip()


def _timeline_claim_time_v1(claim: dict) -> str:
    return str(
        claim.get("timestamp")
        or claim.get("time")
        or claim.get("datetime")
        or claim.get("timestamp_minute")
        or claim.get("date")
        or ""
    ).strip()


def _timeline_claim_action_v1(claim: dict) -> str:
    return str(
        claim.get("event_type")
        or claim.get("event")
        or claim.get("action")
        or claim.get("operation")
        or claim.get("reason")
        or ""
    ).strip()


def _timeline_fact_time_text_v1(fact: dict) -> str:
    parts = []
    for key in (
        "timestamp", "time", "datetime", "timestamp_minute",
        "date", "created", "modified", "accessed", "changed",
        "mtime", "atime", "ctime", "btime",
    ):
        value = _timeline_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            parts.append(str(value))
    return " ".join(parts).lower()


def _timeline_fact_action_text_v1(fact: dict) -> str:
    parts = []
    for key in (
        "event_type", "event", "action", "operation", "reason",
        "timestamp_type", "entry_type", "activity", "type",
    ):
        value = _timeline_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            parts.append(str(value))
    return " ".join(parts).lower()


def _timeline_facts_for_path_v1(tdb: TypedEvidenceDB, path_value: str) -> list[dict]:
    raw = str(path_value or "").strip()
    if not raw:
        return []

    keys = {
        normalize_path(raw),
        raw.replace("\\", "/").strip().lower(),
        raw.strip().lower(),
    }
    keys = {k for k in keys if k}

    out = []
    for key in keys:
        out.extend(tdb.facts_by_index("by_path", key, "filesystem_timeline_fact") or [])

    if out:
        seen = set()
        deduped = []
        for fact in out:
            fid = fact.get("fact_id")
            if fid and fid in seen:
                continue
            if fid:
                seen.add(fid)
            deduped.append(fact)
        return deduped

    for fact in _timeline_all_facts_v1(tdb):
        if keys.intersection(set(_timeline_path_candidates_v1(fact))):
            out.append(fact)

    return out


def _timeline_apply_constraints_v1(facts: list[dict], claim: dict):
    out = facts

    contains = _timeline_claim_contains_v1(claim)
    if contains:
        needle = contains.lower()
        if len(needle) < 3:
            return None, "contains constraint too short for deterministic timeline validation"
        out = [
            fact for fact in out
            if needle in _timeline_fact_text_v1(fact)
            or any(needle in c for c in _timeline_path_candidates_v1(fact))
        ]

    timestamp = _timeline_claim_time_v1(claim)
    if timestamp:
        needle = timestamp.lower()
        out = [
            fact for fact in out
            if needle in _timeline_fact_time_text_v1(fact)
            or needle in _timeline_fact_text_v1(fact)
        ]

    action = _timeline_claim_action_v1(claim)
    if action:
        needle = action.lower()
        out = [
            fact for fact in out
            if needle in _timeline_fact_action_text_v1(fact)
            or needle in _timeline_fact_text_v1(fact)
        ]

    return out, None


def _t_filesystem_timeline(claim: dict, tdb: TypedEvidenceDB):
    all_facts = _timeline_all_facts_v1(tdb)
    if not all_facts:
        return None

    path = _timeline_claim_path_v1(claim)
    contains = _timeline_claim_contains_v1(claim)

    if path:
        facts = _timeline_facts_for_path_v1(tdb, path)
        if not facts:
            return ("MISMATCH", "no typed filesystem_timeline_fact matched path")
    elif contains:
        needle = contains.lower()
        if len(needle) < 3:
            return None
        facts = [
            fact for fact in all_facts
            if needle in _timeline_fact_text_v1(fact)
            or any(needle in c for c in _timeline_path_candidates_v1(fact))
        ]
        if not facts:
            return ("MISMATCH", "no typed filesystem_timeline_fact matched contains constraint")
    else:
        return None

    facts, reason = _timeline_apply_constraints_v1(facts, claim)
    if reason:
        return None
    if not facts:
        return ("MISMATCH", "filesystem_timeline_fact matched primary constraint but optional constraints did not")

    return ("MATCH", "typed filesystem timeline fact match")


def _t_mft_timeline(claim: dict, tdb: TypedEvidenceDB):
    return _t_filesystem_timeline(claim, tdb)


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["filesystem_timeline"] = _t_filesystem_timeline
_TYPED_CHECKERS["mft_timeline"] = _t_mft_timeline

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"filesystem_timeline", "mft_timeline"}
)


# RDP_ARTIFACT_TYPED_VALIDATOR_V1
#
# parse_rdp_artifacts -> rdp_artifact_fact validation.
#
# Dataset-agnostic rules:
# - Reads only compiled rdp_artifact_fact rows from current EvidenceDB.
# - Requires at least one concrete constraint: path, user/account, host/address,
#   artifact_type/kind, timestamp, or a non-trivial contains substring.
# - Never treats generic RDP existence as proof.
# - Uses normalized fields plus raw_excerpt JSON only as already-compiled fact data.
# - No dataset names, fixed hosts, fixed users, fixed IPs, fixed paths, or case-key values.

def _rdp_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    containers = [fact]
    for ck in ("fields", "normalized", "data", "attributes", "extension"):
        cv = fact.get(ck)
        if isinstance(cv, dict):
            containers.append(cv)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            containers.append(decoded)

    wanted = {str(k).lower() for k in keys}
    for c in containers:
        direct = {str(k).lower(): v for k, v in c.items()}
        for key in wanted:
            if key in direct:
                return direct[key]

    return None


def _rdp_text_v1(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(_rdp_text_v1(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_rdp_text_v1(v) for v in value.values())
    return str(value)


def _rdp_fact_blob_v1(fact: dict) -> str:
    if not isinstance(fact, dict):
        return ""

    parts = []
    for key in (
        "artifact_type", "type", "kind", "category", "source_tool",
        "path", "file_path", "source_path", "target_path", "normalized_path",
        "username", "user", "account", "account_name", "sid",
        "host", "remote_host", "server", "remote_server",
        "address", "remote_address", "ip", "remote_ip",
        "timestamp", "time", "datetime", "last_connected",
        "raw_excerpt", "artifact", "fields",
    ):
        parts.append(_rdp_text_v1(fact.get(key)))

    return " ".join(p for p in parts if p).lower()


def _rdp_path_candidates_v1(fact: dict) -> list[str]:
    vals = []
    for key in (
        "normalized_path", "path", "file_path", "source_path",
        "target_path", "artifact_path", "source_file",
    ):
        value = _rdp_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            vals.append(str(value))

    artifact = fact.get("artifact") if isinstance(fact, dict) else None
    if isinstance(artifact, list):
        vals.extend(str(v) for v in artifact if isinstance(v, str) and v.strip())

    out = []
    seen = set()
    for value in vals:
        raw = str(value).strip()
        if not raw:
            continue
        for candidate in (
            normalize_path(raw),
            raw.replace("\\", "/").strip().lower(),
            raw.strip().lower(),
        ):
            if candidate and candidate not in seen:
                seen.add(candidate)
                out.append(candidate)

    return out


def _rdp_fact_values_text_v1(fact: dict, *keys) -> str:
    vals = []
    for key in keys:
        value = _rdp_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            vals.append(str(value))
    return " ".join(vals).lower()


def _rdp_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("rdp_artifact_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _rdp_claim_path_v1(claim: dict) -> str:
    return str(
        claim.get("path")
        or claim.get("file_path")
        or claim.get("source_path")
        or claim.get("target_path")
        or claim.get("normalized_path")
        or claim.get("value")
        or claim.get("artifact")
        or ""
    ).strip()


def _rdp_claim_contains_v1(claim: dict) -> str:
    return str(
        claim.get("contains")
        or claim.get("artifact_contains")
        or claim.get("path_contains")
        or ""
    ).strip()


def _rdp_claim_user_v1(claim: dict) -> str:
    return str(
        claim.get("username")
        or claim.get("user")
        or claim.get("account")
        or claim.get("account_name")
        or claim.get("sid")
        or ""
    ).strip()


def _rdp_claim_host_v1(claim: dict) -> str:
    return str(
        claim.get("host")
        or claim.get("remote_host")
        or claim.get("server")
        or claim.get("remote_server")
        or claim.get("address")
        or claim.get("remote_address")
        or claim.get("ip")
        or claim.get("remote_ip")
        or ""
    ).strip()


def _rdp_claim_kind_v1(claim: dict) -> str:
    return str(
        claim.get("artifact_type")
        or claim.get("rdp_artifact_type")
        or claim.get("kind")
        or claim.get("category")
        or ""
    ).strip()


def _rdp_claim_time_v1(claim: dict) -> str:
    return str(
        claim.get("timestamp")
        or claim.get("time")
        or claim.get("datetime")
        or claim.get("last_connected")
        or ""
    ).strip()


def _rdp_facts_for_path_v1(tdb: TypedEvidenceDB, path_value: str) -> list[dict]:
    raw = str(path_value or "").strip()
    if not raw:
        return []

    keys = {
        normalize_path(raw),
        raw.replace("\\", "/").strip().lower(),
        raw.strip().lower(),
    }
    keys = {k for k in keys if k}

    out = []
    for key in keys:
        out.extend(tdb.facts_by_index("by_path", key, "rdp_artifact_fact") or [])

    if out:
        seen = set()
        deduped = []
        for fact in out:
            fid = fact.get("fact_id")
            if fid and fid in seen:
                continue
            if fid:
                seen.add(fid)
            deduped.append(fact)
        return deduped

    for fact in _rdp_all_facts_v1(tdb):
        if keys.intersection(set(_rdp_path_candidates_v1(fact))):
            out.append(fact)

    return out


def _rdp_apply_constraint_v1(facts: list[dict], claim: dict):
    out = facts

    path = _rdp_claim_path_v1(claim)
    if path:
        path_keys = {
            normalize_path(path),
            path.replace("\\", "/").strip().lower(),
            path.strip().lower(),
        }
        path_keys = {k for k in path_keys if k}
        out = [
            fact for fact in out
            if path_keys.intersection(set(_rdp_path_candidates_v1(fact)))
            or any(k in _rdp_fact_blob_v1(fact) for k in path_keys)
        ]

    contains = _rdp_claim_contains_v1(claim)
    if contains:
        needle = contains.lower()
        if len(needle) < 3:
            return None, "contains constraint too short for deterministic RDP artifact validation"
        out = [
            fact for fact in out
            if needle in _rdp_fact_blob_v1(fact)
            or any(needle in c for c in _rdp_path_candidates_v1(fact))
        ]

    user = _rdp_claim_user_v1(claim)
    if user:
        needle = user.lower()
        out = [
            fact for fact in out
            if needle in _rdp_fact_values_text_v1(
                fact, "username", "user", "account", "account_name", "sid"
            )
            or needle in _rdp_fact_blob_v1(fact)
        ]

    host = _rdp_claim_host_v1(claim)
    if host:
        needle = host.lower()
        out = [
            fact for fact in out
            if needle in _rdp_fact_values_text_v1(
                fact,
                "host", "remote_host", "server", "remote_server",
                "address", "remote_address", "ip", "remote_ip"
            )
            or needle in _rdp_fact_blob_v1(fact)
        ]

    kind = _rdp_claim_kind_v1(claim)
    if kind:
        needle = kind.lower()
        out = [
            fact for fact in out
            if needle in _rdp_fact_values_text_v1(
                fact, "artifact_type", "type", "kind", "category"
            )
            or needle in _rdp_fact_blob_v1(fact)
        ]

    timestamp = _rdp_claim_time_v1(claim)
    if timestamp:
        needle = timestamp.lower()
        out = [
            fact for fact in out
            if needle in _rdp_fact_values_text_v1(
                fact, "timestamp", "time", "datetime", "last_connected"
            )
            or needle in _rdp_fact_blob_v1(fact)
        ]

    return out, None


def _t_rdp_artifact(claim: dict, tdb: TypedEvidenceDB):
    all_facts = _rdp_all_facts_v1(tdb)
    if not all_facts:
        return None

    has_constraint = any((
        _rdp_claim_path_v1(claim),
        _rdp_claim_contains_v1(claim),
        _rdp_claim_user_v1(claim),
        _rdp_claim_host_v1(claim),
        _rdp_claim_kind_v1(claim),
        _rdp_claim_time_v1(claim),
    ))
    if not has_constraint:
        return None

    path = _rdp_claim_path_v1(claim)
    if path:
        facts = _rdp_facts_for_path_v1(tdb, path)
        if not facts:
            return ("MISMATCH", "no typed rdp_artifact_fact matched path")
    else:
        facts = all_facts

    facts, reason = _rdp_apply_constraint_v1(facts, claim)
    if reason:
        return None
    if not facts:
        return ("MISMATCH", "no typed rdp_artifact_fact matched RDP artifact constraints")

    return ("MATCH", "typed RDP artifact fact match")


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["rdp_artifact"] = _t_rdp_artifact

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES) | {"rdp_artifact"}
)


# WMI_SUBSCRIPTION_TYPED_VALIDATOR_V1
#
# parse_wmi_subscription -> wmi_subscription_fact validation.
#
# Dataset-agnostic rules:
# - Reads only compiled wmi_subscription_fact rows from current EvidenceDB.
# - Requires at least one concrete constraint: name, filter, consumer, query,
#   command/action, namespace/class, path, user/SID, or a non-trivial contains.
# - Never treats generic WMI existence as proof.
# - No dataset names, fixed hosts, fixed users, fixed IPs, fixed hashes, or case-key values.

def _wmi_fact_nested_value_v1(fact: dict, *keys):
    if not isinstance(fact, dict):
        return None

    containers = [fact]
    for ck in ("fields", "normalized", "data", "attributes", "extension"):
        cv = fact.get(ck)
        if isinstance(cv, dict):
            containers.append(cv)

    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            containers.append(decoded)

    wanted = {str(k).lower() for k in keys}
    for c in containers:
        direct = {str(k).lower(): v for k, v in c.items()}
        for key in wanted:
            if key in direct:
                return direct[key]

    return None


def _wmi_text_v1(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(_wmi_text_v1(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_wmi_text_v1(v) for v in value.values())
    return str(value)


def _wmi_fact_blob_v1(fact: dict) -> str:
    if not isinstance(fact, dict):
        return ""

    parts = []
    for key in (
        "extracted_name", "name", "subscription_name",
        "filter", "filter_name", "event_filter",
        "consumer", "consumer_name", "event_consumer",
        "binding", "binding_name",
        "query", "event_query", "wql",
        "command", "command_line", "script_text", "script", "action",
        "executable", "arguments",
        "namespace", "event_namespace", "wmi_namespace",
        "class", "wmi_class", "artifact_type", "type", "kind",
        "path", "file_path", "normalized_path",
        "user", "username", "account", "sid", "creator_sid",
        "timestamp", "time", "datetime",
        "source_tool", "raw_excerpt", "artifact", "fields",
    ):
        parts.append(_wmi_text_v1(fact.get(key)))

    return " ".join(p for p in parts if p).lower()


def _wmi_fact_values_text_v1(fact: dict, *keys) -> str:
    vals = []
    for key in keys:
        value = _wmi_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            vals.append(str(value))
    return " ".join(vals).lower()


def _wmi_path_candidates_v1(fact: dict) -> list[str]:
    vals = []
    for key in ("normalized_path", "path", "file_path", "target_path", "source_file"):
        value = _wmi_fact_nested_value_v1(fact, key)
        if value not in (None, ""):
            vals.append(str(value))

    artifact = fact.get("artifact") if isinstance(fact, dict) else None
    if isinstance(artifact, list):
        vals.extend(str(v) for v in artifact if isinstance(v, str) and v.strip())

    out = []
    seen = set()
    for value in vals:
        raw = str(value).strip()
        if not raw:
            continue
        for candidate in (
            normalize_path(raw),
            raw.replace("\\", "/").strip().lower(),
            raw.strip().lower(),
        ):
            if candidate and candidate not in seen:
                seen.add(candidate)
                out.append(candidate)

    return out


def _wmi_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("wmi_subscription_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _wmi_claim_name_v1(claim: dict) -> str:
    return str(
        claim.get("name")
        or claim.get("subscription_name")
        or claim.get("extracted_name")
        or claim.get("value")
        or claim.get("artifact")
        or ""
    ).strip()


def _wmi_claim_filter_v1(claim: dict) -> str:
    return str(
        claim.get("filter")
        or claim.get("filter_name")
        or claim.get("event_filter")
        or ""
    ).strip()


def _wmi_claim_consumer_v1(claim: dict) -> str:
    return str(
        claim.get("consumer")
        or claim.get("consumer_name")
        or claim.get("event_consumer")
        or ""
    ).strip()


def _wmi_claim_query_v1(claim: dict) -> str:
    return str(
        claim.get("query")
        or claim.get("event_query")
        or claim.get("wql")
        or ""
    ).strip()


def _wmi_claim_action_v1(claim: dict) -> str:
    return str(
        claim.get("command")
        or claim.get("command_line")
        or claim.get("script_text")
        or claim.get("script")
        or claim.get("action")
        or claim.get("executable")
        or claim.get("arguments")
        or ""
    ).strip()


def _wmi_claim_namespace_v1(claim: dict) -> str:
    return str(
        claim.get("namespace")
        or claim.get("event_namespace")
        or claim.get("wmi_namespace")
        or ""
    ).strip()


def _wmi_claim_kind_v1(claim: dict) -> str:
    return str(
        claim.get("artifact_type")
        or claim.get("kind")
        or claim.get("class")
        or claim.get("wmi_class")
        or claim.get("type_name")
        or ""
    ).strip()


def _wmi_claim_path_v1(claim: dict) -> str:
    return str(
        claim.get("path")
        or claim.get("file_path")
        or claim.get("target_path")
        or claim.get("normalized_path")
        or ""
    ).strip()


def _wmi_claim_user_v1(claim: dict) -> str:
    return str(
        claim.get("user")
        or claim.get("username")
        or claim.get("account")
        or claim.get("sid")
        or claim.get("creator_sid")
        or ""
    ).strip()


def _wmi_claim_contains_v1(claim: dict) -> str:
    return str(
        claim.get("contains")
        or claim.get("artifact_contains")
        or claim.get("query_contains")
        or claim.get("command_contains")
        or ""
    ).strip()


def _wmi_constraint_pairs_v1(claim: dict):
    return [
        (
            _wmi_claim_name_v1(claim),
            ("extracted_name", "name", "subscription_name", "filter_name", "consumer_name", "binding_name"),
            "name",
        ),
        (
            _wmi_claim_filter_v1(claim),
            ("filter", "filter_name", "event_filter", "name", "extracted_name"),
            "filter",
        ),
        (
            _wmi_claim_consumer_v1(claim),
            ("consumer", "consumer_name", "event_consumer", "name", "extracted_name"),
            "consumer",
        ),
        (
            _wmi_claim_query_v1(claim),
            ("query", "event_query", "wql"),
            "query",
        ),
        (
            _wmi_claim_action_v1(claim),
            ("command", "command_line", "script_text", "script", "action", "executable", "arguments"),
            "action",
        ),
        (
            _wmi_claim_namespace_v1(claim),
            ("namespace", "event_namespace", "wmi_namespace"),
            "namespace",
        ),
        (
            _wmi_claim_kind_v1(claim),
            ("artifact_type", "type", "kind", "class", "wmi_class"),
            "kind",
        ),
        (
            _wmi_claim_user_v1(claim),
            ("user", "username", "account", "sid", "creator_sid"),
            "user",
        ),
    ]


def _wmi_apply_constraints_v1(facts: list[dict], claim: dict):
    out = facts

    for value, keys, label in _wmi_constraint_pairs_v1(claim):
        if not value:
            continue
        needle = value.lower()
        if len(needle) < 2:
            return None, f"{label} constraint too short for deterministic WMI validation"
        out = [
            fact for fact in out
            if needle in _wmi_fact_values_text_v1(fact, *keys)
            or needle in _wmi_fact_blob_v1(fact)
        ]

    path = _wmi_claim_path_v1(claim)
    if path:
        path_keys = {
            normalize_path(path),
            path.replace("\\", "/").strip().lower(),
            path.strip().lower(),
        }
        path_keys = {k for k in path_keys if k}
        out = [
            fact for fact in out
            if path_keys.intersection(set(_wmi_path_candidates_v1(fact)))
            or any(k in _wmi_fact_blob_v1(fact) for k in path_keys)
        ]

    contains = _wmi_claim_contains_v1(claim)
    if contains:
        needle = contains.lower()
        if len(needle) < 3:
            return None, "contains constraint too short for deterministic WMI validation"
        out = [
            fact for fact in out
            if needle in _wmi_fact_blob_v1(fact)
            or any(needle in c for c in _wmi_path_candidates_v1(fact))
        ]

    return out, None


def _t_wmi_subscription(claim: dict, tdb: TypedEvidenceDB):
    all_facts = _wmi_all_facts_v1(tdb)
    if not all_facts:
        return None

    has_constraint = any((
        _wmi_claim_name_v1(claim),
        _wmi_claim_filter_v1(claim),
        _wmi_claim_consumer_v1(claim),
        _wmi_claim_query_v1(claim),
        _wmi_claim_action_v1(claim),
        _wmi_claim_namespace_v1(claim),
        _wmi_claim_kind_v1(claim),
        _wmi_claim_path_v1(claim),
        _wmi_claim_user_v1(claim),
        _wmi_claim_contains_v1(claim),
    ))
    if not has_constraint:
        return None

    facts, reason = _wmi_apply_constraints_v1(all_facts, claim)
    if reason:
        return None
    if not facts:
        return ("MISMATCH", "no typed wmi_subscription_fact matched WMI subscription constraints")

    return ("MATCH", "typed WMI subscription fact match")


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["wmi_subscription"] = _t_wmi_subscription

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES) | {"wmi_subscription"}
)



# PROCESS_ENVVAR_TYPED_VALIDATOR_V1
#
# Typed validation for vol_envars -> environment_variable_fact.
#
# Claim types:
#   process_envvar          pid/process + variable/name/envvar_name, optional value
#   process_envvar_contains pid/process + contains substring across variable/value
#   envvar                  global environment variable match, optional pid/process
#
# Dataset-agnostic:
# - Reads only compiled environment_variable_fact rows.
# - Matches structural fields only.
# - No dataset-specific process names, variable names, values, users, paths, IPs,
#   hashes, PIDs, or case labels.
def _env_fact_value_v1(fact: dict, *names):
    if not isinstance(fact, dict):
        return None
    for name in names:
        if name in fact and fact.get(name) not in (None, ""):
            return fact.get(name)
    fields = fact.get("fields")
    if isinstance(fields, dict):
        for name in names:
            if name in fields and fields.get(name) not in (None, ""):
                return fields.get(name)
    return None


def _env_text_v1(value) -> str:
    return str(value or "").strip()


def _env_lower_v1(value) -> str:
    return _env_text_v1(value).lower()


def _env_fact_pid_v1(fact: dict):
    return _int_or_none(_env_fact_value_v1(fact, "pid", "PID"))


def _env_fact_process_v1(fact: dict) -> str:
    return _env_lower_v1(
        _env_fact_value_v1(
            fact,
            "process_name",
            "process",
            "Process",
            "image_name",
            "ImageFileName",
        )
    )


def _env_fact_name_v1(fact: dict) -> str:
    return _env_lower_v1(
        _env_fact_value_v1(
            fact,
            "variable_name",
            "variable",
            "Variable",
            "name",
            "Name",
            "envvar",
            "EnvVar",
        )
    )


def _env_fact_value_text_v1(fact: dict) -> str:
    return _env_text_v1(
        _env_fact_value_v1(
            fact,
            "value",
            "Value",
            "data",
            "Data",
        )
    )


def _env_all_facts_v1(tdb: TypedEvidenceDB) -> list[dict]:
    facts = (tdb.typed_facts or {}).get("environment_variable_fact") or []
    return [f for f in facts if isinstance(f, dict)]


def _env_facts_for_pid_v1(tdb: TypedEvidenceDB, pid) -> list[dict]:
    pid_i = _int_or_none(pid)
    if pid_i is None:
        return []
    indexed = list(
        tdb.facts_by_index("by_pid", pid_i, "environment_variable_fact") or []
    )
    if indexed:
        return indexed
    return [f for f in _env_all_facts_v1(tdb) if _env_fact_pid_v1(f) == pid_i]


def _env_filter_process_v1(facts: list[dict], process_name: str):
    proc = _env_lower_v1(process_name)
    if not proc:
        return facts, False
    out = []
    saw_process = False
    for fact in facts:
        actual = _env_fact_process_v1(fact)
        if not actual:
            continue
        saw_process = True
        if _names_match(actual, proc):
            out.append(fact)
    return out, saw_process and not out


def _env_claim_name_v1(claim: dict) -> str:
    return _env_lower_v1(
        claim.get("variable")
        or claim.get("variable_name")
        or claim.get("envvar")
        or claim.get("envvar_name")
        or claim.get("name")
    )


def _env_claim_value_v1(claim: dict) -> str:
    return _env_text_v1(
        claim.get("value")
        if claim.get("value") not in (None, "") else
        claim.get("env_value")
        if claim.get("env_value") not in (None, "") else
        claim.get("data")
    )


def _env_claim_contains_v1(claim: dict) -> str:
    return _env_lower_v1(
        claim.get("contains")
        or claim.get("value_contains")
        or claim.get("env_contains")
    )


def _env_match_facts_v1(facts: list[dict], claim: dict):
    name = _env_claim_name_v1(claim)
    expected_value = _env_claim_value_v1(claim)
    contains = _env_claim_contains_v1(claim)

    if not (name or expected_value or contains):
        return None

    narrowed = facts

    if name:
        narrowed = [
            f for f in narrowed
            if _env_fact_name_v1(f) == name
        ]
        if not narrowed:
            return False

    if expected_value:
        expected_l = expected_value.lower()
        narrowed = [
            f for f in narrowed
            if _env_fact_value_text_v1(f).lower() == expected_l
        ]
        if not narrowed:
            return False

    if contains:
        narrowed = [
            f for f in narrowed
            if contains in (
                _env_fact_name_v1(f) + " " + _env_fact_value_text_v1(f).lower()
            )
        ]
        if not narrowed:
            return False

    return bool(narrowed)


def _t_process_envvar(claim: dict, tdb: TypedEvidenceDB):
    pid = _int_or_none(claim.get("pid"))
    proc = claim.get("process") or claim.get("process_name") or ""
    if pid is None and not proc:
        return None

    facts = _env_facts_for_pid_v1(tdb, pid) if pid is not None else _env_all_facts_v1(tdb)
    if not facts:
        return None

    facts, process_mismatch = _env_filter_process_v1(facts, proc)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "environment variable facts exist, but process did not match")
        return None

    matched = _env_match_facts_v1(facts, claim)
    if matched is None:
        return None
    if matched:
        return ("MATCH", "typed process environment variable fact match")
    return ("MISMATCH", "no typed environment_variable_fact matched process envvar constraints")


def _t_process_envvar_contains(claim: dict, tdb: TypedEvidenceDB):
    if not _env_claim_contains_v1(claim):
        return None
    return _t_process_envvar(claim, tdb)


def _t_envvar(claim: dict, tdb: TypedEvidenceDB):
    facts = _env_all_facts_v1(tdb)
    if not facts:
        return None

    pid = _int_or_none(claim.get("pid"))
    if pid is not None:
        facts = [f for f in facts if _env_fact_pid_v1(f) == pid]
        if not facts:
            return None

    proc = claim.get("process") or claim.get("process_name") or ""
    facts, process_mismatch = _env_filter_process_v1(facts, proc)
    if not facts:
        if process_mismatch:
            return ("MISMATCH", "environment variable facts exist, but process did not match")
        return None

    matched = _env_match_facts_v1(facts, claim)
    if matched is None:
        return None
    if matched:
        return ("MATCH", "typed environment variable fact match")
    return ("MISMATCH", "no typed environment_variable_fact matched envvar constraints")


_TYPED_CHECKERS = dict(_TYPED_CHECKERS)
_TYPED_CHECKERS["process_envvar"] = _t_process_envvar
_TYPED_CHECKERS["process_envvar_contains"] = _t_process_envvar_contains
_TYPED_CHECKERS["envvar"] = _t_envvar

TYPED_SUPPORTED_CLAIM_TYPES = frozenset(
    set(TYPED_SUPPORTED_CLAIM_TYPES)
    | {"process_envvar", "process_envvar_contains", "envvar"}
)

# SIFT_TYPED_VALIDATOR_FAMILY_REGISTRY_EXPOSURE_V2
# Exposes universal fact-family roles to validator/report probes.
# This is schema taxonomy only; no dataset-specific literals are permitted here.
try:
    from sift_sentinel.analysis.validation_family_registry import (
        get_validation_family_registry as _sift_get_validation_family_registry_v2,
        is_family_registered as _sift_is_family_registered_v2,
        family_role as _sift_family_role_v2,
        tool_role_summary as _sift_tool_role_summary_v2,
    )

    SIFT_VALIDATION_FAMILY_REGISTRY = _sift_get_validation_family_registry_v2()

    def sift_validation_family_role(family: str) -> str:
        return _sift_family_role_v2(family)

    def sift_validation_family_registered(family: str) -> bool:
        return _sift_is_family_registered_v2(family)

except Exception:
    SIFT_VALIDATION_FAMILY_REGISTRY = {}

    def sift_validation_family_role(family: str) -> str:
        return ""

    def sift_validation_family_registered(family: str) -> bool:
        return False


# ── R1B_CLAIM_RESCUE_V1 ──────────────────────────────────────────────────
# Additive-only rescue layer for findings that died "no recognized claim
# types": (1) pid-less process-EXISTENCE binding by process-name scan over
# compiled process facts (Volatility truncation tolerated via _names_match);
# (2) ttp-tag FAMILY matching against the pipeline's own registered tag
# grammar (underscore word-boundary prefix), recovering claims whose tag is a
# more-specific spelling of a compiled tag. Both upgrades can only turn an
# abstain/MISMATCH into a MATCH that real compiled facts support -- they never
# introduce a new MISMATCH and never touch disposition (a rescued finding
# still passes every confirmed-bucket gate downstream). Kill-switch:
# SIFT_CLAIM_RESCUE_R1B=0. Structural/shape-keyed; no case literals.

def _r1b_enabled_v1() -> bool:
    import os as _os  # local: typed_validator has no module-level os import
    return _os.environ.get("SIFT_CLAIM_RESCUE_R1B", "1").strip().lower() \
        not in ("0", "false", "no", "off")


_R1B_PROC_FACT_FAMILIES = ("process_fact", "psxview_fact")
_R1B_PROC_NAME_KEYS = (
    "process_name", "image_name", "ImageFileName", "name", "process")

_t_process_exists_v1_ref = _TYPED_CHECKERS.get("process_exists")


def _t_process_exists_v2(claim: dict, tdb: TypedEvidenceDB):
    if _t_process_exists_v1_ref is not None:
        v1 = _t_process_exists_v1_ref(claim, tdb)
        if v1 is not None:
            return v1
    if not _r1b_enabled_v1():
        return None
    name = str(claim.get("process") or claim.get("value") or "").strip()
    if not name or " " in name or "\\" in name or "/" in name:
        return None
    for _fam in _R1B_PROC_FACT_FAMILIES:
        for _f in (tdb.typed_facts or {}).get(_fam) or []:
            if not isinstance(_f, dict):
                continue
            for _k in _R1B_PROC_NAME_KEYS:
                _v = _f.get(_k)
                if _v and _names_match(str(_v), name):
                    return ("MATCH",
                            "typed process-name match (pid-less, %s)" % _fam)
    return None


_TYPED_CHECKERS["process_exists"] = _t_process_exists_v2


def _r1b_ttp_tag_family_match(a, b) -> bool:
    """True when one tag is an underscore-word-boundary prefix of the other."""
    al, bl = str(a or "").lower(), str(b or "").lower()
    if not al or not bl:
        return False
    if al == bl:
        return True
    shorter, longer = (al, bl) if len(al) <= len(bl) else (bl, al)
    return longer.startswith(shorter) and longer[len(shorter)] == "_"


_t_powershell_command_v1_ref = _TYPED_CHECKERS.get("powershell_command")


def _t_powershell_command_v2(claim, tdb):
    v1 = (_t_powershell_command_v1_ref(claim, tdb)
          if _t_powershell_command_v1_ref is not None else None)
    if not _r1b_enabled_v1() or v1 is None or v1[0] != "MISMATCH":
        return v1
    ttp = claim.get("ttp_tag")
    if not ttp:
        return v1
    for _key in ((tdb.indexes or {}).get("by_ttp_tag") or {}):
        if _r1b_ttp_tag_family_match(_key, ttp):
            if tdb.facts_by_index(
                    "by_ttp_tag", _key, "powershell_command_fact"):
                return ("MATCH",
                        "ttp-tag family match (%s ~ %s)" % (ttp, _key))
    return v1


_TYPED_CHECKERS["powershell_command"] = _t_powershell_command_v2
