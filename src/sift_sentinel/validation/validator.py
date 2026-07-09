"""
Sentinel Qwen Ensemble - Deterministic finding validator.
Checks every factual claim in a finding against the paired reference set.
Code checks AI, not AI checks AI.
"""

from __future__ import annotations

from sift_sentinel.validation.reference_set import normalize_timestamp
from sift_sentinel.validation.typed_validator import (
    TYPED_SUPPORTED_CLAIM_TYPES,
    TypedEvidenceDB,
    typed_check_claim,
)

import threading as _threading

# ── Shared TypedEvidenceDB (Step-10 perf: build once, reuse across findings) ──
# Step 10 validates N findings in an 8-thread pool, each calling
# validate_finding with the SAME evidence_db dict. Building a fresh
# TypedEvidenceDB per finding rebuilds the _fid map + the lazy path/registry
# indexes over the full typed-fact set (~370k facts) every time -- pure-Python,
# GIL-serialized, so the pool gives no speedup (measured wall=106s,
# avg=2.65s/finding for 40 findings). TypedEvidenceDB holds no per-finding state
# and is documented read-only-shareable across validator threads, so we memoize
# the most-recent one by OBJECT IDENTITY (`is`, never id() -- no GC
# address-reuse hazard). Universal: no case data; works on any evidence_db.
_SHARED_TDB_LOCK = _threading.Lock()
_SHARED_TDB = {"src": None, "tdb": None}


def _shared_typed_evidence_db(evidence_db):
    """Return a TypedEvidenceDB for *evidence_db*, reusing the last one when the
    caller passes the same dict object again. None for falsy input (preserves the
    ``... if evidence_db else None`` contract)."""
    if not evidence_db:
        return None
    # Lock-free fast path: steady-state cache hit (same dict for every finding).
    if _SHARED_TDB["src"] is evidence_db:
        return _SHARED_TDB["tdb"]
    with _SHARED_TDB_LOCK:
        if _SHARED_TDB["src"] is evidence_db:  # double-checked under lock
            return _SHARED_TDB["tdb"]
        tdb = TypedEvidenceDB(evidence_db)
        # Set tdb BEFORE src so a lock-free reader that sees the new src never
        # reads a stale tdb (dict item writes are atomic under the GIL).
        _SHARED_TDB["tdb"] = tdb
        _SHARED_TDB["src"] = evidence_db
        return tdb


def _telemetry(used: bool, typed_m: int = 0,
               ref_m: int = 0, unsupported: int = 0) -> dict:
    """Slot 31E-DB.2 validator telemetry payload."""
    return {
        "typed_evidence_db_used": used,
        "typed_fact_matches": typed_m,
        "reference_set_fallback_matches": ref_m,
        "unsupported_claim_type_count": unsupported,
    }


def validate_finding(
    finding: dict, reference_set: dict,
    *, strict_validation: bool = False,
    evidence_db: dict | None = None,
) -> dict:
    """Validate a finding and stamp canonical telemetry onto it.

    Slot 31E-DB.5.1: the backend validator is the single source of truth
    for evidence-validation telemetry. The per-finding result is stamped
    onto ``finding["_validation_telemetry"]`` (purely additive -- the
    return value and pass/block semantics are unchanged) so the wrapper
    can aggregate a canonical telemetry object instead of recomputing
    stale default zeros downstream.
    """
    result = _validate_finding_impl(
        finding, reference_set,
        strict_validation=strict_validation,
        evidence_db=evidence_db,
    )
    if isinstance(finding, dict):
        finding["_validation_telemetry"] = {
            "typed_evidence_db_used": bool(
                result.get("typed_evidence_db_used")),
            "typed_fact_matches": int(
                result.get("typed_fact_matches", 0) or 0),
            "reference_set_fallback_matches": int(
                result.get("reference_set_fallback_matches", 0) or 0),
            "unsupported_claim_type_count": int(
                result.get("unsupported_claim_type_count", 0) or 0),
        }
        # Slot 31E-DB.5a-alpha TASK 1 (EXPLICIT_FACT_ID_IN_CLAIMS_GATE):
        # the *validator* -- not Inv2 -- attaches durable references
        # resolving each MATCHed claim back to the typed fact / reference
        # artifact that backed it. These refs are what the confirmed
        # bucket's CLAIM_FACT_REFERENCE_GATE consumes; they are derived
        # from real validator checks, never invented upstream.
        if result.get("status") == "MATCH":
            refs = _build_validator_fact_refs(result.get("checks") or [])
            if refs:
                finding["validator_fact_refs"] = refs
            corroborating = _entity_corroborating_refs(finding, evidence_db)
            if corroborating:
                finding["corroborating_fact_refs"] = corroborating
    return result


# Map a claim type onto the typed fact family it is checked against.
_CLAIM_TYPE_TO_FACT_TYPE = {
    "wmi_subscription": "wmi_subscription_fact",
    "rdp_artifact": "rdp_artifact_fact",
    "mft_timeline": "filesystem_timeline_fact",
    "filesystem_timeline": "filesystem_timeline_fact",
    "scheduled_task_action": "scheduled_task_fact",
    "scheduled_task": "scheduled_task_fact",
    "file_object": "filesystem_listing_fact",
    "filesystem_listing": "filesystem_listing_fact",
    "pid": "process_fact",
    "process_exists": "process_fact",
    "child_process": "process_relationship_fact",
    "connection": "network_connection_fact",
    "hash": "file_execution_fact",
    "timestamp": "timeline_fact",
    "path": "file_execution_fact",
    "srum_usage": "srum_usage_fact",  # 31K-SRUM-TYPED-VALIDATOR
    "process_cmdline": "process_cmdline_fact",
    "process_cmdline_contains": "process_cmdline_fact",
    "process_cmdline_empty": "process_cmdline_fact",
    "process_dll_loaded": "dll_load_fact",
    "dll_loaded": "dll_load_fact",
    "dll_path_loaded": "dll_load_fact",
    "process_privilege": "privilege_fact",
    "process_privilege_enabled": "privilege_fact",
    "process_sid": "sid_fact",
    "process_account_sid": "sid_fact",
    "ssdt_integrity": "ssdt_integrity_fact",
    "kernel_ssdt_entry": "ssdt_integrity_fact",
    "service": "service_fact",
    "service_state": "service_fact",
    "service_binary": "service_fact",
    "process_handle_contains": "handle_fact",
    "process_handle_type": "handle_fact",
    "process_handle": "handle_fact",
}


try:
    from sift_sentinel.validation.typed_validator import (
        normalize_ip as _corro_norm_ip,
        normalize_path as _corro_norm_path,
        normalize_registry as _corro_norm_reg,
    )
except Exception:  # pragma: no cover - normalizers ship in-tree
    def _corro_norm_ip(s):
        return str(s).strip() if s else ""
    def _corro_norm_path(s):
        return str(s).strip().lower() if s else ""
    def _corro_norm_reg(s):
        return str(s).strip().lower() if s else ""


def _entity_corroborating_refs(finding, evidence_db):
    """Entity-keyed corroboration across ALL typed-fact indexes.

    For every entity a finding already asserts (pid, path, registry path,
    ip, port, service/task name, hash) look it up in every typed index and
    return one durable ref per entity-sharing fact -- whatever its
    fact_type. Corroboration only: it enriches the evidence basis of a
    finding that already validated (so behavior facts such as
    memory_injection / network / registry / service appear in the audit
    trail, not just the process/file facts the claim-type map yields). It
    never originates or confirms a finding, and is written to a SEPARATE
    field so the confirmed-bucket gate is untouched. Keyed purely on the
    finding's own normalized entities -> fully dataset-agnostic; covers any
    present or future fact_type an index already carries.
    """
    if not isinstance(evidence_db, dict):
        return []
    tdb = _shared_typed_evidence_db(evidence_db)
    if tdb is None or not tdb.available():
        return []
    _PER_KEY_CAP = 50
    _TOTAL_CAP = 300
    seen = set()
    refs = []

    def _emit(facts, index_name, key):
        n = 0
        for f in facts:
            if len(refs) >= _TOTAL_CAP or n >= _PER_KEY_CAP:
                break
            if not isinstance(f, dict):
                continue
            fid = f.get("fact_id")
            if not fid or fid in seen:
                continue
            seen.add(fid)
            n += 1
            refs.append({
                "fact_type": f.get("fact_type", "evidence_fact"),
                "fact_id": fid,
                "via_index": index_name,
                "matched_key": str(key),
                "source": "typed_evidence_db",
                "relation": "entity_corroboration",
            })

    def _lk(index_name, key):
        if key in (None, "") or len(refs) >= _TOTAL_CAP:
            return
        _emit(tdb.facts_by_index(index_name, key), index_name, key)

    for claim in (finding.get("claims") or []):
        if not isinstance(claim, dict):
            continue
        for pk in ("pid", "process_id"):
            pv = claim.get(pk)
            if pv not in (None, ""):
                _lk("by_pid", str(pv).strip())
        raw = claim.get("value")
        if raw in (None, ""):
            raw = claim.get("artifact")
        if raw not in (None, ""):
            s = str(raw)
            np = _corro_norm_path(s)
            if np:
                _lk("by_path", np)
            nr = _corro_norm_reg(s)
            if nr:
                _lk("by_registry_path", nr)
            low = s.strip().lower()
            _lk("by_task_name", low)
            _lk("by_service_name", low)
            nip = _corro_norm_ip(s)
            if nip:
                _lk("by_ip", nip)
            ss = s.strip()
            if ss.isdigit():
                _lk("by_event_id", ss)
        for ak in ("foreign_addr", "ip", "local_addr", "remote_addr"):
            av = claim.get(ak)
            if av not in (None, ""):
                nip = _corro_norm_ip(str(av))
                if nip:
                    _lk("by_ip", nip)
        for pk in ("port", "foreign_port", "local_port", "remote_port"):
            pv = claim.get(pk)
            if pv not in (None, ""):
                _lk("by_port", str(pv).strip())
        for hk in ("hash", "sha1", "sha256"):
            hv = claim.get(hk)
            if hv not in (None, ""):
                _lk("by_hash", str(hv).strip().lower())
    return refs


def _build_validator_fact_refs(checks: list) -> list[dict]:
    """Build durable fact references from MATCHed validator checks.

    Each ref records the claim type, the resolved fact_type family, and
    the check source (``typed_evidence_db`` / ``reference_set``) so a
    downstream consumer can audit value-to-artifact linkage without
    re-running the validator.
    """
    refs: list[dict] = []
    for i, c in enumerate(checks):
        if not isinstance(c, dict) or c.get("result") != "MATCH":
            continue
        claim = c.get("claim") or {}
        ctype = str(claim.get("type", "")) if isinstance(claim, dict) else ""
        if ctype == "typed_fact":
            fact_type = str(claim.get("fact_type") or "").strip() or "evidence_fact"
        else:
            fact_type = _CLAIM_TYPE_TO_FACT_TYPE.get(ctype, "evidence_fact")
        refs.append({
            "fact_type": fact_type,
            "claim_type": ctype,
            "claim_index": i,
            "source": c.get("source", "reference_set"),
        })
    return refs


def _validate_finding_impl(
    finding: dict, reference_set: dict,
    *, strict_validation: bool = False,
    evidence_db: dict | None = None,
) -> dict:
    """Validate a finding's factual claims.

    Prefers first-class typed forensic facts from the Step 7 EvidenceDB
    sidecar (*evidence_db*) when supplied; otherwise -- and for any claim
    the typed layer cannot deterministically answer -- falls back to the
    legacy paired reference set. Validation is never weakened: a claim
    still passes only when an artifact deterministically backs it.

    Each claim in finding["claims"] is checked:
      hash:       SHA1 exists AND maps to claimed filename
      pid:        PID exists AND maps to claimed process
      timestamp:  timestamp exists for claimed artifact
      connection: PID+foreign_addr exists with correct process

    When *strict_validation* is True, a finding needs 3+ MATCH claims
    to pass.  Single-source findings are blocked with MISMATCH so the
    self-correction loop can strengthen them.

    Returns {"status": "MATCH"|"MISMATCH"|"UNRESOLVED",
             "checks": [...], "detail": str,
             plus Slot 31E-DB.2 telemetry keys
             (typed_evidence_db_used, typed_fact_matches,
              reference_set_fallback_matches,
              unsupported_claim_type_count)}.

    When *evidence_db* is None the typed path is skipped entirely and
    behavior is byte-identical to the pre-31E-DB.2 reference_set-only
    validator (clean rollback contract).
    """
    tdb = _shared_typed_evidence_db(evidence_db)
    typed_used = bool(tdb and tdb.available())

    claims = finding.get("claims", [])
    if not claims:
        return {
            "status": "UNRESOLVED",
            "checks": [],
            "detail": "no checkable claims in finding",
            **_telemetry(typed_used),
        }

    _checkers = {
        "hash": _check_hash,
        "pid": _check_pid,
        "timestamp": _check_timestamp,
        "connection": _check_connection,
        "child_process": _check_child_process,
        "process_exists": _check_process_exists,
    }

    # Types that are recognized but have no checker -- they pass through
    # without verification. Findings with ONLY passthrough claims are
    # UNRESOLVED (no checkable claims), but passthrough claims mixed with
    # verifiable claims do not block the finding.
    _passthrough_types = {"path", "raw", "artifact"}
    # Block findings with unknown claim types -- can't verify what we
    # don't understand, so the finding must not pass the deterministic gate.
    #
    # Runtime alignment: claim types implemented by the typed validator are
    # first-class known claim types. They are not passthrough and still must
    # be checked by the typed EvidenceDB path below.
    try:
        from sift_sentinel.validation.typed_validator import (
            _TYPED_CHECKERS as _SIFT_TYPED_CHECKERS,
        )
    except Exception:
        _SIFT_TYPED_CHECKERS = {}

    _typed_supported = set(_SIFT_TYPED_CHECKERS)
    _known_claim_types = set(_checkers) | set(_passthrough_types) | _typed_supported

    # 1. Unknown types -- not understood by ANY checker -- block as UNRESOLVED.
    unknown_types_list = [
        claim.get("type", "")
        for claim in claims
        if claim.get("type", "") not in _known_claim_types
    ]
    unknown_types = sorted(set(unknown_types_list))
    if unknown_types:
        return {
            "status": "UNRESOLVED",
            "checks": [],
            "detail": f"unrecognized claim types: {', '.join(unknown_types)}",
            **_telemetry(typed_used, unsupported=len(unknown_types_list)),
        }

    # 2. Typed-layer-unsupported count: claim types the typed validator
    # cannot deterministically check (even though reference_set can).
    # Used downstream to know which claims rely on the legacy ref_set.
    unsupported_count = sum(
        1 for claim in claims
        if claim.get("type", "") not in _typed_supported
        and claim.get("type", "") in _checkers
    )

    checks = []
    typed_matches = 0
    ref_matches = 0
    for claim in claims:
        # Prefer a deterministic typed-fact verdict; fall back to the
        # reference_set checker when the typed layer abstains (None).
        typed_verdict = (
            typed_check_claim(claim, tdb) if typed_used else None
        )
        if typed_verdict is not None:
            result, detail = typed_verdict
            checks.append({
                "claim": claim, "result": result, "detail": detail,
                "source": "typed_evidence_db",
            })
            if result == "MATCH":
                typed_matches += 1
            continue

        checker = _checkers.get(claim.get("type", ""))
        if checker:
            # _check_timestamp uses finding.artifact as fallback when
            # claim.artifact is unknown to the reference set.
            if checker is _check_timestamp:
                c = checker(claim, reference_set)
            else:
                c = checker(claim, reference_set)
            c["source"] = "reference_set"
            checks.append(c)
            if c["result"] == "MATCH":
                ref_matches += 1
        # else: passthrough/unverifiable claim with no typed answer ->
        # legacy behavior (contributes no check, never a new block).

    tele = _telemetry(
        typed_used, typed_matches, ref_matches, unsupported_count)

    if not checks:
        return {
            "status": "UNRESOLVED",
            "checks": [],
            "detail": "no recognized claim types",
            **tele,
        }

    if any(c["result"] == "MISMATCH" for c in checks):
        first_bad = next(c for c in checks if c["result"] == "MISMATCH")
        return {
            "status": "MISMATCH",
            "checks": checks,
            "detail": first_bad["detail"],
            **tele,
        }

    match_count = sum(1 for c in checks if c["result"] == "MATCH")

    if all(c["result"] == "MATCH" for c in checks):
        # Strict validation: require 3+ corroborating MATCH claims
        if strict_validation and match_count < 3:
            return {
                "status": "MISMATCH",
                "checks": checks,
                "detail": (
                    f"Strict validation: finding had only {match_count} "
                    f"corroborating claim{'s' if match_count != 1 else ''}. "
                    f"Strict mode requires 3+. "
                    f"Add more corroborating evidence from different tool types."
                ),
                **tele,
            }
        return {
            "status": "MATCH", "checks": checks, "detail": "", **tele,
        }

    return {
        "status": "UNRESOLVED",
        "checks": checks,
        "detail": "some claims could not be verified",
        **tele,
    }


# ── Helpers ──────────────────────────────────────────────────────────────

def _norm_str(value: object) -> str:
    """Safely coerce to str; None/non-str becomes ''."""
    return value if isinstance(value, str) else ""


# _EPROCESS.ImageFileName: 16-byte buffer (15 chars + NUL); tools render 14-15
# visible chars. A prefix of >= this length means kernel truncation, not a
# different process.
_EPROCESS_NAME_CAP = 14


def _names_match(a: str, b: str) -> bool:
    """Case-insensitive match with Windows name truncation tolerance.

    Netscan Owner field comes from _EPROCESS.ImageFileName (15-char limit).
    Long names like ``LONGPROCESS.EXE`` are stored as ``longprocess.ex``.
    Accepts prefix match when the shorter string is within 4 chars of the
    longer one and at least 5 chars long (avoids trivially short prefixes);
    additionally, a shorter name at the kernel cap (>=14 chars) matches on
    prefix alone -- the kernel cut the rest, so ANY remainder length is
    possible (a <=4 diff only covers a dropped ".exe", which false-blocked
    long process names as "typed cross-contamination").
    """
    al, bl = a.lower(), b.lower()
    if al == bl:
        return True
    if not al or not bl:
        return False
    shorter, longer = (al, bl) if len(al) <= len(bl) else (bl, al)
    if not longer.startswith(shorter):
        return False
    if len(shorter) >= _EPROCESS_NAME_CAP:
        return True
    return len(shorter) >= 5 and len(longer) - len(shorter) <= 4


# ── Claim checkers ───────────────────────────────────────────────────────

def _check_hash(claim: dict, ref: dict) -> dict:
    """Validate SHA1 plus filename/path with case and basename tolerance.

    Strict rule:
      - SHA1 must exist in the reference set.
      - The claimed filename must match the filename mapped to that SHA1.
      - Case and path/basename differences are tolerated.
      - A different known or unknown filename remains MISMATCH.
    """
    sha1 = (_norm_str(claim.get("sha1")) or "").lower()
    claimed = _norm_str(
        claim.get("filename") or claim.get("artifact") or claim.get("path")
    )
    hashes = ref.get("hashes", {}) or {}

    def _base(value: object) -> str:
        s = _norm_str(value).replace(chr(92), "/").rstrip("/")
        return s.rsplit("/", 1)[-1].lower()

    if not sha1:
        return _result(claim, "MISMATCH", "missing sha1")
    if not claimed:
        return _result(claim, "MISMATCH", "missing filename")

    actual_key = None
    for k in hashes:
        if str(k).lower() == sha1:
            actual_key = k
            break

    if actual_key is None:
        return _result(
            claim,
            "MISMATCH",
            f"SHA1 {sha1} not found in reference set",
        )

    actual = hashes[actual_key]
    if isinstance(actual, dict):
        values = [
            actual.get("filename"),
            actual.get("artifact"),
            actual.get("path"),
            actual.get("value"),
        ]
    elif isinstance(actual, (list, tuple, set)):
        values = list(actual)
    else:
        values = [actual]

    actual_bases = {_base(v) for v in values if _norm_str(v)}
    claimed_base = _base(claimed)

    if claimed_base in actual_bases:
        return _result(claim, "MATCH", "")

    actual_display = next((_norm_str(v) for v in values if _norm_str(v)), str(actual))
    return _result(
        claim,
        "MISMATCH",
        f"SHA1 {sha1} belongs to {actual_display}, "
        f"not {claimed} (cross-contamination)",
    )

def _check_pid(claim: dict, ref: dict) -> dict:
    pid = claim.get("pid")
    claimed = _norm_str(claim.get("process"))
    pid_map = ref.get("pid_to_process", {})

    if pid not in pid_map:
        return _result(claim, "MISMATCH",
                       f"PID {pid} not found in reference set")

    actual = pid_map[pid]

    # pid_to_process stores lists (PID reuse: same PID, different
    # processes at different times).  Legacy single-string refs are
    # handled via the isinstance fallback.
    if isinstance(actual, list):
        for name in actual:
            if _names_match(name, claimed):
                return _result(claim, "MATCH", "")
        if len(set(n.lower() for n in actual)) > 1:
            return _result(
                claim, "MATCH",
                f"PID {pid} reuse detected "
                f"({', '.join(dict.fromkeys(actual))}), accepting")
        return _result(
            claim, "MISMATCH",
            f"PID {pid} is {actual[0]}, "
            f"not {claimed} (cross-contamination)")

    # Legacy: single-string value
    if not _names_match(actual, claimed):
        return _result(claim, "MISMATCH",
                       f"PID {pid} is {actual}, "
                       f"not {claimed} (cross-contamination)")

    return _result(claim, "MATCH", "")


def _check_timestamp(claim: dict, ref: dict) -> dict:
    """Validate timestamp plus artifact with case and basename tolerance.

    Strict rule:
      - Artifact must exist in the reference timestamp map.
      - Timestamp must match that artifact's timestamp list.
      - Case and path/basename differences are tolerated.
      - Unknown artifacts remain MISMATCH.
    """
    ts = normalize_timestamp(claim.get("timestamp"))
    artifact = _norm_str(
        claim.get("artifact") or claim.get("filename") or claim.get("path")
    )
    ts_map = (
        ref.get("timestamps_per_artifact")
        or ref.get("timestamps")
        or {}
    )

    def _base(value: object) -> str:
        s = _norm_str(value).replace(chr(92), "/").rstrip("/")
        return s.rsplit("/", 1)[-1].lower()

    if not ts:
        return _result(claim, "MISMATCH", "missing timestamp")
    if not artifact:
        return _result(claim, "MISMATCH", "missing artifact")

    artifact_key = None
    artifact_base = _base(artifact)
    artifact_full = _norm_str(artifact).lower()

    for key in ts_map:
        key_full = _norm_str(key).lower()
        if key_full == artifact_full or _base(key) == artifact_base:
            artifact_key = key
            break

    if artifact_key is None:
        return _result(
            claim,
            "MISMATCH",
            f"artifact {artifact!r} not found in reference set",
        )

    normalized_refs = [normalize_timestamp(t) for t in ts_map[artifact_key]]
    if ts not in normalized_refs:
        return _result(
            claim,
            "MISMATCH",
            f"timestamp {ts} not found for {artifact}",
        )

    return _result(claim, "MATCH", "")

def _check_connection(claim: dict, ref: dict) -> dict:
    pid = claim.get("pid")
    foreign_addr = _norm_str(claim.get("foreign_addr"))
    claimed_process = _norm_str(claim.get("process"))
    connections = ref.get("connections", {})

    for key, owner in connections.items():
        # Key format: "{pid}:{local_addr}:{local_port}->{foreign_addr}:{foreign_port}"
        parts = key.split("->")
        if len(parts) != 2:
            continue
        local_part, foreign_part = parts
        key_pid_str = local_part.split(":")[0]
        key_foreign_addr = foreign_part.rsplit(":", 1)[0]

        if str(pid) != key_pid_str:
            continue
        if foreign_addr != key_foreign_addr:
            continue

        if claimed_process and not _names_match(owner, claimed_process):
            return _result(claim, "MISMATCH",
                           f"connection from PID {pid} owned by "
                           f"{owner}, not {claimed_process}")
        return _result(claim, "MATCH", "")

    return _result(claim, "MISMATCH",
                   f"no connection found for PID {pid} to {foreign_addr}")


def _check_child_process(claim: dict, ref: dict) -> dict:
    """Verify parent-child process relationship.

    Claim schema: {"type": "child_process", "parent_pid": int, "child_pid": int}

    Verifies:
      1. child_pid exists in pid_to_process
      2. parent_pid exists in pid_to_process
      3. pid_to_parent_pid[child_pid] == parent_pid

    Stronger than two separate pid claims: verifies the relationship,
    not just both endpoints.
    """
    parent_pid = claim.get("parent_pid")
    child_pid = claim.get("child_pid")
    pid_map = ref.get("pid_to_process", {})
    parent_map = ref.get("pid_to_parent_pid", {})

    if child_pid not in pid_map:
        return _result(claim, "MISMATCH",
                       f"child PID {child_pid} not found in reference set")
    if parent_pid not in pid_map:
        return _result(claim, "MISMATCH",
                       f"parent PID {parent_pid} not found in reference set")

    actual_parent = parent_map.get(child_pid)
    if actual_parent is None:
        return _result(claim, "MISMATCH",
                       f"no parent recorded for PID {child_pid}")
    if actual_parent != parent_pid:
        return _result(
            claim, "MISMATCH",
            f"PID {child_pid} parent is {actual_parent}, not {parent_pid}")

    return _result(claim, "MATCH", "")


def _check_process_exists(claim: dict, ref: dict) -> dict:
    """Verify a process exists in the reference set.

    Claim schema: {"type": "process_exists", "pid": int}

    Verifies PID is present in pid_to_process. If the PID is also in
    hidden_pids (DKOM candidate: present in psscan but not pstree),
    returns MATCH with a note so callers can flag it.
    """
    pid = claim.get("pid")
    pid_map = ref.get("pid_to_process", {})
    hidden = ref.get("hidden_pids", set())

    if pid not in pid_map:
        return _result(claim, "MISMATCH",
                       f"PID {pid} not found in reference set")

    if pid in hidden:
        return _result(
            claim, "MATCH",
            f"PID {pid} present but hidden (DKOM candidate: "
            "in psscan, not in pstree)")

    return _result(claim, "MATCH", "")


def _result(claim: dict, result: str, detail: str) -> dict:
    return {"claim": claim, "result": result, "detail": detail}

# 31K-PS-DECODED-COMMAND-WIRE:
# Durable audit refs must resolve to the typed fact family, not generic evidence_fact.
_CLAIM_TYPE_TO_FACT_TYPE = dict(_CLAIM_TYPE_TO_FACT_TYPE)
_CLAIM_TYPE_TO_FACT_TYPE["powershell_command"] = "powershell_command_fact"
_CLAIM_TYPE_TO_FACT_TYPE["decoded_string"] = "decoded_string_fact"

# PROCESS_ENVVAR_VALIDATOR_FACT_REF_MAP_V1
_CLAIM_TYPE_TO_FACT_TYPE["process_envvar"] = "environment_variable_fact"
_CLAIM_TYPE_TO_FACT_TYPE["process_envvar_contains"] = "environment_variable_fact"
_CLAIM_TYPE_TO_FACT_TYPE["envvar"] = "environment_variable_fact"

_CLAIM_TYPE_TO_FACT_TYPE["event_log"] = "event_log_fact"
_CLAIM_TYPE_TO_FACT_TYPE["appcompatcache"] = "appcompatcache_execution_fact"

