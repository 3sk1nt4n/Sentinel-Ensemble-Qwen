"""SIFT Sentinel -- Malicious semantic signal registry (Slot 31E-DB.5.4).

A verified event is NOT automatically malicious. A process can *exist*,
a port can be *listening*, an MSI installer event can be *logged* -- and
none of that is, by itself, evidence of compromise. Those are
environment-context facts.

This module draws the deterministic line between:

  * malicious *semantic* signals -- a fact whose shape carries adversary
    meaning (RWX private memory, null cmdline on a real executable, a
    Run key pointing into a staging path, ...), and
  * environment-context signals -- a fact that merely proves something
    exists or is reachable.

Every signal owns a callable matcher. Matchers are pure, deterministic,
dataset-agnostic functions of the form::

    matcher(fact: dict, evidence_db: dict | None = None) -> bool

No matcher hard-codes a dataset-specific hostname, IP, hash, PID, or
finding id. Detection is structural. ``has_malicious_semantic`` is the
single public entry point used by the disposition layer before any
``confirmed_malicious_atomic`` routing.

Reverting Slot 31E-DB.5.4 deletes this module and the
``malicious_semantics`` import in ``disposition.py``; the confirmed
bucket then falls back to the pre-31E-DB.5 evidence gate with no schema
or contract migration required.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any

from sift_sentinel.analysis.reverse_shell_cmdline import is_reverse_shell_strong_idiom

# ── Token vocabularies (structural, NOT dataset-specific) ──────────────

# Transient / staging directory fragments. These are OS-shape tokens,
# not case artifacts: any payload that lives here is, by definition,
# running from a place legitimate software installs do not.
_TEMP_PATH_TOKENS = (
    "\\temp\\", "/tmp/", "\\windows\\temp\\", "\\appdata\\local\\temp\\",
    "\\programdata\\", "\\users\\public\\", "\\$recycle.bin\\",
    "\\perflogs\\", "/dev/shm/", "\\downloads\\", "\\appdata\\roaming\\temp\\",
)

# Microsoft/vendor-managed installer & component caches. OS-shape tokens,
# NOT case artifacts: these dirs (under ProgramData/Windows) legitimately hold
# executables that run during install/repair, so executing from them is normal
# installer behaviour -- not staging. Checked before _TEMP_PATH_TOKENS.
_BENIGN_INSTALLER_CACHE_TOKENS = (
    "\\package cache\\",
    "\\windows\\installer\\",
)

# Living-off-the-land binaries frequently abused as a launch proxy.
_LOLBINS = set({
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "certutil.exe", "msbuild.exe", "installutil.exe",
    "bitsadmin.exe", "mavinject.exe", "msiexec.exe",
})

# Script / interpreter children that, when chained off a lolbin, signal
# a staged execution rather than normal child spawning.
_SUSPICIOUS_CHILD_TOKENS = (
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", ".hta", ".vbs", ".js", ".ps1", ".bat",
    ".scr", ".pif",
)

# Hidden / obfuscated scheduled-task or persistence action markers.
_HIDDEN_ACTION_TOKENS = (
    "-w hidden", "-windowstyle hidden", "/create", "-enc ", "-encodedcommand",
    "-nop", "-noprofile", "frombase64string", "downloadstring",
    "iex(", "invoke-expression", "hidden", "vbhide",
)

# RWX / unusual memory protection tokens emitted by malfind-class tools.
_RWX_TOKENS = (
    "page_execute_readwrite", "rwx", "execute_readwrite",
    "execute_writecopy",
)

# Process-hollowing / image-mismatch indicators.
_HOLLOWING_TOKENS = (
    "unmapped", "image_mismatch", "vad_mismatch", "hollow", "hollowed",
    "no_backing_file", "unbacked_executable", "replaced_image",
    "process_doppel", "process_herpaderp",
)

# Run-key path fragments.
_RUN_KEY_TOKENS = (
    "\\currentversion\\run", "\\currentversion\\runonce",
    "\\currentversion\\runservices", "\\winlogon\\shell",
    "\\winlogon\\userinit", "\\policies\\explorer\\run",
)

_EXE_SUFFIXES = (".exe", ".scr", ".com", ".pif")


# ── Signal sets ────────────────────────────────────────────────────────

# Facts that merely prove existence / reachability. Never sufficient,
# on their own, to confirm maliciousness.
ENVIRONMENT_CONTEXT_SIGNALS = set({
    "msi_installer_event",
    "service_listening_port_only",
    "process_exists",
    "file_exists_on_disk",
    "network_port_listening_only",
    "certificate_exists",
})

# Processes for which a null/empty command line is normal kernel
# behaviour and must NOT be treated as a malicious signal.
LEGITIMATE_NULL_CMDLINE_PROCESSES = set({
    "system",
    "registry",
    "memcompression",
    "smss.exe",
    "csrss.exe",
})


# ── Small structural helpers ───────────────────────────────────────────

import json as _json


def _s(value):
    return str(value).strip().lower() if value is not None else ""


def _has_token(text: str, tokens) -> bool:
    return any(tok in text for tok in tokens)


# RUN17_P0_MALICIOUS_SEMANTICS_VIEW_PURITY
#
# Do not cache normalized fact views by object id.
#
# Python may reuse a dict object's id after that object is freed. A cache keyed
# only by id(fact) can return a previous fact's normalized view for a later,
# unrelated fact. That corrupts matcher decisions in registry-order loops and
# long-running pipelines. Every matcher must see a fresh normalized view of the
# current fact only.
def _clear_view_cache() -> None:
    """Compatibility no-op.

    Disposition code may call this at route-pass boundaries. Views are
    intentionally uncached, so there is nothing to clear.
    """
    return None


def _view(fact):
    return _view_uncached(fact)


def _view_uncached(fact):
    """Normalize a fact for matching.

    Returns ``(flat, blob, ftype)`` where:

      * ``flat`` is a lower-cased-key scalar map. A JSON-string
        ``raw_excerpt`` (the EvidenceDB typed-fact carrier) is decoded
        and merged so matchers see ``Cmd`` / ``ImageFileName`` / ``Path``
        etc. without each matcher re-parsing.
      * ``blob`` is every scalar string value concatenated, lower-cased
        -- the conservative free-text fallback for token matchers.
      * ``ftype`` is the fact-type token.
    """
    flat: dict = {}

    def _ingest(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    lk = str(k).strip().lower()
                    if lk not in flat:
                        flat[lk] = v

    if isinstance(fact, dict):
        _ingest(fact)
        re_ = fact.get("raw_excerpt")
        if isinstance(re_, str) and re_.strip():
            try:
                dec = _json.loads(re_)
            except Exception:
                dec = None
            if isinstance(dec, dict):
                _ingest(dec)
            else:
                flat.setdefault("raw_excerpt_text", re_)
    parts = [v for v in flat.values() if isinstance(v, str)]
    blob = " ".join(parts).lower()
    ftype = _s(flat.get("type") or flat.get("fact_type"))
    return flat, blob, ftype


def _g(flat: dict, *names: str) -> str:
    for n in names:
        v = flat.get(n)
        if v is not None and str(v).strip() != "":
            return _s(v)
    return ""


# RUN17_FACT_FLAT_FIELDS_HELPER_V1
#
# Shared typed-fact flattener for semantic matchers.
#
# Dataset-agnostic:
# - Reads only fields already present on the current fact object.
# - Does not use finding IDs, hashes, IPs, PIDs, case paths, answer labels,
#   caches, or external allowlists.
# - Supports both flat typed facts and EvidenceDB compiler facts that keep
#   normalized values under a nested "fields" dict.
def _fact_flat_fields(fact) -> dict:
    flat: dict = {}

    def _put(key, value) -> None:
        lk = str(key).strip().lower()
        if not lk:
            return
        if isinstance(value, str):
            flat.setdefault(lk, value.strip().lower())
        elif isinstance(value, (int, float, bool)) or value is None:
            flat.setdefault(lk, value)

    def _ingest(obj) -> None:
        if not isinstance(obj, dict):
            return
        for key, value in obj.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                _put(key, value)

    if not isinstance(fact, dict):
        _put("value", fact)
        return flat

    # Top-level typed fact fields.
    _ingest(fact)

    # Common nested carriers used by EvidenceDB compiler specs and sidecars.
    for carrier in (
        "fields",
        "fact",
        "data",
        "record",
        "attributes",
        "metadata",
    ):
        nested = fact.get(carrier)
        if isinstance(nested, dict):
            _ingest(nested)

    # raw_excerpt often contains the original row as JSON.
    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw.strip():
        try:
            decoded = _json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            _ingest(decoded)
        else:
            flat.setdefault("raw_excerpt_text", raw.strip().lower())

    return flat


# ── Matchers (each: matcher(fact, evidence_db=None) -> bool) ───────────

_NON_EXECUTION_FACT_TYPES = frozenset({
    # Facts that reference a path the process TOUCHES, not the image it runs FROM.
    "handle_fact", "dll_load_fact",
})


def match_executes_from_temp_path(fact, evidence_db=None) -> bool:
    """Process / file executes from a transient or staging path."""
    flat, blob, ftype = _view(fact)
    # Only an EXECUTION raises this signal -- not merely holding a handle to, or loading a
    # DLL from, a file in a transient dir (e.g. a handle to a ProgramData GPU shader cache,
    # or a vendor DLL loaded from a shared dir). Those are resource references, not the
    # executing image, and must not masquerade as "executes from temp".
    # 2a guarded the _view subtype (ftype), but a file HANDLE views as "file" while its
    # authoritative fact_type is "handle_fact" -- so a handle to a ProgramData shader cache
    # slipped past and false-fired TEMP. Guard the authoritative fact_type too: a handle (or
    # DLL load) is a resource reference, never the executing image, on any image.
    _raw_ft = fact.get("fact_type") if isinstance(fact, dict) else getattr(fact, "fact_type", None)
    if ftype in _NON_EXECUTION_FACT_TYPES or _raw_ft in _NON_EXECUTION_FACT_TYPES:
        return False
    path = _g(
        flat, "image_path", "path", "exe_path", "process_path",
        "imagefilename", "command_line", "cmdline", "cmd", "file_path",
        "raw_excerpt_text",
    )
    # 31K-SLASH: normalize slashes+case (like the lnk/jumplist/appcompat matchers) so
    # matching is slash-agnostic. A forward-slash / mount-read path (e.g. the isolated
    # evidence mount /tmp/sift-isolated-mount-.../ntfs/Windows/...) is normalized to
    # backslash+lower and fires ONLY when truly in a Windows staging dir -- instead of
    # false-matching the '/tmp/' host-mount root on every mount-read path (Prefetch,
    # System32, ...). Net: real staging detection on mount-read paths improves.
    def _bs(t: str) -> str:
        return str(t or "").replace("/", "\\").lower()
    # SIFT_BENIGN_INSTALLER_CACHE_V1: OS/vendor-managed installer & MSI caches
    # legitimately hold executables run during install/repair; executing there
    # is not staging. Checked before the staging tokens so a real staging hit
    # still fires, and only the cache subdir is exempt (not all of ProgramData).
    if path and _has_token(_bs(path), _BENIGN_INSTALLER_CACHE_TOKENS):
        return False
    if path and _has_token(_bs(path), _TEMP_PATH_TOKENS):
        return True
    if _has_token(_bs(blob), _BENIGN_INSTALLER_CACHE_TOKENS):
        return False
    return _has_token(_bs(blob), _TEMP_PATH_TOKENS)


def match_null_or_empty_cmdline_on_executable(fact, evidence_db=None) -> bool:
    """Real executable carrying a null/empty command line, excluding the
    handful of kernel processes for which that is legitimate."""
    # SIFT_DEGRADED_CMDLINE_GUARD_V1: on degraded memory the cmdline plugin cannot
    # reliably read the PEB, so an empty/None Args is an extraction artifact
    # (cmdline_is_empty conflates observed-empty with uncollected), not a real
    # observed-empty command line. Do not treat it as a malicious signal here.
    if os.environ.get("SIFT_DEGRADED", "0") == "1":
        return False
    flat, _, ftype = _view(fact)
    name = _g(flat, "process", "imagefilename", "image_name", "name",
              "process_name")
    if not name:
        return False
    if name in LEGITIMATE_NULL_CMDLINE_PROCESSES:
        return False
    path = _g(flat, "image_path", "path", "exe_path", "imagefilename")
    looks_exe = name.endswith(_EXE_SUFFIXES) or bool(path)
    if not looks_exe:
        return False
    has_cmd_key = any(
        k in flat for k in ("cmd", "cmdline", "command_line"))
    if not has_cmd_key:
        return False
    cmd = flat.get("cmd", flat.get("cmdline", flat.get("command_line")))
    return cmd is None or str(cmd).strip() == ""


def match_rwx_memory_region_with_unusual_protection(
        fact, evidence_db=None) -> bool:
    """Private RWX / write+execute region. A typed ``memory_injection_
    fact`` is itself the injection signal (it is only emitted by the
    malfind-class injection detector); an explicit RWX token corroborates
    it for non-typed claim shapes."""
    flat, blob, ftype = _view(fact)
    if ftype == "memory_injection_fact":
        return True
    prot = _g(flat, "protection", "page_protection", "memory_protection")
    if _has_token(prot + " " + _s(flat.get("flags")), _RWX_TOKENS):
        is_private = flat.get("is_private")
        if is_private is None:
            is_private = "private" in _s(flat.get("region_type")) or not (
                _g(flat, "mapped_file", "backing_file"))
        return bool(is_private)
    return _has_token(blob, _RWX_TOKENS)


def match_injected_pe_image_in_executable_memory(fact, evidence_db=None) -> bool:
    """Executable memory whose CONTENT is an injected PE image or shellcode payload
    (characterization mz_pe / pe-header / shellcode). This is the definitive
    injected-payload signal -- distinct from a bare RWX region, which a managed/JIT
    runtime also produces -- so it CORROBORATES an RWX injection finding (a real
    injected PE is not "RWX alone"). A benign JIT region has no PE/shellcode payload
    and never matches. Universal: keyed on the payload characterization token, never
    a case value."""
    flat, blob, ftype = _view(fact)
    if ftype != "memory_injection_fact":
        return False
    char = _g(
        flat, "characterization", "payload", "content_type",
        "region_content", "payload_characterization",
    ).lower()
    return _has_token(
        char,
        ("mz_pe", "mz pe", "pe_header", "pe header", "pe_image",
         "shellcode", "injected_pe", "injected pe"),
    )


def match_process_hollowing_indicators(fact, evidence_db=None) -> bool:
    """Process hollowing / unmapped or replaced main-image indicators."""
    flat, blob, _ = _view(fact)
    explicit = " ".join(
        _s(flat.get(k))
        for k in (
            "hollowing_indicator", "indicator", "indicators",
            "anomaly", "vad_state", "image_state", "notes",
        )
    )
    return _has_token(explicit + " " + blob, _HOLLOWING_TOKENS)


def match_spawned_by_lolbin_with_suspicious_chain(
        fact, evidence_db=None) -> bool:
    """Suspicious lineage: a lolbin parent spawning a script/interpreter
    or a child that runs from a staging path."""
    flat, _, _ = _view(fact)
    parent = _g(flat, "parent_process", "parent", "parent_image",
                "parentimage")
    leaf = parent.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if parent not in _LOLBINS and leaf not in _LOLBINS:
        return False
    child = _g(flat, "child_process", "child", "process", "child_image",
               "imagefilename")
    child_path = _g(flat, "child_path", "child_image_path", "image_path",
                    "path")
    if child and _has_token(child, _SUSPICIOUS_CHILD_TOKENS):
        return True
    if child_path and _has_token(child_path, _TEMP_PATH_TOKENS):
        return True
    return False


def match_registry_run_key_pointing_to_temp(fact, evidence_db=None) -> bool:
    """Autostart persistence key whose payload lives in a staging path."""
    flat, _, _ = _view(fact)
    key = _g(flat, "registry_path", "key", "key_path", "registry_key",
             "path")
    if not _has_token(key, _RUN_KEY_TOKENS):
        return False
    data = _g(flat, "value_data", "data", "value", "target", "command")
    if not data:
        return False
    return _has_token(data, _TEMP_PATH_TOKENS)


def match_scheduled_task_with_hidden_action(fact, evidence_db=None) -> bool:
    """Scheduled task carrying a hidden / obfuscated action."""
    flat, _, _ = _view(fact)
    if flat.get("hidden") is True or _s(flat.get("hidden")) in (
            "true", "1", "yes"):
        return True
    action = _g(flat, "action", "command", "exec", "arguments",
                "task_action", "actions")
    if not action:
        return False
    return _has_token(action, _HIDDEN_ACTION_TOKENS)


def match_outbound_to_known_c2_pattern(fact, evidence_db=None) -> bool:
    """Outbound connection / IOC flagged suspicious or C2-like *with*
    process attribution. Dataset-agnostic: relies on a structural
    suspicion flag or a non-trivial IOC classification, never a
    hard-coded endpoint. An ``unknown`` IOC classification never fires."""
    flat, _, ftype = _view(fact)
    direction = _s(flat.get("direction"))
    if direction and direction not in ("outbound", "out", "egress"):
        return False
    has_proc = bool(_g(flat, "process", "owner", "image_name",
                       "process_name", "imagefilename"))
    has_pid = flat.get("pid") not in (None, "", 0, "0")
    if not (has_proc or has_pid):
        return False
    if flat.get("is_suspicious") is True or flat.get("is_c2") is True:
        return True
    cls = _s(flat.get("classification"))
    if cls and cls not in ("unknown", "benign", "clean", "none", ""):
        return True
    flag = " ".join(
        _s(flat.get(k))
        for k in ("ioc_match", "threat_label", "verdict", "tag"))
    return _has_token(
        flag, ("c2", "command_and_control", "beacon", "malicious"))


_SENSITIVE_LISTENER_PORTS = frozenset({
    3389,  # RDP
    445,   # SMB
    139,   # NetBIOS session
    135,   # MSRPC / DCOM endpoint mapper
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    22,    # SSH
    23,    # Telnet
    5900,  # VNC
})


def _port_int(value):
    """Coerce a port (int or str) to int; None if not a usable port number."""
    try:
        p = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return p if 0 < p < 65536 else None


def _addr_is_external(addr) -> bool:
    """True iff addr is a routable, non-local IP. Structural and dataset-
    agnostic: private / loopback / link-local / reserved / multicast /
    unspecified and wildcards are NOT external. No endpoint is hard-coded."""
    import ipaddress
    s = str(addr or "").strip().split("%")[0]
    if not s or s in ("*", "0.0.0.0", "::"):
        return False
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def match_external_inbound_to_sensitive_listener(fact, evidence_db=None) -> bool:
    """Inbound counterpart to match_outbound_to_known_c2_pattern: a sensitive
    remote-access listener on THIS host (RDP/SMB/WinRM/SSH/Telnet/RPC/NetBIOS/
    VNC, by local port) has an EXTERNAL peer connected -- the host is exposing
    a lateral-movement service to a routable foreign address. Dataset-agnostic:
    keys on the local listener-port class and a structural external-address
    test, never on a specific endpoint."""
    raw_ft = fact.get("fact_type") if isinstance(fact, dict) else getattr(fact, "fact_type", None)
    if raw_ft and raw_ft != "network_connection_fact":
        return False
    flat, _, _ = _view(fact)
    flat = flat if isinstance(flat, dict) else {}
    lp = _port_int(flat.get("localport"))
    fa = flat.get("foreignaddr")
    if lp is None or not fa:
        import json as _json
        try:
            rx = _json.loads(str(flat.get("raw_excerpt") or "") or "{}")
        except Exception:
            rx = {}
        if lp is None:
            lp = _port_int(rx.get("LocalPort"))
        if not fa:
            fa = rx.get("ForeignAddr")
    if lp not in _SENSITIVE_LISTENER_PORTS:
        return False
    return _addr_is_external(fa)


# ── Registry ───────────────────────────────────────────────────────────

def match_appcompatcache_execution_from_staging(fact, evidence_db=None) -> bool:
    """31K-APPCOMPAT-TYPED-CANDIDATE: AppCompatCache/ShimCache path in a
    transient or staging directory. Compatibility evidence only; corroborate
    before process-execution claims."""
    flat = _fact_flat_fields(fact)
    path = _g(flat, "expanded_path", "normalized_path", "path", "raw_excerpt_text")
    def _bs(value):
        return str(value or "").replace("/", "\\")
    if path and _has_token(_bs(path), _TEMP_PATH_TOKENS):
        return True
    return False


def match_lnk_execution_from_staging(fact, evidence_db=None) -> bool:
    """31K-LNK-SIGNAL: LNK shortcut whose target/working dir points into a transient
    or staging path. Mirrors match_executes_from_temp_path, reusing this
    module's own _TEMP_PATH_TOKENS (no cross-module regex dependency)."""
    flat, blob, _ = _view(fact)
    path = _g(
        flat, "local_path", "target_abs_path", "working_directory",
        "arguments", "raw_excerpt_text",
    )
    # 31K-LNK-SLASH: facts pass through normalize_path (forward-slash, lower); the token
    # vocabulary is backslash-shaped. Normalize the candidate to backslash+lower
    # so matching is slash-agnostic across compiled facts and raw EZ output.
    def _bs(t: str) -> str:
        return t.replace("/", "\\").lower()
    if path and _has_token(_bs(path), _TEMP_PATH_TOKENS):
        return True
    return _has_token(_bs(blob), _TEMP_PATH_TOKENS)


def match_jumplist_access_to_staging(fact, evidence_db=None) -> bool:
    """31K-LNK-SIGNAL: Jump List entry whose accessed path points into a transient or
    staging path. Same discipline as the LNK matcher."""
    flat, blob, _ = _view(fact)
    path = _g(flat, "path", "arguments", "raw_excerpt_text")
    # 31K-LNK-SLASH: slash-agnostic (see LNK matcher) -- normalize candidate to backslash+lower.
    def _bs(t: str) -> str:
        return t.replace("/", "\\").lower()
    if path and _has_token(_bs(path), _TEMP_PATH_TOKENS):
        return True
    return _has_token(_bs(blob), _TEMP_PATH_TOKENS)


# 31AG-D2: archive/container extensions (universal file-format knowledge,
# not case data).
_ARCHIVE_EXTS = (
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".tbz", ".tbz2",
    ".bz2", ".xz", ".cab", ".iso", ".ace", ".arj", ".lzh",
)


def match_archive_in_staging_path(fact, evidence_db=None) -> bool:
    """31AG-D2: archive/container file under a user-writable transient/staging
    path (Collection / MITRE T1560 data staging). Structural only -- archive
    extension + transient-path token; no threshold, no case literal.
    Dataset-agnostic. Surfacing is corroboration-gated upstream (a lone
    single-source filesystem_timeline candidate never reaches validation_ready),
    so this never floods needs-review with benign installer archives."""
    flat = _fact_flat_fields(fact)
    path = _g(flat, "path", "normalized_path", "raw_excerpt_text")
    p = str(path or "").replace("/", "\\").lower()
    if not p or not p.endswith(_ARCHIVE_EXTS):
        return False
    return _has_token(p, _TEMP_PATH_TOKENS)


def _srum_fact_egress(fact) -> float:
    """Per-row SRUM egress bytes from a srum_usage_fact (bytes_total, else
    bytes_sent + bytes_received). 0.0 for non-SRUM / empty rows."""
    if not isinstance(fact, dict):
        return 0.0
    flds = fact.get("fields") if isinstance(fact.get("fields"), dict) else fact
    v = flds.get("bytes_total")
    if not isinstance(v, (int, float)) or v <= 0:
        bs = flds.get("bytes_sent")
        br = flds.get("bytes_received")
        v = (bs if isinstance(bs, (int, float)) else 0) + (
            br if isinstance(br, (int, float)) else 0)
    return float(v) if isinstance(v, (int, float)) and v > 0 else 0.0


def _srum_egress_values(evidence_db) -> list:
    """All positive per-row egress values across the image's srum_usage_fact corpus."""
    vals = []
    if not isinstance(evidence_db, dict):
        return vals
    tf = evidence_db.get("typed_facts")
    bucket = tf.get("srum_usage_fact") if isinstance(tf, dict) else None
    if isinstance(bucket, list):
        for f in bucket:
            e = _srum_fact_egress(f)
            if e > 0:
                vals.append(e)
    return vals


def _srum_egress_outlier_threshold(values):
    """Image-relative outlier floor = mean + 2*stdev over positive egress values.
    Returns None when the sample is too small (<8) to be meaningful. A standard
    statistical-outlier rule -- no fixed forensic byte constant, no case data."""
    vals = [v for v in values if isinstance(v, (int, float)) and v > 0]
    if len(vals) < 8:
        return None
    mean = sum(vals) / len(vals)
    sd = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
    return mean + 2.0 * sd


def match_srum_egress_outlier(fact, evidence_db=None) -> bool:
    """31AG-D5: a SRUM per-app network-usage row whose egress is a statistical
    outlier (> mean+2sigma) RELATIVE TO THIS IMAGE's own SRUM distribution -- a
    candidate data-exfiltration volume signal (MITRE T1048 / T1567). Dataset-
    agnostic and self-relative: the threshold is derived from the image's own
    SRUM corpus; no fixed byte constant, no host/app/path literal. Recomputed per
    call (no global cache) so there is no cross-image state hazard."""
    this = _srum_fact_egress(fact)
    if this <= 0:
        return False
    thr = _srum_egress_outlier_threshold(_srum_egress_values(evidence_db))
    if thr is None:
        return False
    return this > thr


_INHIBIT_RECOVERY_TOKENS = (
    "delete shadows", "shadows delete", "shadowcopy delete", "delete catalog",
    "delete systemstatebackup", "recoveryenabled no",
    "bootstatuspolicy ignoreallfailures", "delete-vssshadow", "remove-vssshadow",
)


def match_inhibit_system_recovery(fact, evidence_db=None) -> bool:
    """31AG-C: MITRE T1490 Inhibit System Recovery -- universal Windows recovery-
    sabotage commands (shadow-copy/backup/boot-recovery deletion) in a fact's
    cmdline / event / script / task text. A near-universal ransomware precursor.
    Dataset-agnostic: universal command substrings, no family names or case IOCs."""
    flat, blob, _ = _view(fact)
    b = (" ".join((
        str(blob or ""),
        str(_g(flat, "cmdline", "command", "command_line", "arguments",
               "message", "action", "value_data", "raw_excerpt_text") or ""),
    ))).lower()
    if any(t in b for t in _INHIBIT_RECOVERY_TOKENS):
        return True
    return ("win32_shadowcopy" in b
            and ("remove-wmiobject" in b or "delete" in b))


# 31-ANTIFORENSICS: universal defense-evasion / anti-forensics EXECUTION tokens
# (MITRE T1070 Indicator Removal, T1485 Data Destruction). Secure-file-wipe,
# event-log clearing, and USN-journal deletion are rare for normal users and
# common to BOTH ransomware (cleanup) and insider theft (covering tracks) -- a
# cross-case signal. Universal command substrings only; NO family names, NO case
# paths. `cipher /w` (the wipe switch) only -- never bare `cipher` (legit EFS).
_ANTI_FORENSICS_TOKENS = (
    # --- dedicated secure file / free-space wipe TOOLS (rare on a normal host;
    #     keyed on the universal tool/binary name, exactly as "sdelete" is) ---
    "sdelete", "sdelete64",              # SysInternals secure-delete
    "bleachbit",                         # BleachBit -- the classic insider wiper
    "bcwipe",                            # Jetico BCWipe
    "eraser.exe", "eraserl.exe",         # Eraser ('eraser' is an English word -> anchor on .exe)
    "privazer",                          # PrivaZer
    "hardwipe",                          # Hardwipe
    "freeraser",                         # Freeraser
    "wipefile",                          # WipeFile
    # --- built-in free-space / change-journal wipe COMMANDS (switch-scoped) ---
    "cipher /w", "cipher.exe /w",        # cipher free-space wipe (NOT bare cipher = legit EFS)
    "fsutil usn deletejournal",          # USN change-journal deletion
    # --- timestamp forgery (T1070.006 Timestomp) ---
    "timestomp", "setmace",
    # --- audit / event-log destruction (T1070.001) ---
    "wevtutil cl", "wevtutil clearev",   # event-log clear
    "clear-eventlog", "clear-winevent",  # PowerShell log-clear cmdlets
    "auditpol /clear",                   # audit-policy reset
)


def match_anti_forensics_execution(fact, evidence_db=None) -> bool:
    """Defense-evasion / anti-forensics EXECUTION: secure file/free-space wipe
    (SDelete, cipher /w), event-log clearing (wevtutil cl, Clear-EventLog), or
    USN-journal deletion, observed in a fact's command / execution / event text.
    Also the audit-log-cleared EVENT (1102 Security / 104 System) -- the artifact-
    side trace of log destruction, often the ONLY one (log cleared via API, command
    not captured). Scoped to execution-evidence fact types (see required_fact_types)
    so it keys on a tool that RAN, not one merely present on disk. Dataset-agnostic:
    universal command substrings + universal Event IDs, no family names, no case
    IOCs/paths."""
    flat, blob, _ftype = _view(fact)
    # SCOPE GUARD: this signal keys on a tool that RAN. Skip non-execution fact
    # types that only CARRY free text -- a model-authored ``finding_excerpt``
    # (which may annotate a cross-reference as "(bcwipe)") and a raw
    # ``filesystem_timeline_fact`` (whose serialized row contains the FIELD NAME
    # "timestomped": false -- a NEGATIVE assertion the bare substring would
    # wrongly match). Real execution evidence (event_log / cmdline / powershell /
    # appcompatcache / file_execution / decoded_string) is unaffected, so a
    # genuine wiper still fires. Universal: fact-type class only, no case data.
    if str(_ftype) in ("finding_excerpt", "filesystem_timeline_fact",
                       "filesystem_listing_fact"):
        return False
    b = (" ".join((
        str(blob or ""),
        str(_g(flat, "cmdline", "command", "command_line", "arguments",
               "message", "action", "value_data", "process_name",
               "executable", "raw_excerpt_text") or ""),
    ))).lower()
    # Event-side log clearing (T1070.001). 1102 = unambiguous Security-log-cleared;
    # 104 is reused by other providers, so require a 'cleared' log token.
    eid = str(_g(flat, "event_id", "EventID", "entity_id") or "").strip()
    if eid == "1102":
        return True
    if eid == "104" and "cleared" in b and "log" in b:
        return True
    return any(t in b for t in _ANTI_FORENSICS_TOKENS)


# 31-MASS-ENCRYPTION: universal user-data/document file-type vocabulary (NOT
# ransomware family names, NOT case paths) -- used to recognize a file that has a
# foreign extension APPENDED after a recognized data type (report.docx.<enc>), the
# structural signature of in-place ransomware encryption (MITRE T1486).
_DATA_DOC_EXTS = frozenset({
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "psd", "dwg",
    "zip", "rar", "7z", "tar", "gz", "sql", "mdb", "accdb", "pst", "ost",
})


def match_mass_encryption_burst(fact, evidence_db=None) -> bool:
    """A file bearing a uniform FOREIGN extension appended after a recognized data
    extension (name.<data>.<enc>) -- the per-file signature of in-place ransomware
    encryption (T1486). The corpus-level BURST (many such files sharing one appended
    extension across DIVERSE data types) is detected at candidate-build; this
    per-fact matcher recognizes a single encrypted file (and supports the registry +
    declared-signal path). Dataset-agnostic: universal file-type vocabulary, no
    ransomware family names, no case paths."""
    flat, blob, _ = _view(fact)
    p = str(_g(flat, "normalized_path", "path", "file_path", "filename")
            or "").lower().replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    parts = base.split(".")
    if len(parts) < 3:
        return False
    orig, enc = parts[-2], parts[-1]
    # original is a real data type; appended is a non-empty short token that is NOT
    # itself a data type (so report.docx.pdf -- a legit conversion -- does not fire).
    return (orig in _DATA_DOC_EXTS and bool(enc) and len(enc) <= 12
            and enc.isalnum() and enc not in _DATA_DOC_EXTS)


# 31-ACCOUNT-CONTEXT: built-in LOW-privilege SERVICE identities (by well-known SID
# RID, not name) that should run specific non-interactive services -- NOT shells.
_SERVICE_ACCOUNT_SIDS = frozenset({"s-1-5-19", "s-1-5-20"})  # LOCAL/NETWORK SERVICE
# Interactive shells / scripting hosts (basenames). A service account spawning one
# is the classic account-context abuse of lateral movement / malicious service.
_INTERACTIVE_SHELL_PROCS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "powershell.ex", "powershell",  # Vol 14-char truncation tolerant
})


def match_service_account_interactive(fact, evidence_db=None) -> bool:
    """Account-context anomaly: a built-in LOW-privilege SERVICE account
    (LOCAL SERVICE / NETWORK SERVICE, by well-known SID) owning an INTERACTIVE
    shell / scripting host (cmd / powershell / wscript / cscript / mshta). Those
    accounts run specific services, never interactive shells -- a service account
    holding a shell is the signature of service abuse / lateral movement
    (T1078 valid accounts, T1569 service execution). Dataset-agnostic: keys on
    well-known SID RIDs + a universal shell vocabulary, no account-name lists."""
    flat, blob, _ = _view(fact)
    sid = str(_g(flat, "sid", "owner_sid", "account_sid") or "").lower().strip()
    if sid not in _SERVICE_ACCOUNT_SIDS:
        return False
    proc = str(_g(flat, "process_name", "image_name", "process", "image")
               or "").lower().replace("\\", "/")
    base = proc.rsplit("/", 1)[-1]
    return base in _INTERACTIVE_SHELL_PROCS


# 31-LATERAL-EVENTS: high-value Security-log events (by universal Windows Event ID,
# not case data). Built-in admin/hidden shares -- access to these is the SMB
# lateral-movement signature (T1021.002).
_ADMIN_SHARE_TOKENS = ("\\c$", "/c$", "admin$", "ipc$")


def _event_id_of(fact) -> str:
    flat, _b, _ = _view(fact)
    return str(_g(flat, "event_id", "EventID", "entity_id") or "").strip()


def match_admin_share_access(fact, evidence_db=None) -> bool:
    """A network-share-access Security event (5140/5145) targeting a built-in
    ADMIN/hidden share (C$ / ADMIN$ / IPC$) -- the SMB lateral-movement signature
    (MITRE T1021.002). Dataset-agnostic: universal Event IDs + universal admin-
    share names, no host/IP/case data."""
    if _event_id_of(fact) not in ("5140", "5145"):
        return False
    _flat, blob, _ = _view(fact)
    b = str(blob or "").lower()
    return any(t in b for t in _ADMIN_SHARE_TOKENS)


def match_explicit_credential_logon(fact, evidence_db=None) -> bool:
    """An explicit-credential logon (Security Event 4648, 'logon using explicit
    credentials' / RunAs) -- a lateral-movement / alternate-credential indicator
    (MITRE T1078/T1550). Noisy alone (legit RunAs), so registered as a CORROBORAT-
    ING (weak-alone) signal -- it strengthens a finding rather than surfacing
    standalone. Dataset-agnostic: universal Event ID only."""
    return _event_id_of(fact) == "4648"


# 31-PRIV-GROUP: member-added-to-security-group Security events, scoped to
# PRIVILEGED groups by universal well-known RID (not localized group name).
_PRIV_GROUP_ADD_EIDS = ("4732", "4728", "4756")  # local / global / universal group
# BUILTIN privileged groups, S-1-5-32-<RID>: Administrators 544, Account Operators
# 548, Server Operators 549, Print Operators 550, Backup Operators 551.
_PRIV_BUILTIN_RIDS = ("544", "548", "549", "550", "551")
# Domain privileged groups, S-1-5-21-<dom>-<RID>: Domain Admins 512, Domain
# Controllers 516, Schema Admins 518, Enterprise Admins 519, Group Policy Creator
# Owners 520.
_PRIV_DOMAIN_RIDS = frozenset({"512", "516", "518", "519", "520"})
# English-name fallback for the common privileged groups (RID match is primary).
_PRIV_GROUP_NAME_TOKENS = (
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "backup operators", "account operators", "server operators",
)
_PRIV_DOMAIN_SID_RE = re.compile(r"s-1-5-21-\d+-\d+-\d+-(\d+)")


def _is_privileged_group_text(b: str) -> bool:
    """True if the (lowercased) event text names a PRIVILEGED group by well-known
    RID or English name. RID match is universal/locale-independent; non-privileged
    groups (Users S-1-5-32-545, Remote Desktop Users) do not match."""
    if any(("s-1-5-32-" + rid) in b for rid in _PRIV_BUILTIN_RIDS):
        return True
    m = _PRIV_DOMAIN_SID_RE.search(b)
    if m and m.group(1) in _PRIV_DOMAIN_RIDS:
        return True
    return any(t in b for t in _PRIV_GROUP_NAME_TOKENS)


def match_privileged_group_modification(fact, evidence_db=None) -> bool:
    """A member was added to a PRIVILEGED security group (Security Event 4732
    local / 4728 global / 4756 universal) -- adding an account to Administrators /
    Domain Admins / Enterprise Admins / operators groups is account-manipulation
    persistence / privilege escalation (MITRE T1098). FP-bound to privileged groups
    by well-known RID: a 4732 adding to non-privileged Users (S-1-5-32-545) does
    NOT fire. Dataset-agnostic: universal Event IDs + universal well-known RIDs,
    no host/account/case data."""
    if _event_id_of(fact) not in _PRIV_GROUP_ADD_EIDS:
        return False
    _flat, blob, _ = _view(fact)
    return _is_privileged_group_text(str(blob or "").lower())


_SAFEBOOT_DEFAULT_SHELL = "cmd.exe"  # OS-default AlternateShell value

# Conclusive registry-persistence signals whose verdict is fully decidable from
# a single registry fact (value-data vs OS default / Debugger presence). A bare
# DECLARATION of these is not trusted when candidate facts exist -- the matcher
# must actually fire (see has_malicious_semantic). Keyed on the registered
# signal names, never case data.
_DECLARATION_REQUIRES_MATCHER = frozenset({
    "safeboot_alternateshell_persistence",
    "ifeo_debugger_hijack",
})


def _safeboot_fact_decides(fact, evidence_db) -> bool | None:
    """Three-valued read of one fact for the SafeBoot declaration:
    True  = identifies the AlternateShell key with a real NON-default value
            (matcher fires -> declaration confirmed),
    False = identifies the key with a real value that is the OS default
            (matcher does not fire -> declaration disconfirmed),
    None  = does not identify the key, or carries no decidable value-data."""
    flat, _blob, _ftype = _view(fact)
    key = _g(flat, "normalized_registry_path", "registry_path",
             "canonical_entity_id", "key", "path")
    value_name = _g(flat, "value_name", "name")
    is_safeboot_key = (
        "safeboot" in key or "alternateshell" in key
        or _g(flat, "persistence_type") == "safeboot"
        or value_name == "alternateshell")
    if not is_safeboot_key:
        return None
    data = _g(flat, "value_data", "data", "command")
    if not data or "safeboot" in data or "alternateshell" in data:
        return None  # no decidable value-data (path-only / placeholder)
    return bool(match_safeboot_alternateshell_persistence(fact, evidence_db))


def _safeboot_declaration_disconfirmed(facts, evidence_db) -> bool:
    """True only when the AlternateShell value is AFFIRMATIVELY the OS default.

    ``SafeBoot\\AlternateShell`` is a GLOBAL SINGLETON key -- exactly one value
    per system -- so reading its authoritative record from the EvidenceDB is
    correct, not cross-entity contamination. We consult the finding's own
    candidate facts first, then the EvidenceDB ``registry_persistence_fact``
    rows directly (entity-id scoping can hide the record when the fact is keyed
    on ``...\\SafeBoot`` while the finding's entity is ``...\\SafeBoot\\Alternate
    Shell``). A real value resolving to NON-default (matcher fires) preserves
    the declaration; the OS default (cmd.exe) disconfirms it. No decidable
    value anywhere -> undecidable -> declaration preserved (the F034 fix never
    suppresses a real hijack, and never fires on an abstract placeholder)."""
    decided_default = False
    for fact in facts or []:
        v = _safeboot_fact_decides(fact, evidence_db)
        if v is True:
            return False          # confirmed non-default -> keep declaration
        if v is False:
            decided_default = True
    if decided_default:
        return True
    # Authoritative singleton lookup straight from the EvidenceDB.
    if isinstance(evidence_db, dict):
        container = evidence_db.get("typed_facts")
        rows = (container.get("registry_persistence_fact")
                if isinstance(container, dict) else None) or []
        for fact in rows:
            if not isinstance(fact, dict):
                continue
            v = _safeboot_fact_decides(fact, evidence_db)
            if v is True:
                return False
            if v is False:
                decided_default = True
    return decided_default


_DECLARATION_DISCONFIRMERS = {
    "safeboot_alternateshell_persistence": _safeboot_declaration_disconfirmed,
}

# Declared signals whose registered matcher is fully evidence-decidable: a bare
# declaration is trusted ONLY if the matcher fires on a candidate fact (see
# has_malicious_semantic). Prevents a model over-declaration from a contaminated
# excerpt confirming a benign finding. Keyed on registered signal names.
_DECLARATION_REQUIRES_MATCHER_FIRE = frozenset({
    "anti_forensics_execution",
})


def match_ifeo_debugger_hijack(fact, evidence_db=None) -> bool:
    """An Image File Execution Options ``<exe>\\Debugger`` value = debugger-hijack
    persistence (MITRE T1546.012): Windows launches the named Debugger instead of
    the target executable. The PRESENCE of a Debugger value under IFEO is the
    malicious primitive -- fired regardless of the Debugger target, because the
    classic accessibility backdoor (sethc/utilman) points it at a SYSTEM binary
    (cmd.exe), which a value-based baseline check wrongly clears. Universal: keys
    on the registry-key SHAPE (any exe under IFEO with a Debugger value), never a
    specific exe name; no host/case data."""
    flat, _blob, ftype = _view(fact)
    key = _g(flat, "normalized_registry_path", "registry_path",
             "canonical_entity_id", "key", "path")
    if _g(flat, "persistence_type") != "ifeo" and \
            "image file execution options" not in key:
        return False
    value_name = _g(flat, "value_name", "name")
    has_debugger = (
        value_name == "debugger" or key.endswith("/debugger") or "\\debugger" in key
    )
    return bool(has_debugger and _g(flat, "value_data", "data", "value", "target"))


def match_safeboot_alternateshell_persistence(fact, evidence_db=None) -> bool:
    """``SafeBoot\\...\\AlternateShell`` set to anything other than the OS default
    (cmd.exe) = safe-mode persistence (MITRE T1547.006): the attacker's binary
    runs when the host boots into Safe Mode, where many defenses are inactive.
    Universal: the key is a fixed Windows path and the default value is OS-defined;
    flag ONLY a non-default value -- the default cmd.exe is benign and must not
    fire (validated against a real record where AlternateShell=cmd.exe was the
    default). Honors an explicit is_default flag if present."""
    flat, _blob, _ftype = _view(fact)
    key = _g(flat, "normalized_registry_path", "registry_path",
             "canonical_entity_id", "key", "path")
    value_name = _g(flat, "value_name", "name")
    if "safeboot" not in key and _g(flat, "persistence_type") != "safeboot":
        return False
    if "alternateshell" not in key and value_name != "alternateshell":
        return False
    if _s(flat.get("is_default")) in ("true", "1", "yes"):
        return False
    data = _g(flat, "value_data", "data", "value", "target", "command")
    if not data:
        return False
    # A registry KEY PATH is not value-data. A model path-only claim stores the
    # key under ``value``; reading that as the AlternateShell value wrongly
    # fired the non-default check (the F034 FP: AlternateShell=cmd.exe is the OS
    # default). Cannot decide deviation without the real value -> fail-closed.
    if "safeboot" in data or "alternateshell" in data:
        return False
    return _SAFEBOOT_DEFAULT_SHELL not in data


# Standard kernel-driver locations. A kernel-mode driver (.sys) registered to
# load from ANYWHERE ELSE has no benign explanation -- legitimate drivers live
# in the System32 driver store. Universal path SHAPE; no product/case literal.
_DRIVER_STORE_RE = re.compile(
    r"(system32|syswow64)[\\/]+(drivers|driverstore)[\\/]", re.I)
_SYS_PATH_RE = re.compile(r"([a-zA-Z]:[\\/][^\s\"',;|<>]*?\.sys)\b", re.I)
_CORE_KERNEL_MODULES = frozenset({
    "ntoskrnl", "ntkrnlpa", "ntkrnlmp", "ntkrnl", "win32k", "win32kbase",
    "win32kfull", "halmacpi", "halacpi", "hal", "fastfat", "ntfs", "acpi",
    "tcpip", "ndis", "cdfs", "fltmgr", "ksecdd", "netbt", "wmilib", "clfs",
    "fwpkclnt", "msrpc", "afd", "http", "volmgr", "partmgr", "disk", "mountmgr",
})


def _nonstandard_kernel_driver_path(text) -> str:
    """The first .sys image path in *text* that is a kernel driver loaded from a
    NON-standard location (not the System32 driver store, not a core kernel
    module basename). '' when none. Handles \\??\\ and \\SystemRoot\\ prefixes."""
    # Normalise NT / env path prefixes to a drive-letter form so the .sys
    # regex (which anchors on a drive letter) sees the real location.
    s = str(text or "")
    s = re.sub(r"\\\?\?\\", "", s)                       # \??\C:\... -> C:\...
    s = re.sub(r"\\SystemRoot\\|%systemroot%\\?|%windir%\\?",
               r"C:\\Windows\\", s, flags=re.I)
    for m in _SYS_PATH_RE.finditer(s):
        p = m.group(1).replace("\\", "/").lower()
        if _DRIVER_STORE_RE.search(p):
            continue
        base = p.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        if base in _CORE_KERNEL_MODULES:
            continue
        return p
    return ""


def match_kernel_driver_nonstandard_path(fact, evidence_db=None) -> bool:
    """A kernel-mode driver (.sys) whose service ImagePath / Event-7045 install
    path is OUTSIDE the System32 driver store and is not a core Windows kernel
    module = a kernel-rootkit loading primitive (MITRE T1014 / T1543.003).

    Legitimate drivers always load from System32\\drivers (or the DriverStore);
    a .sys anywhere else has no benign explanation -- so this is forensically
    conclusive on its own. A .exe service (e.g. an EDR/agent) is not a kernel
    driver and never fires, regardless of path. Universal: keyed on the
    driver-path SHAPE only -- no product / case / hash / PID literal."""
    flat, blob, _ftype = _view(fact)
    # 1) registry service ImagePath value
    value_name = _g(flat, "value_name", "name")
    nrp = _g(flat, "normalized_registry_path", "registry_path", "key", "path")
    if value_name == "imagepath" or nrp.endswith("/imagepath") or (
            "/services/" in nrp and nrp.endswith("imagepath")):
        if _nonstandard_kernel_driver_path(
                _g(flat, "value_data", "data", "value")):
            return True
    # 2) an explicit image-path field on a service / driver fact
    if _nonstandard_kernel_driver_path(_g(flat, "image_path", "imagepath")):
        return True
    # 3) a 7045 service-install event whose message carries the driver path
    if ("7045" in blob or "service control manager" in blob
            or "service was installed" in blob):
        if _nonstandard_kernel_driver_path(blob):
            return True
    return False


# Signals that are forensically CONCLUSIVE on their own: malicious by STRUCTURE
# with no benign explanation, independent of corroboration count. Behind
# SIFT_CONCLUSIVE_CONFIRM these may auto-confirm. Keep this set tight -- only
# add a signal whose matcher has a provably-empty benign class.
CONCLUSIVE_STRUCTURAL_SIGNALS = frozenset({
    "kernel_driver_nonstandard_path",
})


# A PowerShell download cradle / encoded fetch from an EXTERNAL, non-vendor domain.
# Universal: keys on the cradle STRUCTURE + a known-good VENDOR allowlist (never a
# blocklist or case domain); the domain is EXTRACTED, not hardcoded.
# A download/fetch VERB anywhere in the command -> cradle context.
_C2_VERB_RE = re.compile(
    r"(?:iex|invoke-expression|downloadstring|downloadfile|downloaddata|"
    r"invoke-webrequest|invoke-restmethod|net\.webclient|start-bitstransfer|"
    r"download_cradle|encodedcommand|\bwget\b|\bcurl\b)",
    re.IGNORECASE,
)
# The host comes from an actual http(s):// URL (so '.NET.WebClient' etc. can never
# be mistaken for a domain). The domain is EXTRACTED, never hardcoded.
_C2_URL_HOST_RE = re.compile(r"https?://([a-z0-9.\-]+)", re.IGNORECASE)
# known-good vendor / CDN / cert authorities every Windows host legitimately
# contacts -- the universal ALLOWLIST (inverse of an answer-key blocklist).
_C2_KNOWN_GOOD_RE = re.compile(
    r"(?:microsoft\.com|windowsupdate\.com|windows\.net|microsoftonline|office(?:cdn|365|apps)|"
    r"msftncsi|msftconnecttest|live\.com|skype|xboxlive|"
    r"adobe\.com|armmf\.adobe|google\.com|gstatic|googleapis|googleusercontent|"
    r"mozilla|firefox|vmware|chocolatey|nagios|nxlog|sysinternals|"
    r"akamai|edgesuite|cloudfront|amazonaws\.com|azureedge|azure\.com|trafficmanager|"
    r"digicert|verisign|symantec|entrust|sectigo|globalsign|letsencrypt|ocsp|crl\.|"
    r"schema\.org|w3\.org|apple\.com|icloud\.com)",
    re.IGNORECASE,
)
# segments that look like a TLD but are really a file extension / non-domain token.
_C2_NON_TLD = frozenset({
    "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr", "sys", "tmp",
    "dat", "log", "txt", "xml", "json", "local", "lan", "internal", "arpa",
    "example", "test", "invalid", "localhost",
})


def match_c2_staging_domain(fact, evidence_db=None) -> bool:
    """PowerShell download cradle / encoded fetch to an EXTERNAL non-vendor domain
    = the attacker's staging / C2 host (MITRE T1105 / T1071.001). The domain itself
    is the IOC. Universal: cradle STRUCTURE + vendor ALLOWLIST, domain EXTRACTED."""
    flat, blob, _ftype = _view(fact)
    if not _C2_VERB_RE.search(blob):
        return False  # no download / fetch cradle context
    for m in _C2_URL_HOST_RE.finditer(blob):
        host = m.group(1).strip(".").lower()
        parts = host.split(".")
        if len(parts) < 2 or parts[-1] in _C2_NON_TLD:
            continue
        if host.replace(".", "").isdigit():
            continue  # an IPv4, not a domain
        if _C2_KNOWN_GOOD_RE.search(host):
            continue  # known-good vendor / CDN / cert authority
        return True   # an external, non-vendor domain fetched in a cradle context
    return False


# RUN17_C2_REVERSE_SHELL_CMDLINE_V1 -- env-gated (SIFT_C2_CMDLINE_CONFIRM, default OFF =>
# byte-identical to baseline). When ON, a process / powershell / event-log fact whose
# command line is STRUCTURALLY a reverse or bind shell (listen flag bound to a port WITH
# an explicit remote socket endpoint, netcat exec-redirection, the /dev/tcp bash idiom, or
# an encoded PowerShell download one-liner) carries this NON-WEAK signal -- so a finding
# that also clears the one-claim corroboration gate confirms DETERMINISTICALLY instead of
# depending on LLM ensemble sampling. Universal: command-line GRAMMAR only (see
# analysis/reverse_shell_cmdline), never a binary / host / port literal -- metamorphic
# relabelling of the values leaves the verdict unchanged.
def match_c2_reverse_shell_cmdline(fact, evidence_db=None) -> bool:
    # KILL-SWITCH (default ENABLED, like every other registered matcher): set
    # SIFT_C2_CMDLINE_CONFIRM=0 to fall back to the pre-signal behavior for an A/B
    # comparison run. The detector itself is conservative and the disposition one-claim
    # gate still requires corroboration, so this is FP-safe on by default.
    if os.environ.get("SIFT_C2_CMDLINE_CONFIRM", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return False
    flat, blob, _ftype = _view(fact)
    cmd = _g(flat, "command_line", "commandline", "cmdline", "cmd", "command",
             "args", "arguments", "process_command_line", "decoded", "script",
             "raw_excerpt_text")
    return is_reverse_shell_strong_idiom(cmd or blob)


# ---------------------------------------------------------------------------
# URL-shape / DGA-entropy structural signal + C2 corroboration-axis stacking.
# All structural: entropy + label shape + cross-fact axis counting. No domain
# list, no intel feed -- works on any host's data including the held-out box.
# ---------------------------------------------------------------------------
_VOWELS = frozenset("aeiou")
_RAW_IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", re.IGNORECASE)
# a port that is NOT one of the ordinary web ports -> odd-port C2 beacon.
_ODD_PORT_URL_RE = re.compile(r"https?://[a-z0-9.\-]+:(\d{2,5})", re.IGNORECASE)
_ORDINARY_PORTS = frozenset({"80", "443", "8080", "8443"})


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((k / n) * math.log2(k / n) for k in freq.values())


def _registrable_label(host: str) -> str:
    """The label just left of the public suffix (e.g. 'a1b2c3' of 'a1b2c3.com').
    Coarse (no PSL): second-to-last for 2-label hosts, third-to-last when the last
    two look like a ccTLD+sld (co.uk) -- good enough for a structural score."""
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return parts[0] if parts else ""
    if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        return parts[-3]  # something.co.uk -> 'something'
    return parts[-2]


def dga_host_score(host: str) -> int:
    """Structural DGA-likeness of a host (0-4). Universal: Shannon entropy + length
    + digit ratio + consonant ratio of the registrable label. No domain list."""
    label = _registrable_label(host)
    if not label or not label.replace("-", "").isalnum() or len(label) < 7:
        return 0
    n = len(label)
    ent = _shannon_entropy(label)
    digits = sum(c.isdigit() for c in label) / n
    vowels = sum(c in _VOWELS for c in label) / n
    score = 0
    if ent >= 3.6:
        score += 1            # high-entropy random string
    if n >= 16:
        score += 1            # unusually long label
    if digits >= 0.30:
        score += 1            # digit-heavy (algorithmic)
    if vowels <= 0.20:
        score += 1            # consonant-heavy (no pronounceable structure)
    return score


def match_dga_domain(fact, evidence_db=None) -> bool:
    """A structurally anomalous host -- DGA-like (high-entropy / long / digit- or
    consonant-heavy registrable label), a raw-IP URL, or a non-standard-port URL.
    Universal: keys on the STRING STRUCTURE of the host, never a domain list."""
    flat, blob, _ftype = _view(fact)
    if _RAW_IP_URL_RE.search(blob):
        return True
    for m in _ODD_PORT_URL_RE.finditer(blob):
        if m.group(1) not in _ORDINARY_PORTS:
            return True
    for m in _C2_URL_HOST_RE.finditer(blob):
        host = m.group(1).strip(".").lower()
        if _C2_KNOWN_GOOD_RE.search(host):
            continue  # never DGA-flag a known-good vendor / CDN
        if dga_host_score(host) >= 2:
            return True
    # Bare-domain IOC (no URL wrapper): a network_ioc_fact carries the host as
    # its value/entity_id with no scheme, so the URL regex above misses it. DGA
    # is about the host STRUCTURE alone, so score the bare domain directly.
    # Scoped to a domain-typed network IOC -- never a process/file value.
    if _ftype == "network_ioc_fact" or _netioc_artifact_is_domain(flat):
        host = _netioc_host_value(flat)
        if host and not _C2_KNOWN_GOOD_RE.search(host) and dga_host_score(host) >= 2:
            return True
    return False


def _netioc_artifact_is_domain(flat) -> bool:
    art = flat.get("artifact")
    return (isinstance(art, (list, tuple)) and len(art) >= 1
            and str(art[0]).strip().lower() in ("domain", "url", "fqdn", "host"))


# Universal file-format extensions -- a carved string like ``gara.ttf`` or
# ``21d13ed0.msi`` is a FILENAME, not a registrable domain. These are
# OS/file-format primitives (fonts, documents, media, archives, binaries, code,
# data), NOT a TLD list and NOT case data, so excluding them generalises to any
# evidence box and prevents a hex/digit-heavy filename from false-positiving as a
# DGA host. A real public TLD is never in this set.
# NOTE: extensions that are ALSO real TLDs (com, sh, pl, cat, zip, mov, ...) are
# deliberately EXCLUDED -- for a network IOC the domain interpretation must win,
# so they are never filtered here (a DGA host like ``xj9k2mfp.com`` must survive).
_FILE_FORMAT_EXT = frozenset({
    # executables / installers / libraries
    "exe", "dll", "sys", "msi", "msp", "cab", "bat", "cmd", "scr", "cpl",
    "ocx", "drv", "efi", "ko",
    # scripts / code
    "ps1", "psm1", "vbs", "vbe", "jse", "wsf", "pyc", "rb",
    "php", "jar", "class", "lua",
    # documents
    "pdf", "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb",
    "ppt", "pptx", "pptm", "rtf", "txt", "csv", "odt", "ods", "odp", "one",
    # fonts
    "ttf", "otf", "fon", "fnt", "ttc", "woff", "woff2", "eot",
    # images / media
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "tif", "tiff", "svg", "webp",
    "wav", "mp3", "mp4", "avi", "wmv", "flv", "mkv", "ogg", "m4a",
    # archives
    "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "lz", "iso", "vhd",
    "vhdx", "dmg",
    # data / config / logs
    "dat", "sqlite", "log", "xml", "json", "ini", "cfg", "conf", "tmp",
    "bak", "lnk", "reg", "evtx", "etl", "manifest", "mui", "nls",
    "gpd", "inf", "pnf", "chm", "hlp", "rll", "tlb",
})


def _netioc_host_value(flat) -> str:
    """The bare registrable host from a network_ioc_fact (entity_id / value /
    artifact[1]). '' when it is an IP, carries no domain shape, or is actually a
    carved FILENAME (last label is a known file-format extension)."""
    host = _g(flat, "host", "domain", "value", "entity_id")
    if not host:
        art = flat.get("artifact")
        if isinstance(art, (list, tuple)) and len(art) >= 2:
            host = str(art[1])
    host = str(host or "").strip().lower().split("://", 1)[-1]
    host = host.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
    host = host.split(":", 1)[0].strip(".")
    if "." not in host or host.replace(".", "").isdigit():
        return ""               # empty or an IPv4
    tld = host.rsplit(".", 1)[-1]
    if not (tld.isalpha() and len(tld) >= 2):
        return ""
    if tld in _FILE_FORMAT_EXT:
        return ""               # a carved filename (e.g. gara.ttf), not a host
    return host


# The independent structural AXES that can point at a C2 host. Confidence rises
# only when >= 2 DISTINCT axes converge -- the "3+ independent signals" model,
# applied to the SAME host. Each axis is structural; none is a domain/intel list.
_C2_OBFUSCATION_TOKENS = (
    "encodedcommand", "-enc ", "-e ", "frombase64string", "invoke-obfuscation",
    "-encoded", "[char]", "-bxor", "compression.deflatestream",
)


def c2_corroboration_axes(finding: dict, evidence_db=None) -> set[str]:
    """Distinct INDEPENDENT structural axes that point at a C2/staging host for this
    finding. Universal -- every axis is a fact SHAPE, never a name/intel list:

      * ``cradle``      -- a PowerShell download cradle / fetch verb (T1105)
      * ``obfuscation`` -- an encoded / base64 / char-array obfuscated command
      * ``injection``   -- the finding also carries an RWX / memory-injection signal
      * ``dga``         -- the host itself is structurally anomalous (DGA / raw-IP)

    A finding with only ``cradle`` is a high-prior heuristic -> needs-review; two or
    more axes is a defensible C2 call -> confirm-eligible."""
    if not isinstance(finding, dict):
        return set()
    sigs = {str(s).lower() for s in (finding.get("malicious_semantic_signals") or [])}
    # text blob: the finding's own fields + every claim's scalar values, so the
    # obfuscation axis sees the actual command text wherever the schema carries it.
    parts = [str(finding.get(k, "")) for k in ("title", "description", "raw_excerpt")]
    for c in (finding.get("claims") or []):
        if isinstance(c, dict):
            parts += [str(v) for v in c.values() if isinstance(v, (str, int, float))]
    blob = " ".join(parts).lower()
    axes: set[str] = set()
    if "c2_staging_domain" in sigs or match_c2_staging_domain({"command": blob}):
        axes.add("cradle")
    if any(t in blob for t in _C2_OBFUSCATION_TOKENS):
        axes.add("obfuscation")
    if sigs & {"rwx_memory_region_with_unusual_protection",
               "private_executable_memory_injection", "process_hollowing_indicator"}:
        axes.add("injection")
    if "dga_domain" in sigs or match_dga_domain({"command": blob}):
        axes.add("dga")
    return axes


def c2_finding_is_corroborated(finding: dict, evidence_db=None) -> bool:
    """True when a C2/staging-domain finding has >= 2 independent structural axes --
    the threshold that turns a high-prior heuristic into a defensible confirm."""
    return len(c2_corroboration_axes(finding, evidence_db)) >= 2


MALICIOUS_SEMANTIC_SIGNALS: dict[str, dict] = {
    "kernel_driver_nonstandard_path": {
        "required_fact_types": [
            "registry_persistence_fact", "event_log_fact",
            # MEMORY path: a kernel_module_fact (vol_modscan) carries the loaded
            # driver's image_path, so a nonstandard .sys is detectable even when
            # no registry/Event-7045 install record survived.
            "kernel_module_fact",
        ],
        "matcher": match_kernel_driver_nonstandard_path,
        "description": (
            "Kernel-mode driver (.sys) installed via a service / Event 7045 from "
            "OUTSIDE the System32 driver store -- a kernel-rootkit loading "
            "primitive (MITRE T1014 / T1543.003). Legitimate drivers load from "
            "System32\\drivers; a .sys elsewhere has no benign explanation"
        ),
    },
    "c2_staging_domain": {
        "required_fact_types": [
            "powershell_command_fact", "decoded_string_fact", "network_ioc_fact",
        ],
        "matcher": match_c2_staging_domain,
        "description": (
            "PowerShell download cradle / encoded fetch to an external, non-vendor "
            "domain -- the attacker's payload-staging / C2 host (MITRE T1105 / "
            "T1071.001); the domain is the IOC, extracted structurally"
        ),
    },
    "dga_domain": {
        "required_fact_types": [
            "powershell_command_fact", "decoded_string_fact", "network_ioc_fact",
        ],
        "matcher": match_dga_domain,
        "description": (
            "Structurally anomalous host -- DGA-like (high-entropy / long / digit- or "
            "consonant-heavy registrable label), a raw-IP URL, or a non-standard-port "
            "beacon (MITRE T1568.002 / T1571). Keyed on host STRING STRUCTURE, never "
            "a domain list"
        ),
    },
    "c2_reverse_shell_cmdline": {
        "required_fact_types": [
            "process_fact", "process_relationship_fact",
            "powershell_command_fact", "event_log_fact",
        ],
        "matcher": match_c2_reverse_shell_cmdline,
        "description": (
            "Command line is structurally a reverse / bind shell -- a listen flag bound "
            "to a port with an explicit remote socket endpoint, netcat exec-redirection, "
            "the /dev/tcp bash idiom, or an encoded PowerShell download one-liner (MITRE "
            "T1059 / T1071). Keyed on command-line GRAMMAR, never a binary or host "
            "literal; env-gated (SIFT_C2_CMDLINE_CONFIRM) and confirms only once the "
            "one-claim corroboration gate is cleared"
        ),
    },
    "ifeo_debugger_hijack": {
        "required_fact_types": ["registry_persistence_fact"],
        "matcher": match_ifeo_debugger_hijack,
        "description": (
            "Image File Execution Options <exe>\\Debugger value -- debugger-hijack "
            "persistence / privilege escalation (MITRE T1546.012); the classic "
            "sticky-keys (sethc/utilman) SYSTEM-shell backdoor"
        ),
    },
    "safeboot_alternateshell_persistence": {
        "required_fact_types": ["registry_persistence_fact"],
        "matcher": match_safeboot_alternateshell_persistence,
        "description": (
            "SafeBoot AlternateShell set to a non-default value (not cmd.exe) -- "
            "Safe Mode persistence (MITRE T1547.006)"
        ),
    },
    "admin_share_access": {
        "required_fact_types": ["event_log_fact", "rdp_artifact_fact"],
        "matcher": match_admin_share_access,
        "description": (
            "Access to a built-in admin/hidden share (C$/ADMIN$/IPC$) -- SMB "
            "lateral movement (MITRE T1021.002)"
        ),
    },
    "explicit_credential_logon": {
        "required_fact_types": ["event_log_fact", "rdp_artifact_fact"],
        "matcher": match_explicit_credential_logon,
        "description": (
            "Explicit-credential / RunAs logon (Event 4648) -- lateral movement / "
            "alternate credentials (MITRE T1078/T1550); corroborating signal"
        ),
    },
    "privileged_group_modification": {
        "required_fact_types": ["event_log_fact"],
        "matcher": match_privileged_group_modification,
        "description": (
            "Member added to a PRIVILEGED security group (Event 4732/4728/4756 -- "
            "Administrators/Domain Admins/Enterprise Admins) -- account-manipulation "
            "persistence / privilege escalation (MITRE T1098)"
        ),
    },
    "service_account_interactive_execution": {
        "required_fact_types": ["sid_fact", "process_fact"],
        "matcher": match_service_account_interactive,
        "description": (
            "Built-in low-privilege service account (LOCAL/NETWORK SERVICE) owning "
            "an interactive shell -- account-context abuse / lateral movement "
            "(MITRE T1078/T1569)"
        ),
    },
    "mass_encryption_burst": {
        "required_fact_types": [
            "filesystem_timeline_fact", "filesystem_listing_fact",
            "file_object_fact",
        ],
        "matcher": match_mass_encryption_burst,
        "description": (
            "Uniform foreign extension appended across diverse data files -- "
            "in-place mass encryption, ransomware impact (MITRE T1486)"
        ),
    },
    "anti_forensics_execution": {
        "required_fact_types": [
            "file_execution_fact", "process_fact", "event_log_fact",
            "powershell_command_fact", "scheduled_task_fact",
        ],
        "matcher": match_anti_forensics_execution,
        "description": (
            "Anti-forensics execution (secure-wipe / event-log clear / USN-journal "
            "deletion) -- indicator removal, MITRE T1070/T1485"
        ),
    },
    "inhibit_system_recovery": {
        "required_fact_types": [
            "process_fact", "event_log_fact", "powershell_command_fact",
            "scheduled_task_fact",
        ],
        "matcher": match_inhibit_system_recovery,
        "description": (
            "Recovery sabotage (shadow-copy/backup/boot-recovery deletion) -- "
            "ransomware precursor, MITRE T1490"
        ),
    },
    "archive_in_staging_path": {
        "required_fact_types": ["filesystem_timeline_fact"],
        "matcher": match_archive_in_staging_path,
        "description": (
            "Archive/container file staged under a user-writable transient "
            "path (collection / T1560 data staging)"
        ),
    },
    "srum_egress_outlier": {
        "required_fact_types": ["srum_usage_fact"],
        "matcher": match_srum_egress_outlier,
        "description": (
            "Per-app SRUM network egress that is a statistical outlier for this "
            "image (candidate data-exfiltration volume, T1048/T1567)"
        ),
    },
    "executes_from_temp_path": {
        "required_fact_types": ["file_execution_fact", "process_fact"],
        "matcher": match_executes_from_temp_path,
        "description": "Process executes from a transient or staging path",
    },
    "null_or_empty_cmdline_on_executable": {
        "required_fact_types": ["process_fact"],
        "matcher": match_null_or_empty_cmdline_on_executable,
        "description": (
            "Executable has null or empty command line outside known "
            "legitimate exceptions"
        ),
    },
    "rwx_memory_region_with_unusual_protection": {
        "required_fact_types": ["memory_injection_fact"],
        "matcher": match_rwx_memory_region_with_unusual_protection,
        "description": "Private RWX memory region suggesting injection",
    },
    "injected_pe_image_in_executable_memory": {
        "required_fact_types": ["memory_injection_fact"],
        "matcher": match_injected_pe_image_in_executable_memory,
        "description": (
            "Executable memory region contains an injected PE image or shellcode "
            "payload (a real injected payload, not a bare JIT RWX region)"
        ),
    },
    "process_hollowing_indicators": {
        "required_fact_types": ["memory_injection_fact", "process_fact"],
        "matcher": match_process_hollowing_indicators,
        "description": (
            "Process hollowing or unmapped executable indicators"
        ),
    },
    "spawned_by_lolbin_with_suspicious_chain": {
        "required_fact_types": ["process_relationship_fact", "process_fact"],
        "matcher": match_spawned_by_lolbin_with_suspicious_chain,
        "description": (
            "Suspicious process lineage involving lolbins and staging"
        ),
    },
    "registry_run_key_pointing_to_temp": {
        "required_fact_types": ["registry_persistence_fact"],
        "matcher": match_registry_run_key_pointing_to_temp,
        "description": (
            "Persistence key points to transient or staging payload"
        ),
    },
    "scheduled_task_with_hidden_action": {
        "required_fact_types": ["scheduled_task_fact"],
        "matcher": match_scheduled_task_with_hidden_action,
        "description": "Scheduled task has suspicious hidden action",
    },
    "outbound_to_known_c2_pattern": {
        "required_fact_types": ["network_connection_fact", "network_ioc_fact"],
        "matcher": match_outbound_to_known_c2_pattern,
        "description": (
            "Outbound suspicious or C2-like endpoint with process "
            "attribution"
        ),
    },
    "external_inbound_to_sensitive_listener": {
        "required_fact_types": ["network_connection_fact"],
        "matcher": match_external_inbound_to_sensitive_listener,
        "description": (
            "External peer connected to a sensitive local listening service "
            "(RDP/SMB/WinRM/SSH/Telnet/RPC/NetBIOS/VNC) -- remote-access exposure"
        ),
    },
    "appcompatcache_execution_from_staging": {
        "required_fact_types": ["appcompatcache_execution_fact"],
        "matcher": match_appcompatcache_execution_from_staging,
        "description": (
            "AppCompatCache/ShimCache entry points into a transient or staging path"
        ),
    },
    "lnk_execution_from_staging": {
        "required_fact_types": ["lnk_execution_fact"],
        "matcher": match_lnk_execution_from_staging,
        "description": (
            "LNK shortcut target resolves into a transient or staging path"
        ),
    },
    "jumplist_access_to_staging": {
        "required_fact_types": ["jumplist_fact"],
        "matcher": match_jumplist_access_to_staging,
        "description": (
            "Jump List access points into a transient or staging path"
        ),
    },
}


# ── Fact harvesting ────────────────────────────────────────────────────

def _fact_type(obj: Any) -> str:
    if isinstance(obj, dict):
        return _s(obj.get("type") or obj.get("fact_type"))
    return ""


def _entity_ids(finding: dict) -> set[str]:
    """Canonical entity ids the finding's claims reference (pid:N,
    sha1:..., etc.) -- used to scope EvidenceDB facts to THIS finding."""
    ids: set[str] = set()
    for c in finding.get("claims") or []:
        if not isinstance(c, dict):
            continue
        pid = c.get("pid")
        if isinstance(pid, int) and not isinstance(pid, bool):
            ids.add("pid:%d" % pid)
        elif isinstance(pid, str) and pid.strip().isdigit():
            ids.add("pid:%s" % pid.strip())
        for k in ("sha1", "sha256", "md5"):
            v = c.get(k)
            if isinstance(v, str) and v.strip():
                ids.add("%s:%s" % (k, v.strip().lower()))
        for k in ("path", "filename", "file", "image", "image_path", "target_path"):
            v = c.get(k)
            if isinstance(v, str) and v.strip():
                _p = v.strip().lower().replace("\\", "/")
                if len(_p) >= 2 and _p[1] == ":":
                    _p = _p[2:]
                _p = _p.lstrip("/")
                if "/" in _p:
                    ids.add(_p)
    return ids


def _candidate_facts(
    finding: dict, evidence_db: dict | None,
) -> list[dict]:
    """Collect every dict that could carry a semantic-bearing fact.

    Sources, in order:
      * the finding's own claims and any embedded typed fact ref dicts;
      * a synthetic finding-level fact carrying ``raw_excerpt`` so the
        conservative free-text token matchers can read what the upstream
        analyst actually cited;
      * EvidenceDB ``typed_facts`` (the canonical 31E-DB.1 sidecar
        shape: ``{fact_type: [fact, ...]}``), scoped to the finding's
        own canonical entity ids when those are derivable so a finding
        is matched on ITS facts, not the whole DB.
    """
    facts: list[dict] = []
    for key in ("claims", "typed_fact_refs", "facts", "evidence_facts"):
        seq = finding.get(key)
        if isinstance(seq, (list, tuple)):
            facts.extend(c for c in seq if isinstance(c, dict))
    vm = finding.get("validator_metadata")
    if isinstance(vm, dict):
        for ref in vm.get("typed_fact_refs") or []:
            if isinstance(ref, dict):
                facts.append(ref)

    excerpt = finding.get("raw_excerpt")
    if isinstance(excerpt, str) and excerpt.strip():
        facts.append({
            "type": "finding_excerpt",
            "raw_excerpt_text": excerpt,
            "action": excerpt,
            "value_data": excerpt,
        })

    if isinstance(evidence_db, dict):
        entity_ids = _entity_ids(finding)
        for container_key in ("typed_facts", "facts"):
            container = evidence_db.get(container_key)
            buckets: list = []
            if isinstance(container, dict):
                buckets = [
                    b for b in container.values() if isinstance(b, list)
                ]
            elif isinstance(container, list):
                buckets = [container]
            for bucket in buckets:
                for f in bucket:
                    if not isinstance(f, dict):
                        continue
                    if not entity_ids:
                        # Fail closed: no derivable entity ids -> draw
                        # nothing from the DB (stops cross-entity
                        # semantic contamination).
                        continue
                    cid = str(f.get("canonical_entity_id") or "").lower()
                    if not cid or not any(
                        cid.startswith(e) or e in cid
                        for e in entity_ids
                    ):
                        continue
                    facts.append(f)
    return facts


def has_malicious_semantic(
    finding: dict,
    evidence_db: dict | None = None,
) -> tuple[bool, list[str]]:
    """Return ``(has_signal, signal_names)`` for a finding.

    A signal is recognised either because the finding explicitly declares
    it under ``malicious_semantic_signals`` *and the name is a registered
    signal*, or because a registered matcher fires on one of the
    finding's candidate facts. Arbitrary free-text strings cannot inject
    a signal -- only registry-known names count.

    Environment-context-only support never produces a malicious signal:
    ``ENVIRONMENT_CONTEXT_SIGNALS`` and unknown declared strings are
    ignored here by construction.
    """
    if not isinstance(finding, dict):
        return False, []

    # View-once safety invariant: route_findings_for_report clears the cache at
    # pass start and leaves it warm. The only non-route caller (severity_ledger,
    # step 13.7) passes evidence_db=None and builds fresh synthetic facts; clearing
    # here makes any cross-step id() aliasing impossible regardless of GC timing.
    # Route always passes the real evidence_db (non-None), so cross-finding reuse
    # within a pass is untouched.
    if evidence_db is None:
        _clear_view_cache()

    found: list[str] = []

    facts = _candidate_facts(finding, evidence_db)

    declared = finding.get("malicious_semantic_signals") or []
    if isinstance(declared, (list, tuple)):
        for name in declared:
            n = str(name)
            if n not in MALICIOUS_SEMANTIC_SIGNALS or n in found:
                continue
            # CONCLUSIVE-REGISTRY DECLARATION VERIFICATION: the SafeBoot
            # persistence signal is fully decidable from one registry fact
            # (value-data vs the OS default). A model can DECLARE it on a
            # path-only claim; trusting the bare name confirmed a benign
            # default (AlternateShell=cmd.exe) as persistence (the F034 live
            # FP). Drop the declaration ONLY when a candidate fact
            # AFFIRMATIVELY disconfirms it (identified key, real value-data,
            # OS default). An undecidable placeholder claim keeps the
            # declaration -> no regression to the ReAct-vs-persistence
            # override. Universal: a real hijack's deviating value is never
            # disconfirmed; the OS default always is.
            _disconf = _DECLARATION_DISCONFIRMERS.get(n)
            if _disconf is not None and facts:
                try:
                    if _disconf(facts, evidence_db):
                        continue  # over-declared on benign/default evidence
                except Exception:
                    pass
            # MATCHER-FIRE VERIFICATION: a declared signal whose registered
            # matcher is fully evidence-decidable (e.g. anti_forensics_execution
            # keys on a wiper/log-clear token in real execution evidence) must be
            # CONFIRMED by the matcher firing on a candidate fact. A model can
            # over-declare it from a contaminated excerpt ("(bcwipe)" annotating
            # an installer finding); the bare name then confirmed a benign
            # installer. When candidate facts exist and the matcher fires on none,
            # drop the declaration. No facts -> cannot verify -> keep (no
            # regression). Universal: the matcher is structural, no case data.
            # Deterministically-emitted findings carry the signal by construction
            # (provenance-backed) -- trust their declaration. Only MODEL-emitted
            # declarations are matcher-verified.
            _is_det = bool(finding.get("deterministic_finding")
                           or finding.get("malicious_semantic_provenance"))
            if (n in _DECLARATION_REQUIRES_MATCHER_FIRE and facts
                    and not _is_det):
                _spec = MALICIOUS_SEMANTIC_SIGNALS.get(n) or {}
                _matcher = _spec.get("matcher")
                if callable(_matcher):
                    _fired = False
                    for _fc in facts:
                        try:
                            if _matcher(_fc, evidence_db=evidence_db):
                                _fired = True
                                break
                        except Exception:
                            continue
                    if not _fired:
                        continue  # over-declared; matcher does not corroborate
            found.append(n)

    if facts:
        for name, spec in MALICIOUS_SEMANTIC_SIGNALS.items():
            if name in found:
                continue
            matcher = spec.get("matcher")
            if not callable(matcher):
                continue
            for fact in facts:
                try:
                    if matcher(fact, evidence_db=evidence_db):
                        found.append(name)
                        break
                except Exception:
                    # A defensive matcher never crashes disposition.
                    continue

    return (len(found) > 0), sorted(set(found))


def environment_context_signals(finding: dict) -> list[str]:
    """Return the environment-context signal names a finding declares
    (registry-validated; unknown strings ignored)."""
    if not isinstance(finding, dict):
        return []
    declared = finding.get("environment_context_signals") or []
    out: list[str] = []
    if isinstance(declared, (list, tuple)):
        for name in declared:
            n = str(name)
            if n in ENVIRONMENT_CONTEXT_SIGNALS and n not in out:
                out.append(n)
    return sorted(out)


# ── Slot 31E-DB.5a-alpha: semantic signal provenance ───────────────────
#
# A malicious semantic signal is only allowed to drive confirmed routing
# when it is backed by *provenance*: which typed fact carried it, from
# which tool, with which fact refs, and the raw excerpt the analyst saw.
# A bare declared string with no matcher firing and no explicit support
# block is free-text inference and is NOT sufficient (SEMANTIC_SIGNAL_
# PROVENANCE_GATE / MALICIOUS_SEMANTIC_PROVENANCE_GATE).
#
# Provenance is sourced from EITHER:
#   * an explicit finding["semantic_signal_support"] entry, validated
#     against the signal's required_fact_types, OR
#   * a registered matcher actually firing on a candidate fact, in which
#     case provenance is *synthesized from that real fact* (the matcher
#     firing on a typed fact is itself provenance, never inference).

_SUPPORT_REQUIRED_FIELDS = (
    "supporting_fact_type",
    "supporting_tool",
    "supporting_fact_refs",
    "supporting_raw_excerpt",
)


def _excerpt_for(fact: dict) -> str:
    """A non-empty raw excerpt for a matched fact: an explicit
    raw_excerpt, else a compact deterministic scalar summary."""
    if isinstance(fact, dict):
        re_ = fact.get("raw_excerpt")
        if isinstance(re_, str) and re_.strip():
            return re_.strip()
        flat, blob, _ = _view(fact)
        if blob.strip():
            return blob.strip()[:240]
    return ""


def _tool_for(fact: dict) -> str:
    for k in ("source_tool", "tool", "source", "tool_name", "collector"):
        v = fact.get(k) if isinstance(fact, dict) else None
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "evidence_db"


def _refs_for(fact: dict, ftype: str) -> list[str]:
    refs: list[str] = []
    if isinstance(fact, dict):
        for k in ("fact_id", "canonical_entity_id", "id", "fact_ref"):
            v = fact.get(k)
            if isinstance(v, (str, int)) and str(v).strip():
                refs.append("%s" % v)
    if not refs:
        refs.append("%s:matched" % (ftype or "fact"))
    return refs


def _validate_explicit_support(entry: dict) -> tuple[dict | None, str | None]:
    """Return (clean_entry, problem). A clean entry has every required
    field, a registered signal, and a supporting_fact_type that is one
    of the signal's required_fact_types."""
    if not isinstance(entry, dict):
        return None, "support_not_a_dict"
    sig = str(entry.get("signal") or "")
    if sig not in MALICIOUS_SEMANTIC_SIGNALS:
        return None, "support_unregistered_signal:%s" % (sig or "?")
    for f in _SUPPORT_REQUIRED_FIELDS:
        val = entry.get(f)
        if f == "supporting_fact_refs":
            if not (isinstance(val, (list, tuple)) and [
                v for v in val if str(v).strip()
            ]):
                return None, "support_missing_field:%s:%s" % (sig, f)
        else:
            if not (isinstance(val, str) and val.strip()):
                return None, "support_missing_field:%s:%s" % (sig, f)
    required = MALICIOUS_SEMANTIC_SIGNALS[sig].get(
        "required_fact_types", [])
    if str(entry.get("supporting_fact_type")) not in required:
        return None, "support_fact_type_incompatible:%s:%s" % (
            sig, entry.get("supporting_fact_type"))
    return {
        "signal": sig,
        "supporting_fact_type": str(entry.get("supporting_fact_type")),
        "supporting_tool": str(entry.get("supporting_tool")),
        "supporting_fact_refs": [
            str(v) for v in entry.get("supporting_fact_refs")
            if str(v).strip()
        ],
        "supporting_raw_excerpt": str(
            entry.get("supporting_raw_excerpt")).strip(),
        "provenance": "explicit",
    }, None


def resolve_semantic_signal_support(
    finding: dict,
    evidence_db: dict | None = None,
) -> tuple[list[dict], list[str]]:
    """Resolve provenance for every malicious semantic signal a finding
    relies on.

    Returns ``(support, problems)``. ``support`` is the list of
    provenance objects (explicit or matcher-synthesized). ``problems``
    is a list of explicit reason strings for signals that are present
    but unsupported (bare string, missing field, incompatible fact
    type). When ``has_malicious_semantic`` is False this returns
    ``([], [])`` -- the malicious-semantic gate handles that case.
    """
    if not isinstance(finding, dict):
        return [], []

    has_sem, signals = has_malicious_semantic(finding, evidence_db)
    if not has_sem:
        return [], []

    support: list[dict] = []
    problems: list[str] = []
    covered: set[str] = set()

    # 1. Explicit support blocks the finding declares.
    declared = finding.get("semantic_signal_support")
    if isinstance(declared, (list, tuple)):
        for entry in declared:
            clean, prob = _validate_explicit_support(entry)
            if clean is not None:
                support.append(clean)
                covered.add(clean["signal"])
            elif prob:
                problems.append(prob)

    # 2. For any still-uncovered signal, synthesize provenance ONLY from
    #    a registered matcher firing on a real candidate fact.
    facts = _candidate_facts(finding, evidence_db)
    for sig in signals:
        if sig in covered:
            continue
        spec = MALICIOUS_SEMANTIC_SIGNALS.get(sig) or {}
        matcher = spec.get("matcher")
        required = spec.get("required_fact_types", []) or []
        matched = None
        if callable(matcher):
            for fact in facts:
                try:
                    if matcher(fact, evidence_db=evidence_db):
                        matched = fact
                        break
                except Exception:
                    continue
        if matched is None:
            # Declared but only as a bare string (or title/description
            # inference) -- not sufficient for confirmed routing.
            problems.append("bare_string_signal:%s" % sig)
            continue
        ftype = _fact_type(matched)
        if ftype not in required:
            ftype = required[0] if required else (ftype or "fact")
        excerpt = _excerpt_for(matched)
        if not excerpt:
            problems.append("support_missing_raw_excerpt:%s" % sig)
            continue
        support.append({
            "signal": sig,
            "supporting_fact_type": ftype,
            "supporting_tool": _tool_for(matched),
            "supporting_fact_refs": _refs_for(matched, ftype),
            "supporting_raw_excerpt": excerpt,
            "provenance": "matcher",
        })
        covered.add(sig)

    return support, problems

# ── A+++ deterministic ancestry semantic wrapper ──────────────────────
# Dataset-agnostic: recognizes only findings emitted from
# validation.ancestry.check_ancestry() and backed by a child_process claim.
# It does not inspect dataset-specific process IDs, paths, IOCs, or labels.
try:
    _sift_orig_has_malicious_semantic = has_malicious_semantic  # type: ignore[name-defined]

    def _sift_ancestry_semantic_signals(finding):
        if not isinstance(finding, dict):
            return []
        if finding.get("deterministic_kind") != "process_ancestry_violation":
            return []

        claims = finding.get("claims") or []
        has_edge = any(
            isinstance(c, dict)
            and str(c.get("type") or "").lower() == "child_process"
            and c.get("parent_pid") is not None
            and c.get("child_pid") is not None
            for c in claims
        )
        has_context = (
            bool(finding.get("parent_process"))
            and bool(finding.get("child_process"))
            and bool(finding.get("expected_parent_processes"))
        )
        if has_edge and has_context:
            return ["process_ancestry_violation"]
        return []

    def has_malicious_semantic(finding, evidence_db=None):  # noqa: F811
        has, signals = _sift_orig_has_malicious_semantic(finding, evidence_db)
        extra = _sift_ancestry_semantic_signals(finding)
        merged = sorted(set(list(signals or []) + extra))
        return bool(has or extra), merged

except NameError:
    pass
