"""Deterministic candidate-observations layer for typed EvidenceDB.

Candidate observations are ZEROFAKE triage hints, not findings. They are
derived only from typed facts already present in evidence_db["typed_facts"].
Inv2 may use them to classify/merge observations, but validation still gates
every claim before any report promotion.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
import json
import logging
import re
from typing import Any, Iterable
import json as _json

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "candidate_observations_v1"

# PERF: high-volume fact types that empirically produce ZERO candidate signals
# (profiled on a 201k-fact paired run: these are ~66% of all facts). They are
# skipped from per-fact SCORING only -- still grouped for corroboration, and
# filesystem_timeline_fact still feeds the mass-encryption-burst pass. Kill-switch
# SIFT_CANDOBS_SKIP_NONSCORING=0 restores scoring every fact.
import os as _candobs_os
_NONSCORING_FACT_TYPES = frozenset({
    "handle_fact", "filesystem_timeline_fact", "filesystem_listing_fact",
})
_CANDOBS_SKIP_NONSCORING = _candobs_os.environ.get(
    "SIFT_CANDOBS_SKIP_NONSCORING", "1") != "0"

# 31E-CANDIDATE-REVIEW-WORTHY-TELEMETRY: candidate_type values that are
# context-only by design and must never count toward the validation-ready
# ceiling regardless of their score.
_CONTEXT_CANDIDATE_TYPES = frozenset({"context_only", "remote_access_context"})

# 31G-CANDIDATE-PROMPT-RESERVE:
# Prevent source-family starvation in the Inv2 prompt. This does not promote
# candidates, change validation_ready, or create findings. It only ensures
# already-validation-ready, reportable registry/RDP/suspicious-task candidates
# remain visible even when the generic top-N score list is saturated by another
# behavior family.
_PROMPT_RESERVE_SOURCE_TOOLS = frozenset({
    "parse_registry_persistence",
    "parse_scheduled_tasks_disk",
    "parse_rdp_artifacts",
})

_PROMPT_RESERVE_REGISTRY_SIGNALS = frozenset({
    "high_risk_persistence",
    "registry_points_to_staging_path",
    "service_points_to_staging_path",
})

_PROMPT_RESERVE_TASK_SIGNALS = frozenset({
    "scheduled_task_points_to_staging_path",
    "scheduled_task_encoded_or_download",
})

_PROMPT_RESERVE_RDP_SIGNALS = frozenset({
    "rdp_target_reference",
})


def _candidate_score_int(candidate: dict) -> int:
    try:
        return int(candidate.get("score") or 0)
    except (TypeError, ValueError):
        return 0


def _candidate_tool_set(candidate: dict) -> set[str]:
    return {str(x) for x in (candidate.get("source_tools") or []) if x}


def _candidate_signal_set(candidate: dict) -> set[str]:
    return {str(x) for x in (candidate.get("signals") or []) if x}


def _is_prompt_reserve_candidate(candidate: dict) -> bool:
    """True only for already-validation-ready candidates worth preserving.

    This is a visibility reserve, not a truth promotion. Hidden scheduled tasks
    without suspicious action are deliberately excluded.
    """
    if not isinstance(candidate, dict):
        return False
    if not candidate.get("validation_ready"):
        return False
    if candidate.get("suppression_reason"):
        return False

    tools = _candidate_tool_set(candidate)
    if not (tools & _PROMPT_RESERVE_SOURCE_TOOLS):
        return False

    signals = _candidate_signal_set(candidate)
    ctype = str(candidate.get("candidate_type") or "")

    if "parse_registry_persistence" in tools:
        if signals & _PROMPT_RESERVE_REGISTRY_SIGNALS:
            return True
        if ctype == "high_risk_persistence":
            return True

    if "parse_rdp_artifacts" in tools:
        if (signals & _PROMPT_RESERVE_RDP_SIGNALS
                and ctype not in _CONTEXT_CANDIDATE_TYPES):
            return True

    if "parse_scheduled_tasks_disk" in tools:
        # Hidden-only tasks stay context unless their action is suspicious.
        if signals & _PROMPT_RESERVE_TASK_SIGNALS:
            return True

    return False


def _select_prompt_reserve_candidates(
    candidates: list[dict],
    *,
    rendered_ready_ids: set[str],
    limit: int = 30,
) -> list[dict]:
    reserve = []
    for candidate in candidates or []:
        if not isinstance(candidate, dict):
            continue
        cid = str(candidate.get("candidate_id") or "")
        if cid and cid in rendered_ready_ids:
            continue
        if _is_prompt_reserve_candidate(candidate):
            reserve.append(candidate)

    reserve.sort(
        key=lambda c: (
            _candidate_score_int(c),
            len(c.get("fact_types") or []),
            len(c.get("source_tools") or []),
            str(c.get("candidate_id") or ""),
        ),
        reverse=True,
    )
    return reserve[:limit]


def _render_candidate_prompt_line(candidate: dict) -> str:
    sources = ", ".join(str(x) for x in (candidate.get("source_tools") or []))
    fact_types = ", ".join(str(x) for x in (candidate.get("fact_types") or []))
    signals = ", ".join(str(x) for x in (candidate.get("signals") or []))
    fact_ids = ", ".join(str(x) for x in (candidate.get("fact_ids") or []) if x)

    lines = [
        (
            f"- candidate_id={candidate.get('candidate_id')} "
            f"[{candidate.get('candidate_type')}] "
            f"score={candidate.get('score')} "
            f"entity={candidate.get('entity_key')}"
        ),
        f"  sources={sources}; fact_types={fact_types}; signals={signals}",
    ]
    if fact_ids:
        lines.append(f"  fact_ids={fact_ids}")
    claim_templates = candidate.get("claim_templates") or []
    if claim_templates:
        lines.append(f"  claim_templates={claim_templates!r}")
    return "\n".join(lines)


# Review-worthy threshold (corroborated but not validation-ready):
# multi-source + multi-fact-type + non-suppressed + non-context + score>=60.
# This is the deterministic ceiling on what a downstream report COULD
# defensibly claim if the validator widened, not what it is allowed to
# claim now. Validation semantics are unchanged by this rung.
_REVIEW_WORTHY_MIN_SCORE = 60
_REVIEW_WORTHY_MIN_SOURCES = 2
_REVIEW_WORTHY_MIN_FACT_TYPES = 2

_EXEC_EXT_RE = re.compile(r"\.(exe|dll|ps1|bat|cmd|vbs|js|scr|hta|msi|lnk)\b", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# FQDN-shaped token (e.g. an internal host such as host.subdomain.example.lan).
# Anchored and applied only to isolated target tokens (never the whole blob) so
# file paths / event-log basenames are not mistaken for hosts.
_FQDN_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63})+$")
# Content-hash token (MD5/SHA1/SHA256). Used for cross-family entity linking
# from DEDICATED hash fields only -- never blob hex, which catches GUIDs/record
# ids. A content hash is a specific identity, not a baseline one, so no ubiquity
# guard is needed (per-candidate support caps bound any group regardless).
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
_ENCODED_OR_DOWNLOAD_RE = re.compile(
    r"(-enc\b|encodedcommand|frombase64string|downloadstring|\biex\b|"
    r"invoke-expression|webclient|virtualalloc|marshal|shellcode|gzipstream|base64)",
    re.I,
)
_LOLBIN_RE = re.compile(
    r"\b(powershell|pwsh|cmd(?:\.exe)?|wmic|rundll32|regsvr32|mshta|"
    r"wscript|cscript|schtasks|bitsadmin|certutil|psexec|psexesvc|"
    r"pwdump|procdump|vssadmin|winrm|wsmprovhost|sc(?:\.exe)?)\b",
    re.I,
)
_SENSITIVE_BASELINE_NAMES = {
    "system", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe",
    "csrss.exe", "smss.exe", "explorer.exe",
}

# slot31AU: candidate-observation vocabulary for phase2 typed_facts.
# Windows OS-standard sensitive token privileges (mimikatz / token-theft
# / driver-load prerequisites). winnt.h ABI constants - identical on
# every Windows system, not dataset-specific.
_SENSITIVE_PRIV_NAMES: frozenset = frozenset({
    "sedebugprivilege", "seimpersonateprivilege",
    "seassignprimarytokenprivilege", "seloaddriverprivilege",
    "setcbprivilege", "secreatetokenprivilege",
    "sebackupprivilege", "serestoreprivilege",
    "setakeownershipprivilege",
})

# Windows OS-standard kernel module names. Anything else in the SSDT is
# a kernel hook. Universal Windows ABI module names.
_KERNEL_MODULE_RE = re.compile(
    r"^(ntoskrnl|ntkrnlpa|ntkrnlmp|ntkrnl|win32k|halmacpi|halacpi|hal|"
    r"fastfat|ntfs|acpi|tcpip|ndis|cdfs|fltmgr|ksecdd|netbt|wmilib|"
    r"clfs|fwpkclnt|msrpc)(\.sys|\.exe|\.dll)?$",
    re.I,
)


def _parse_raw_excerpt(fact: dict) -> dict:
    """Parse raw_excerpt JSON. Returns the original tool record dict
    or {}. raw_excerpt is the structural source-of-truth for typed_fact
    semantic content: phase2/3 extractors emit typed fields but the
    storage layer normalizes facts to a fixed schema, stripping
    non-contract fields. raw_excerpt preserves the verbatim original
    Vol3/disk-tool record. Candidate observations read from here."""
    raw = fact.get("raw_excerpt") or ""
    if not raw or not isinstance(raw, str):
        return {}
    try:
        out = _json.loads(raw)
        return out if isinstance(out, dict) else {}
    except (_json.JSONDecodeError, ValueError, TypeError):
        return {}
_REMOTE_MGMT_RE = re.compile(r"\b(winrm|wsmprovhost|wmi|psexec|psexesvc|rdp|termsrv)\b", re.I)
_SUSPICIOUS_STAGING_RE = re.compile(
    r"(^|[\\/])(windows[\\/]temp|temp|users[\\/]public|appdata[\\/]local[\\/]temp|"
    r"programdata[\\/]staging|programdata[\\/]temp|perflogs|recycler|\$recycle\.bin)"
    r"([\\/].*)?",
    re.I,
)
# 31AG-D2: universal archive/container extensions (file-format knowledge, like
# _EXEC_EXT_RE; NOT case data). Used by the Collection/data-staging signal.
_ARCHIVE_EXT_RE = re.compile(
    r"\.(zip|rar|7z|tar|gz|tgz|tbz2?|bz2|xz|cab|iso|ace|arj|lzh|z)(\b|$)",
    re.I,
)
# 31AG-C: universal recovery-sabotage command substrings (MITRE T1490 Inhibit
# System Recovery) -- a near-universal ransomware precursor. Universal Windows
# commands, NOT ransomware-family names or case IOCs.
_INHIBIT_RECOVERY_TOKENS = (
    "delete shadows", "shadows delete", "shadowcopy delete", "delete catalog",
    "delete systemstatebackup", "recoveryenabled no",
    "bootstatuspolicy ignoreallfailures", "delete-vssshadow", "remove-vssshadow",
)


def _is_inhibit_system_recovery(text_l: str) -> bool:
    """True iff text carries a recovery-sabotage command (T1490). Dataset-agnostic."""
    if any(t in text_l for t in _INHIBIT_RECOVERY_TOKENS):
        return True
    return ("win32_shadowcopy" in text_l
            and ("remove-wmiobject" in text_l or "delete" in text_l))


# 31-ANTIFORENSICS: universal defense-evasion / anti-forensics EXECUTION detection
# (T1070/T1485) -- secure-wipe tools, event-log clear, USN-journal deletion,
# timestomping. The vocabulary lives in ONE place (malicious_semantics
# ._ANTI_FORENSICS_TOKENS) so the candidate-side and disposition-side detectors
# can never drift; broaden the tool family there.
def _is_anti_forensics_execution(text_l: str) -> bool:
    """True iff text carries an anti-forensics command (T1070/T1485). Dataset-agnostic.

    Uses the SINGLE canonical vocabulary in malicious_semantics (lazy-imported to
    avoid an import cycle). See _ANTI_FORENSICS_TOKENS there.
    """
    from sift_sentinel.analysis.malicious_semantics import _ANTI_FORENSICS_TOKENS
    return any(t in text_l for t in _ANTI_FORENSICS_TOKENS)


# 31-MASS-ENCRYPTION: universal user-data/document file-type vocabulary (NOT
# ransomware family names, NOT case paths) for detecting a foreign extension
# appended after a recognized data type (report.docx.<enc>) -- ransomware T1486.
_MASS_ENCRYPTION_DATA_EXTS = frozenset({
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "psd", "dwg",
    "zip", "rar", "7z", "tar", "gz", "sql", "mdb", "accdb", "pst", "ost",
})

# 31-ACCOUNT-CONTEXT: built-in LOW-privilege service identities (well-known SID
# RIDs, not names) that run specific non-interactive services -- never shells.
_SVC_ACCOUNT_SIDS = frozenset({"s-1-5-19", "s-1-5-20"})  # LOCAL / NETWORK SERVICE
_INTERACTIVE_SHELL_PROCS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "powershell.ex", "powershell",
})


# Execution-evidence fact types: the anti-forensics signal fires only on facts
# that attest a tool RAN (amcache/prefetch execution, process, event-log process
# create, PowerShell, scheduled task) -- never on access/reference artifacts
# (jumplist/LNK/filesystem listing) that merely name a path containing a token.
_ANTI_FORENSICS_EXEC_FACT_TYPES = frozenset({
    "file_execution_fact", "process_fact", "process_relationship_fact",
    "event_log_fact", "powershell_command_fact", "scheduled_task_fact",
})
_PERSISTENCE_HIGH_RE = re.compile(
    r"(safeboot|alternateshell|commandlineeventconsumer|eventconsumer|eventfilter|"
    r"root[\\/]+subscription|currentversion[\\/]+run|runonce|winlogon|ifeo|"
    r"image file execution options)",
    re.I,
)
_VENDOR_OR_UPDATE_RE = re.compile(
    r"(windowsupdate\.com|update\.microsoft\.com|download\.microsoft\.com|"
    r"officecdn|adobe\.com|armmf\.adobe\.com|google\.com|mozilla|vmware|"
    r"puppet labs|puppet|nxlog|nagios|chocolatey|sysmon|microsoft shared|winsxs)",
    re.I,
)
_NORMAL_SERVICE_IMAGE_RE = re.compile(
    r"^(%systemroot%|\\systemroot|system32|%windir%|c:[\\/]+windows[\\/]+system32|"
    r"/windows/system32)"
    r".*(\\drivers\\|/drivers/|svchost\.exe|lsass\.exe|services\.exe|alg\.exe|"
    r"spoolsv\.exe|dllhost\.exe|audiodg\.exe)",
    re.I,
)
_BENIGN_PATH_NOISE_RE = re.compile(
    r"(^|/)(windows/assembly/(temp|nativeimages)|windows/winsxs|program files|"
    r"program files \(x86\))/",
    re.I,
)
_NOISY_EVENT_PROVIDER_RE = re.compile(
    r"(KnownFolders|Security-SPP|ESENT|Diagnosis-DPS|User Profiles Service|"
    r"VSS|MsiInstaller|WindowsUpdate)",
    re.I,
)


def _sval(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, sort_keys=True)
        except Exception:
            return str(value)
    return str(value)


def _get(fact: dict, *keys: str) -> Any:
    lower = {str(k).lower(): k for k in fact.keys()}
    for key in keys:
        real = lower.get(key.lower())
        if real is not None:
            value = fact.get(real)
            if value not in (None, "", [], {}, ()):
                return value
    return None


def normalize_path(value: Any) -> str:
    text = _sval(value).strip().replace("\\", "/")
    text = re.sub(r"^/Device/HarddiskVolume\d+/", "/", text, flags=re.I)
    text = re.sub(r"^[a-zA-Z]:/", "/", text)
    text = re.sub(r"/+", "/", text)
    text = text.lower()
    return text[1:] if text.startswith("/") else text


def _blob(fact: dict) -> str:
    keys = (
        "raw_excerpt", "artifact", "path", "normalized_path", "registry_path",
        "value_name", "value_data", "process_name", "image_name", "cmdline",
        "command_line", "owner", "task_name", "task_path", "actions",
        "triggers", "service_name", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "state", "provider", "Provider", "channel", "Channel",
        "Message",
    )
    vals = []
    for key in keys:
        value = _get(fact, key)
        if value not in (None, ""):
            vals.append(_sval(value))
    return " | ".join(vals)


def _is_public_ip(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(_sval(value))
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def _is_private_or_loopback_ip(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(_sval(value))
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def iter_typed_facts(evidence_db: dict | None) -> Iterable[dict]:
    if not isinstance(evidence_db, dict):
        return []
    typed = evidence_db.get("typed_facts")
    if not isinstance(typed, dict):
        return []
    out: list[dict] = []
    for family, facts in typed.items():
        if not isinstance(facts, list):
            continue
        for fact in facts:
            if isinstance(fact, dict):
                obj = dict(fact)
                obj.setdefault("fact_type", family)
                out.append(obj)
    return out


def _entity_keys(fact: dict) -> list[str]:
    keys: list[str] = []
    fact_type = _sval(fact.get("fact_type"))

    pid = _get(fact, "pid", "PID")
    proc = _get(fact, "process_name", "image_name", "owner", "ImageFileName")
    if pid not in (None, ""):
        keys.append(f"pid:{pid}")
        if proc:
            keys.append(f"process:{_sval(proc).lower()}:{pid}")

    path = _get(fact, "normalized_path", "path", "file_path", "Path", "ImagePath")
    if path:
        norm = normalize_path(path)
        if norm:
            keys.append(f"path:{norm}")

    service = _get(fact, "service_name")
    if service:
        keys.append(f"service:{_sval(service).lower()}")

    task = _get(fact, "task_name", "task_path")
    if task:
        keys.append(f"task:{_sval(task).lower()}")

    registry = _get(fact, "normalized_registry_path", "registry_path")
    if registry:
        keys.append(f"registry:{_sval(registry).replace(chr(92), '/').lower()}")

    src_ip = _get(fact, "src_ip", "LocalAddr")
    dst_ip = _get(fact, "dst_ip", "ForeignAddr")
    src_port = _get(fact, "src_port", "LocalPort")
    dst_port = _get(fact, "dst_port", "ForeignPort")
    if src_ip and src_port:
        keys.append(f"socket:{src_ip}:{src_port}")
    if dst_ip and dst_port and _sval(dst_ip) not in {"*", "0.0.0.0", "::"}:
        keys.append(f"peer:{dst_ip}:{dst_port}")
    for ip in (src_ip, dst_ip):
        if ip and _sval(ip) not in {"*", "0.0.0.0", "::"}:
            keys.append(f"ip:{ip}")

    text = _blob(fact)
    for url in _URL_RE.findall(text)[:3]:
        keys.append(f"url:{url.lower().rstrip('.,;')}")
    for ip in _IP_RE.findall(text)[:3]:
        keys.append(f"ip:{ip}")

    # Cross-family hash linking: a file's content hash corroborates facts about
    # the same file across families (amcache/listing/yara/execution) even when
    # the path representation differs. Dedicated hash fields only. Dataset-
    # agnostic: keys on hash shape, never on a specific value.
    for hk in ("sha256", "sha1", "md5", "imphash", "file_hash", "hash"):
        hv = _sval(fact.get(hk)).lower()
        if _HASH_RE.match(hv):
            keys.append(f"hash:{hv}")

    # Cross-family remote-host linking: a remote/destination FQDN corroborates
    # facts about the same external peer across families (rdp/netscan/dns/event).
    # Remote-target fields ONLY -- never the local 'computer' field (the host
    # itself, which would over-link everything); file-name-shaped tokens excluded.
    _local_computer = _sval(fact.get("computer")).lower()
    for hk in ("host_or_target", "remote_host", "server", "dns_name", "dst_host"):
        hv = _sval(fact.get(hk)).lower()
        if hv and hv != _local_computer and _FQDN_RE.match(hv) and not _EXEC_EXT_RE.search(hv):
            keys.append(f"host:{hv}")

    if not keys:
        fallback = _sval(_get(fact, "artifact") or fact.get("fact_signature") or fact.get("fact_id"))[:120].lower()
        keys.append(f"artifact:{fallback}")

    if fact_type == "rdp_artifact_fact":
        # RDP event-type clusters are context, not ready findings by themselves.
        # Keep them grouped but do not let them masquerade as a strong entity.
        raw = _sval(fact.get("raw_excerpt") or fact.get("artifact"))
        event_match = re.search(r"EventID[=: ]+(\d+)", raw, re.I)
        if event_match:
            keys.append(f"rdp_event:{event_match.group(1)}")

    return list(dict.fromkeys(keys))


def _fact_ref(fact: dict, score: int, signals: list[str]) -> dict:
    return {
        "fact_id": fact.get("fact_id"),
        "fact_type": fact.get("fact_type"),
        "source_tool": fact.get("source_tool"),
        "record_ref": fact.get("record_ref"),
        "score": int(score),
        "signals": list(signals),
        "excerpt": _sval(fact.get("raw_excerpt") or fact.get("artifact") or _blob(fact))[:360],
    }



_POWERSHELL_VALIDATION_TTP_TAGS = frozenset(
    {
        "encoded_command",
        "long_base64_blob",
        "download_cradle",
        "no_profile_hidden",
        "ps_remoting_lateral",
        "lsass_access",
        "credential_harvest",
        "bypass_execution_policy",
        "invoke_mimikatz",
        "amsi_bypass",
        "reflection_load",
        "wmi_execution",
    }
)


def _powershell_ttp_tags_from_signals(signals: set[str]) -> list[str]:
    """Extract exact validator-backed PowerShell TTP tags from candidate signals."""
    tags: set[str] = set()
    for raw in signals or ():
        signal = str(raw).strip().lower().replace("-", "_")
        if signal.startswith("powershell_ttp:"):
            tag = signal.split(":", 1)[1].strip()
            if tag in _POWERSHELL_VALIDATION_TTP_TAGS:
                tags.add(tag)
    return sorted(tags)


_OS_DEFAULT_SHELL_BINS = {"explorer.exe", "userinit.exe"}
_SYSTEM_DIR_RE = re.compile(
    r"^(windows/(system32|syswow64)/|"
    r"%windir%/(system32|syswow64)/|"
    r"%systemroot%/(system32|syswow64)/|"
    r"systemroot/(system32|syswow64)/)",
    re.I,
)


def _registry_value_is_baseline(value_data: str) -> bool:
    """True only when a registry persistence value is the unmodified Windows baseline:
    exactly one token that is a bare OS-default shell binary OR resolves (via normalize_path)
    into a Windows system directory, with NO staging path, NO appended second token, NO LOLBIN
    or encoded payload. The directories/binaries are OS invariants identical on every Windows
    install -- not case data. Any deviation -> False -> still flagged. Universal.
    NOTE: _NORMAL_SERVICE_IMAGE_RE is intentionally NOT reused -- it additionally requires a
    service binary (svchost/lsass/...), so it cannot match Winlogon Shell/Userinit or Run-key
    values; _SYSTEM_DIR_RE is the correct structural system-directory test for this path."""
    raw = (value_data or "").strip()
    if not raw:
        return False
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if len(parts) != 1:
        return False
    token = parts[0]
    tl = token.lower()
    nt = normalize_path(token)
    if (_SUSPICIOUS_STAGING_RE.search(nt) or _LOLBIN_RE.search(tl)
            or _ENCODED_OR_DOWNLOAD_RE.search(tl)):
        return False
    if _SYSTEM_DIR_RE.search(nt):
        return True
    return tl in _OS_DEFAULT_SHELL_BINS


def _rdp_target_token(fact: dict) -> str:
    """Return an RDP target host/IP (or '') from the typed target fields or the
    EVTX ``Value=`` payload.

    The outbound RDPClient "Server Name" event (lateral-movement evidence)
    carries the target as an FQDN (an internal host referenced by name, not
    address); the original scorer credited only IP targets, so those records
    were suppressed as ``rdp_context_without_target`` and never surfaced as a
    candidate. Credits an IP or an FQDN-shaped hostname. Dataset-agnostic: keys
    on token shape only, never on specific host values. File-name-shaped tokens
    (an executable/script extension) are rejected so a ``Value=foo.dll`` payload
    is never mistaken for a host.
    """

    def _ok(tok: str) -> bool:
        tok = (tok or "").strip()
        if not tok or " " in tok:
            return False
        if _IP_RE.fullmatch(tok):
            return True
        if _EXEC_EXT_RE.search(tok):
            return False
        return bool(_FQDN_RE.match(tok))

    for key in ("host_or_target", "source_ip", "remote_host",
                "target", "server", "hostname"):
        v = _sval(fact.get(key)).strip()
        if _ok(v):
            return v
    raw = _sval(fact.get("raw_excerpt") or fact.get("artifact"))
    m = re.search(r"[Vv]alue=([^\s]+)", raw)
    if m and _ok(m.group(1)):
        return m.group(1)
    return ""


def _score_fact(fact: dict) -> tuple[int, list[str], list[str]]:
    fact_type = _sval(fact.get("fact_type"))
    text = _blob(fact)
    text_l = text.lower()
    score = 0
    signals: list[str] = []
    suppressions: list[str] = []

    # 31AG-C: ransomware recovery-sabotage (T1490) -- fact-type-agnostic: fires on
    # any fact whose text carries the command (process cmdline, event log,
    # PowerShell, scheduled task).
    if _is_inhibit_system_recovery(text_l):
        score += 80
        signals.append("inhibit_system_recovery")

    # 31-ANTIFORENSICS: defense-evasion EXECUTION (secure-wipe / log-clear /
    # USN-journal delete). Scoped to execution-evidence fact types so the signal
    # keys on a tool that RAN -- not on a jump-list / LNK / filesystem REFERENCE
    # to a path containing "sdelete" (e.g. a browser's recent-downloads list),
    # which is access provenance, not execution.
    if fact_type in _ANTI_FORENSICS_EXEC_FACT_TYPES and _is_anti_forensics_execution(text_l):
        score += 80
        signals.append("anti_forensics_execution")

    # 31-ACCOUNT-CONTEXT: a built-in LOW-priv service account (LOCAL/NETWORK
    # SERVICE, by well-known SID) owning an INTERACTIVE shell -> account-context
    # abuse / lateral movement. Per-fact: the sid_fact carries both sid + process.
    if fact_type == "sid_fact":
        _sid_v = _sval(_get(fact, "sid", "owner_sid", "account_sid")).lower().strip()
        if _sid_v in _SVC_ACCOUNT_SIDS:
            _proc_v = _sval(_get(fact, "process_name", "process", "image_name")).lower()
            _proc_base = _proc_v.replace("\\", "/").rsplit("/", 1)[-1]
            if _proc_base in _INTERACTIVE_SHELL_PROCS:
                score += 70
                signals.append("service_account_interactive_execution")

    if fact_type == "memory_injection_fact":
        score += 100
        signals.append("memory_injection")

    if fact_type == "memprocfs_indicator_fact":
        # FIX D (#3): MemProcFS FindEvil is MemProcFS's own anomaly detector
        # (injected / unlinked / no-image PE, bad parent, suspicious thread, AV
        # hit). Score the FindEvil ANOMALY family as promote-eligible so it
        # surfaces as a candidate on a memory-only case; the benign baseline
        # families (process/service/net/dns/module/handle listings, timelines,
        # prefetch, tasks) are context, NOT candidates -> suppressed so they
        # cannot flood the set. Universal: keys on MemProcFS-internal
        # semantic_family / semantic_role, not on any malware/product name.
        # FP-safety: a FindEvil hit is a single MEMORY source -> promote-eligible,
        # but the confirm gate + XCORR (same-PID malfind/ldrmodules) decide the
        # final tier; a lone FindEvil indicator does not auto-confirm.
        _fields = fact.get("fields") if isinstance(fact.get("fields"), dict) else {}
        sem_family = (_sval(_get(fact, "semantic_family"))
                      or _sval(_fields.get("semantic_family"))).lower()
        sem_role = (_sval(_get(fact, "semantic_role"))
                    or _sval(_fields.get("semantic_role"))).lower()
        if sem_family == "findevil_indicators" or sem_role == "anomaly_indicator":
            score += 70
            signals.append("memprocfs_findevil_indicator")
        else:
            suppressions.append("memprocfs_baseline_listing")

    if fact_type in {"process_fact", "process_relationship_fact"}:
        proc = _sval(_get(fact, "process_name", "image_name", "owner", "ImageFileName")).lower()
        path = normalize_path(_get(fact, "path", "Path", "image_name", "ImageFileName") or "")
        if _ENCODED_OR_DOWNLOAD_RE.search(text):
            score += 75
            signals.append("encoded_or_download_execution")
        if path and _SUSPICIOUS_STAGING_RE.search(path) and _EXEC_EXT_RE.search(path):
            score += 55
            signals.append("process_from_staging_path")
        if _LOLBIN_RE.search(text) and proc not in _SENSITIVE_BASELINE_NAMES:
            score += 25
            signals.append("lolbin_or_admin_process")

    if fact_type == "filesystem_timeline_fact":
        # 31AG-D2: Collection / data-staging (TA0009 / T1560). An archive or
        # bulk-container file under a user-writable staging path is a dataset-
        # agnostic staging indicator. Reuses _SUSPICIOUS_STAGING_RE (no new path
        # list) + universal _ARCHIVE_EXT_RE. Keys on NO host/user/IP/case
        # literal. Modest score: corroborating only -- a lone single-source/
        # single-type signal stays review_worthy and never auto-promotes
        # (validation_ready needs multi-source + multi-fact-type + score>=60).
        _fp = normalize_path(_get(fact, "path", "Path") or "")
        if _fp and _ARCHIVE_EXT_RE.search(_fp) and _SUSPICIOUS_STAGING_RE.search(_fp):
            score += 40
            signals.append("archive_in_staging_path")

    if fact_type == "file_execution_fact":
        path = normalize_path(_get(fact, "normalized_path", "path") or "")
        if _SUSPICIOUS_STAGING_RE.search(path) and _EXEC_EXT_RE.search(path):
            score += 55
            signals.append("execution_from_staging_path")
        if _LOLBIN_RE.search(path):
            score += 35
            signals.append("admin_or_lolbin_artifact")
        if _BENIGN_PATH_NOISE_RE.search(path) and not _LOLBIN_RE.search(path):
            suppressions.append("benign_system_or_vendor_path_noise")

    if fact_type == "registry_persistence_fact":
        service = _sval(_get(fact, "service_name")).lower()
        value_name = _sval(_get(fact, "value_name")).lower()
        value_data = _sval(_get(fact, "value_data"))
        normalized_value = normalize_path(value_data)
        is_image_path = value_name == "imagepath"

        if _PERSISTENCE_HIGH_RE.search(text):
            if _registry_value_is_baseline(value_data):
                suppressions.append("registry_persistence_default_value")
            else:
                score += 95
                signals.append("high_risk_persistence")
        if is_image_path and _SUSPICIOUS_STAGING_RE.search(normalized_value) and _EXEC_EXT_RE.search(normalized_value):
            score += 85
            signals.append("registry_points_to_staging_path")
        if service and _REMOTE_MGMT_RE.search(service):
            score += 30
            signals.append("remote_management_or_admin_service")
        if service and _LOLBIN_RE.search(service):
            score += 45
            signals.append("admin_service_name")
        if is_image_path and _LOLBIN_RE.search(value_data) and not _NORMAL_SERVICE_IMAGE_RE.search(normalized_value):
            score += 40
            signals.append("registry_lolbin_imagepath")
        if is_image_path and _NORMAL_SERVICE_IMAGE_RE.search(normalized_value) and not signals:
            suppressions.append("normal_windows_service_imagepath")
        if not signals and _sval(_get(fact, "persistence_type")).lower() == "service":
            suppressions.append("baseline_service_registry")

    if fact_type == "scheduled_task_fact":
        actions = _sval(_get(fact, "actions", "action"))
        if _SUSPICIOUS_STAGING_RE.search(actions) and _EXEC_EXT_RE.search(actions):
            score += 85
            signals.append("scheduled_task_points_to_staging_path")
        if _ENCODED_OR_DOWNLOAD_RE.search(actions):
            score += 80
            signals.append("scheduled_task_encoded_or_download")
        if re.search(r"\btrue\b|hidden", _sval(_get(fact, "hidden") or text), re.I):
            score += 35
            signals.append("hidden_scheduled_task")
        if not signals:
            suppressions.append("scheduled_task_without_suspicious_action")

    if fact_type == "lnk_execution_fact":
        # 31K-LNK-SCORE: LNK = per-user execution provenance. Score on a suspicious
        # target/args; SUPPRESS benign baseline shell LNKs (e.g. /name shell verbs
        # with no executable target), mirroring the file_execution discipline.
        lpath = normalize_path(_get(fact, "local_path", "target_abs_path") or "")
        targ = normalize_path(_get(fact, "target_abs_path") or "")
        args = _sval(_get(fact, "arguments"))
        combo = " ".join((lpath, targ, args)).strip()
        has_exec_target = bool(_EXEC_EXT_RE.search(lpath) or _EXEC_EXT_RE.search(targ))
        if _SUSPICIOUS_STAGING_RE.search(lpath or targ) and has_exec_target:
            score += 70
            signals.append("lnk_target_in_staging_path")
        if _ENCODED_OR_DOWNLOAD_RE.search(combo):
            score += 75
            signals.append("lnk_encoded_or_download_argument")
        if _LOLBIN_RE.search(combo) and has_exec_target:
            score += 45
            signals.append("lnk_lolbin_target")
        if not signals:
            suppressions.append("baseline_or_benign_shortcut")

    if fact_type == "jumplist_fact":
        # 31K-LNK-SCORE: Jump List = per-application access history. Same target
        # discipline as LNK; benign app-recent entries suppress.
        jpath = normalize_path(_get(fact, "path") or "")
        jargs = _sval(_get(fact, "arguments"))
        jcombo = " ".join((jpath, jargs)).strip()
        jhas_exec = bool(_EXEC_EXT_RE.search(jpath))
        if _SUSPICIOUS_STAGING_RE.search(jpath) and jhas_exec:
            score += 65
            signals.append("jumplist_access_to_staging_path")
        if _ENCODED_OR_DOWNLOAD_RE.search(jcombo):
            score += 70
            signals.append("jumplist_encoded_or_download_argument")
        if _LOLBIN_RE.search(jcombo) and jhas_exec:
            score += 40
            signals.append("jumplist_lolbin_access")
        if not signals:
            suppressions.append("baseline_application_access_history")


    if fact_type == "srum_usage_fact":
        # 31K-SRUM-TYPED-VALIDATOR: SRUM is aggregate app/user/resource/
        # network usage context, not process-creation proof. Promote only
        # suspicious app usage patterns; keep generic SRUM rows as baseline.
        app_path = normalize_path(
            _get(fact, "normalized_path", "application_path", "application") or ""
        )
        app_text = " ".join((
            app_path,
            _sval(_get(fact, "application", "application_path")),
            _sval(_get(fact, "table")),
        )).strip()
        table = _sval(_get(fact, "table")).lower()

        def _to_int(v):
            try:
                s = str(v if v is not None else "").replace(",", "").strip()
                if not s:
                    return 0
                return int(float(s))
            except Exception:
                return 0

        bytes_total = _to_int(_get(fact, "bytes_total"))
        network_hint = bool(bytes_total > 0 or "network" in table)

        if app_path and _SUSPICIOUS_STAGING_RE.search(app_path) and (
            _EXEC_EXT_RE.search(app_path)
            or any(app_path.lower().endswith(x) for x in (".dll", ".ps1", ".vbs", ".js", ".cmd", ".bat"))
        ):
            score += 65
            signals.append("srum_staging_app_usage")
        if _LOLBIN_RE.search(app_text):
            score += 45
            signals.append("srum_lolbin_app_usage")
        if network_hint:
            score += 35
            signals.append("srum_network_usage_context")
        if bytes_total >= 10 * 1024 * 1024:
            score += 55
            signals.append("srum_high_volume_network_usage")
        if not signals:
            suppressions.append("baseline_srum_usage_context")

    if fact_type == "usb_device_fact":
        # USB-WIRE: removable-media connection/usage (USBSTOR serial /
        # MountedDevices drive letter / per-user MountPoints2 volume->user).
        # Corroborating-only and FP-safe: bare removable-media presence is benign
        # context, so this stays well below the auto-promote floor (score < 60)
        # and never promotes alone -- a finding needs corroboration (data movement
        # via SRUM/MFT/archive, or anti-forensics). Universal: keys on the fact
        # type, no device / serial / user literal.
        score += 30
        signals.append("removable_media_connection")

    if fact_type == "appcompatcache_execution_fact":
        # 31K-APPCOMPAT-TYPED-CANDIDATE: ShimCache/AppCompatCache is
        # execution-compatibility evidence. Score suspicious paths strongly,
        # but do not convert baseline OS/application entries into candidates.
        apath = normalize_path(_get(fact, "expanded_path", "normalized_path", "path") or "")
        raw_path = _sval(_get(fact, "path", "normalized_path", "expanded_path"))
        executed_raw = _sval(_get(fact, "executed_raw", "executed")).lower()
        combo = " ".join((apath, raw_path)).strip()

        if _SUSPICIOUS_STAGING_RE.search(combo) and _EXEC_EXT_RE.search(combo):
            score += 85
            signals.append("appcompatcache_staging_execution_artifact")
        if _LOLBIN_RE.search(combo) and _EXEC_EXT_RE.search(combo):
            score += 45
            signals.append("appcompatcache_lolbin_execution_artifact")
        if executed_raw in {"yes", "true", "1"} and signals:
            score += 25
            signals.append("appcompatcache_executed_flag")
        if not signals:
            suppressions.append("baseline_appcompatcache_entry")

    if fact_type == "service_fact":
        service = _sval(_get(fact, "service_name")).lower()
        if _SUSPICIOUS_STAGING_RE.search(text) and _EXEC_EXT_RE.search(text):
            score += 85
            signals.append("service_points_to_staging_path")
        if service and _REMOTE_MGMT_RE.search(service):
            score += 25
            signals.append("remote_management_service_context")
        if service and _LOLBIN_RE.search(service):
            score += 45
            signals.append("admin_service_name")
        if not signals:
            suppressions.append("baseline_service_context")

    if fact_type == "network_connection_fact":
        owner = _sval(_get(fact, "owner", "process_name")).lower()
        state = _sval(_get(fact, "state")).upper()
        src_ip = _sval(_get(fact, "src_ip", "LocalAddr"))
        dst_ip = _sval(_get(fact, "dst_ip", "ForeignAddr"))
        src_port = _sval(_get(fact, "src_port", "LocalPort"))
        dst_port = _sval(_get(fact, "dst_port", "ForeignPort"))

        if _is_public_ip(dst_ip):
            score += 55
            signals.append("public_remote_peer")
        if _is_private_or_loopback_ip(src_ip) and src_ip.startswith("127.") and src_port.isdigit() and int(src_port) >= 1024:
            score += 20
            signals.append("localhost_high_port_context")
        if "LISTEN" in state and src_port.isdigit() and int(src_port) >= 1024 and owner not in _SENSITIVE_BASELINE_NAMES:
            score += 35
            signals.append("non_system_high_port_listener")
        if _LOLBIN_RE.search(owner) and owner not in _SENSITIVE_BASELINE_NAMES:
            score += 25
            signals.append("admin_or_sensitive_process_network")

    if fact_type == "network_ioc_fact":
        classification = _sval(_get(fact, "classification")).lower()
        urls = _URL_RE.findall(text)
        ips = _IP_RE.findall(text)
        has_private = classification in {"private", "loopback", "local"} or any(_is_private_or_loopback_ip(ip) for ip in ips)
        has_public = classification in {"public", "external"} or any(_is_public_ip(ip) for ip in ips)
        non_vendor_url = any(not _VENDOR_OR_UPDATE_RE.search(url) for url in urls)

        if has_public and non_vendor_url:
            score += 55
            signals.append("public_non_allowlisted_network_ioc")
        if has_private and non_vendor_url:
            score += 35
            signals.append("internal_or_loopback_url_context")
        if _ENCODED_OR_DOWNLOAD_RE.search(text) and non_vendor_url:
            score += 70
            signals.append("script_download_network_ioc")
        if urls and all(_VENDOR_OR_UPDATE_RE.search(url) for url in urls):
            suppressions.append("known_vendor_update_url")

        # BARE-DOMAIN DGA EMISSION (SIFT_DGA_NETIOC_V1): a bare host carried by a
        # network_ioc_fact (no URL wrapper, no IP) was never scored above, so a
        # DGA / algorithmic-C2 domain was INVISIBLE to the candidate pool. Emit a
        # candidate ONLY when the host is structurally DGA-like (dga_host_score>=2
        # via match_dga_domain) -- balanced + bounded: ordinary domains and carved
        # filenames score nothing, so a normal box emits ZERO and a DGA-C2 box only
        # a handful (never overflows the compiler / DB / validator). Universal:
        # keyed on host string STRUCTURE, never a domain list.
        if not urls and not ips:
            try:
                from sift_sentinel.analysis.malicious_semantics import (
                    match_dga_domain as _mdd)
                if _mdd(fact):
                    score += 75
                    signals.append("dga_domain")
            except Exception:
                pass

    if fact_type == "event_log_fact":
        provider = _sval(_get(fact, "Provider", "provider"))
        if _ENCODED_OR_DOWNLOAD_RE.search(text):
            score += 75
            signals.append("event_encoded_or_download_execution")
        if _PERSISTENCE_HIGH_RE.search(text):
            score += 80
            signals.append("event_high_risk_persistence")
        if _SUSPICIOUS_STAGING_RE.search(text) and _EXEC_EXT_RE.search(text):
            score += 55
            signals.append("event_staging_path")
        urls = _URL_RE.findall(text)
        if urls and any(not _VENDOR_OR_UPDATE_RE.search(url) for url in urls):
            score += 45
            signals.append("event_non_allowlisted_url")
        raw_el = _parse_raw_excerpt(fact)
        el_eid = str(raw_el.get("EventID") or fact.get("entity_id") or "")
        # 31-LATERAL-EVENTS: high-value Security events for lateral movement.
        if el_eid in ("5140", "5145"):
            _shmsg = (str(raw_el.get("Message") or "") + " " + text).lower()
            if any(t in _shmsg for t in ("\\c$", "/c$", "admin$", "ipc$")):
                score += 70
                signals.append("admin_share_access")  # SMB admin-share (T1021.002)
        if el_eid == "4648":
            score += 40
            signals.append("explicit_credential_logon")  # RunAs/alt-creds (corroborating)
        # 1102 (Security) / 104 (System) audit-log cleared = T1070.001. Event-side
        # corroboration of the command-side wevtutil/Clear-EventLog detector, and
        # often the only trace (cleared via API). 1102 unambiguous; 104 reused by
        # other providers -> require a 'cleared' log token. Universal Event IDs.
        if el_eid in ("1102", "104"):
            _clrmsg = (str(raw_el.get("Message") or "") + " " + text).lower()
            if el_eid == "1102" or ("cleared" in _clrmsg and "log" in _clrmsg):
                score += 80
                signals.append("anti_forensics_execution")  # event-side log clear
        # 4732/4728/4756 member added to a PRIVILEGED security group = T1098 account
        # manipulation (persistence / privilege escalation). Reuses the matcher's
        # privileged-group predicate (well-known RID) so score_fact + matcher agree;
        # FP-bound to privileged groups (non-privileged Users 545 does not fire).
        if el_eid in ("4732", "4728", "4756"):
            from sift_sentinel.analysis.malicious_semantics import _is_privileged_group_text
            _pgmsg = (str(raw_el.get("Message") or "") + " " + text).lower()
            if _is_privileged_group_text(_pgmsg):
                score += 75
                signals.append("privileged_group_modification")  # T1098
        if el_eid == "7045":
            _msg = str(raw_el.get("Message") or "") or text
            _pm = re.search(r"([a-zA-Z]:[\\/][^\s|,;]*\.(?:sys|exe|dll))", _msg, re.I)
            _img = _pm.group(1).strip().strip(chr(34)).strip(chr(39)) if _pm else ""
            if _img:
                _base = _img.replace(chr(92), "/").split("/")[-1].strip()
                if not _NORMAL_SERVICE_IMAGE_RE.search(_img) and not _KERNEL_MODULE_RE.match(_base):
                    score += 80
                    signals.append("event_service_install_abnormal")
                    if _base.lower().endswith(".sys"):
                        signals.append("event_kernel_driver_nonstandard_path")
        if _NOISY_EVENT_PROVIDER_RE.search(provider) and not signals:
            suppressions.append("noisy_event_provider_without_behavior_signal")

    if fact_type == "powershell_command_fact":
        tags = fact.get("ttp_tags") or []
        tag_set = set(tags)
        for _ps_tag in sorted(str(t).strip().lower().replace("-", "_") for t in tag_set):
            if _ps_tag in _POWERSHELL_VALIDATION_TTP_TAGS:
                signals.append(f"powershell_ttp:{_ps_tag}")
        urls = fact.get("urls") or []
        if "invoke_mimikatz" in tag_set or "lsass_access" in tag_set:
            score += 95
            signals.append("powershell_credential_dumping")
        if "encoded_command" in tag_set:
            score += 85
            signals.append("powershell_encoded_command")
        if "download_cradle" in tag_set:
            score += 80
            signals.append("powershell_download_cradle")
        if "amsi_bypass" in tag_set or "reflection_load" in tag_set:
            score += 80
            signals.append("powershell_evasion_or_load")
        if "ps_remoting_lateral" in tag_set or "wmi_execution" in tag_set:
            score += 70
            signals.append("powershell_lateral_or_wmi")
        if "credential_harvest" in tag_set:
            score += 60
            signals.append("powershell_credential_harvest")
        if "bypass_execution_policy" in tag_set or "no_profile_hidden" in tag_set:
            score += 45
            signals.append("powershell_stealth_flags")
        if "long_base64_blob" in tag_set and not any(
            s in signals for s in ("powershell_encoded_command", "powershell_download_cradle")):
            score += 35
            signals.append("powershell_base64_blob")
        if urls and any(not _VENDOR_OR_UPDATE_RE.search(str(u)) for u in urls):
            score += 30
            signals.append("powershell_non_allowlisted_url")
        if fact.get("domains") or fact.get("ips"):
            score += 20
            signals.append("powershell_network_indicator")
        if fact.get("suspicious_markers"):
            score += 25
            signals.append("powershell_suspicious_marker")
        # powershell_high_severity_floor_v1: reflective injection / credential
        # access / evasion PowerShell is confirmed-malicious-grade. Floor its
        # candidate score into the top tier so true severity ranks correctly and
        # it can never be buried below the prompt's score cut. Generic TTP tag
        # names only -- no case literals.
        _ps_high_sev = {"invoke_mimikatz", "lsass_access", "reflection_load",
                        "amsi_bypass", "encoded_command", "download_cradle",
                        "credential_harvest"}
        if tag_set & _ps_high_sev:
            score = max(score, 210)
            if "powershell_high_severity" not in signals:
                signals.append("powershell_high_severity")
        # Raw-command fallback (tag-INDEPENDENT): the upstream tagger can miss a command,
        # so scan the command TEXT directly. If an encoded one-liner or download cradle is
        # present but its validator-backed TTP tag was not supplied, synthesize the tag so
        # the candidate still reaches validation-ready. The grammar IS in the fact, so the
        # claim stays existence-validatable. Universal: command grammar only, no literals.
        _ps_cmd = _sval(_get(fact, "command", "command_line", "cmdline", "decoded",
                             "script", "value")) or _blob(fact)
        if _ps_cmd:
            if "encoded_command" not in tag_set and re.search(
                    r"(?:^|\s)[-/]e(?:nc|ncodedcommand|c)?\b\s+[A-Za-z0-9+/=]{20,}",
                    _ps_cmd, re.I):
                score += 85
                for _s in ("powershell_ttp:encoded_command", "powershell_encoded_command"):
                    if _s not in signals:
                        signals.append(_s)
            if ("download_cradle" not in tag_set
                    and re.search(r"(?:Net\.WebClient|DownloadString|DownloadFile|"
                                  r"DownloadData|Invoke-WebRequest|Invoke-RestMethod)",
                                  _ps_cmd, re.I)
                    and "powershell_ttp:encoded_command" not in signals
                    and "powershell_ttp:download_cradle" not in signals):
                score += 80
                for _s in ("powershell_ttp:download_cradle", "powershell_download_cradle"):
                    if _s not in signals:
                        signals.append(_s)

    if fact_type == "rdp_artifact_fact":
        # Credit an IP target (anywhere in the blob, original behaviour) OR an
        # FQDN target read from the typed fields / EVTX Value= payload so a
        # lateral-movement RDP connection to an internal host referenced by
        # name is not suppressed. Stays remote_access_context (never ready).
        if _IP_RE.search(text) or _rdp_target_token(fact):
            score += 25
            signals.append("rdp_target_reference")
        else:
            suppressions.append("rdp_context_without_target")

    if fact_type == "wmi_subscription_fact":
        # slot31AV: read from raw_excerpt (typed extractor fields stripped
        # by storage). Score only consumer-type records that carry an
        # actual payload (script body, script filename, or command-line
        # template). Default consumers shipped with Windows (NTEventLog,
        # SCM Event Log Consumer, SMTP, LogFile, VolumeChange class defs)
        # have no payload -> excluded by the gate. Dataset-agnostic: keys
        # on consumer-type substring + payload presence + the shared
        # suspicion regexes only; no specific name literals.
        raw = _parse_raw_excerpt(fact)
        wtype = str(raw.get("type") or "").lower()
        payload = " ".join(
            str(raw.get(k) or "")
            for k in (
                "extracted_script_text",
                "extracted_script_filename",
                "extracted_command_template",
                "extracted_executable_path",
            )
        )
        has_payload = bool(payload.strip())
        is_consumer = "consumer" in wtype
        if is_consumer and not has_payload:
            suppressions.append("wmi_default_consumer_no_payload")
        elif is_consumer and has_payload:
            fired_persistence = False
            if _ENCODED_OR_DOWNLOAD_RE.search(payload):
                score += 85
                fired_persistence = True
            if _SUSPICIOUS_STAGING_RE.search(payload) and _EXEC_EXT_RE.search(payload):
                score += 80
                fired_persistence = True
            if _LOLBIN_RE.search(payload):
                score += 60
                fired_persistence = True
            urls = _URL_RE.findall(payload)
            if urls and any(not _VENDOR_OR_UPDATE_RE.search(u) for u in urls):
                score += 45
                fired_persistence = True
            if fired_persistence:
                signals.append("wmi_event_subscription_persistence")
            # consumer with payload but no suspicious marker -> weak
            # context, NOT strong-ready (no signal emitted)

    if fact_type == "userassist_fact":
        # slot31AV: read from raw_excerpt (typed fields stripped by storage).
        # Vol3 userassist record field names vary - try multiple variants.
        raw = _parse_raw_excerpt(fact)
        reg_path = normalize_path(str(
            raw.get("KeyPath") or raw.get("Path") or raw.get("RegistryPath") or ""
        ).strip())
        entry = normalize_path(str(
            raw.get("Name") or raw.get("Value") or raw.get("EntryName") or ""
        ).strip())
        combined = reg_path + " " + entry
        if _SUSPICIOUS_STAGING_RE.search(combined) and _EXEC_EXT_RE.search(combined):
            score += 55
            signals.append("userassist_execution_from_staging")

    if fact_type == "privilege_fact":
        # slot31AV: read from raw_excerpt. Vol3 privileges record fields:
        # PID, Process, Privilege, Attributes (comma-separated string).
        raw = _parse_raw_excerpt(fact)
        priv = str(raw.get("Privilege") or "").lower()
        proc = str(raw.get("Process") or "").lower()
        attrs_raw = str(raw.get("Attributes") or "")
        attrs_lower = {a.strip().lower() for a in attrs_raw.split(",") if a.strip()}
        if priv in _SENSITIVE_PRIV_NAMES and "enabled" in attrs_lower:
            if proc not in _SENSITIVE_BASELINE_NAMES:
                score += 65
                signals.append("sensitive_privilege_enabled_on_non_baseline")

    if fact_type == "ssdt_integrity_fact":
        # slot31AV: read from raw_excerpt. Vol3 ssdt record fields:
        # Index, Module, Symbol, Address.
        raw = _parse_raw_excerpt(fact)
        module = str(raw.get("Module") or "").lower()
        if module and not _KERNEL_MODULE_RE.match(module):
            score += 90
            signals.append("kernel_ssdt_hook")

    if fact_type == "psxview_fact":
        # slot31AV (narrowed): read from raw_excerpt. Vol3 PsXView
        # view-field names vary across versions: pslist + psscan are
        # universal; thrdscan vs thrdproc varies; csrss/session/deskthrd
        # may or may not be present. Collect ALL known boolean view
        # names defensively.
        #
        # The DKOM signature is NOT "any view disagreement" - most
        # disagreement rows on real Windows images are benign:
        #   * terminated processes (Exit Time set) drop out of pslist
        #     and the thread views while the pool scan still finds them;
        #   * kernel meta-processes (System, Registry, Memory
        #     Compression, Secure System, PIDs 0/4) routinely miss
        #     csrss/session/deskthrd views;
        #   * a process visible in pool scan only with no live threads
        #     is by definition terminated, not hidden.
        # Firing process_view_inconsistency for those is a false
        # positive (validation-ready process_hiding_indicator
        # candidates that cite nothing). Restrict the strong signal to
        # the active-but-unlinked DKOM pattern:
        #   pslist=False (unlinked from active list)
        #   psscan=True  (process still in the pool)
        #   not terminated (no exit time)
        #   non-kernel    (PID not in {0,4}; name not a system
        #                  meta-process)
        #   live threads  (when thrdscan/thrdproc is present we require
        #                  at least one True; when neither key exists in
        #                  this Vol3 build we allow it to preserve recall)
        # process_view_inconsistency remains strong-ready at +80; only
        # the gating WHEN it fires changes here.
        raw = _parse_raw_excerpt(fact)
        _view_names = ("pslist", "psscan", "thrdproc", "thrdscan",
                       "csrss", "session", "deskthrd")
        views = {k: raw.get(k) for k in _view_names if k in raw}
        present = [k for k, v in views.items() if v is True]
        absent = [k for k, v in views.items() if v is False]
        if not present and not absent:
            suppressions.append("psxview_no_view_data")
        else:
            try:
                _pid_raw = raw.get("PID") if raw.get("PID") is not None else raw.get("Pid")
                pid = int(_pid_raw) if _pid_raw is not None else None
            except (TypeError, ValueError):
                pid = None
            name = str(raw.get("Name") or "").strip().lower()
            terminated = bool(
                str(raw.get("Exit Time") or raw.get("ExitTime") or "").strip()
            )
            _SYSTEM_META_PROC_NAMES = {
                "system", "registry", "memory compression",
                "memcompression", "secure system",
            }
            is_kernel = (
                pid in (0, 4)
                or name in _SYSTEM_META_PROC_NAMES
            )
            thread_view_present = ("thrdscan" in views) or ("thrdproc" in views)
            has_threads = (
                views.get("thrdscan") is True
                or views.get("thrdproc") is True
            )
            unlinked = (
                views.get("pslist") is False
                and views.get("psscan") is True
            )
            active = (not thread_view_present) or has_threads
            if unlinked and active and not terminated and not is_kernel:
                score += 80
                signals.append("process_view_inconsistency")
            # benign / terminated / kernel / non-DKOM disagreement ->
            # no strong signal, no false-positive hiding candidate

    if _VENDOR_OR_UPDATE_RE.search(text) and not any(
        s in signals for s in (
            "memory_injection",
            "process_view_inconsistency",
            "kernel_ssdt_hook",
            "sensitive_privilege_enabled_on_non_baseline",
            "userassist_execution_from_staging",
            "encoded_or_download_execution",
            "event_encoded_or_download_execution",
            "script_download_network_ioc",
            "high_risk_persistence",
            "registry_points_to_staging_path",
            "scheduled_task_points_to_staging_path",
            "service_points_to_staging_path",
            "wmi_event_subscription_persistence",
        )
    ):
        suppressions.append("known_vendor_or_update_noise")

    return int(score), sorted(set(signals)), sorted(set(suppressions))


def _candidate_type(signals: set[str]) -> str:
    if "kernel_ssdt_hook" in signals:
        return "kernel_rootkit_indicator"
    if "memory_injection" in signals:
        return "memory_injection"
    if "process_view_inconsistency" in signals:
        return "process_hiding_indicator"
    if "wmi_event_subscription_persistence" in signals:
        return "wmi_event_subscription_persistence"
    if "sensitive_privilege_enabled_on_non_baseline" in signals:
        return "elevated_privilege_context"
    ps_tags = _powershell_ttp_tags_from_signals(signals)
    if ps_tags:
        if {"encoded_command", "download_cradle", "long_base64_blob"} & set(ps_tags):
            return "encoded_powershell_or_download_cradle"
        return "suspicious_powershell_command"
    if {"encoded_or_download_execution", "event_encoded_or_download_execution", "scheduled_task_encoded_or_download", "script_download_network_ioc"} & signals:
        return "encoded_powershell_or_download_cradle"
    if {"high_risk_persistence", "event_high_risk_persistence", "registry_points_to_staging_path", "scheduled_task_points_to_staging_path", "service_points_to_staging_path", "hidden_scheduled_task", "userassist_execution_from_staging"} & signals:
        return "high_risk_persistence"
    if {"admin_service_name", "registry_lolbin_imagepath", "remote_management_or_admin_service"} & signals:
        return "admin_or_remote_management_persistence"
    if {"public_remote_peer", "public_non_allowlisted_network_ioc"} & signals:
        return "network_c2_or_external_peer"
    if {"internal_or_loopback_url_context", "localhost_high_port_context", "non_system_high_port_listener"} & signals:
        return "internal_or_local_staging_network"
    if "srum_egress_self_relative_outlier" in signals:
        return "data_exfiltration_egress_outlier"
    if {"srum_staging_app_usage", "srum_lolbin_app_usage",
            "srum_network_usage_context",
            "srum_high_volume_network_usage"} & signals:
        return "srum_usage_context"
    if {"execution_from_staging_path", "process_from_staging_path", "event_staging_path", "lnk_target_in_staging_path", "lnk_encoded_or_download_argument", "lnk_lolbin_target", "jumplist_access_to_staging_path", "jumplist_encoded_or_download_argument", "jumplist_lolbin_access", "appcompatcache_staging_execution_artifact", "appcompatcache_lolbin_execution_artifact"} & signals:
        return "suspicious_file_or_process_execution"
    if "rdp_target_reference" in signals:
        return "remote_access_context"
    if "admin_share_access" in signals:
        return "lateral_movement_admin_share"
    if "privileged_group_modification" in signals:
        return "privilege_escalation_group_modification"
    if "service_account_interactive_execution" in signals:
        return "account_context_anomaly"
    if "mass_encryption_burst" in signals:
        return "ransomware_mass_encryption"
    if "event_kernel_driver_nonstandard_path" in signals:
        return "kernel_driver_nonstandard_path"
    if "event_service_install_abnormal" in signals:
        return "service_install_nonstandard_path"
    if "anti_forensics_execution" in signals:
        return "defense_evasion_anti_forensics"
    if "inhibit_system_recovery" in signals:
        return "system_recovery_inhibition"
    if "archive_in_staging_path" in signals:
        return "data_collection_staging"
    if "removable_media_connection" in signals:
        return "removable_media_usage"
    return "context_only"

def _claim_templates(signals: set[str]) -> list[str]:
    claims: list[str] = []
    if "memory_injection" in signals:
        claims.append("memory_injection: validate PID/process, VAD/protection, and source record from memory_injection_fact.")
    if "kernel_ssdt_hook" in signals:
        claims.append("kernel_rootkit_indicator: validate ssdt_integrity_fact rows; SSDT syscall entry points to a non-kernel module. Cross-reference vol_modscan / vol_callbacks / vol_driverirp for corroborating kernel-rootkit evidence.")
    if "sensitive_privilege_enabled_on_non_baseline" in signals:
        claims.append("elevated_privilege_context: validate privilege_fact; non-baseline process holds an Enabled sensitive privilege (SeDebug/SeImpersonate/SeAssignPrimaryToken/SeLoadDriver/etc). Corroborate with process cmdline + parent for token-theft / mimikatz patterns.")
    if "userassist_execution_from_staging" in signals:
        claims.append("userassist_staging_execution: validate userassist_fact; per-user registry recorded execution of binary from suspicious staging path. Corroborate with amcache / prefetch / MFT for hash + timestamp.")
    if "process_view_inconsistency" in signals:
        claims.append("process_hiding_indicator: validate psxview_fact row; process appears in some Vol3 views (pslist/psscan/thrdproc/csrss/session/deskthrd) but missing from others. Cross-reference exit_time and kernel-only PID status before promoting as DKOM rootkit candidate.")
    if {"encoded_or_download_execution", "event_encoded_or_download_execution", "scheduled_task_encoded_or_download", "script_download_network_ioc"} & signals:
        claims.append("encoded_execution: validate encoded command, IEX/DownloadString/WebClient, or shellcode-loading text from supporting facts.")
    if {"high_risk_persistence", "event_high_risk_persistence", "registry_points_to_staging_path", "scheduled_task_points_to_staging_path", "service_points_to_staging_path", "hidden_scheduled_task"} & signals:
        claims.append("persistence: validate registry key, service, scheduled task, WMI/EventConsumer, SafeBoot, or action path from typed facts.")
    if {"execution_from_staging_path", "process_from_staging_path", "event_staging_path"} & signals:
        claims.append("file_execution: validate executable/script path, source tool, and timestamp/hash when available.")
    # 31K-LNK-CLAIM-DISCIPLINE: LNK/JumpList artifacts are disk-side
    # shortcut/access provenance. Do not let prompt templates silently turn
    # access/reference evidence into process-execution proof.
    if {"srum_staging_app_usage", "srum_lolbin_app_usage", "srum_network_usage_context", "srum_high_volume_network_usage"} & signals:
        claims.append("srum_usage: validate SRUM table, application/path, user/SID, timestamp, and byte counters from SRUDB.dat. Treat as aggregate resource/network usage telemetry; do not claim process creation, command line, or exact remote endpoint without corroboration.")
    if "removable_media_connection" in signals:
        claims.append("removable_media: validate usb_device_fact (USBSTOR serial / mounted drive letter / per-user MountPoints2 volume->user). Removable-media connection/usage is corroborating context; do not claim data theft without a corroborating data-movement (SRUM/MFT/archive staging) or anti-forensics fact.")
    if {"appcompatcache_staging_execution_artifact", "appcompatcache_lolbin_execution_artifact"} & signals:
        claims.append("appcompatcache: validate ShimCache/AppCompatCache path, Executed flag, LastModifiedTimeUTC, ControlSet, and source SYSTEM hive. Treat as execution-compatibility evidence; do not claim exact process execution time without corroboration.")
    if {"lnk_target_in_staging_path", "lnk_encoded_or_download_argument", "lnk_lolbin_target"} & signals:
        claims.append("lnk_shortcut: validate LNK target/local path, arguments, source shortcut file, and timestamps. Treat as shortcut/access provenance unless corroborated by process, Amcache, Prefetch, or event-log execution.")
    if {"jumplist_access_to_staging_path", "jumplist_encoded_or_download_argument", "jumplist_lolbin_access"} & signals:
        claims.append("jumplist_access: validate Jump List path, arguments, AppId/source file, and timestamps. Treat as application access history; do not claim process execution without independent execution evidence.")
    if {"public_remote_peer", "public_non_allowlisted_network_ioc", "internal_or_loopback_url_context", "localhost_high_port_context", "non_system_high_port_listener"} & signals:
        claims.append("network: validate peer/socket/URL, owner PID/process where available, and source tool record.")
    if "admin_service_name" in signals or "registry_lolbin_imagepath" in signals or "remote_management_or_admin_service" in signals:
        claims.append("admin_tooling: validate service/tool name and corroborate with process, registry, network, or file-execution facts before promotion.")
    if "rdp_target_reference" in signals:
        claims.append("remote_access_context: validate RDP target/user/session fields; do not promote without corroboration.")
    if "archive_in_staging_path" in signals:
        claims.append("data_collection_staging: validate filesystem_timeline_fact path + timestamp; an archive/container file resides under a user-writable staging path (potential data collection/staging, T1560). Corroborate with SRUM byte volume, cloud-sync/USB artifacts, or network egress before promoting toward exfiltration.")
    if "wmi_event_subscription_persistence" in signals:
        claims.append("wmi_event_subscription_persistence: validate consumer type (ActiveScript/CommandLine), the payload body (extracted_script_text / extracted_command_template / extracted_executable_path) carries the suspicious marker, and the bound EventFilter (extracted_filter_ref) from a wmi_filter_to_consumer_binding fact. Default consumers without payload must not be promoted.")
    for _ps_tag in _powershell_ttp_tags_from_signals(signals):
        claims.append('{"type": "powershell_command", "ttp_tag": "' + _ps_tag + '"}')
    return claims or ["context: do not promote without a second corroborating typed fact family."]


def _is_strong_ready(signals: set[str]) -> bool:
    if _powershell_ttp_tags_from_signals(signals):
        return True
    return bool(signals & {
        "memory_injection",
        "process_view_inconsistency",
        "kernel_ssdt_hook",
        "sensitive_privilege_enabled_on_non_baseline",
        "userassist_execution_from_staging",
        "encoded_or_download_execution",
        "event_encoded_or_download_execution",
        "scheduled_task_encoded_or_download",
        "script_download_network_ioc",
        "high_risk_persistence",
        "event_high_risk_persistence",
        # Unambiguous, low-FP event indicators (the dual-use admin_share_access /
        # privileged_group_modification are deliberately EXCLUDED -> stay corroborating).
        "event_service_install_abnormal",          # 7045 service from a temp/non-std path (T1543)
        "event_kernel_driver_nonstandard_path",    # 7045 driver from a non-std path (rootkit)
        "anti_forensics_execution",                # 1102/104 audit-log cleared (T1070.001)
        "registry_points_to_staging_path",
        "scheduled_task_points_to_staging_path",
        "service_points_to_staging_path",
        "execution_from_staging_path",
        "process_from_staging_path",
        "wmi_event_subscription_persistence",
        "lnk_target_in_staging_path",  # 31K-LNK-TYPE
        "lnk_encoded_or_download_argument",
        "lnk_lolbin_target",
        "jumplist_access_to_staging_path",
        "jumplist_encoded_or_download_argument",
        "jumplist_lolbin_access",
        "appcompatcache_staging_execution_artifact",  # 31K-APPCOMPAT-TYPED-CANDIDATE
        "appcompatcache_lolbin_execution_artifact",
        "srum_staging_app_usage",  # 31K-SRUM-TYPED-VALIDATOR
        "srum_lolbin_app_usage",
        "srum_high_volume_network_usage",
    })


def _suppression_reason(suppressions: list[str], signals: set[str], score: int) -> str:
    if _is_strong_ready(signals):
        return ""
    counts = Counter(suppressions)
    if counts and score < 120:
        return "; ".join(k for k, _ in counts.most_common(3))
    if signals == {"registry_persistence"} or signals == {"multiple_supporting_facts", "registry_persistence"}:
        return "baseline_service_registry_without_suspicious_imagepath"
    if "rdp_target_reference" not in signals and signals <= {"multiple_supporting_facts", "rdp_artifact"}:
        return "rdp_context_without_correlated_process_or_network"
    return ""


def _is_review_worthy(candidate: dict) -> bool:
    """Predicate for corroborated-but-not-ready candidates (the recall ceiling).

    Pure boolean test. Does NOT change validation gating: a True result
    here means the candidate could plausibly become a finding IF the
    validator widened, never that it is permitted to be a finding now.
    """
    if not isinstance(candidate, dict):
        return False
    if candidate.get("validation_ready"):
        return False
    if candidate.get("suppression_reason"):
        return False
    if candidate.get("candidate_type") in _CONTEXT_CANDIDATE_TYPES:
        return False
    sources = candidate.get("source_tools") or []
    fact_types = candidate.get("fact_types") or []
    try:
        score = int(candidate.get("score") or 0)
    except (TypeError, ValueError):
        return False
    if len(sources) < _REVIEW_WORTHY_MIN_SOURCES:
        return False
    if len(fact_types) < _REVIEW_WORTHY_MIN_FACT_TYPES:
        return False
    if score < _REVIEW_WORTHY_MIN_SCORE:
        return False
    return True


def _candidate_recall_ceiling(
    candidates,
    *,
    returned_validation_ready=None,
) -> dict:
    """Recall-ceiling telemetry over the full candidate pool.

    Pure helper. Buckets every non-ready candidate exactly once into one
    of four mutually exclusive buckets and reports
    ``max_defensible = ready_full + review_worthy`` -- the upper bound
    on validator-backed findings the system *could* defensibly produce
    if the validator widened to accept corroborated multi-source claims.
    Validation semantics are unchanged: this function reports a ceiling,
    it does not promote anything.

    Bucket priority (each non-ready candidate counts in exactly one):
      1. suppressed              -- has any suppression_reason
      2. context_type            -- candidate_type in _CONTEXT_CANDIDATE_TYPES
      3. corroborated_review_worthy -- _is_review_worthy(c) is True
      4. thin_single_source_or_type -- everything else non-ready

    Returns a dict with: total_candidates, validation_ready_total,
    returned_validation_ready, nonready_total, nonready_bucket_counts,
    review_worthy_count, max_defensible.
    """
    if not isinstance(candidates, list):
        candidates = list(candidates or [])

    total = len(candidates)
    ready = [c for c in candidates if isinstance(c, dict) and c.get("validation_ready")]
    nonready = [c for c in candidates if isinstance(c, dict) and not c.get("validation_ready")]

    buckets = {
        "suppressed": 0,
        "context_type": 0,
        "corroborated_review_worthy": 0,
        "thin_single_source_or_type": 0,
    }
    for c in nonready:
        if c.get("suppression_reason"):
            buckets["suppressed"] += 1
        elif c.get("candidate_type") in _CONTEXT_CANDIDATE_TYPES:
            buckets["context_type"] += 1
        elif _is_review_worthy(c):
            buckets["corroborated_review_worthy"] += 1
        else:
            buckets["thin_single_source_or_type"] += 1

    review_worthy_count = buckets["corroborated_review_worthy"]
    ready_full = len(ready)
    if returned_validation_ready is None:
        returned_validation_ready_val = ready_full
    else:
        returned_validation_ready_val = int(returned_validation_ready)

    return {
        "total_candidates": total,
        "validation_ready_total": ready_full,
        "returned_validation_ready": returned_validation_ready_val,
        "nonready_total": len(nonready),
        "nonready_bucket_counts": buckets,
        "review_worthy_count": review_worthy_count,
        "max_defensible": ready_full + review_worthy_count,
    }


def _select_review_worthy_candidates(candidates) -> list[dict]:
    """Deterministic, score-DESC ordering of corroborated-review candidates.

    Same selection predicate as :func:`_is_review_worthy`. Ordering is
    (score DESC, len(source_tools) DESC, len(fact_types) DESC,
    candidate_type ASC, entity_key ASC). Mirrors the main candidate
    sort key shape (without the validation_ready first axis since these
    are by definition not ready).
    """
    if not isinstance(candidates, list):
        return []
    eligible = [c for c in candidates if _is_review_worthy(c)]
    eligible.sort(
        key=lambda c: (
            int(c.get("score") or 0),
            len(c.get("source_tools") or []),
            len(c.get("fact_types") or []),
            -1,  # placeholder so subsequent ASC keys can be appended via tuple
        ),
        reverse=True,
    )
    # Re-sort with explicit DESC/ASC mix: stable sort, ASC tiebreakers second.
    eligible.sort(key=lambda c: (str(c.get("candidate_type") or ""),
                                 str(c.get("entity_key") or "")))
    eligible.sort(
        key=lambda c: (
            int(c.get("score") or 0),
            len(c.get("source_tools") or []),
            len(c.get("fact_types") or []),
        ),
        reverse=True,
    )
    return eligible


# Highest-value detectors: injection / hidden-process / unlinked-DLL / kernel-rootkit /
# WMI-persistence / hollowing / anti-forensics. A candidate sourced from any of these is
# protected from the return cap ahead of ordinary baseline-noise candidates, so a busy
# image can never let low-value context push a real injection/rootkit candidate out of the
# returned set. Tool-class keyed; no case data.
_HIGH_VALUE_TOOLS = frozenset({
    "vol_malfind", "vol_psxview", "vol_ldrmodules", "vol_hollowprocesses",
    "parse_wmi_subscription", "vol_ssdt", "vol_modscan", "vol_driverscan",
    "vol_modules", "vol_threads", "vol_handles",
})


def _is_high_value_candidate(candidate: dict) -> bool:
    """True iff this candidate is sourced from one of the highest-value detectors."""
    if not isinstance(candidate, dict):
        return False
    return any(str(t) in _HIGH_VALUE_TOOLS for t in (candidate.get("source_tools") or []))


def build_candidate_observations(
    evidence_db: dict | None,
    *,
    max_candidates: int = 1000,
    support_cap_per_signal: int = 4,
) -> dict:
    facts = list(iter_typed_facts(evidence_db))

    # SIFT_EGRESS_OUTLIER_PROMOTE_V1 (Fix A): a self-relative SRUM egress outlier
    # (egress > the image's OWN mean+2sigma) is self-validating -- the deviation
    # from the image's own baseline IS the evidence -- so it surfaces for review
    # even though SRUM is the only artifact that measures bytes (single-source,
    # which otherwise fails the multi-source ready gate). HARD-BOUNDED to the
    # top-K outliers so it can never flood the candidate set. Uses the SAME
    # threshold helper as the disposition-time match_srum_egress_outlier, so a
    # promoted candidate also satisfies that matcher downstream. Self-relative;
    # no fixed byte constant, no host/app/path literal.
    _EGRESS_OUTLIER_PROMOTE_CAP = 5
    _egress_outlier_fact_ids: set = set()
    try:
        from sift_sentinel.analysis.malicious_semantics import (
            _srum_fact_egress as _ms_egress,
            _srum_egress_values as _ms_vals,
            _srum_egress_outlier_threshold as _ms_thr,
        )
        _eg_thr = _ms_thr(_ms_vals(evidence_db))
        if _eg_thr is not None:
            _ranked = sorted(
                (
                    (_ms_egress(_f), _f.get("fact_id"))
                    for _f in facts
                    if _sval(_f.get("fact_type")) == "srum_usage_fact"
                ),
                key=lambda _t: _t[0], reverse=True,
            )
            for _eg_val, _eg_fid in _ranked:
                if (_eg_val > _eg_thr and _eg_fid
                        and len(_egress_outlier_fact_ids) < _EGRESS_OUTLIER_PROMOTE_CAP):
                    _egress_outlier_fact_ids.add(_eg_fid)
            if _egress_outlier_fact_ids:
                logger.info(
                    "SRUM_EGRESS_OUTLIER_PROMOTE count=%d threshold_bytes=%d "
                    "(self-relative mean+2sigma; single-source bypass, top-%d cap)",
                    len(_egress_outlier_fact_ids), int(_eg_thr),
                    _EGRESS_OUTLIER_PROMOTE_CAP,
                )
    except Exception:
        _egress_outlier_fact_ids = set()

    # SIFT_MASS_ENCRYPTION_BURST_V1 (#1): ransomware in-place encryption (T1486)
    # leaves a corpus-level fingerprint -- one FOREIGN extension appended across
    # MANY files of DIVERSE original data types (report.docx.<enc>, sheet.xlsx.<enc>
    # ...). Detect the dominant appended-extension whose file count is a self-
    # relative outlier (mean+2sigma over per-appended-ext counts; or, with too few
    # groups, the dominant one) AND that spans >=3 distinct data types (the FP-bound
    # vs a single app's double-extension). Emitted below as a synthetic validation-
    # ready candidate so it RIDES the gen-fix. Vocabulary-free re: count (self-
    # relative); the only list is the universal data-type vocabulary. Routes to
    # needs-review (human triages mass-backup vs encryption).
    _enc_burst = None
    try:
        _ext_groups: dict[str, dict] = {}
        for _f in facts:
            if _sval(_f.get("fact_type")) != "filesystem_timeline_fact":
                continue
            _fp = normalize_path(_get(_f, "normalized_path", "path", "file_path") or "")
            _base = _fp.replace("\\", "/").rsplit("/", 1)[-1].lower()
            _parts = _base.split(".")
            if len(_parts) < 3:
                continue
            _orig, _enc = _parts[-2], _parts[-1]
            if (_orig not in _MASS_ENCRYPTION_DATA_EXTS or not _enc
                    or len(_enc) > 12 or not _enc.isalnum()
                    or _enc in _MASS_ENCRYPTION_DATA_EXTS):
                continue
            _grp = _ext_groups.setdefault(_enc, {"origs": set(), "fact_ids": []})
            _grp["origs"].add(_orig)
            _fid = _f.get("fact_id")
            if _fid:
                _grp["fact_ids"].append(_fid)
        _diverse = [(len(g["fact_ids"]), e, g) for e, g in _ext_groups.items()
                    if len(g["origs"]) >= 3]
        if _diverse:
            _bcounts = [c for c, _, _ in _diverse]
            if len(_bcounts) >= 4:
                _bm = sum(_bcounts) / len(_bcounts)
                _bsd = (sum((c - _bm) ** 2 for c in _bcounts) / len(_bcounts)) ** 0.5
                _bthr = _bm + 2.0 * _bsd
            else:
                _bthr = 0.0  # too few groups for stats: type-diversity alone qualifies
            _diverse.sort(reverse=True)
            _tc, _te, _tg = _diverse[0]
            if _tc > _bthr:
                _enc_burst = {
                    "ext": _te,
                    "fact_ids": _tg["fact_ids"][:20],
                    "file_count": _tc,
                    "original_types": sorted(_tg["origs"]),
                }
    except Exception:
        _enc_burst = None

    groups: dict[str, list[dict]] = defaultdict(list)
    for fact in facts:
        for key in _entity_keys(fact):
            groups[key].append(fact)

    candidates: list[dict] = []
    for entity_key, group_facts in groups.items():
        source_tools = sorted({_sval(f.get("source_tool")) for f in group_facts if f.get("source_tool")})
        fact_types = sorted({_sval(f.get("fact_type")) for f in group_facts if f.get("fact_type")})
        score = 0
        supporting: list[dict] = []
        all_signals: list[str] = []
        all_suppressions: list[str] = []
        signal_budget: Counter = Counter()

        for fact in group_facts:
            # PERF: the high-volume fact types below (66% of facts on a paired run:
            # handles + the two filesystem corpora) empirically NEVER produce a
            # candidate signal, yet _score_fact/_blob over them dominate Step-7. Skip
            # SCORING them here -- they still participated in the _entity_keys grouping
            # above (corroboration intact) and filesystem_timeline_fact already fed the
            # mass-encryption-burst pass. Byte-identical output; kill-switch off.
            if (_CANDOBS_SKIP_NONSCORING
                    and _sval(fact.get("fact_type")) in _NONSCORING_FACT_TYPES):
                continue
            local_score, signals, suppressions = _score_fact(fact)
            all_suppressions.extend(suppressions)
            # Fix A: a top-K self-relative egress outlier is retained even if its
            # per-fact score/signals are thin -- the anomaly itself is the evidence.
            _is_egress_outlier = fact.get("fact_id") in _egress_outlier_fact_ids
            if (local_score <= 0 or not signals) and not _is_egress_outlier:
                continue
            kept = []
            for signal in signals:
                budget_key = (signal, _sval(fact.get("source_tool")), _sval(fact.get("fact_type")))
                if signal_budget[budget_key] < support_cap_per_signal:
                    signal_budget[budget_key] += 1
                    kept.append(signal)
            if _is_egress_outlier and "srum_egress_self_relative_outlier" not in kept:
                kept.append("srum_egress_self_relative_outlier")
            if not kept:
                continue
            supporting.append(_fact_ref(fact, local_score, kept))
            score += min(local_score, 100)
            all_signals.extend(kept)

        signals_set = set(all_signals)
        if len(source_tools) >= 2 and supporting:
            score += 35
            signals_set.add("multi_source")
        if len(fact_types) >= 2 and supporting:
            score += 30
            signals_set.add("multi_fact_type")
        if len(supporting) >= 3:
            score += 10
            signals_set.add("multiple_supporting_facts")

        ctype = _candidate_type(signals_set)
        suppression = _suppression_reason(all_suppressions, signals_set, score)
        validation_ready = bool(
            supporting
            and not suppression
            and ctype not in {"context_only", "remote_access_context"}
            and (
                (_is_strong_ready(signals_set) and score >= 80)
                or (score >= 130 and len(fact_types) >= 2 and len(source_tools) >= 2)
            )
        )
        # SIFT_EGRESS_OUTLIER_PROMOTE_V1 (Fix A): a top-K self-relative SRUM egress
        # outlier surfaces for review even single-source. Bounded upstream to the
        # top-K (cannot flood); its ctype is the dedicated
        # data_exfiltration_egress_outlier, never a context type.
        if (not validation_ready and supporting
                and "srum_egress_self_relative_outlier" in signals_set):
            validation_ready = True

        if not supporting and not suppression:
            continue
        if score < 35 and not validation_ready:
            continue

        candidates.append({
            "candidate_id": "",
            "candidate_type": ctype,
            "score": int(score),
            "entity_key": entity_key,
            "validation_ready": validation_ready,
            "signals": sorted(signals_set),
            "source_tools": source_tools,
            "fact_types": fact_types,
            "fact_ids": [x.get("fact_id") for x in supporting[:20] if x.get("fact_id")],
            "supporting_facts": supporting[:20],
            "disconfirming_facts": sorted(set(all_suppressions)),
            "suppression_reason": suppression,
            "claim_templates": _claim_templates(signals_set),
        })

    # SIFT_MASS_ENCRYPTION_BURST_V1 (#1): inject ONE synthetic validation-ready
    # candidate for the detected ransomware encryption burst so it RIDES the
    # gen-fix (deterministic emission). entity = the encrypting extension; the
    # affected-file fact_ids become per-file path claims downstream (multi-claim
    # -> clears the one-claim gate -> needs-review). Bounded to one candidate.
    if _enc_burst:
        candidates.append({
            "candidate_id": "",
            "candidate_type": "ransomware_mass_encryption",
            "score": 100,
            "entity_key": "encryption_burst:%s" % _enc_burst["ext"],
            "validation_ready": True,
            "signals": ["mass_encryption_burst"],
            "source_tools": ["extract_mft_timeline"],
            "fact_types": ["filesystem_timeline_fact"],
            "fact_ids": list(_enc_burst["fact_ids"]),
            "supporting_facts": [],
            "disconfirming_facts": [],
            "suppression_reason": "",
            "claim_templates": [],
        })
        logger.info(
            "MASS_ENCRYPTION_BURST_PROMOTE ext=.%s files=%d original_types=%d "
            "(uniform foreign extension across diverse data types; self-relative)",
            _enc_burst["ext"], _enc_burst["file_count"],
            len(_enc_burst["original_types"]),
        )

    # Sort axes (DESC): validation_ready FIRST (always kept), then high-value-detector
    # candidates (injection/rootkit/WMI/...) so the cap drops ordinary baseline noise
    # before a real high-value candidate, then score / breadth / type / entity.
    candidates.sort(
        key=lambda c: (
            bool(c["validation_ready"]),
            _is_high_value_candidate(c),
            int(c["score"]),
            len(c["fact_types"]),
            len(c["source_tools"]),
            c["candidate_type"],
            c["entity_key"],
        ),
        reverse=True,
    )
    for i, candidate in enumerate(candidates, 1):
        candidate["candidate_id"] = f"cand-{i:04d}"

    # LOSSLESS-CAP: validation-ready candidates sort first, so stretching the
    # cap to the ready count guarantees the cap only ever drops the NON-ready
    # tail (baseline noise) -- structurally, on any case size, instead of
    # relying on ready_count staying below the constant. Raising the constant
    # (1000 -> 1200) would not give this guarantee and would only admit more
    # thin single-source noise into the Inv2 prompt.
    _ready_count = sum(1 for c in candidates if c.get("validation_ready"))
    _effective_cap = max(max_candidates, _ready_count)
    if _effective_cap > max_candidates:
        logger.info(
            "LOSSLESS_CAP_STRETCH max_candidates=%d -> %d "
            "(validation-ready count exceeds the cap; none may be dropped)",
            max_candidates, _effective_cap)
    returned = candidates[:_effective_cap]

    # 31E-CANDIDATE-REVIEW-WORTHY-TELEMETRY: recall-ceiling telemetry +
    # separated corroborated-review candidate list. The ceiling reports
    # what could defensibly be claimed IF the validator widened; it
    # does NOT promote anything and does NOT change validation_ready.
    returned_validation_ready_count = sum(
        1 for c in returned if c.get("validation_ready")
    )
    ceiling = _candidate_recall_ceiling(
        candidates,
        returned_validation_ready=returned_validation_ready_count,
    )
    review_worthy_candidates = _select_review_worthy_candidates(candidates)
    logger.info(
        "CANDIDATE_READY_CEILING total=%d ready_full=%d ready_returned=%d "
        "review_worthy=%d max_defensible=%d",
        ceiling["total_candidates"],
        ceiling["validation_ready_total"],
        ceiling["returned_validation_ready"],
        ceiling["review_worthy_count"],
        ceiling["max_defensible"],
    )
    for _bucket_name, _bucket_count in sorted(
        ceiling["nonready_bucket_counts"].items()
    ):
        logger.info(
            'CANDIDATE_NONREADY_BUCKET bucket="%s" count=%d',
            _bucket_name, _bucket_count,
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "total_facts": len(facts),
        "total_groups": len(groups),
        "candidate_count": len(candidates),
        # Pre-cap reality: how many candidates EXISTED before the return cap, so
        # the operator sees how much was truncated (returned vs total).
        "total_candidate_count": int(ceiling["total_candidates"]),
        "returned_candidate_count": len(returned),
        "validation_ready_count": sum(1 for c in candidates if c.get("validation_ready")),
        "returned_validation_ready_count": returned_validation_ready_count,
        "candidate_type_counts": dict(Counter(c["candidate_type"] for c in candidates)),
        "candidates": returned,
        "validation_ready_ceiling": ceiling,
        "corroborated_review_candidates": review_worthy_candidates,
    }


def render_candidate_observations_for_prompt(payload: dict | None, *, top_n: int = 40) -> str:
    if not isinstance(payload, dict):
        return ""
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        return ""
    ready = [c for c in candidates if isinstance(c, dict) and c.get("validation_ready")]
    review_worthy = payload.get("corroborated_review_candidates") or []
    if not ready and not review_worthy:
        return ""

    lines: list[str] = []
    if ready:
        lines.extend([
            "### Deterministic Candidate Observations (ZEROFAKE triage hints)",
            "These candidates are generated from typed EvidenceDB facts. They are NOT findings and NOT proof by themselves.",
            "Use them to classify, merge, or split observations. Emit final findings only when claims can be validated against cited fact_ids/source tools.",
            "Do not invent IOCs, paths, users, hosts, malware names, or timestamps beyond candidate support.",
            "",
            "### Validation-ready candidate conversion rules",
            "Each listed validation-ready candidate is a concrete work item, not a vague hint.",
            "Create one finding per distinct validation-ready candidate unless another candidate has the same entity_key, candidate_type, and same core behavior.",
            "If 20 or more validation-ready candidates are listed, attempt at least 20 distinct validator-backed findings.",
            "Do NOT collapse unrelated candidates into one broad attack-chain narrative.",
            "For each candidate-derived finding, include the candidate_id and supporting fact_ids in raw_excerpt or description for traceability.",
            "Use the concrete claim_templates exactly when they are JSON validator claims, especially powershell_command ttp_tag claims.",
            "Never invent values to reach a count; skip only candidates that cannot support a validator-typed claim.",
            "",
        ])
        for c in ready[:top_n]:
            facts = ", ".join(str(x) for x in (c.get("fact_ids") or [])[:8])
            sources = ", ".join(str(x) for x in c.get("source_tools") or [])
            fact_types = ", ".join(str(x) for x in c.get("fact_types") or [])
            signals = ", ".join(str(x) for x in c.get("signals") or [])
            claims = " | ".join(str(x) for x in c.get("claim_templates") or [])
            lines.extend([
                f"- candidate_id={c.get('candidate_id')} [{c.get('candidate_type')}] score={c.get('score')} entity={c.get('entity_key')}",
                f"  sources={sources}; fact_types={fact_types}; signals={signals}",
                f"  fact_ids={facts}",
                f"  claim_templates={claims}",
            ])

    # 31E-CANDIDATE-REVIEW-WORTHY-TELEMETRY: separated review section.

    rendered_ready_ids = {
        str(c.get("candidate_id") or "")
        for c in ready[:top_n]
        if isinstance(c, dict)
    }
    reserve_candidates = _select_prompt_reserve_candidates(
        ready,
        rendered_ready_ids=rendered_ready_ids,
    )
    if reserve_candidates:
        lines.append("")
        lines.append(
            "### validation_ready_reserve_candidates "
            "(reportable, validation-ready, outside generic top-N)"
        )
        lines.append(
            "These candidates are already validation_ready. They are shown to "
            "prevent registry/RDP/suspicious-task source-family starvation. "
            "Treat them like validation_ready_candidates; if promoted, include "
            "candidate_id and fact_ids for traceability."
        )
        for c in reserve_candidates:
            lines.append(_render_candidate_prompt_line(c))

    # Inv2 receives these as triage context only -- corroborated by
    # >=2 source tools and >=2 fact types, score >=60, no suppression,
    # no context-only candidate_type -- but they are NOT validation-ready
    # and MUST NOT be presented as validated findings. Use them to
    # decide whether to allocate an investigation thread, never to emit
    # a claim that the validator has not already accepted.
    if review_worthy:
        if lines:
            lines.append("")
        lines.extend([
            "### corroborated_review_candidates (NOT validation-ready, NOT findings)",
            "These candidates are corroborated by multiple source tools and multiple fact types but have NOT passed validation gating.",
            "They are exposed here as recall-ceiling triage hints only.",
            "Do NOT cite them as findings. Do NOT include them in the validated-claim count.",
            "Use them only to decide whether to allocate a follow-up investigation thread.",
            "",
        ])
        for c in review_worthy[:top_n]:
            facts = ", ".join(str(x) for x in (c.get("fact_ids") or [])[:8])
            sources = ", ".join(str(x) for x in c.get("source_tools") or [])
            fact_types = ", ".join(str(x) for x in c.get("fact_types") or [])
            signals = ", ".join(str(x) for x in c.get("signals") or [])
            lines.extend([
                f"- candidate_id={c.get('candidate_id')} [{c.get('candidate_type')}] score={c.get('score')} entity={c.get('entity_key')}",
                f"  sources={sources}; fact_types={fact_types}; signals={signals}",
                f"  fact_ids={facts}",
            ])
    return "\n".join(lines)

# 31G-CANDIDATE-RESERVE-COVERAGE: deterministic post-Inv2 audit of
# reportable validation-ready reserve candidates. This does NOT promote
# candidates and does NOT change truth. It only prevents silent drops by
# freezing whether reserved candidates were traceably carried into final
# findings via candidate_id or fact_ids.
_RESERVE_COVERAGE_TOOLS = frozenset({
    "parse_registry_persistence",
    "parse_scheduled_tasks_disk",
    "parse_rdp_artifacts",
})
_RESERVE_COVERAGE_REPORTABLE_TYPES = frozenset({
    "high_risk_persistence",
    "admin_or_remote_management_persistence",
    "suspicious_file_or_process_execution",
})
_RESERVE_COVERAGE_SUSPICIOUS_TASK_SIGNALS = frozenset({
    "scheduled_task_points_to_staging_path",
    "scheduled_task_encoded_or_download",
})


def _reserve_coverage_tools(candidate: dict) -> set[str]:
    return {str(x) for x in (candidate.get("source_tools") or []) if x}


def _reserve_coverage_signals(candidate: dict) -> set[str]:
    return {str(x) for x in (candidate.get("signals") or []) if x}


def _reserve_coverage_is_hidden_only_task(candidate: dict) -> bool:
    tools = _reserve_coverage_tools(candidate)
    signals = _reserve_coverage_signals(candidate)
    return (
        "parse_scheduled_tasks_disk" in tools
        and "hidden_scheduled_task" in signals
        and not (signals & _RESERVE_COVERAGE_SUSPICIOUS_TASK_SIGNALS)
    )


def _is_candidate_reserve_coverage_candidate(candidate: dict) -> bool:
    if not isinstance(candidate, dict):
        return False
    if not candidate.get("validation_ready"):
        return False

    tools = _reserve_coverage_tools(candidate)
    if not (tools & _RESERVE_COVERAGE_TOOLS):
        return False

    if _reserve_coverage_is_hidden_only_task(candidate):
        return False

    ctype = str(candidate.get("candidate_type") or "")
    signals = _reserve_coverage_signals(candidate)
    return (
        ctype in _RESERVE_COVERAGE_REPORTABLE_TYPES
        or "rdp_target_reference" in signals
    )


def _reserve_coverage_blob(value) -> str:
    try:
        return json.dumps(value, default=str, ensure_ascii=False, sort_keys=True).lower()
    except Exception:
        return str(value).lower()


def _reserve_candidate_trace_tokens(candidate: dict) -> list[str]:
    tokens: list[str] = []
    cid = str(candidate.get("candidate_id") or "").strip()
    if cid:
        tokens.append(cid.lower())
    for fact_id in candidate.get("fact_ids") or []:
        fid = str(fact_id or "").strip()
        if fid:
            tokens.append(fid.lower())
    return tokens


def _reserve_finding_trace_hit(candidate: dict, finding: dict) -> bool:
    if not isinstance(finding, dict):
        return False
    blob = _reserve_coverage_blob(finding)
    return any(tok and tok in blob for tok in _reserve_candidate_trace_tokens(candidate))


def _compact_reserve_candidate(candidate: dict) -> dict:
    return {
        "candidate_id": candidate.get("candidate_id"),
        "candidate_type": candidate.get("candidate_type"),
        "score": candidate.get("score"),
        "entity_key": candidate.get("entity_key"),
        "source_tools": list(candidate.get("source_tools") or []),
        "fact_types": list(candidate.get("fact_types") or []),
        "signals": list(candidate.get("signals") or []),
        "fact_ids": list(candidate.get("fact_ids") or []),
        "claim_templates": list(candidate.get("claim_templates") or []),
    }


def build_candidate_reserve_coverage(
    candidate_payload: dict | None,
    findings_final: list | None,
) -> dict:
    """Return a deterministic coverage audit for reportable reserve candidates.

    The audit status is intentionally non-promotional:
      * covered_traceable: a final finding contains candidate_id or fact_id.
      * not_promoted_reserved_for_review: reserve candidate was shown to Inv2
        but no final finding carried its trace tokens.

    This gives Step 13A / report_truth a frozen explanation for every
    reportable reserve candidate, instead of silently losing high-value
    registry/RDP persistence observations.
    """
    candidates = []
    if isinstance(candidate_payload, dict):
        raw_candidates = candidate_payload.get("candidates") or []
        if isinstance(raw_candidates, list):
            candidates = [c for c in raw_candidates if isinstance(c, dict)]

    findings = [f for f in (findings_final or []) if isinstance(f, dict)]
    reserved = [c for c in candidates if _is_candidate_reserve_coverage_candidate(c)]

    rows: list[dict] = []
    covered_ids: list[str] = []
    not_promoted_ids: list[str] = []

    for candidate in reserved:
        cid = str(candidate.get("candidate_id") or "")
        matching_findings = []
        for finding in findings:
            if _reserve_finding_trace_hit(candidate, finding):
                matching_findings.append(str(finding.get("finding_id") or finding.get("id") or ""))

        matching_findings = sorted({x for x in matching_findings if x})
        row = _compact_reserve_candidate(candidate)
        row["matching_finding_ids"] = matching_findings

        if matching_findings:
            row["status"] = "covered_traceable"
            row["reason"] = "candidate_id_or_fact_id_present_in_final_finding"
            covered_ids.append(cid)
        else:
            row["status"] = "not_promoted_reserved_for_review"
            row["reason"] = "reserved_candidate_shown_to_inv2_but_no_final_finding_carried_candidate_id_or_fact_ids"
            not_promoted_ids.append(cid)

        rows.append(row)

    return {
        "schema_version": "candidate_reserve_coverage_v1",
        "gate": "PASS",
        "reserved_count": len(reserved),
        "covered_count": len(covered_ids),
        "not_promoted_count": len(not_promoted_ids),
        "reserved_candidate_ids": [str(c.get("candidate_id") or "") for c in reserved],
        "covered_candidate_ids": covered_ids,
        "not_promoted_candidate_ids": not_promoted_ids,
        "coverage": rows,
    }


__all__ = [
    "SCHEMA_VERSION",
    "build_candidate_observations",
    "build_candidate_reserve_coverage",
    "iter_typed_facts",
    "normalize_path",
    "render_candidate_observations_for_prompt",
]

# 31K-SRUM-CANDIDATE-READY: SRUM suspicious usage candidates are non-context and validation-ready.

# 31K-PS-DECODED-COMMAND-WIRE:
# decoded_string_fact is a typed, validator-checkable derived artifact. Score it
# only when precise decoded tags exist; do not let arbitrary decoded text create
# findings.
_31K_BASE_SCORE_FACT = _score_fact
_31K_BASE_CANDIDATE_TYPE = _candidate_type
_31K_BASE_CLAIM_TEMPLATES = _claim_templates
_31K_BASE_IS_STRONG_READY = _is_strong_ready


def _31k_decoded_tags_from_fact(fact: dict) -> set[str]:
    tags: set[str] = set()
    for key in ("tags", "keywords", "ttp_tags"):
        val = fact.get(key)
        if isinstance(val, list):
            tags.update(str(x) for x in val if x)
        elif val:
            tags.add(str(val))
    for item in (fact.get("artifact") or []):
        if isinstance(item, str) and "|" in item:
            tags.update(x for x in item.split("|") if x)
    return tags


def _31k_decoded_tags_from_signals(signals: set[str]) -> list[str]:
    out = []
    for sig in sorted(signals):
        if sig.startswith("decoded_ttp:"):
            tag = sig.split(":", 1)[1]
            if tag and tag not in out:
                out.append(tag)
    return out


def _score_fact(fact: dict) -> tuple[int, list[str], list[str]]:
    score, signals, suppressions = _31K_BASE_SCORE_FACT(fact)
    if fact.get("fact_type") != "decoded_string_fact":
        return score, signals, suppressions

    tags = _31k_decoded_tags_from_fact(fact)
    if "encoded_command" in tags:
        score += 90
        signals.append("decoded_encoded_command")
        signals.append("decoded_ttp:encoded_command")
    if "download_cradle" in tags:
        score += 85
        signals.append("decoded_download_cradle")
        signals.append("decoded_ttp:download_cradle")
    if "long_base64_blob" in tags:
        score += 60
        signals.append("decoded_long_base64_blob")
        signals.append("decoded_ttp:long_base64_blob")

    return int(score), sorted(set(signals)), sorted(set(suppressions))


def _candidate_type(signals: set[str]) -> str:
    if (
        {"decoded_encoded_command", "decoded_download_cradle", "decoded_long_base64_blob"} & signals
        or _31k_decoded_tags_from_signals(signals)
    ):
        return "encoded_powershell_or_download_cradle"
    return _31K_BASE_CANDIDATE_TYPE(signals)


def _claim_templates(signals: set[str]) -> list[str]:
    claims = list(_31K_BASE_CLAIM_TEMPLATES(signals))
    tags = _31k_decoded_tags_from_signals(signals)
    if tags:
        if claims == ["context: do not promote without a second corroborating typed fact family."]:
            claims = []
        if not any("encoded_execution:" in c for c in claims):
            claims.append("encoded_execution: validate decoded base64/string payload and source artifact from decoded_string_fact.")
        for tag in tags:
            claims.append('{"type": "decoded_string", "ttp_tag": "' + tag + '"}')
    return claims or ["context: do not promote without a second corroborating typed fact family."]


def _is_strong_ready(signals: set[str]) -> bool:
    if (
        {"decoded_encoded_command", "decoded_download_cradle"} & signals
        or _31k_decoded_tags_from_signals(signals)
    ):
        return True
    # parity: a service/persistence whose ImagePath resolves to a LOLBIN is as
    # strong as the lnk/jumplist/appcompat/srum LOLBIN signals already treated
    # as strong-ready (signal already excludes svchost/normal service images).
    if "registry_lolbin_imagepath" in signals:  # 31K-REGSVC-LOLBIN-STRONG
        return True
    return _31K_BASE_IS_STRONG_READY(signals)

