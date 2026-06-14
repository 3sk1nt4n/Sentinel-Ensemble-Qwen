from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# SIFT_VALIDATION_FAMILY_REGISTRY_V2
#
# Dataset-agnostic registry.
#
# This file describes product schema semantics only:
#   tool name -> typed fact family -> validation role
#
# It must never contain case-specific PIDs, IPs, hashes, users, hostnames,
# dataset names, or expected malicious outcomes.

ROLE_FINDING_CAPABLE = "finding_capable"
ROLE_TRIGGERED_FINDING_CAPABLE = "triggered_finding_capable"
ROLE_CONTEXT_ONLY = "context_only"
ROLE_HEALTH_ONLY = "health_only"


@dataclass(frozen=True)
class ValidationFamily:
    family: str
    role: str
    producer_tools: tuple[str, ...]
    claim_types: tuple[str, ...]
    candidate_policy: str
    validator_policy: str


ALIASES = {
    "vol_svescan": "vol_svcscan",
    "tool_vol_svescan": "vol_svcscan",
    "tool_vol_svcscan": "vol_svcscan",
    "tool_decode_base64_strings": "decode_base64_strings",
    "tool_extract_network_iocs": "extract_network_iocs",
    "tool_parse_event_logs": "parse_event_logs",
    "tool_parse_scheduled_tasks_disk": "parse_scheduled_tasks_disk",
    "tool_parse_wmi_subscription": "parse_wmi_subscription",
    "tool_run_jlecmd": "run_jlecmd",
    "tool_run_lecmd": "run_lecmd",
    "tool_vol_cmdline": "vol_cmdline",
    "tool_vol_dlllist": "vol_dlllist",
    "tool_vol_filescan": "vol_filescan",
    "tool_vol_getsids": "vol_getsids",
    "tool_vol_handles": "vol_handles",
    "tool_vol_privileges": "vol_privileges",
    "tool_vol_reg_hivelist": "vol_reg_hivelist",
    "tool_vol_sessions": "vol_sessions",
    "tool_vol_ssdt": "vol_ssdt",
}


def canonical_tool_name(name: Any) -> str:
    raw = str(name or "").strip()
    if not raw:
        return ""
    raw = raw.removeprefix("tool_")
    return ALIASES.get(str(name or "").strip(), ALIASES.get(raw, raw))


FAMILIES: dict[str, ValidationFamily] = {
    "decoded_string_fact": ValidationFamily(
        family="decoded_string_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("decode_base64_strings",),
        claim_types=("decoded_string", "encoded_payload", "raw"),
        candidate_policy="candidate when decoded content contains suspicious command, credential, network, script, or payload indicators",
        validator_policy="claim must match decoded string fact from current-run tool output",
    ),
    "network_ioc_fact": ValidationFamily(
        family="network_ioc_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("extract_network_iocs",),
        claim_types=("network_ioc", "ip", "domain", "url", "connection"),
        candidate_policy="candidate when IOC is external, rare, suspicious, or corroborates process/network evidence",
        validator_policy="claim must match extracted IOC fact from current-run collected outputs",
    ),
    "event_log_fact": ValidationFamily(
        family="event_log_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("parse_event_logs",),
        claim_types=("event_log", "event", "log_entry"),
        candidate_policy="candidate when event ID/provider/message indicates logon, service, task, PowerShell, persistence, auth, or security-relevant behavior",
        validator_policy="claim must match event channel/provider/event_id/timestamp/message fields",
    ),
    "scheduled_task_fact": ValidationFamily(
        family="scheduled_task_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("parse_scheduled_tasks_disk",),
        claim_types=("scheduled_task", "task"),
        candidate_policy="candidate when task action/user/path/timing is suspicious or persistence-relevant",
        validator_policy="claim must match scheduled task XML-derived fact",
    ),
    "wmi_subscription_fact": ValidationFamily(
        family="wmi_subscription_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("parse_wmi_subscription",),
        claim_types=("wmi_subscription", "wmi_persistence", "wmi"),
        candidate_policy="candidate when filter/consumer/binding exists or command/action is suspicious",
        validator_policy="claim must match WMI filter, consumer, or binding fact",
    ),
    "jumplist_fact": ValidationFamily(
        family="jumplist_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("run_jlecmd",),
        claim_types=("jumplist", "execution_artifact"),
        candidate_policy="candidate when JumpList target indicates suspicious execution path, staging, LOLBin, or user activity",
        validator_policy="claim must match JumpList parsed target/application/user/timestamp fields",
    ),
    "lnk_execution_fact": ValidationFamily(
        family="lnk_execution_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("run_lecmd",),
        claim_types=("lnk", "shortcut", "execution_artifact"),
        candidate_policy="candidate when LNK target indicates suspicious path, removable media, staging, LOLBin, or user execution",
        validator_policy="claim must match LNK target/path/timestamp fields",
    ),
    "process_cmdline_fact": ValidationFamily(
        family="process_cmdline_fact",
        role=ROLE_TRIGGERED_FINDING_CAPABLE,
        producer_tools=("vol_cmdline",),
        claim_types=("cmdline", "process_cmdline", "process"),
        candidate_policy="candidate only for encoded commands, suspicious interpreters, LOLBins, download/execute chains, credentials, or abnormal paths",
        validator_policy="claim must match PID/process/cmdline fact",
    ),
    "dll_load_fact": ValidationFamily(
        family="dll_load_fact",
        role=ROLE_TRIGGERED_FINDING_CAPABLE,
        producer_tools=("vol_dlllist",),
        claim_types=("dll", "module", "loaded_module"),
        candidate_policy="context by default; candidate only for suspicious path, missing backing, user/temp module, unexpected module, or hidden/unlinked corroboration",
        validator_policy="claim must match loaded module fact and should not be malicious by path alone without trigger",
    ),
    "filesystem_listing_fact": ValidationFamily(
        family="filesystem_listing_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("vol_filescan",),
        claim_types=("path", "file_object", "filesystem_listing"),
        candidate_policy="candidate when file path/object is suspicious, deleted, temp/user staging, credential-related, or corroborates execution",
        validator_policy="claim must match current-run filesystem/file-object fact",
    ),
    "sid_fact": ValidationFamily(
        family="sid_fact",
        role=ROLE_CONTEXT_ONLY,
        producer_tools=("vol_getsids",),
        claim_types=("sid", "user_sid", "user_account"),
        candidate_policy="attribution/context by default; not standalone malicious",
        validator_policy="claim may support attribution, owner, or privilege context",
    ),
    "handle_fact": ValidationFamily(
        family="handle_fact",
        role=ROLE_TRIGGERED_FINDING_CAPABLE,
        producer_tools=("vol_handles",),
        claim_types=("handle", "object_handle"),
        candidate_policy="candidate only for sensitive object access such as LSASS, SAM/SECURITY/SYSTEM hives, raw disk, suspicious pipes, tokens, or cross-process evidence",
        validator_policy="claim must match PID/process/handle/object fact",
    ),
    "privilege_fact": ValidationFamily(
        family="privilege_fact",
        role=ROLE_TRIGGERED_FINDING_CAPABLE,
        producer_tools=("vol_privileges",),
        claim_types=("privilege", "token_privilege"),
        candidate_policy="context by default; candidate when unusual process has debug/TCB/backup/restore/impersonation privileges or corroborates suspicious behavior",
        validator_policy="claim must match PID/process/privilege state fact",
    ),
    "registry_hive_fact": ValidationFamily(
        family="registry_hive_fact",
        role=ROLE_CONTEXT_ONLY,
        producer_tools=("vol_reg_hivelist",),
        claim_types=("registry_hive", "hive"),
        candidate_policy="context/coverage by default; not standalone malicious",
        validator_policy="claim may support hive availability and registry parsing context",
    ),
    "session_fact": ValidationFamily(
        family="session_fact",
        role=ROLE_CONTEXT_ONLY,
        producer_tools=("vol_sessions",),
        claim_types=("session", "logon_session"),
        candidate_policy="session/user context by default; candidate only when joined with suspicious process/logon/network evidence",
        validator_policy="claim may support session/user attribution",
    ),
    "ssdt_integrity_fact": ValidationFamily(
        family="ssdt_integrity_fact",
        role=ROLE_HEALTH_ONLY,
        producer_tools=("vol_ssdt",),
        claim_types=("ssdt", "kernel_integrity"),
        candidate_policy="health/integrity baseline by default; candidate only when hooks or suspicious module ownership are detected",
        validator_policy="claim must match SSDT integrity/hook fact",
    ),
    "service_fact": ValidationFamily(
        family="service_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("vol_svcscan",),
        claim_types=("service", "windows_service"),
        candidate_policy="candidate when service path/name/start type/account/state is suspicious or corroborates persistence",
        validator_policy="claim must match service PID/name/path/state fact",
    ),
    "registry_persistence_fact": ValidationFamily(
        family="registry_persistence_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("parse_registry_persistence",),
        claim_types=("registry_persistence", "registry_value", "path"),
        candidate_policy="candidate when persistence key/value/action exists and is not known-benign context",
        validator_policy="claim must match registry persistence parser fact",
    ),
    "usb_device_fact": ValidationFamily(
        family="usb_device_fact",
        role=ROLE_TRIGGERED_FINDING_CAPABLE,
        producer_tools=("parse_usb_devices",),
        claim_types=("usb_device", "removable_media", "path"),
        candidate_policy="candidate when a removable device's connection/mount/user attribution corroborates suspicious data movement or anti-forensics; bare device presence is benign context, never a finding alone",
        validator_policy="claim must match a usb_device_fact (USBSTOR serial / mounted drive letter / per-user MountPoints2 volume)",
    ),
    "userassist_fact": ValidationFamily(
        family="userassist_fact",
        role=ROLE_TRIGGERED_FINDING_CAPABLE,
        producer_tools=("vol_userassist", "parse_userassist"),
        claim_types=("userassist", "execution", "path"),
        candidate_policy="candidate when a per-user UserAssist GUI-launch points to a suspicious/staging path or corroborates other execution evidence; benign program launches are context, never a finding alone",
        validator_policy="claim must match a userassist_fact (per-user UserAssist Count entry: program + run count + last-run)",
    ),
    "malfind_fact": ValidationFamily(
        family="malfind_fact",
        role=ROLE_TRIGGERED_FINDING_CAPABLE,
        producer_tools=("vol_malfind",),
        claim_types=("malfind", "memory_region", "injection"),
        candidate_policy="candidate when executable/private/RWX memory has suspicious bytes or corroborating process/network/module context",
        validator_policy="claim must match malfind region and must be reconciled against benign explainers",
    ),
    "connection_fact": ValidationFamily(
        family="connection_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("vol_netscan",),
        claim_types=("connection", "network_connection", "listener"),
        candidate_policy="candidate when connection/listener is anomalous, external, suspicious port, or corroborates process behavior",
        validator_policy="claim must match network endpoint/state/PID/process fact",
    ),
    "process_fact": ValidationFamily(
        family="process_fact",
        role=ROLE_FINDING_CAPABLE,
        producer_tools=("vol_pstree", "vol_psscan"),
        claim_types=("pid", "process", "process_identity", "process_ancestry"),
        candidate_policy="candidate when process identity, parentage, timing, path, or cross-view mismatch is suspicious",
        validator_policy="claim must match PID/process/parent/process-tree facts",
    ),
}


TOOL_EXPECTED_FAMILIES: dict[str, tuple[str, ...]] = {}
for family, spec in FAMILIES.items():
    for tool in spec.producer_tools:
        TOOL_EXPECTED_FAMILIES.setdefault(tool, tuple())
        TOOL_EXPECTED_FAMILIES[tool] = TOOL_EXPECTED_FAMILIES[tool] + (family,)


def get_validation_family_registry() -> dict[str, dict[str, Any]]:
    return {
        k: {
            "family": v.family,
            "role": v.role,
            "producer_tools": list(v.producer_tools),
            "claim_types": list(v.claim_types),
            "candidate_policy": v.candidate_policy,
            "validator_policy": v.validator_policy,
        }
        for k, v in FAMILIES.items()
    }


def expected_families_for_tool(tool: str) -> tuple[str, ...]:
    return TOOL_EXPECTED_FAMILIES.get(canonical_tool_name(tool), tuple())


def family_role(family: str) -> str:
    spec = FAMILIES.get(str(family or ""))
    return spec.role if spec else ""


def is_family_registered(family: str) -> bool:
    return str(family or "") in FAMILIES


def is_context_or_health_family(family: str) -> bool:
    return family_role(family) in {ROLE_CONTEXT_ONLY, ROLE_HEALTH_ONLY}


def is_finding_capable_family(family: str) -> bool:
    return family_role(family) in {
        ROLE_FINDING_CAPABLE,
        ROLE_TRIGGERED_FINDING_CAPABLE,
    }


def tool_role_summary(tool: str) -> dict[str, Any]:
    canonical = canonical_tool_name(tool)
    fams = expected_families_for_tool(canonical)
    roles = sorted({family_role(f) for f in fams if family_role(f)})
    return {
        "tool": canonical,
        "families": list(fams),
        "roles": roles,
        "finding_capable": any(is_finding_capable_family(f) for f in fams),
        "context_or_health_only": bool(fams) and all(is_context_or_health_family(f) for f in fams),
    }


# SIFT_VALIDATION_FAMILY_POWERSHELL_EVENT_FACT_V3
# Universal family contract:
# parse_event_logs can emit general event_log_fact records and derived
# powershell_command_fact records when PowerShell channels/events exist.
# This is tool/family taxonomy only; no dataset-specific PIDs, IPs, hashes, paths,
# or case labels are used.

SIFT_VALIDATION_FAMILY_EXTRA_EXPECTED_V3 = {
    "parse_event_logs": {"powershell_command_fact"},
}

try:
    _sift_vf_prior_expected_families_for_tool_v3 = expected_families_for_tool
except NameError:  # pragma: no cover
    _sift_vf_prior_expected_families_for_tool_v3 = None

try:
    _sift_vf_prior_get_validation_family_registry_v3 = get_validation_family_registry
except NameError:  # pragma: no cover
    _sift_vf_prior_get_validation_family_registry_v3 = None


def _sift_vf_add_expected_overlay_v3(tool_name, families):
    tool = str(tool_name or "").replace("tool_", "")
    out = set(families or [])
    out.update(SIFT_VALIDATION_FAMILY_EXTRA_EXPECTED_V3.get(tool, set()))
    return out


def expected_families_for_tool(tool_name):
    base = set()
    if _sift_vf_prior_expected_families_for_tool_v3 is not None:
        try:
            base.update(_sift_vf_prior_expected_families_for_tool_v3(tool_name) or [])
        except Exception:
            base.update([])
    return sorted(_sift_vf_add_expected_overlay_v3(tool_name, base))


def get_validation_family_registry():
    if _sift_vf_prior_get_validation_family_registry_v3 is not None:
        try:
            registry = _sift_vf_prior_get_validation_family_registry_v3()
        except Exception:
            registry = {}
    else:
        registry = {}

    try:
        if isinstance(registry, dict):
            entry = registry.setdefault("parse_event_logs", {})
            if isinstance(entry, dict):
                vals = set(entry.get("expected_families") or entry.get("families") or [])
                vals.update(SIFT_VALIDATION_FAMILY_EXTRA_EXPECTED_V3["parse_event_logs"])
                entry["expected_families"] = sorted(vals)
                entry.setdefault("roles", ["finding_capable"])
    except Exception:
        pass

    return registry


# SIFT_VALIDATION_FAMILY_REGISTRY_SHAPE_V3B
# Registry contract:
# - get_validation_family_registry() returns fact-family keys only.
# - Tool-to-family expectations belong in gate/tool maps, not as registry keys.
# - parse_event_logs may produce powershell_command_fact through PowerShell EVTX data.

try:
    _sift_vfr_original_get_validation_family_registry_v3b = get_validation_family_registry
except NameError:  # pragma: no cover
    _sift_vfr_original_get_validation_family_registry_v3b = None


def _sift_vfr_dict_spec_v3b(spec):
    if isinstance(spec, dict):
        return dict(spec)
    data = {}
    for name in ("family", "fact_type", "roles", "claim_types", "source_tools", "description"):
        if hasattr(spec, name):
            data[name] = getattr(spec, name)
    return data


def _sift_vfr_list_v3b(value, fallback):
    if value is None:
        return list(fallback)
    if isinstance(value, (list, tuple, set)):
        cleaned = [str(v) for v in value if str(v).strip()]
        return cleaned or list(fallback)
    text = str(value).strip()
    return [text] if text else list(fallback)


def _sift_vfr_powershell_command_spec_v3b(base_spec):
    spec = _sift_vfr_dict_spec_v3b(base_spec)
    spec["family"] = "powershell_command_fact"
    spec["fact_type"] = "powershell_command_fact"
    spec["description"] = (
        "PowerShell command evidence derived from Windows event log records "
        "parsed by parse_event_logs."
    )
    spec["roles"] = _sift_vfr_list_v3b(
        spec.get("roles"),
        ["finding_capable"],
    )
    if "finding_capable" not in spec["roles"]:
        spec["roles"].append("finding_capable")
    spec["claim_types"] = _sift_vfr_list_v3b(
        spec.get("claim_types"),
        ["powershell_command", "event_log", "raw"],
    )
    if "powershell_command" not in spec["claim_types"]:
        spec["claim_types"].append("powershell_command")
    spec["source_tools"] = _sift_vfr_list_v3b(
        spec.get("source_tools"),
        ["parse_event_logs"],
    )
    if "parse_event_logs" not in spec["source_tools"]:
        spec["source_tools"].append("parse_event_logs")
    return spec


def get_validation_family_registry(*args, **kwargs):
    base = {}
    if _sift_vfr_original_get_validation_family_registry_v3b is not None:
        base = _sift_vfr_original_get_validation_family_registry_v3b(*args, **kwargs) or {}

    reg = dict(base)

    # Remove accidental tool-name overlays. This keeps the registry pure.
    for key in list(reg):
        if not str(key).endswith("_fact"):
            reg.pop(key, None)

    event_spec = reg.get("event_log_fact", {})
    if "powershell_command_fact" not in reg:
        reg["powershell_command_fact"] = _sift_vfr_powershell_command_spec_v3b(event_spec)
    else:
        reg["powershell_command_fact"] = _sift_vfr_powershell_command_spec_v3b(
            reg.get("powershell_command_fact")
        )

    return reg


# SIFT_VALIDATION_FAMILY_REGISTRY_SHAPE_V3C
# Universal registry contract:
# - get_validation_family_registry() returns fact-family keys only.
# - every fact-family spec has non-empty roles and claim_types.
# - tool-to-family overlays must not leak as registry keys.
# - parse_event_logs may produce powershell_command_fact via PowerShell EVTX data.

try:
    _sift_vfr_original_get_validation_family_registry_v3c = get_validation_family_registry
except NameError:  # pragma: no cover
    _sift_vfr_original_get_validation_family_registry_v3c = None


_SIFT_VFR_DEFAULT_CLAIMS_V3C = {
    "decoded_string_fact": ["decoded_string", "encoded_payload", "raw"],
    "network_ioc_fact": ["network_ioc", "ip", "domain", "url", "raw"],
    "event_log_fact": ["event_log", "raw"],
    "powershell_command_fact": ["powershell_command", "event_log", "raw"],
    "scheduled_task_fact": ["scheduled_task", "task", "path", "raw"],
    "wmi_subscription_fact": ["wmi_subscription", "wmi_event_filter", "wmi_event_consumer", "raw"],
    "jumplist_fact": ["jumplist", "file_execution", "path", "raw"],
    "lnk_execution_fact": ["lnk_execution", "file_execution", "path", "raw"],
    "process_cmdline_fact": ["cmdline", "process_exists", "pid", "raw"],
    "dll_load_fact": ["dll_load", "process_module", "raw"],
    "filesystem_listing_fact": ["path", "file", "hash", "raw"],
    "sid_fact": ["sid", "user_account", "raw"],
    "handle_fact": ["handle", "file_handle", "registry_handle", "raw"],
    "privilege_fact": ["privilege", "raw"],
    "registry_hive_fact": ["registry_hive", "raw"],
    "session_fact": ["session", "raw"],
    "ssdt_integrity_fact": ["ssdt_integrity", "raw"],
    "service_fact": ["service", "service_config", "raw"],
    "registry_persistence_fact": ["registry_persistence", "registry_value", "raw"],
    "appcompatcache_execution_fact": ["appcompatcache", "file_execution", "path", "raw"],
    "file_execution_fact": ["file_execution", "path", "hash", "raw"],
    "prefetch_execution_fact": ["prefetch", "file_execution", "path", "raw"],
    "filesystem_timeline_fact": ["filesystem_timeline", "path", "file", "raw"],
    "rdp_artifact_fact": ["rdp_artifact", "event_log", "raw"],
    "string_artifact_fact": ["string_artifact", "decoded_string", "raw"],
    "process_fact": ["process_exists", "pid", "raw"],
    "process_relationship_fact": ["child_process", "parent_process", "raw"],
    "network_connection_fact": ["connection", "network_ioc", "raw"],
    "memory_injection_fact": ["memory_injection", "pid", "raw"],
}


_SIFT_VFR_DEFAULT_ROLES_V3C = {
    "sid_fact": ["context_only"],
    "registry_hive_fact": ["context_only"],
    "session_fact": ["context_only"],
    "ssdt_integrity_fact": ["health_only"],
}


def _sift_vfr_dict_spec_v3c(spec):
    if isinstance(spec, dict):
        return dict(spec)
    data = {}
    for name in (
        "family",
        "fact_type",
        "roles",
        "role",
        "validation_roles",
        "claim_types",
        "claim_type",
        "source_tools",
        "producer_tools",
        "candidate_policy",
        "description",
    ):
        if hasattr(spec, name):
            data[name] = getattr(spec, name)
    return data


def _sift_vfr_list_v3c(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _sift_vfr_first_nonempty_v3c(spec, keys):
    for key in keys:
        vals = _sift_vfr_list_v3c(spec.get(key))
        if vals:
            return vals
    return []


def _sift_vfr_default_roles_v3c(family, spec):
    if family in _SIFT_VFR_DEFAULT_ROLES_V3C:
        return list(_SIFT_VFR_DEFAULT_ROLES_V3C[family])
    if "health" in str(spec.get("candidate_policy", "")).lower():
        return ["health_only"]
    if spec.get("candidate_policy") or spec.get("claim_types") or spec.get("producer_tools") or spec.get("source_tools"):
        return ["finding_capable"]
    return ["context_only"]


def _sift_vfr_default_claims_v3c(family):
    return list(_SIFT_VFR_DEFAULT_CLAIMS_V3C.get(family, ["raw"]))


def _sift_vfr_normalize_family_spec_v3c(family, spec):
    spec = _sift_vfr_dict_spec_v3c(spec)

    spec["family"] = family
    spec["fact_type"] = spec.get("fact_type") or family

    roles = _sift_vfr_first_nonempty_v3c(spec, ("roles", "role", "validation_roles"))
    if not roles:
        roles = _sift_vfr_default_roles_v3c(family, spec)
    spec["roles"] = roles

    claim_types = _sift_vfr_first_nonempty_v3c(spec, ("claim_types", "claim_type"))
    if not claim_types:
        claim_types = _sift_vfr_default_claims_v3c(family)
    spec["claim_types"] = claim_types

    source_tools = _sift_vfr_first_nonempty_v3c(spec, ("source_tools", "producer_tools"))
    if source_tools:
        spec["source_tools"] = source_tools
        spec["producer_tools"] = _sift_vfr_first_nonempty_v3c(spec, ("producer_tools", "source_tools"))

    return spec


def get_validation_family_registry(*args, **kwargs):
    base = {}
    if _sift_vfr_original_get_validation_family_registry_v3c is not None:
        base = _sift_vfr_original_get_validation_family_registry_v3c(*args, **kwargs) or {}

    reg = {}
    for family, spec in dict(base).items():
        family = str(family)
        if not family.endswith("_fact"):
            continue
        reg[family] = _sift_vfr_normalize_family_spec_v3c(family, spec)

    if "powershell_command_fact" not in reg:
        reg["powershell_command_fact"] = _sift_vfr_normalize_family_spec_v3c(
            "powershell_command_fact",
            {
                "description": (
                    "PowerShell command evidence derived from Windows event log records "
                    "parsed by parse_event_logs."
                ),
                "roles": ["finding_capable"],
                "claim_types": ["powershell_command", "event_log", "raw"],
                "producer_tools": ["parse_event_logs"],
                "source_tools": ["parse_event_logs"],
            },
        )
    else:
        spec = reg["powershell_command_fact"]
        tools = set(_sift_vfr_list_v3c(spec.get("source_tools")) + _sift_vfr_list_v3c(spec.get("producer_tools")))
        tools.add("parse_event_logs")
        spec["source_tools"] = sorted(tools)
        spec["producer_tools"] = sorted(tools)
        claims = set(_sift_vfr_list_v3c(spec.get("claim_types")))
        claims.update(["powershell_command", "event_log", "raw"])
        spec["claim_types"] = sorted(claims)
        roles = set(_sift_vfr_list_v3c(spec.get("roles")))
        roles.add("finding_capable")
        spec["roles"] = sorted(roles)
        reg["powershell_command_fact"] = _sift_vfr_normalize_family_spec_v3c(
            "powershell_command_fact",
            spec,
        )

    return reg
# SIFT_VALIDATION_FAMILY_USER_ACCOUNT_FACT_V1
# User attribution facts are context/enrichment facts. They may be produced by
# process/session/handle-derived enrichment, but they are not standalone
# malicious-finding facts.
_SIFT_BASE_GET_VALIDATION_FAMILY_REGISTRY_USER_ACCOUNT_V1 = globals().get("get_validation_family_registry")

def get_validation_family_registry():
    base = _SIFT_BASE_GET_VALIDATION_FAMILY_REGISTRY_USER_ACCOUNT_V1
    reg = dict(base() if callable(base) else {})

    reg["user_account_fact"] = {
        "family": "user_account_fact",
        "producer_tools": [
            "vol_cmdline",
            "vol_handles",
            "vol_sessions",
            "vol_getsids",
            "owned_pids_join",
            "entity_reconcile",
        ],
        "roles": ["context_only", "attribution_supporting"],
        "role": "context_only",
        "claim_types": ["user_account", "user_context"],
        "required_fields_any": [
            ["user"],
            ["username"],
            ["account"],
            ["sid"],
            ["domain", "user"],
        ],
        "validation_policy": (
            "Context-only attribution fact used to explain process ownership or "
            "user association. It may enrich a finding but must not independently "
            "promote a finding to confirmed malicious."
        ),
    }

    # Shape normalization for all specs so existing registry tests stay stable.
    for family, spec in list(reg.items()):
        if not isinstance(spec, dict):
            reg.pop(family, None)
            continue
        spec.setdefault("family", family)
        roles = spec.get("roles")
        if not roles:
            role = spec.get("role") or "context_only"
            roles = [role] if isinstance(role, str) else ["context_only"]
            spec["roles"] = roles
        if "role" not in spec:
            spec["role"] = roles[0] if isinstance(roles, list) and roles else "context_only"
        if not spec.get("claim_types"):
            spec["claim_types"] = [family.replace("_fact", "")]
        if not spec.get("producer_tools"):
            spec["producer_tools"] = []

    return reg

# SIFT_VALIDATION_FAMILY_USER_ACCOUNT_FACT_V1B
# Context/attribution family with complete registry shape for all registry gates.
_SIFT_BASE_GET_VALIDATION_FAMILY_REGISTRY_USER_ACCOUNT_V1B = globals().get("get_validation_family_registry")

def get_validation_family_registry():
    base = _SIFT_BASE_GET_VALIDATION_FAMILY_REGISTRY_USER_ACCOUNT_V1B
    reg = dict(base() if callable(base) else {})

    reg["user_account_fact"] = {
        "family": "user_account_fact",
        "fact_type": "user_account_fact",
        "producer_tools": [
            "vol_cmdline",
            "vol_handles",
            "vol_sessions",
            "vol_getsids",
            "owned_pids_join",
            "entity_reconcile",
        ],
        "roles": ["context_only", "attribution_supporting"],
        "role": "context_only",
        "claim_types": ["user_account", "user_context"],
        "required_fields_any": [
            ["user"],
            ["username"],
            ["account"],
            ["sid"],
            ["domain", "user"],
        ],
        "candidate_policy": (
            "Context-only user attribution may enrich a validated finding when "
            "joined from process/session/SID/handle evidence. It must not be a "
            "standalone malicious finding."
        ),
        "validator_notes": (
            "Treat as attribution support only. Do not promote a finding solely "
            "because a user_account_fact exists."
        ),
        "validation_policy": (
            "Context-only attribution fact used to explain process ownership or "
            "user association. It may enrich a finding but must not independently "
            "promote a finding to confirmed malicious."
        ),
    }

    for family, spec in list(reg.items()):
        if not isinstance(spec, dict) or not str(family).endswith("_fact"):
            reg.pop(family, None)
            continue
        spec.setdefault("family", family)
        spec.setdefault("fact_type", family)
        roles = spec.get("roles")
        if not roles:
            role = spec.get("role") or "context_only"
            roles = [role] if isinstance(role, str) else ["context_only"]
            spec["roles"] = roles
        spec.setdefault("role", roles[0] if isinstance(roles, list) and roles else "context_only")
        spec.setdefault("claim_types", [family.replace("_fact", "")])
        spec.setdefault("producer_tools", ["unknown_context_source"])
        spec.setdefault(
            "candidate_policy",
            "Candidate only when the fact can be traced to a producer tool and validator-supported evidence.",
        )
        spec.setdefault(
            "validator_notes",
            "Registry default: validator must require traceable producer evidence before promotion.",
        )
        spec.setdefault("required_fields_any", [["raw"], ["artifact"], ["value"]])

    return reg

# SIFT_USER_ACCOUNT_FACT_COMPLETE_SPEC_V1D
# user_account_fact is attribution/context, not an independent malicious-finding family.
# It may be produced by joins/enrichment from memory facts and must be available to
# validation-family wiring gates without being treated as a standalone producer signal.

def _sift_user_account_fact_complete_spec_v1d(existing=None):
    spec = dict(existing or {})
    spec.update({
        "family": "user_account_fact",
        "fact_type": "user_account_fact",
        "role": spec.get("role") or "context_only",
        "roles": spec.get("roles") or ["context_only", "attribution"],
        "producer_tools": spec.get("producer_tools") or [
            "vol_cmdline",
            "vol_handles",
            "vol_sessions",
            "entity_reconcile",
        ],
        "claim_types": spec.get("claim_types") or ["user_account", "user_context"],
        "required_fields_any": spec.get("required_fields_any") or [
            ["user"],
            ["username"],
            ["account"],
            ["sid"],
            ["domain", "user"],
        ],
        "candidate_policy": spec.get("candidate_policy") or (
            "Context/attribution only: user account facts may enrich ownership, "
            "per-user narrative, and entity context, but must not independently "
            "create or promote malicious findings."
        ),
        "validator_policy": spec.get("validator_policy") or (
            "May validate user attribution/user_account context only when joined "
            "to another producer-backed fact. A user_account_fact alone is not "
            "sufficient evidence for a confirmed malicious finding."
        ),
        "finding_policy": spec.get("finding_policy") or (
            "Never standalone; attribution/enrichment only."
        ),
        "description": spec.get("description") or (
            "User/account attribution facts derived from process, handle, session, "
            "or enrichment joins."
        ),
    })
    return spec


try:
    _sift_original_get_validation_family_registry_v1d = get_validation_family_registry
except NameError:  # defensive for partial imports
    _sift_original_get_validation_family_registry_v1d = None


def get_validation_family_registry(*args, **kwargs):  # type: ignore[override]
    if _sift_original_get_validation_family_registry_v1d is None:
        reg = {}
    else:
        reg = dict(_sift_original_get_validation_family_registry_v1d(*args, **kwargs) or {})

    reg["user_account_fact"] = _sift_user_account_fact_complete_spec_v1d(
        reg.get("user_account_fact")
    )

    # Normalize any partial spec shape so older and newer registry tests agree.
    for family, spec in list(reg.items()):
        if not isinstance(spec, dict):
            continue
        spec.setdefault("family", family)
        spec.setdefault("fact_type", family)
        spec.setdefault("role", "context_only")
        spec.setdefault("roles", [spec.get("role") or "context_only"])
        spec.setdefault("producer_tools", [])
        spec.setdefault("claim_types", [])
        spec.setdefault("required_fields_any", [])
        spec.setdefault("candidate_policy", "No standalone candidate policy declared.")
        spec.setdefault("validator_policy", "Validated by family-specific typed validator policy.")
        reg[family] = spec

    return reg


# SIFT_ACTUAL_EVIDENCEDB_FACT_FAMILIES_V1F
# Actual EvidenceDB fact-family compatibility:
# - Volatility malfind compiles to memory_injection_fact.
# - Volatility netscan compiles to network_connection_fact.
# - pstree/psscan compile both process_fact and process_relationship_fact.
# These are first-class families, not unregistered extras.

def _sift_v1f_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v]
    if isinstance(value, tuple):
        return [v for v in value if v]
    if isinstance(value, set):
        return sorted(v for v in value if v)
    return [value]


def _sift_v1f_complete_spec(
    *,
    family,
    producer_tools,
    role,
    roles,
    claim_types,
    required_fields_any,
    candidate_policy,
    validator_policy,
):
    return {
        "family": family,
        "fact_type": family,
        "role": role,
        "roles": _sift_v1f_list(roles),
        "producer_tools": _sift_v1f_list(producer_tools),
        "claim_types": _sift_v1f_list(claim_types),
        "required_fields_any": required_fields_any,
        "candidate_policy": candidate_policy,
        "validator_policy": validator_policy,
    }


def _sift_v1f_apply_actual_evidencedb_families(reg):
    reg = dict(reg or {})

    reg["memory_injection_fact"] = _sift_v1f_complete_spec(
        family="memory_injection_fact",
        producer_tools=["vol_malfind", "vol_ldrmodules"],
        role="triggered_finding_capable",
        roles=["triggered_finding_capable"],
        claim_types=[
            "memory_injection",
            "malfind_region",
            "process_exists",
            "pid",
            "raw",
        ],
        required_fields_any=[
            ["pid"],
            ["process_id"],
            ["process", "address"],
            ["image", "protection"],
        ],
        candidate_policy=(
            "Candidate when malfind reports executable or writable/executable "
            "private regions, suspicious VADs, or injection-like memory regions."
        ),
        validator_policy=(
            "Claim must match a memory_injection_fact produced by vol_malfind; "
            "benign explainers may route the finding to review/FP but may not erase the fact."
        ),
    )

    reg["network_connection_fact"] = _sift_v1f_complete_spec(
        family="network_connection_fact",
        producer_tools=["vol_netscan"],
        role="finding_capable",
        roles=["finding_capable"],
        claim_types=[
            "connection",
            "network_connection",
            "network_ioc",
            "pid",
            "process_exists",
            "raw",
        ],
        required_fields_any=[
            ["pid", "local_addr", "foreign_addr"],
            ["pid", "remote_ip"],
            ["process", "foreign_addr"],
            ["owner", "foreign_addr"],
        ],
        candidate_policy=(
            "Candidate when network endpoints, listening services, or external "
            "connections are suspicious after process and destination context."
        ),
        validator_policy=(
            "Claim must match a network_connection_fact from vol_netscan by PID/process "
            "and endpoint fields. Endpoint existence alone is not proof of exfiltration."
        ),
    )

    reg["process_relationship_fact"] = _sift_v1f_complete_spec(
        family="process_relationship_fact",
        producer_tools=["vol_pstree", "vol_psscan"],
        role="finding_capable",
        roles=["finding_capable", "context_only"],
        claim_types=[
            "child_process",
            "parent_process",
            "process_tree",
            "process_relationship",
            "process_exists",
            "pid",
            "raw",
        ],
        required_fields_any=[
            ["pid", "ppid"],
            ["child_pid", "parent_pid"],
            ["process", "parent"],
            ["image", "parent_image"],
        ],
        candidate_policy=(
            "Candidate when process ancestry, parent/child relationships, or process "
            "visibility patterns violate expected OS process relationships."
        ),
        validator_policy=(
            "Claim must match process relationship facts from pstree/psscan; "
            "relationship anomalies require corroboration before confirmed-malicious routing."
        ),
    )

    # Keep user_account_fact fully shaped if previous patches only added a partial spec.
    ua = dict(reg.get("user_account_fact") or {})
    if ua:
        ua.setdefault("family", "user_account_fact")
        ua.setdefault("fact_type", "user_account_fact")
        ua.setdefault("role", "context_only")
        ua.setdefault("roles", ["context_only", "attribution_supporting"])
        ua.setdefault("producer_tools", [
            "vol_cmdline",
            "vol_handles",
            "vol_getsids",
            "vol_sessions",
            "owned_pids_join",
            "entity_reconcile",
        ])
        ua.setdefault("claim_types", ["user_account", "user_context", "sid", "owner"])
        ua.setdefault("required_fields_any", [
            ["user"],
            ["username"],
            ["account"],
            ["sid"],
            ["domain", "user"],
        ])
        ua.setdefault(
            "candidate_policy",
            "Attribution/context only; may explain ownership, user session, or SID context.",
        )
        ua.setdefault(
            "validator_policy",
            "May support attribution and ownership context but cannot independently establish maliciousness.",
        )
        reg["user_account_fact"] = ua

    return reg


try:
    _SIFT_V1F_PREV_GET_VALIDATION_FAMILY_REGISTRY
except NameError:
    _SIFT_V1F_PREV_GET_VALIDATION_FAMILY_REGISTRY = get_validation_family_registry


def get_validation_family_registry():
    return _sift_v1f_apply_actual_evidencedb_families(
        _SIFT_V1F_PREV_GET_VALIDATION_FAMILY_REGISTRY()
    )

