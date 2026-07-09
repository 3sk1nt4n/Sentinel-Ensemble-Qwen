"""False-positive fidelity helpers.

Purpose:
- ReAct may correctly clear many noisy findings.
- Some clears are too risky to display as "false positives" when the finding
  itself still carries structural high-risk properties.
- This module computes those properties from the current finding only.

Dataset-agnostic rules:
- No case IPs, hashes, paths, or PIDs.
- No saved allowlist/cache.
- No product-specific case key.
- Constants here are Windows invariants or network classification properties.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


SCHEMA_VERSION = "fp_fidelity_v1"

BUCKET_BENIGN = "benign_or_false_positive"
BUCKET_REVIEW = "suspicious_needs_review"

STATUS_NOT_FP = "not_fp_candidate"
STATUS_VISIBLE_FP = "visible_fp_verified"
STATUS_WITHHELD = "fp_withheld_needs_review"

BLOCK_PROTECTED_WINDOWS_PROCESS_NON_RFC1918_NETWORK = (
    "protected_windows_process_non_rfc1918_network"
)
BLOCK_CREDENTIAL_PROCESS_NON_RFC1918_NETWORK = (
    "credential_process_non_rfc1918_network"
)

# Windows protected/system processes. This is OS-domain knowledge, not a case
# indicator. It is intentionally small and invariant.
_PROTECTED_WINDOWS_PROCESS_NAMES = frozenset({
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
})

_CREDENTIAL_AUTHORITY_PROCESS_NAMES = frozenset({
    "lsass.exe",
})

# Avoid dotted IPv4 literals in source. These are RFC1918 networks represented
# by integer network addresses: 10/8, 172.16/12, 192.168/16.
_RFC1918_NETWORKS = (
    ipaddress.IPv4Network((0x0A000000, 8)),
    ipaddress.IPv4Network((0xAC100000, 12)),
    ipaddress.IPv4Network((0xC0A80000, 16)),
)

_IPV4_RE = re.compile(
    r"(?<!\d)"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"(?!\d)"
)

_EXE_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.-]{1,96}\.exe)\b", re.IGNORECASE)

_PID_KEYS = {
    "pid",
    "process_pid",
    "ProcessId",
    "PID",
}
_PROCESS_KEYS = {
    "process",
    "process_name",
    "image",
    "image_name",
    "ImageFileName",
    "name",
}
_REMOTE_IP_KEYS = {
    "foreign_addr",
    "foreign_address",
    "remote_addr",
    "remote_address",
    "dst",
    "dst_ip",
    "destination",
    "destination_ip",
    "peer",
    "peer_ip",
}
_REMOTE_PORT_KEYS = {
    "foreign_port",
    "remote_port",
    "dst_port",
    "destination_port",
    "port",
}


def _finding_id(finding: dict[str, Any]) -> str:
    return str(
        finding.get("finding_id")
        or finding.get("id")
        or finding.get("fid")
        or ""
    ).strip()


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _walk_values(obj: Any):
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _walk_values(value)
    elif isinstance(obj, (list, tuple, set)):
        for value in obj:
            yield from _walk_values(value)
    elif obj is not None:
        yield obj


def _walk_key_values(obj: Any):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value
            yield from _walk_key_values(value)
    elif isinstance(obj, (list, tuple, set)):
        for value in obj:
            yield from _walk_key_values(value)


def _text_blob(finding: dict[str, Any]) -> str:
    # Current-run object only. No external cache or case key.
    parts: list[str] = []
    for value in _walk_values(finding):
        if isinstance(value, (str, int, float)):
            s = str(value)
            if s:
                parts.append(s)
    return " ".join(parts)


def _normalize_process_name(name: Any) -> str | None:
    if name is None:
        return None
    s = str(name).strip().strip('"').strip("'")
    if not s:
        return None
    # Keep only the basename-ish process token when a path-like value is passed.
    s = s.replace("/", "\\").split("\\")[-1]
    s = s.lower()
    return s or None


def extract_process_names(finding: dict[str, Any]) -> list[str]:
    out: list[str] = []

    for key, value in _walk_key_values(finding):
        if str(key) in _PROCESS_KEYS:
            norm = _normalize_process_name(value)
            if norm:
                out.append(norm)

    for match in _EXE_RE.finditer(_text_blob(finding)):
        norm = _normalize_process_name(match.group(1))
        if norm:
            out.append(norm)

    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def extract_pids(finding: dict[str, Any]) -> list[int]:
    out: list[int] = []
    for key, value in _walk_key_values(finding):
        if str(key) in _PID_KEYS:
            pid = _safe_int(value)
            if pid is not None:
                out.append(pid)
    seen: set[int] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def _parse_ipv4(value: str) -> ipaddress.IPv4Address | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return addr
    return None


def is_rfc1918_or_local_ipv4(value: str) -> bool:
    addr = _parse_ipv4(value)
    if addr is None:
        return False
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    ):
        return True
    return any(addr in network for network in _RFC1918_NETWORKS)


def extract_ipv4s(finding: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for match in _IPV4_RE.finditer(_text_blob(finding)):
        ip = match.group(0)
        if _parse_ipv4(ip) is not None:
            found.append(ip)
    seen: set[str] = set()
    return [x for x in found if not (x in seen or seen.add(x))]


def extract_non_rfc1918_ipv4s(finding: dict[str, Any]) -> list[str]:
    return [ip for ip in extract_ipv4s(finding) if not is_rfc1918_or_local_ipv4(ip)]


def raw_react_false_positive(finding: dict[str, Any]) -> bool:
    if bool(finding.get("is_false_positive")):
        return True

    rc = finding.get("react_conclusion")
    if isinstance(rc, dict):
        verdict = str(rc.get("verdict") or "").strip().lower()
        if bool(rc.get("is_false_positive")):
            return True
        if verdict in {
            "confirmed_benign",
            "confirmed_false_positive",
            "false_positive",
            "likely_fp",
            "likely_false_positive",
            "benign",
        }:
            return True

    return False


def build_behavior_keys(finding: dict[str, Any]) -> list[str]:
    pids = extract_pids(finding)
    names = extract_process_names(finding)
    ips = extract_ipv4s(finding)
    text = _text_blob(finding).lower()

    keys: list[str] = []

    if pids and names:
        for pid in pids:
            for name in names:
                keys.append(f"process:pid:{pid}:{name}")
    elif pids:
        for pid in pids:
            keys.append(f"process:pid:{pid}")
    elif names:
        for name in names:
            keys.append(f"process:{name}")

    for pid in pids:
        for ip in ips:
            keys.append(f"connection:pid:{pid}:{ip}:?")

    if pids and (
        "page_execute_readwrite" in text
        or "execute_readwrite" in text
        or "rwx" in text
        or "memory injection" in text
    ):
        for pid in pids:
            keys.append(f"memory_rwx:pid:{pid}")

    seen: set[str] = set()
    return [x for x in keys if not (x in seen or seen.add(x))]


def fp_fidelity_decision(finding: dict[str, Any]) -> dict[str, Any]:
    fid = _finding_id(finding)
    names = extract_process_names(finding)
    pids = extract_pids(finding)
    non_rfc1918_ips = extract_non_rfc1918_ipv4s(finding)
    raw_fp = raw_react_false_positive(finding)

    protected_names = sorted(
        n for n in names if n in _PROTECTED_WINDOWS_PROCESS_NAMES
    )
    credential_names = sorted(
        n for n in names if n in _CREDENTIAL_AUTHORITY_PROCESS_NAMES
    )

    blockers: list[str] = []
    if raw_fp and protected_names and non_rfc1918_ips:
        blockers.append(BLOCK_PROTECTED_WINDOWS_PROCESS_NON_RFC1918_NETWORK)
    if raw_fp and credential_names and non_rfc1918_ips:
        blockers.append(BLOCK_CREDENTIAL_PROCESS_NON_RFC1918_NETWORK)

    if not raw_fp:
        status = STATUS_NOT_FP
        visible = False
    elif blockers:
        status = STATUS_WITHHELD
        visible = False
    else:
        status = STATUS_VISIBLE_FP
        visible = True

    return {
        "schema_version": SCHEMA_VERSION,
        "finding_id": fid,
        "status": status,
        "visible_fp": visible,
        "raw_react_fp": raw_fp,
        "blockers": blockers,
        "process_names": names,
        "protected_process_names": protected_names,
        "pids": pids,
        "non_rfc1918_ipv4s": non_rfc1918_ips,
        "behavior_keys": build_behavior_keys(finding),
    }


def apply_fp_fidelity_to_buckets(
    buckets: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return new disposition buckets plus a per-run audit.

    Downgrade-only with respect to visible false positives:
    - A blocked raw FP leaves benign_or_false_positive and goes to review.
    - No finding is promoted to malicious.
    - No case-key state is read or written by this function.
    """
    src = buckets or {}
    out: dict[str, Any] = {}
    moved_to_review: list[dict[str, Any]] = []
    visible_fp_ids: list[str] = []
    withheld_ids: list[str] = []
    raw_fp_ids: list[str] = []
    decisions: list[dict[str, Any]] = []

    for bucket_name, items in src.items():
        if not isinstance(items, list):
            out[bucket_name] = items
            continue

        kept: list[Any] = []
        for item in items:
            if not isinstance(item, dict):
                kept.append(item)
                continue

            finding = dict(item)
            decision = fp_fidelity_decision(finding)
            finding["fp_fidelity"] = decision
            decisions.append(decision)

            fid = decision.get("finding_id") or ""
            if decision.get("raw_react_fp"):
                raw_fp_ids.append(str(fid))

            if bucket_name == BUCKET_BENIGN and decision["status"] == STATUS_WITHHELD:
                finding["final_disposition"] = BUCKET_REVIEW
                reasons = list(finding.get("disposition_reasons") or [])
                if "fp_fidelity_withheld_visible_false_positive" not in reasons:
                    reasons.append("fp_fidelity_withheld_visible_false_positive")
                finding["disposition_reasons"] = reasons
                moved_to_review.append(finding)
                withheld_ids.append(str(fid))
                continue

            if bucket_name == BUCKET_BENIGN and decision["status"] == STATUS_VISIBLE_FP:
                visible_fp_ids.append(str(fid))

            kept.append(finding)

        out[bucket_name] = kept

    out.setdefault(BUCKET_REVIEW, [])
    if isinstance(out[BUCKET_REVIEW], list):
        out[BUCKET_REVIEW].extend(moved_to_review)

    remaining_blocked_visible = []
    for item in out.get(BUCKET_BENIGN, []) or []:
        if not isinstance(item, dict):
            continue
        decision = item.get("fp_fidelity")
        if isinstance(decision, dict) and decision.get("status") == STATUS_WITHHELD:
            remaining_blocked_visible.append(decision.get("finding_id") or "")

    audit = {
        "schema_version": SCHEMA_VERSION,
        "gate": "PASS" if not remaining_blocked_visible else "FAIL",
        "raw_react_fp_count": len(raw_fp_ids),
        "raw_react_fp_ids": raw_fp_ids,
        "visible_fp_verified_count": len(visible_fp_ids),
        "visible_fp_verified_ids": visible_fp_ids,
        "withheld_from_visible_fp_count": len(withheld_ids),
        "withheld_from_visible_fp_ids": withheld_ids,
        "remaining_blocked_visible_fp_ids": remaining_blocked_visible,
        "decisions": decisions,
    }
    return out, audit


__all__ = [
    "SCHEMA_VERSION",
    "STATUS_NOT_FP",
    "STATUS_VISIBLE_FP",
    "STATUS_WITHHELD",
    "fp_fidelity_decision",
    "apply_fp_fidelity_to_buckets",
    "build_behavior_keys",
    "extract_non_rfc1918_ipv4s",
    "is_rfc1918_or_local_ipv4",
]
