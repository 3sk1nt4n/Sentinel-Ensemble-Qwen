from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# SIFT_SSDT_HEALTH_SIGNAL_V1
#
# Universal policy:
# - SSDT is a health/integrity signal.
# - SSDT failure does not prove compromise.
# - SSDT failure also does not prove clean kernel.
# - Failed, timed out, unavailable, or zero-record SSDT cannot support findings.
# - Only successful data-producing SSDT output may be represented as health evidence.

_BAD_STATUS = {
    "error",
    "failed",
    "failure",
    "timeout",
    "unavailable",
    "not_available",
    "not_applicable",
    "ok_no_records",
    "no_records",
    "empty",
}

_PAGE_ERROR_RE = re.compile(
    r"(page error|unable to read a requested page|page fault|invalid page lookup)",
    re.I,
)


def _records(obj: Any) -> list[Any]:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in ("records", "data", "rows", "results"):
            val = obj.get(key)
            if isinstance(val, list):
                return val
    return []


def _status(obj: Any) -> str:
    if isinstance(obj, dict):
        for key in ("status", "result_status", "tool_status"):
            val = obj.get(key)
            if val is not None:
                return str(val).lower()
    return "ok"


def _text_blob(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str)[:200000]
    except Exception:
        return str(obj)[:200000]


def classify_ssdt_output(obj: Any) -> dict[str, Any]:
    """Classify vol_ssdt as a health signal without inferring clean/malicious."""
    recs = _records(obj)
    status = _status(obj)
    blob = _text_blob(obj)

    if status in _BAD_STATUS:
        return {
            "tool": "vol_ssdt",
            "health_kind": "kernel_integrity",
            "health_status": "unknown",
            "can_support_finding": False,
            "reason": status,
            "record_count": len(recs),
        }

    if _PAGE_ERROR_RE.search(blob):
        return {
            "tool": "vol_ssdt",
            "health_kind": "kernel_integrity",
            "health_status": "unknown",
            "can_support_finding": False,
            "reason": "volatility_page_read_error",
            "record_count": len(recs),
        }

    if len(recs) <= 0:
        return {
            "tool": "vol_ssdt",
            "health_kind": "kernel_integrity",
            "health_status": "unknown",
            "can_support_finding": False,
            "reason": "zero_records",
            "record_count": 0,
        }

    return {
        "tool": "vol_ssdt",
        "health_kind": "kernel_integrity",
        "health_status": "completed",
        "can_support_finding": True,
        "reason": "records_present",
        "record_count": len(recs),
    }


def load_ssdt_from_state(state_dir: str | Path) -> tuple[Any, Path | None]:
    state = Path(state_dir)

    candidates = [
        state / "tool_outputs" / "vol_ssdt.json",
        state / "tool_outputs" / "tool_vol_ssdt.json",
    ]

    for p in candidates:
        if p.exists():
            try:
                return json.loads(p.read_text(errors="ignore")), p
            except Exception:
                return {"status": "error", "error": "unreadable_json"}, p

    all_outputs = state / "all_outputs.json"
    if all_outputs.exists():
        try:
            data = json.loads(all_outputs.read_text(errors="ignore"))
            if isinstance(data, dict):
                if "vol_ssdt" in data:
                    return data["vol_ssdt"], all_outputs
                if "tool_vol_ssdt" in data:
                    return data["tool_vol_ssdt"], all_outputs
        except Exception:
            pass

    return {"status": "not_available", "records": []}, None


def strip_failed_ssdt_from_finding(finding: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Remove vol_ssdt from tool-hit fields and claims if SSDT cannot support findings."""
    changed = 0
    f = dict(finding)

    for field in ("source_tools", "claim_tools", "tools_hit", "hit_tools"):
        val = f.get(field)
        if isinstance(val, list):
            new = [x for x in val if str(x).replace("tool_", "") != "vol_ssdt"]
            if new != val:
                f[field] = new
                changed += len(val) - len(new)

    claims = f.get("claims")
    if isinstance(claims, list):
        new_claims = []
        for claim in claims:
            if isinstance(claim, dict):
                st = str(claim.get("source_tool") or claim.get("tool") or "").replace("tool_", "")
                if st == "vol_ssdt":
                    changed += 1
                    continue
            new_claims.append(claim)
        if new_claims != claims:
            f["claims"] = new_claims

    return f, changed
