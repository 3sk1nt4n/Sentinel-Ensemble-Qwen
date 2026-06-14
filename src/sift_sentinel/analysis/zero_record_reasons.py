"""Zero-record reason auditing.

Dataset-agnostic contract:
- A selected tool may return zero records.
- Zero records are acceptable only when the run can explain why.
- Missing output envelopes are hard failures.
- Successful empty tool outputs are explicit `ok_no_records`, not silent zeros.
- No oracle labels, no case-specific literals, no IOCs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


_RECORD_KEYS = (
    "records",
    "output",
    "entries",
    "events",
    "rows",
    "data",
    "results",
)


def normalize_tool_name(name: Any) -> str:
    raw = "" if name is None else str(name).strip()
    if raw.startswith("tool_"):
        raw = raw[5:]
    return raw


def _is_envelope_like(value: Any) -> bool:
    return isinstance(value, (dict, list, tuple))


def _extract_records(envelope: Any) -> list:
    if envelope is None:
        return []
    if isinstance(envelope, list):
        return envelope
    if isinstance(envelope, tuple):
        return list(envelope)
    if not isinstance(envelope, dict):
        return []

    for key in _RECORD_KEYS:
        value = envelope.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)

    # Some tool wrappers return a single record-like dict without records/output.
    if envelope and not any(k in envelope for k in (
        "record_count",
        "status",
        "reason",
        "error",
        "failure_mode",
        "kind",
        "tool_name",
    )):
        return [envelope]

    return []


def _record_count(envelope: Any) -> int:
    if envelope is None:
        return 0
    if isinstance(envelope, (list, tuple)):
        return len(envelope)
    if isinstance(envelope, dict):
        for key in (
            "record_count",
            "records_count",
            "count",
            "source_record_count",
            "input_record_count",
        ):
            if key in envelope:
                try:
                    return int(envelope.get(key) or 0)
                except Exception:
                    pass
        return len(_extract_records(envelope))
    return 0


def _status_and_reason(envelope: Any) -> tuple[str, str]:
    if envelope is None:
        return (
            "missing_output_envelope",
            "selected tool has no tool_outputs envelope",
        )

    if isinstance(envelope, dict):
        status = str(
            envelope.get("status")
            or envelope.get("kind")
            or envelope.get("outcome")
            or envelope.get("disposition")
            or ""
        ).strip()

        reason = str(
            envelope.get("reason")
            or envelope.get("failure_mode")
            or envelope.get("error")
            or envelope.get("message")
            or ""
        ).strip()

        if reason:
            return (status or "explained_zero", reason)

        if status.lower() in {
            "not_applicable",
            "skipped",
            "suppressed",
            "no_records",
            "empty",
        }:
            return (status, status)

        if status.lower() in {"error", "failed", "failure"}:
            return (status, "tool reported failure without detailed reason")

        return (
            "ok_no_records",
            "tool completed successfully and returned zero records",
        )

    # List/tuple envelope with len == 0 is a real successful empty output.
    return (
        "ok_no_records",
        "tool completed successfully and returned zero records",
    )


def normalize_tool_output_mapping(tool_outputs: Any) -> dict[str, Any]:
    """Normalize heterogeneous tool-output shapes into {tool_name: envelope}."""
    out: dict[str, Any] = {}

    if tool_outputs is None:
        return out

    if isinstance(tool_outputs, dict):
        # Nested common shapes.
        for nested_key in ("tool_outputs", "raw_outputs", "outputs", "results"):
            nested = tool_outputs.get(nested_key)
            if isinstance(nested, dict):
                out.update(normalize_tool_output_mapping(nested))

        # Direct keyed mapping.
        for key, value in tool_outputs.items():
            nkey = normalize_tool_name(key)

            # Avoid treating metadata wrapper keys as tool names.
            if nkey in {
                "tool_outputs",
                "raw_outputs",
                "outputs",
                "results",
                "summary",
                "metadata",
                "coverage",
            }:
                continue

            if _is_envelope_like(value):
                out[nkey] = value

        # Single envelope with tool_name/tool.
        single_tool = (
            tool_outputs.get("tool_name")
            or tool_outputs.get("tool")
            or tool_outputs.get("name")
        )
        if single_tool:
            out[normalize_tool_name(single_tool)] = tool_outputs

        return out

    if isinstance(tool_outputs, (list, tuple)):
        for item in tool_outputs:
            if isinstance(item, dict):
                tool = item.get("tool_name") or item.get("tool") or item.get("name")
                if tool:
                    out[normalize_tool_name(tool)] = item
        return out

    return out


def _load_state_tool_outputs(state_dir: str | Path | None) -> dict[str, Any]:
    if not state_dir:
        return {}

    root = Path(state_dir)
    tool_dir = root / "tool_outputs"
    if not tool_dir.is_dir():
        return {}

    out: dict[str, Any] = {}
    for path in sorted(tool_dir.glob("*.json")):
        try:
            out[normalize_tool_name(path.stem)] = json.loads(
                path.read_text(errors="replace")
            )
        except Exception as exc:
            out[normalize_tool_name(path.stem)] = {
                "tool_name": path.stem,
                "record_count": 0,
                "status": "error",
                "reason": f"could not read tool output json: {exc!r}",
            }
    return out


def _mapping_score(selected: list[str], mapping: Mapping[str, Any]) -> tuple[int, int, int]:
    selected_set = {normalize_tool_name(t) for t in selected}
    present = 0
    envelope_like = 0
    positive_records = 0

    for tool in selected_set:
        if tool in mapping:
            present += 1
            value = mapping[tool]
            if _is_envelope_like(value):
                envelope_like += 1
            if _record_count(value) > 0:
                positive_records += 1

    return envelope_like, present, positive_records


def choose_tool_outputs_for_zero_audit(
    selected_tools: list[str] | tuple[str, ...],
    namespace: Mapping[str, Any] | None = None,
    state_dir: str | Path | None = None,
    explicit_outputs: Any = None,
) -> dict[str, Any]:
    """Choose the most likely current-run tool-output mapping.

    The live bug this guards against: passing the wrong object causes every
    selected tool to look like a missing output envelope. We prefer mappings
    that contain many selected tool names with envelope-like values.
    """
    selected = [normalize_tool_name(t) for t in selected_tools or []]
    candidates: list[tuple[str, dict[str, Any]]] = []

    if explicit_outputs is not None:
        candidates.append(("explicit", normalize_tool_output_mapping(explicit_outputs)))

    ns = namespace or {}
    preferred_names = (
        "raw_outputs",
        "tool_outputs",
        "all_outputs",
        "collected_outputs",
        "results_by_tool",
        "tool_results",
        "outputs",
        "results",
    )

    for name in preferred_names:
        value = ns.get(name)
        if value is not None:
            candidates.append((f"namespace:{name}", normalize_tool_output_mapping(value)))

    # Fallback: scan namespace for any dict with selected tool keys.
    for name, value in list(ns.items()):
        if not isinstance(value, dict):
            continue
        if name.startswith("__"):
            continue
        mapping = normalize_tool_output_mapping(value)
        if mapping:
            candidates.append((f"namespace_scan:{name}", mapping))

    state_mapping = _load_state_tool_outputs(state_dir)
    if state_mapping:
        candidates.append(("state_dir", state_mapping))

    best_name = "empty"
    best_mapping: dict[str, Any] = {}
    best_score = (-1, -1, -1)

    for name, mapping in candidates:
        score = _mapping_score(selected, mapping)
        if score > best_score:
            best_name = name
            best_mapping = mapping
            best_score = score

    # Attach non-tool metadata under a private key; audit ignores private keys.
    best_mapping = dict(best_mapping)
    best_mapping["_zero_record_audit_source"] = {
        "source": best_name,
        "score": list(best_score),
        "selected_count": len(selected),
    }
    return best_mapping


def audit_zero_record_reasons(
    selected_tools: list[str] | tuple[str, ...],
    tool_outputs: Any = None,
    state_dir: str | Path | None = None,
) -> dict[str, Any]:
    selected = [normalize_tool_name(t) for t in selected_tools or []]
    mapping = normalize_tool_output_mapping(tool_outputs)

    if not mapping and state_dir:
        mapping = _load_state_tool_outputs(state_dir)

    meta = {}
    if isinstance(tool_outputs, dict):
        meta = dict(tool_outputs.get("_zero_record_audit_source") or {})

    zero_rows = []
    missing_rows = []

    for tool in selected:
        if tool.startswith("_"):
            continue

        envelope = mapping.get(tool)

        # Also support selected `x` mapping key `tool_x`.
        if envelope is None:
            envelope = mapping.get(f"tool_{tool}")

        if envelope is None:
            row = {
                "tool": tool,
                "record_count": 0,
                "status": "missing_output_envelope",
                "reason": "selected tool has no tool_outputs envelope",
            }
            zero_rows.append(row)
            missing_rows.append(row)
            continue

        rc = _record_count(envelope)
        if rc != 0:
            continue

        status, reason = _status_and_reason(envelope)
        row = {
            "tool": tool,
            "record_count": 0,
            "status": status,
            "reason": reason,
        }
        zero_rows.append(row)

        if status in {"missing_output_envelope", "missing_reason"} or not reason:
            missing_rows.append(row)

    return {
        "schema_version": 2,
        "selected_count": len(selected),
        "output_source": meta,
        "zero_record_tools": zero_rows,
        "missing_reason_tools": missing_rows,
        "gate": "PASS" if not missing_rows else "FAIL",
    }

# ── Public zero-record audit API ───────────────────────────────────────
# Dataset-agnostic: audits current run result envelopes only.
# No registry namespace scans, no oracle labels, no case literals.

def _zr_norm_tool_name(name):
    s = str(name or "").strip()
    return s[5:] if s.startswith("tool_") else s


def _zr_lower(value):
    return str(value or "").strip().lower()


def _zr_first_text(mapping, keys):
    if not isinstance(mapping, dict):
        return ""
    for key in keys:
        value = mapping.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _zr_sequence_value(envelope):
    if isinstance(envelope, list):
        return envelope
    if not isinstance(envelope, dict):
        return None
    for key in ("records", "output", "data", "rows", "results", "matches"):
        value = envelope.get(key)
        if isinstance(value, list):
            return value
    return None


def _zr_record_count(envelope):
    if isinstance(envelope, list):
        return len(envelope)
    if not isinstance(envelope, dict):
        return 0

    for key in ("record_count", "count", "total_records", "returned_count"):
        value = envelope.get(key)
        try:
            if value is not None and str(value).strip() != "":
                return int(value)
        except Exception:
            pass

    seq = _zr_sequence_value(envelope)
    if seq is not None:
        return len(seq)

    return 0


def _zr_has_success_empty_shape(envelope):
    if isinstance(envelope, list):
        return True
    if not isinstance(envelope, dict):
        return False

    if _zr_sequence_value(envelope) is not None:
        return True

    status = _zr_lower(envelope.get("status"))
    kind = _zr_lower(envelope.get("kind"))
    return status in {"ok", "success", "completed"} or kind in {"ok", "success", "completed"}


def _zr_zero_row(tool_name, envelope):
    tool = _zr_norm_tool_name(tool_name)

    if envelope is None:
        return {
            "tool": tool,
            "record_count": 0,
            "status": "missing_output_envelope",
            "reason": "selected tool has no current-run output envelope",
        }

    record_count = _zr_record_count(envelope)
    if record_count != 0:
        return None

    if not isinstance(envelope, dict):
        return {
            "tool": tool,
            "record_count": 0,
            "status": "ok_no_records",
            "reason": "tool completed successfully and returned zero records",
        }

    status = _zr_lower(envelope.get("status"))
    kind = _zr_lower(envelope.get("kind"))
    failure_mode = _zr_lower(envelope.get("failure_mode"))
    reason = _zr_first_text(
        envelope,
        ("reason", "not_applicable_reason", "failure_reason", "error", "message"),
    )

    if status == "not_applicable" or kind == "not_applicable" or failure_mode == "not_applicable":
        if reason:
            return {
                "tool": tool,
                "record_count": 0,
                "status": "not_applicable",
                "reason": reason,
            }
        return {
            "tool": tool,
            "record_count": 0,
            "status": "missing_reason",
            "reason": "not_applicable zero records without explicit reason",
        }

    if status in {"error", "failed", "failure", "timeout"} or envelope.get("error"):
        if reason:
            return {
                "tool": tool,
                "record_count": 0,
                "status": status or "error",
                "reason": reason,
            }
        return {
            "tool": tool,
            "record_count": 0,
            "status": "missing_reason",
            "reason": "error zero records without explicit reason",
        }

    if reason:
        return {
            "tool": tool,
            "record_count": 0,
            "status": status or "explained_zero",
            "reason": reason,
        }

    if _zr_has_success_empty_shape(envelope):
        return {
            "tool": tool,
            "record_count": 0,
            "status": "ok_no_records",
            "reason": "tool completed successfully and returned zero records",
        }

    return {
        "tool": tool,
        "record_count": 0,
        "status": "missing_reason",
        "reason": "zero records without explicit reason",
    }


def build_zero_record_audit(selected_tools=None, tool_outputs=None, disk_mount=None, env=None, **kwargs):
    """Build a zero-record audit from current-run tool output envelopes.

    Args are intentionally flexible for compatibility with prior callers:
    selected_tools/list, tool_outputs/dict, or keyword aliases such as
    outputs/all_outputs. disk_mount/env are accepted for API stability.
    """

    if selected_tools is None:
        selected_tools = (
            kwargs.get("selected_tools")
            or kwargs.get("selected")
            or kwargs.get("tools")
            or []
        )

    if tool_outputs is None:
        tool_outputs = (
            kwargs.get("tool_outputs")
            or kwargs.get("outputs")
            or kwargs.get("all_outputs")
            or {}
        )

    if not isinstance(tool_outputs, dict):
        tool_outputs = {}

    outputs_by_norm = {
        _zr_norm_tool_name(name): envelope
        for name, envelope in tool_outputs.items()
    }

    selected_norm = [_zr_norm_tool_name(t) for t in (selected_tools or [])]
    if not selected_norm:
        selected_norm = list(outputs_by_norm.keys())

    zero_rows = []
    missing_rows = []

    seen = set()
    for tool in selected_norm:
        if not tool or tool in seen:
            continue
        seen.add(tool)

        envelope = outputs_by_norm.get(tool)
        row = _zr_zero_row(tool, envelope)
        if row is None:
            continue

        zero_rows.append(row)
        if row.get("status") in {"missing_reason", "missing_output_envelope"}:
            missing_rows.append(row)

    return {
        "schema_version": 2,
        "selected_count": len(selected_norm),
        "output_source": {
            "source": "all_outputs",
            "selected_count": len(selected_norm),
            "output_count": len(tool_outputs),
        },
        "zero_record_tools": zero_rows,
        "missing_reason_tools": missing_rows,
        "gate": "PASS" if not missing_rows else "FAIL",
    }

# ── Legacy public compatibility API ───────────────────────────────────
# Dataset-agnostic: classifies one current-run zero-record envelope.
# This helper intentionally does not inspect tool registry / namespace.
# It is kept for tests and callers that ask "why did this selected tool
# produce zero records?"

def _zr_compat_envelope_reason(envelope):
    if not isinstance(envelope, Mapping):
        return "", ""

    status = str(
        envelope.get("status")
        or envelope.get("outcome")
        or envelope.get("kind")
        or ""
    ).strip()

    for key in ("reason", "error", "message", "failure_mode"):
        value = envelope.get(key)
        if value:
            return status, str(value)

    # A non-success explicit status is itself a usable reason.
    if status and status.lower() not in {
        "ok", "success", "complete", "completed", "done"
    }:
        return status, status

    return status, ""


def _zr_compat_has_empty_success_shape(envelope):
    if not isinstance(envelope, Mapping):
        return False

    status = str(
        envelope.get("status")
        or envelope.get("outcome")
        or envelope.get("kind")
        or ""
    ).strip().lower()

    if status and status not in {"ok", "success", "complete", "completed", "done"}:
        return False

    for key in ("records", "output", "data", "rows", "items"):
        if key in envelope and isinstance(envelope.get(key), list) and not envelope.get(key):
            return True

    return False


def infer_zero_record_reason(
    tool_name,
    envelope,
    *,
    disk_mount=None,
    tool_outputs=None,
    env=None,
):
    """Return status/reason for one selected tool envelope.

    Public compatibility contract. Status is one of:
      - produced_records
      - not_applicable
      - empty_valid
      - error
      - missing_reason

    The function is intentionally conservative: a bare {"record_count": 0}
    envelope without an explicit reason is not silently accepted.
    """
    tool = _zr_norm_tool_name(tool_name)
    env = env or {}

    count = _zr_record_count(envelope)
    if count > 0:
        return {"status": "produced_records", "reason": "record_count=%d" % count}

    status, reason = _zr_compat_envelope_reason(envelope)

    if reason:
        lowered = (str(status) + " " + str(reason)).lower()
        if any(tok in lowered for tok in ("error", "fail", "exception", "timeout")):
            return {"status": "error", "reason": reason}
        return {"status": "not_applicable", "reason": reason}

    mount = Path(disk_mount) if disk_mount else None

    if tool == "parse_prefetch":
        if mount and not (mount / "Windows" / "Prefetch").is_dir():
            return {
                "status": "not_applicable",
                "reason": "Windows/Prefetch directory absent on mounted disk",
            }

    if tool == "run_srumecmd":
        if mount and not (
            mount / "Windows" / "System32" / "sru" / "SRUDB.dat"
        ).exists():
            return {
                "status": "not_applicable",
                "reason": "SRUDB.dat absent under Windows/System32/sru on mounted disk",
            }

    if tool == "sleuthkit_mactime":
        bodyfile = (
            env.get("SIFT_SLEUTHKIT_BODYFILE")
            or env.get("SIFT_MACTIME_BODYFILE")
            or ""
        ).strip()
        if not bodyfile:
            return {
                "status": "not_applicable",
                "reason": (
                    "no SleuthKit bodyfile configured/generated for mactime; "
                    "generate a bodyfile or use the active filesystem timeline source"
                ),
            }
        if not Path(bodyfile).exists():
            return {
                "status": "not_applicable",
                "reason": "configured mactime bodyfile not found: %s" % bodyfile,
            }

    if _zr_compat_has_empty_success_shape(envelope):
        return {
            "status": "empty_valid",
            "reason": "tool completed successfully and returned zero records",
        }

    return {
        "status": "missing_reason",
        "reason": "zero records without explicit reason",
    }
