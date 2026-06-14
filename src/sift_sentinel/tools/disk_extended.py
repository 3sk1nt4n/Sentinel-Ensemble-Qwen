"""
SIFT Sentinel - Disk forensic tools (Phase 2 extended).
parse_event_logs, parse_shellbags, parse_prefetch.

Parses from mounted disk.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import threading
import time
from pathlib import Path

from sift_sentinel.config import DISK_MOUNT_PATH

logger = logging.getLogger(__name__)


# ── parse_event_logs ─────────────────────────────────────────────────

# 31D-EVTX-PRIORITY-CAP: standard high-value Windows event channels.
# Standard Windows event channels only. Not case data. Does not key on
# host/user/IP/path/message content. Replaces file-walk-order truncation
# at SIFT_EVENT_LOG_MAX_RECORDS with a deterministic per-channel reserve
# so that crown-jewel channels (Security, PowerShell, WinRM, etc.) cannot
# be starved out of the cap by one chatty channel like System.
HIGH_VALUE_EVTX_CHANNELS = frozenset({
    "Security",
    "System",
    "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-WinRM/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
})


def _load_pyevtx():
    """Return PyEvtxParser class, or None if Rust ``evtx`` wheel absent.

    Indirected so tests can monkeypatch this to simulate ImportError
    without touching sys.modules.
    """
    try:
        from evtx import PyEvtxParser  # type: ignore
        return PyEvtxParser
    except Exception:
        return None


def _map_evtxecmd_record(row: dict) -> dict:
    """Map one EvtxECmd CSV row to the same 6-field schema as the pyevtx /
    python-evtx paths (EventID/TimeCreated/Provider/Channel/Computer/Message).

    Dataset-agnostic: pure column rename + int-coerce. Keys on no host, IP,
    path, channel allow-list, or message content.
    """
    def _g(*keys):
        for k in keys:
            v = row.get(k)
            if v not in (None, ""):
                return v
        return ""

    eid_raw = _g("EventId", "EventID")
    try:
        event_id = int(str(eid_raw).strip()) if str(eid_raw).strip() else 0
    except (TypeError, ValueError):
        event_id = 0
    return {
        "EventID": event_id,
        "TimeCreated": str(_g("TimeCreated") or ""),
        "Provider": str(_g("Provider", "Source") or ""),
        "Channel": str(_g("Channel", "LogName") or ""),
        "Computer": str(_g("Computer", "ComputerName") or ""),
        "Message": str(_g("MapDescription", "Payload") or ""),
    }


def _evtx_evtxecmd_fallback(evtx_path, timeout_s: float = 60.0):
    """Last-resort .NET EvtxECmd fallback for EVTX files the pure-Python copy/
    parse path cannot handle (e.g. a FUSE read EOVERFLOW [Errno 75], or a chunk-
    header error that defeats both pyevtx and python-evtx).

    Returns ``(records, err)``. ``records`` is the mapped 6-field list on
    success; on any failure ``records == []`` and ``err`` is the exception so
    the caller keeps its existing copy-skip/error behaviour. Bounded by a thread
    join so a slow/hung EvtxECmd cannot exceed the per-file budget. Universal:
    runs only on the error path, keys on nothing dataset-specific.
    """
    try:
        from sift_sentinel.tools.generic import run_evtxecmd as _ree
    except Exception as _ie:  # pragma: no cover - import guard
        return ([], _ie)

    holder: dict = {}

    def _run():
        try:
            holder["r"] = _ree(evtx_path)
        except Exception as _e:  # pragma: no cover - defensive
            holder["e"] = _e

    _t = threading.Thread(target=_run, daemon=True)
    _t.start()
    _t.join(timeout=timeout_s)
    if _t.is_alive():
        return ([], TimeoutError(f"EvtxECmd fallback exceeded {timeout_s}s"))
    if "e" in holder:
        return ([], holder["e"])
    res = holder.get("r")
    if not isinstance(res, dict) or res.get("error"):
        return ([], RuntimeError(str((res or {}).get("error", "EvtxECmd no result"))))
    rows = res.get("output") or []
    if not isinstance(rows, list):
        return ([], RuntimeError("EvtxECmd output not a list"))
    mapped = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("status") == "complete_no_data":
            continue
        mapped.append(_map_evtxecmd_record(row))
    return (mapped, None)


def _load_python_evtx():
    """Return python-evtx module, or None if absent.

    Used both as the legacy fast-path replacement (when pyevtx is
    available) and as the ultimate fallback when pyevtx is missing or
    errors on a specific file.
    """
    try:
        import Evtx.Evtx as evtx_mod  # type: ignore
        return evtx_mod
    except Exception:
        return None


def _normalize_evtx_systemtime(raw: str) -> str:
    """Render TimeCreated identically whether pyevtx or python-evtx parsed it.

    python-evtx re-serializes the binary record's SystemTime as
    ``str(datetime)`` -- ``"2018-09-06 16:37:25.575949+00:00"`` -- because
    its XML serializer calls into Python's datetime. PyEvtxParser's JSON
    instead emits canonical ISO 8601 -- ``"2018-09-06T16:37:25.575949Z"``.
    To preserve byte-for-byte schema parity (so downstream consumers see
    the same TimeCreated string regardless of which parser ran), this
    helper parses the ISO form and re-renders it via ``str(datetime)``
    matching the xml.etree path. Best-effort: any parse failure passes
    the input through unchanged.
    """
    import datetime as _dt
    if not raw:
        return ""
    try:
        iso = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        return str(_dt.datetime.fromisoformat(iso))
    except (TypeError, ValueError):
        return raw


def _map_pyevtx_record(d: dict) -> dict:
    """Map a single PyEvtxParser JSON record to the 6-field schema.

    Field parity with the python-evtx + xml.etree path:
    EventID (int) / TimeCreated / Provider / Channel / Computer / Message.
    All fields default to "" or 0 exactly as the xml.etree path does.
    Defensive against missing System / EventData and against the dict
    -with-``#text`` shape that PyEvtxParser uses when an element carries
    XML attributes (e.g. ``<EventID Qualifiers="...">`` or
    ``<TimeCreated SystemTime="..."/>``).
    """
    event = d.get("Event") or {}
    system = event.get("System") or {}

    eid_raw = system.get("EventID", 0)
    if isinstance(eid_raw, dict):
        eid_raw = eid_raw.get("#text", 0)
    try:
        event_id = int(eid_raw) if eid_raw not in (None, "") else 0
    except (TypeError, ValueError):
        event_id = 0

    tc = system.get("TimeCreated")
    if isinstance(tc, dict):
        raw_t = (tc.get("#attributes") or {}).get("SystemTime", "") or ""
        time_created = _normalize_evtx_systemtime(raw_t)
    else:
        time_created = ""

    prov = system.get("Provider")
    if isinstance(prov, dict):
        provider = (prov.get("#attributes") or {}).get("Name", "") or ""
    else:
        provider = ""

    chan = system.get("Channel", "")
    channel = chan if isinstance(chan, str) else ("" if chan is None else str(chan))

    comp = system.get("Computer", "")
    computer = comp if isinstance(comp, str) else ("" if comp is None else str(comp))

    ed = event.get("EventData")
    msg_parts: list[str] = []
    if isinstance(ed, dict):
        for k, v in ed.items():
            if k == "#attributes":
                continue
            if k == "#text":
                if isinstance(v, list):
                    for it in v:
                        if it is not None:
                            msg_parts.append(str(it))
                elif v is not None:
                    msg_parts.append(str(v))
                continue
            if v is None:
                continue
            msg_parts.append(str(v))
    elif isinstance(ed, list):
        for it in ed:
            if it is not None:
                msg_parts.append(str(it))
    message = " | ".join(msg_parts)[:200]

    return {
        "EventID": event_id,
        "TimeCreated": time_created,
        "Provider": provider,
        "Channel": channel,
        "Computer": computer,
        "Message": message,
    }


def _sift_env_int(name: str, default: int) -> int:
    """Positive integer env helper for generic forensic caps/timeouts."""
    try:
        import os
        value = int(os.environ.get(name, str(default)))
        return value if value > 0 else int(default)
    except Exception:
        return int(default)


def _compute_evtx_timeouts(base_s: int, cap_s: int, workers: int) -> tuple[int, int]:
    """31AD: GIL-aware EVTX timeout scaling for multi-thread parse mode.

    python-evtx and xml.etree are pure-Python and contend for the GIL.
    Under N-worker parallel mode, each thread gets ~1/N of one core's
    effective compute time. To preserve parsing coverage while still
    bounding worst-case wallclock, scale per-file base and cap by the
    worker count. Serial mode (workers<=1) leaves timeouts unchanged.

    Pure function for direct unit testing.
    """
    if workers > 1:
        return base_s * workers, cap_s * workers
    return base_s, cap_s


def _select_evtx_priority_records(
    records,
    *,
    max_records,
    high_value_channels=None,
    high_value_per_channel_cap,
    other_per_channel_cap,
    fill_chunk,
):
    """Deterministic priority/per-channel selector for parsed EVTX records.

    Pure helper. No parser, no I/O. Replaces the prior file-walk-order
    ``records[:max_records]`` truncation, which silently starved
    crown-jewel channels (Security, Windows PowerShell, WinRM,
    TaskScheduler, ...) when one chatty channel (typically System) ran
    past the global cap before they were ever opened.

    Channel iteration order is sorted channel name (deterministic).
    Within each channel: TimeCreated DESC; missing/unparseable last;
    ties preserve original parser index (stable sort).

    Phase 1 -- high-value reserve:
      * Seed one newest record from each present HV channel.
      * Then round-robin fill (chunk = fill_chunk) across present HV
        channels until each reaches ``high_value_per_channel_cap`` OR
        ``max_records`` is reached.

    Phase 2 -- general fill:
      * Round-robin across all channels with remaining records.
      * Non-HV channels capped at ``other_per_channel_cap`` total.
      * HV channels may take up to an additional ``other_per_channel_cap``
        beyond their phase-1 reserve.

    Telemetry keys: source_total, selected_total, by_channel_source,
    by_channel_kept, by_channel_dropped, high_value_present,
    high_value_starved (also reserved, filled, for the summary line).
    """
    if high_value_channels is None:
        high_value_channels = HIGH_VALUE_EVTX_CHANNELS

    max_records = max(0, int(max_records))
    hv_cap = max(0, int(high_value_per_channel_cap))
    other_cap = max(0, int(other_per_channel_cap))
    chunk = max(1, min(5000, int(fill_chunk)))

    # Bucket by channel, attaching original parser index for stable tie-breaking.
    by_channel: dict[str, list[tuple[int, dict]]] = {}
    for i, rec in enumerate(records):
        chan = rec.get("Channel", "") or ""
        by_channel.setdefault(chan, []).append((i, rec))

    by_channel_source = {c: len(v) for c, v in by_channel.items()}

    # Within each channel, sort TimeCreated DESC with missing/unparseable last.
    # Stable sort keeps original parser index order on ties.
    import datetime as _dt

    _UTC = _dt.timezone.utc

    def _ts_value(tc):
        if not tc:
            return None
        try:
            s = tc
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = _dt.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_UTC)
            return dt
        except (ValueError, TypeError, AttributeError):
            return None

    _TS_FLOOR = _dt.datetime.min.replace(tzinfo=_UTC)

    for chan, items in by_channel.items():
        # Already in original-parser-index order from enumerate(records).
        # Python's sort is stable -> ties preserve that order.
        items.sort(
            key=lambda x: (
                _ts_value(x[1].get("TimeCreated", "")) is not None,
                _ts_value(x[1].get("TimeCreated", "")) or _TS_FLOOR,
            ),
            reverse=True,
        )

    all_channels = sorted(by_channel.keys())
    present_hv = [
        c for c in all_channels if c in high_value_channels and by_channel[c]
    ]

    selected: list[dict] = []
    kept_count: dict[str, int] = {c: 0 for c in all_channels}

    # ── Phase 1: HV reserve ──────────────────────────────────────────
    # 1a. Seed one newest record per present HV channel (fairness floor).
    for chan in present_hv:
        if len(selected) >= max_records:
            break
        if kept_count[chan] < hv_cap and kept_count[chan] < len(by_channel[chan]):
            selected.append(by_channel[chan][kept_count[chan]][1])
            kept_count[chan] += 1

    # 1b. Chunked round-robin up to hv_cap per HV channel.
    while len(selected) < max_records:
        progressed = False
        for chan in present_hv:
            if len(selected) >= max_records:
                break
            remaining_budget = max_records - len(selected)
            remaining_chan_cap = hv_cap - kept_count[chan]
            remaining_chan_recs = len(by_channel[chan]) - kept_count[chan]
            take = min(chunk, remaining_budget, remaining_chan_cap, remaining_chan_recs)
            if take > 0:
                start = kept_count[chan]
                end = start + take
                for _, rec in by_channel[chan][start:end]:
                    selected.append(rec)
                kept_count[chan] = end
                progressed = True
        if not progressed:
            break

    reserved_count = len(selected)
    hv_phase1_take = {c: kept_count.get(c, 0) for c in present_hv}

    # ── Phase 2: general fill across all channels with records left ──
    while len(selected) < max_records:
        progressed = False
        for chan in all_channels:
            if len(selected) >= max_records:
                break
            remaining_chan_recs = len(by_channel[chan]) - kept_count[chan]
            if remaining_chan_recs <= 0:
                continue
            if chan in high_value_channels:
                phase2_taken = kept_count[chan] - hv_phase1_take.get(chan, 0)
                remaining_chan_cap = other_cap - phase2_taken
            else:
                remaining_chan_cap = other_cap - kept_count[chan]
            if remaining_chan_cap <= 0:
                continue
            remaining_budget = max_records - len(selected)
            take = min(chunk, remaining_budget, remaining_chan_cap, remaining_chan_recs)
            if take > 0:
                start = kept_count[chan]
                end = start + take
                for _, rec in by_channel[chan][start:end]:
                    selected.append(rec)
                kept_count[chan] = end
                progressed = True
        if not progressed:
            break

    filled_count = len(selected) - reserved_count

    by_channel_kept = {c: kept_count[c] for c in all_channels if kept_count[c] > 0}
    by_channel_dropped = {
        c: by_channel_source[c] - kept_count.get(c, 0)
        for c in all_channels
        if by_channel_source[c] - kept_count.get(c, 0) > 0
    }
    high_value_present_list = [
        c for c in all_channels
        if c in high_value_channels and by_channel_source.get(c, 0) > 0
    ]
    high_value_starved_list = [
        c for c in high_value_present_list if kept_count.get(c, 0) == 0
    ]

    telemetry = {
        "source_total": sum(by_channel_source.values()),
        "selected_total": len(selected),
        "by_channel_source": by_channel_source,
        "by_channel_kept": by_channel_kept,
        "by_channel_dropped": by_channel_dropped,
        "high_value_present": high_value_present_list,
        "high_value_starved": high_value_starved_list,
        "reserved": reserved_count,
        "filled": filled_count,
    }
    return selected, telemetry


def _sift_evtx_fit_return_budget(records):
    """Bound JSON size of the returned event-log payload.

    MCP stdio ships the whole tool result as one JSON-RPC message; an
    oversized payload silently drops the connection ("Connection closed")
    and the tool records ZERO (observed on a prior live image: ~50000 fat records). Trim
    the already priority-selected list to a byte budget so a large case
    returns a large *partial* set instead of nothing. Size-based and
    dataset-agnostic; no IOC/PID/path logic.
    """
    import json as _json
    if not isinstance(records, list) or not records:
        return records
    # SIFT_EVTX_TRANSPORT_GATE_V1: the 8MB cut only matters when the payload crosses the
    # MCP stdio boundary (server subprocess). In-process/local-first callers
    # have no JSON-RPC limit; capping there drops oldest high-value events.
    # Records are already priority-capped (<=max_records) upstream, so this
    # is transport/size only -- dataset-agnostic, no IOC/PID/path logic.
    import os as _os
    if not _os.environ.get("SIFT_MCP_SERVER_PROC") and not _os.environ.get("SIFT_EVENT_LOG_FORCE_BUDGET"):
        return records
    budget = _sift_env_int("SIFT_EVENT_LOG_MAX_RETURN_BYTES", 8_000_000)
    if budget <= 0:
        return records
    try:
        if len(_json.dumps(records, default=str)) <= budget:
            return records
    except (TypeError, ValueError):
        return records
    lo, hi = 0, len(records)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            size = len(_json.dumps(records[:mid], default=str))
        except (TypeError, ValueError):
            hi = mid - 1
            continue
        if size <= budget:
            lo = mid
        else:
            hi = mid - 1
    logger.warning(
        "EVTX_TRANSPORT_TRIM kept=%d dropped=%d budget_bytes=%d "
        "reason=mcp_payload_size_guard",
        lo, len(records) - lo, budget,
    )
    return records[:lo]


def _evtx_accumulate_capped(records, file_records, chan_counts, hv_cap, other_cap, hv_channels=None):
    """Append file_records into records, capped per-channel, so one huge channel
    (e.g. Security archives, 1M+ rows) cannot blow memory or stall the priority
    selector. Mutates records and chan_counts in place; returns records. HV-first
    file ordering guarantees crown-jewel channels are seen before any channel
    hits its cap, so this never starves them. Standard Windows channel names
    only -- no case data."""
    if hv_channels is None:
        hv_channels = HIGH_VALUE_EVTX_CHANNELS
    for rec in file_records:
        ch = rec.get("Channel", "") or ""
        cap = hv_cap if ch in hv_channels else other_cap
        if chan_counts.get(ch, 0) < cap:
            records.append(rec)
            chan_counts[ch] = chan_counts.get(ch, 0) + 1
    return records


def _xp_evt_record_to_dict(rec, channel):  # SIFT_XP_EVT_V1
    """Map one pyevt .evt record to the same schema the modern .evtx path
    emits (EventID/TimeCreated/Provider/Channel/Computer/Message)."""
    try:
        eid = int(getattr(rec, "event_identifier", 0) or 0) & 0xFFFF
    except Exception:
        eid = 0
    try:
        wt = rec.written_time
        ts = wt.isoformat() if hasattr(wt, "isoformat") else (str(wt) if wt else "")
    except Exception:
        ts = ""
    try:
        strs = [s for s in (rec.strings or []) if s]
    except Exception:
        strs = []
    return {
        "EventID": eid,
        "TimeCreated": ts,
        "Provider": getattr(rec, "source_name", "") or "",
        "Channel": channel,
        "Computer": getattr(rec, "computer_name", "") or "",
        "Message": " | ".join(str(s) for s in strs)[:200],
    }


def _parse_xp_evt_logs(disk_mount):  # SIFT_XP_EVT_V1
    """XP/legacy fallback: parse old .evt logs from {mount}/Windows/System32/
    config/*.evt via pyevt, returning the same {"output":[...],"record_count":N}
    envelope as the modern path. Returns None when pyevt is unavailable or no
    .evt files exist, so the caller falls through to its not-applicable return.
    Dataset-agnostic: channel derived from file stem, no fixed paths."""
    try:
        import pyevt
    except Exception:
        return None
    from sift_sentinel.tools.common import resolve_path_ci as _ci
    config_dir = _ci(disk_mount, "Windows", "System32", "config")
    if not config_dir.is_dir():
        return None
    evt_files = [p for p in config_dir.iterdir()
                 if p.is_file() and p.suffix.lower() == ".evt"]
    if not evt_files:
        return None
    _stem_channel = {"appevent": "Application", "secevent": "Security",
                     "sysevent": "System"}
    records = []
    for ef in evt_files:
        channel = _stem_channel.get(ef.stem.lower(), ef.stem)
        f = None
        try:
            f = pyevt.file()
            f.open(str(ef))
            for i in range(f.number_of_records):
                try:
                    records.append(_xp_evt_record_to_dict(f.get_record(i), channel))
                except Exception:
                    continue
        except Exception:
            continue
        finally:
            if f is not None:
                try:
                    f.close()
                except Exception:
                    pass
    return {"output": records, "record_count": len(records)}


def parse_event_logs(
    disk_mount: str = "",
    max_records: int | None = None,
) -> dict:
    """Windows Event Logs: security events, logon events, service installs.

    Parses .evtx files from *disk_mount*. Prefers the Rust-backed
    ``evtx.PyEvtxParser`` when its wheel is importable (~100x faster on
    pure-Python xml.etree workloads); falls back to ``python-evtx`` +
    ``xml.etree`` on ImportError or per-file PyEvtxParser failure.
    Returns the same 6-field schema either way.
    """
    disk_mount = disk_mount or DISK_MOUNT_PATH

    _PyEvtxParser = _load_pyevtx()
    _evtx_mod = _load_python_evtx()

    if _PyEvtxParser is None and _evtx_mod is None:
        return {
            "output": [],
            "record_count": 0,
            "error": "python-evtx not installed",
        }

    import xml.etree.ElementTree as ET

    from sift_sentinel.tools.common import resolve_path_ci as _ci  # SIFT_CI_PATH
    evtx_dir = _ci(disk_mount, "Windows", "System32", "winevt", "Logs")
    if not evtx_dir.exists():
        _xp = _parse_xp_evt_logs(disk_mount)  # SIFT_XP_EVT_V1
        if _xp is not None:
            return _xp
        # FIX B (#1): EVTX directory absent is a CAPABILITY-ABSENCE, not a tool
        # error. On a memory-only run (no disk mounted) or a non-Windows mount the
        # Windows tree is missing entirely. Return not_applicable with a reason,
        # mirroring sibling disk tools (get_amcache / parse_prefetch /
        # parse_registry_persistence) so the report's applicability section
        # explains it instead of flagging a tool FAILURE -- and so the model never
        # treats a missing-evidence outcome as a finding. Universal: keyed on the
        # structural absence of the Windows tree, no case data.
        # Kill switch SIFT_EVTX_NA_NODISK=0 restores the legacy error envelope.
        import os as _os_evtx
        if str(_os_evtx.environ.get("SIFT_EVTX_NA_NODISK", "1")).strip() != "0":
            _win_dir = _ci(disk_mount, "Windows")
            if not _win_dir.exists():
                _reason = (
                    "No Windows event logs: the Windows directory is absent on "
                    "this mount (no disk evidence, or not a Windows filesystem)"
                )
            else:
                _reason = (
                    f"No Windows event logs: {evtx_dir} is absent on this mount "
                    "(event log directory missing or wiped)"
                )
            return {
                "output": [],
                "record_count": 0,
                "status": "not_applicable",
                "reason": _reason,
                "not_applicable_reason": _reason,
            }
        return {
            "output": [],
            "record_count": 0,
            "error": f"EVTX directory not found: {evtx_dir}",
        }

    ns = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event",
    }
    records: list[dict] = []

    if max_records is None:
        max_records = _sift_env_int("SIFT_EVENT_LOG_MAX_RECORDS", 50000)
    else:
        max_records = max(0, int(max_records))
    # 31Q: adaptive per-file timeout — scales with file size so small EVTX
    # files don't wait the full cap while large files still get headroom.
    #   timeout = base + (size_mb / rate_mb_per_s), clamped to [base, cap]
    _evtx_base = _sift_env_int("SIFT_EVTX_TIMEOUT_BASE_S", 6)
    _evtx_rate = max(1, _sift_env_int("SIFT_EVTX_TIMEOUT_RATE_MB_PER_S", 10))
    _evtx_cap = _sift_env_int("SIFT_EVTX_TIMEOUT_S", 60)  # max cap (legacy env)
    # 31AD: GIL-aware scaling for multi-thread mode
    _evtx_gil_workers = max(1, _sift_env_int("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", 1))
    _evtx_base, _evtx_cap = _compute_evtx_timeouts(_evtx_base, _evtx_cap, _evtx_gil_workers)
    def _evtx_timeout_for(_path):
        try:
            _size_mb = max(1.0, os.path.getsize(_path) / (1024 * 1024))
        except OSError:
            return _evtx_base
        return max(_evtx_base, min(_evtx_cap, int(_evtx_base + _size_mb / _evtx_rate)))

    # 31W: parallel EVTX-file parsing via inner ThreadPoolExecutor.
    # Each file still runs in its own daemon thread for per-file adaptive
    # timeout enforcement (preserved from 31Q). N files run concurrently.
    # Tuning: SIFT_PARSE_EVENT_LOGS_INNER_WORKERS (default 4).
    from concurrent.futures import ThreadPoolExecutor, as_completed
    _inner_workers = max(1, _sift_env_int(
        "SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", 1))

    def _parse_one_file_python_evtx(evtx_path):
        file_records: list[dict] = []
        exc_holder: list[Exception] = []
        per_file_timeout = _evtx_timeout_for(evtx_path)
        if _evtx_mod is None:
            return ([], ImportError("python-evtx not installed"), False, per_file_timeout)
        def _parse_inner():
            try:
                with _evtx_mod.Evtx(str(evtx_path)) as log:
                    for record in log.records():
                        try:
                            root = ET.fromstring(record.xml())
                        except ET.ParseError:
                            continue
                        system = root.find("e:System", ns)
                        if system is None:
                            continue
                        eid_el = system.find("e:EventID", ns)
                        time_el = system.find("e:TimeCreated", ns)
                        prov_el = system.find("e:Provider", ns)
                        chan_el = system.find("e:Channel", ns)
                        comp_el = system.find("e:Computer", ns)
                        msg = ""
                        event_data = root.find("e:EventData", ns)
                        if event_data is not None:
                            parts = []
                            for data_el in event_data.findall("e:Data", ns):
                                if data_el.text:
                                    parts.append(data_el.text)
                            msg = " | ".join(parts)[:200]
                        file_records.append({
                            "EventID": (int(eid_el.text)
                                        if eid_el is not None and eid_el.text else 0),
                            "TimeCreated": (time_el.get("SystemTime", "")
                                            if time_el is not None else ""),
                            "Provider": (prov_el.get("Name", "")
                                         if prov_el is not None else ""),
                            "Channel": (chan_el.text
                                        if chan_el is not None else ""),
                            "Computer": (comp_el.text
                                         if comp_el is not None else ""),
                            "Message": msg,
                        })
            except Exception as _e:
                exc_holder.append(_e)
        _t = threading.Thread(target=_parse_inner, daemon=True)
        _t.start()
        _t.join(timeout=per_file_timeout)
        if _t.is_alive():
            return ([], None, True, per_file_timeout)
        if exc_holder:
            return ([], exc_holder[0], False, per_file_timeout)
        return (file_records, None, False, per_file_timeout)

    def _parse_one_file_pyevtx(evtx_path):
        file_records: list[dict] = []
        exc_holder: list[Exception] = []
        per_file_timeout = _evtx_timeout_for(evtx_path)
        def _parse_inner():
            try:
                parser = _PyEvtxParser(str(evtx_path))
                for rec in parser.records_json():
                    raw = rec.get("data") if isinstance(rec, dict) else None
                    if not raw:
                        continue
                    try:
                        d = json.loads(raw)
                    except Exception:
                        continue
                    try:
                        file_records.append(_map_pyevtx_record(d))
                    except Exception:
                        continue
            except Exception as _e:
                exc_holder.append(_e)
        _t = threading.Thread(target=_parse_inner, daemon=True)
        _t.start()
        _t.join(timeout=per_file_timeout)
        if _t.is_alive():
            return ([], None, True, per_file_timeout)
        if exc_holder:
            return ([], exc_holder[0], False, per_file_timeout)
        return (file_records, None, False, per_file_timeout)

    _primary_parser = "pyevtx" if _PyEvtxParser is not None else "python-evtx"

    def _evtx_copy_to_local(_src):
        """31AF: copy an EVTX file off the mounted image to local scratch via
        chunked read() so an unreadable backing region (missing clusters on an
        incomplete acquisition) surfaces as a *catchable* OSError(EIO) here,
        rather than a SIGBUS during mmap parsing -- which would kill the whole
        worker process and zero every EVTX channel. Returns a local temp path
        (caller must unlink) or raises OSError on read failure."""
        import tempfile as _tf
        _fd, _tmp = _tf.mkstemp(suffix=".evtx", prefix="sift_evtx_")
        try:
            with open(_src, "rb") as _rf, os.fdopen(_fd, "wb") as _wf:
                while True:
                    _chunk = _rf.read(4 * 1024 * 1024)
                    if not _chunk:
                        break
                    _wf.write(_chunk)
            return _tmp
        except BaseException:
            try:
                os.unlink(_tmp)
            except OSError:
                pass
            raise

    def _parse_one_file(evtx_path):
        """Dispatch per-file: copy to local scratch first (SIGBUS-safe), then
        pyevtx fast path, python-evtx fallback on error."""
        _t0 = time.monotonic()
        _local = None
        try:
            _local = _evtx_copy_to_local(evtx_path)
        except OSError as _ce:
            elapsed = time.monotonic() - _t0
            # 31AG-D1a: copy off the FUSE mount failed (e.g. [Errno 75]
            # EOVERFLOW). Last-resort .NET EvtxECmd reads the file directly and
            # recovers crown-jewel channels (Security / RDP) that would
            # otherwise be silently dropped. Dataset-agnostic, error-path only.
            _to = _evtx_timeout_for(evtx_path)
            _fb_recs, _fb_err = _evtx_evtxecmd_fallback(evtx_path, _to)
            if _fb_err is None and _fb_recs:
                return (_fb_recs, None, False, _to, "evtxecmd", elapsed)
            return ([], _ce, False, _to, "copy-skip", elapsed)
        try:
            if _PyEvtxParser is not None:
                recs, err, timed_out, applied = _parse_one_file_pyevtx(_local)
                if (err is not None or timed_out) and _evtx_mod is not None:
                    fb_recs, fb_err, fb_to, fb_applied = _parse_one_file_python_evtx(_local)
                    if fb_err is None and not fb_to:
                        elapsed = time.monotonic() - _t0
                        return (fb_recs, None, False, fb_applied, "python-evtx", elapsed)
                if err is not None or timed_out:
                    # 31AG-D1a: both pure-Python parsers failed -> .NET fallback.
                    _ee_recs, _ee_err = _evtx_evtxecmd_fallback(_local, applied)
                    if _ee_err is None and _ee_recs:
                        elapsed = time.monotonic() - _t0
                        return (_ee_recs, None, False, applied, "evtxecmd", elapsed)
                elapsed = time.monotonic() - _t0
                return (recs, err, timed_out, applied, "pyevtx", elapsed)
            recs, err, timed_out, applied = _parse_one_file_python_evtx(_local)
            if err is not None or timed_out:
                # 31AG-D1a: python-evtx failed -> .NET fallback.
                _ee_recs, _ee_err = _evtx_evtxecmd_fallback(_local, applied)
                if _ee_err is None and _ee_recs:
                    elapsed = time.monotonic() - _t0
                    return (_ee_recs, None, False, applied, "evtxecmd", elapsed)
            elapsed = time.monotonic() - _t0
            return (recs, err, timed_out, applied, "python-evtx", elapsed)
        finally:
            if _local is not None:
                try:
                    os.unlink(_local)
                except OSError:
                    pass

    # 31AE: high-value channels first so the wall-clock budget below only ever
    # drops low-value noise, never a crown-jewel channel that sorts late
    # alphabetically. Channel names map to file stems via '/' -> '%4'.
    def _evtx_hv_rank(_p):
        _stem = _p.stem
        _hv = _stem in HIGH_VALUE_EVTX_CHANNELS or _stem.replace("%4", "/") in HIGH_VALUE_EVTX_CHANNELS
        return (0 if _hv else 1, _stem.lower())
    _evtx_files = sorted(evtx_dir.glob("*.evtx"), key=_evtx_hv_rank)
    _run_t0 = time.monotonic()
    _evtx_budget_s = _sift_env_int("SIFT_EVTX_TOTAL_BUDGET_S", 90)
    _chan_counts: dict[str, int] = {}
    _hv_collect_cap = _sift_env_int("SIFT_EVTX_HV_PER_CHANNEL_CAP", 5000)
    _other_collect_cap = _sift_env_int("SIFT_EVTX_OTHER_PER_CHANNEL_CAP", 2000)
    with ThreadPoolExecutor(
        max_workers=_inner_workers,
        thread_name_prefix="evtx_shard",
    ) as _ex:
        _futures = {_ex.submit(_parse_one_file, _f): _f for _f in _evtx_files}
        for _fut in as_completed(_futures):
            # 31AE: wall-clock budget checked at the TOP of every iteration so
            # it fires whether files succeed OR error -- a run of consecutive
            # corrupt channels must not be able to bypass it. HV channels were
            # submitted first, so only low-value noise is ever dropped.
            if (time.monotonic() - _run_t0) > _evtx_budget_s:
                _pending = [_pf for _pf in _futures if not _pf.done()]
                for _pf in _pending:
                    _pf.cancel()
                logger.warning(
                    "EVTX_TIME_BUDGET_REACHED budget_s=%d files_total=%d files_skipped=%d records=%d",
                    _evtx_budget_s, len(_evtx_files), len(_pending), len(records),
                )
                break
            evtx_file = _futures[_fut]
            try:
                _file_records, _err, _timed_out, _applied, _parser_used, _elapsed = (
                    _fut.result()
                )
            except Exception as _e:
                logger.warning(
                    "EVTX_FILE_RESULT file=%s parser=%s records=0 elapsed_s=- "
                    "status=error err=%s",
                    evtx_file.name, _primary_parser, str(_e)[:100],
                )
                continue
            if _timed_out:
                logger.warning(
                    "EVTX_FILE_RESULT file=%s parser=%s records=0 elapsed_s=%.3f "
                    "status=error err=timeout_after_%ds",
                    evtx_file.name, _parser_used, _elapsed, _applied,
                )
                continue
            if _err is not None:
                logger.warning(
                    "EVTX_FILE_RESULT file=%s parser=%s records=0 elapsed_s=%.3f "
                    "status=error err=%s",
                    evtx_file.name, _parser_used, _elapsed, str(_err)[:100],
                )
                continue
            logger.info(
                "EVTX_FILE_RESULT file=%s parser=%s records=%d elapsed_s=%.3f "
                "status=ok",
                evtx_file.name, _parser_used, len(_file_records), _elapsed,
            )
            # 31AF: cap accumulation per-channel during collection so a single
            # huge channel (Security archives, 1M+ rows) can't blow memory and
            # stall the priority selector -- whose heavy pass over 1M+ rows was
            # starving the MCP stdio reader (BrokenPipe). HV-first ordering means
            # crown-jewel channels are collected before any channel caps out, so
            # this never starves them; the selector below still does the final
            # most-recent-per-channel + global-cap selection over the bounded set.
            _evtx_accumulate_capped(records, _file_records, _chan_counts,
                                    _hv_collect_cap, _other_collect_cap)
    _run_elapsed = time.monotonic() - _run_t0
    logger.info(
        "EVTX_SUMMARY parser=%s files=%d records=%d elapsed_s=%.3f",
        _primary_parser, len(_evtx_files), len(records), _run_elapsed,
    )

    # ── 31D-EVTX-PRIORITY-CAP: deterministic per-channel selection ───
    # Selector runs against the FULL parsed corpus. The prior file-walk
    # early-stop has been removed (it starved late-walked HV channels);
    # the in-run per-file timeout still bounds wall-clock as before. On
    # any selector exception the function reverts to the legacy
    # timestamp-DESC truncation and emits EVTX_PRIORITY_FALLBACK.
    total = len(records)
    logger.info("parse_event_logs: %d records parsed, applying priority cap %d",
                total, max_records)
    _hv_cap = _sift_env_int("SIFT_EVTX_HV_PER_CHANNEL_CAP", 5000)
    _other_cap = _sift_env_int("SIFT_EVTX_OTHER_PER_CHANNEL_CAP", 2000)
    _fill_chunk = _sift_env_int("SIFT_EVTX_FILL_CHUNK", 256)
    try:
        records, _tel = _select_evtx_priority_records(
            records,
            max_records=max_records,
            high_value_per_channel_cap=_hv_cap,
            other_per_channel_cap=_other_cap,
            fill_chunk=_fill_chunk,
        )
        # 31D-MCP-STDOUT-HYGIENE: telemetry routed via logger only.
        # MCP stdio reserves stdout for JSON-RPC; any non-JSON line
        # corrupts the framing and the client fails parsing. Logging
        # goes through stderr handlers and never collides.
        _summary_line = (
            f"EVTX_PRIORITY_SUMMARY total={_tel['selected_total']} "
            f"source_total={_tel['source_total']} "
            f"selected_total={_tel['selected_total']} "
            f"cap={max_records} "
            f"high_value_present={len(_tel['high_value_present'])} "
            f"reserved={_tel['reserved']} filled={_tel['filled']}"
        )
        logger.info(_summary_line)
        for _chan, _kept in sorted(_tel["by_channel_kept"].items()):
            _src_n = _tel["by_channel_source"].get(_chan, 0)
            logger.info(
                'EVTX_RETAINED_BY_CHANNEL channel="%s" kept=%d source=%d',
                _chan, _kept, _src_n,
            )
        for _chan, _dropped in sorted(_tel["by_channel_dropped"].items()):
            if _dropped > 0:
                logger.info(
                    'EVTX_PRIORITY_DROPPED channel="%s" dropped=%d',
                    _chan, _dropped,
                )
    except Exception as _sel_exc:
        logger.warning(
            'EVTX_PRIORITY_FALLBACK reason="%s"',
            str(_sel_exc)[:200],
        )
        records.sort(key=lambda r: r.get("TimeCreated", ""), reverse=True)
        records = records[:max_records]

    records = _sift_evtx_fit_return_budget(records)
    return {"output": records, "record_count": len(records)}


# ── parse_prefetch ──────────────────────────────────────────────────

def parse_prefetch(
    disk_mount: str = "",
    max_entries: int = 1024,
) -> dict:
    """Windows Prefetch: proves program execution, run count, loaded DLLs.

    Parses .pf files from {disk_mount}/Windows/Prefetch/.
    """
    mount = disk_mount or DISK_MOUNT_PATH
    logger.info("Prefetch: searching %s/Windows/Prefetch/", mount)
    from sift_sentinel.tools.common import resolve_path_ci as _ci  # SIFT_CI_PATH
    prefetch_dir = _ci(mount, "Windows", "Prefetch")
    if not prefetch_dir.is_dir():
        logger.warning("Prefetch: not available on this system (disabled by default on Windows Server): %s", prefetch_dir)
        # Commit 24: return structured not_applicable status instead of
        # error. Prefetch is disabled by default on Windows Server and
        # is not a failure. collect_tool_failures at coordinator.py:1361
        # keys on "error" key presence; omitting it here naturally
        # excludes this from the failures list, matching the intent
        # documented in that function's docstring ("Empty results are
        # NOT failures -- malfind, netscan, prefetch, etc. can all
        # legitimately return zero rows").
        return {
            "output": [],
            "record_count": 0,
            "status": "not_applicable",
            "reason": f"Prefetch directory not present (disabled by default on Windows Server): {prefetch_dir}",
        }

    records: list[dict] = []
    pf_files = sorted(
        f for f in prefetch_dir.iterdir()
        if f.suffix.lower() == ".pf"
    )
    logger.info("Prefetch: found %d .pf files in %s", len(pf_files), prefetch_dir)
    for pf_file in pf_files[:max_entries]:
        name = pf_file.stem  # e.g. "PSEXEC.EXE-AD70946C"
        parts = name.rsplit("-", 1)
        exe_name = parts[0] if len(parts) == 2 else name
        records.append({
            "executable_name": exe_name,
            "run_count": 0,
            "last_run_times": [],
            "path": str(pf_file),
            "files_accessed": [],
        })

    logger.info("Prefetch: returning %d records", len(records))
    return {"output": records, "record_count": len(records)}


# ── parse_shellbags ──────────────────────────────────────────────────

def parse_shellbags(
    csv_path: str = "",
) -> dict:
    """Shellbags: folder access history, user activity timeline.

    Reads *csv_path* with csv.DictReader.
    """
    if not csv_path:
        return {
            "output": [],
            "record_count": 0,
            "error": "no shellbags path provided",
        }
    csv_p = Path(csv_path)
    if not csv_p.is_file():
        return {
            "output": [],
            "record_count": 0,
            "error": f"CSV not found or not a file: {csv_path}",
        }

    records: list[dict] = []
    with open(csv_p, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(dict(row))

    return {"output": records, "record_count": len(records)}

# RUN17_P0_PARSE_EVENT_LOGS_TIME_DESC_SORT
#
# parse_event_logs must return event records in descending event-time order.
# This wrapper preserves the existing parser/export behavior and only sorts
# the returned current-run records after parsing.
#
# Dataset-agnostic behavior:
# - Sorts only by timestamp fields emitted by the parser.
# - Does not sort by EventID, source name, filename, host, user, path, IP,
#   hash, PID, or any case-specific value.
# - Missing or unparseable timestamps sort last.
def _sift_event_log_sort_datetime(value):
    from datetime import datetime, timezone

    floor = datetime.min.replace(tzinfo=timezone.utc)

    if value is None:
        return floor

    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        if not s:
            return floor

        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        if s.lower().endswith(" utc"):
            s = s[:-4] + "+00:00"

        dt = None
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%m/%d/%Y %I:%M:%S %p",
            ):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    pass

        if dt is None:
            return floor

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _sift_event_log_record_sort_key(record):
    if not isinstance(record, dict):
        return _sift_event_log_sort_datetime(None)

    for key in (
        "TimeCreated",
        "time_created",
        "Timestamp",
        "timestamp",
        "TimeGenerated",
        "time_generated",
        "Created",
        "created",
    ):
        value = record.get(key)
        if value not in (None, ""):
            return _sift_event_log_sort_datetime(value)

    return _sift_event_log_sort_datetime(None)


def _sift_sort_event_log_output(result):
    if not isinstance(result, dict):
        return result

    records = result.get("output")
    if not isinstance(records, list):
        return result

    sorted_records = sorted(
        records,
        key=_sift_event_log_record_sort_key,
        reverse=True,
    )

    out = dict(result)
    out["output"] = sorted_records
    if isinstance(out.get("record_count"), int):
        out["record_count"] = len(sorted_records)
    return out


from functools import wraps as _sift_event_log_sort_wraps

if "_sift_parse_event_logs_unsorted" not in globals():
    _sift_parse_event_logs_unsorted = parse_event_logs


@_sift_event_log_sort_wraps(_sift_parse_event_logs_unsorted)
def parse_event_logs(*args, **kwargs):
    return _sift_sort_event_log_output(
        _sift_parse_event_logs_unsorted(*args, **kwargs)
    )

# RUN17_ZERO_RECORD_REASON_PREFETCH_WRAPPER_V1
#
# Universal zero-record contract for Prefetch parsing.
# Empty Prefetch is valid on some systems; emit an explicit reason.
def _sift_prefetch_zr_count_v1(result):
    if not isinstance(result, dict):
        return 0
    rc = result.get("record_count")
    if isinstance(rc, int):
        return rc
    out = result.get("output")
    return len(out) if isinstance(out, list) else 0


def _sift_prefetch_zr_has_reason_v1(result):
    if not isinstance(result, dict):
        return False
    for key in ("reason", "zero_record_reason", "not_applicable_reason", "error"):
        if result.get(key) not in (None, ""):
            return True
    return False


def _sift_prefetch_zr_with_reason_v1(result, *, status, reason):
    if not isinstance(result, dict):
        return result
    if _sift_prefetch_zr_count_v1(result) != 0:
        return result
    out = dict(result)
    out.setdefault("status", status)
    out.setdefault("reason", reason)
    out.setdefault(
        "zero_record_reason",
        {
            "status": out.get("status") or status,
            "reason": out.get("reason") or reason,
        },
    )
    return out


def _sift_prefetch_disk_mount_v1(original, args, kwargs):
    if "disk_mount" in kwargs:
        return kwargs.get("disk_mount")
    if "mount_path" in kwargs:
        return kwargs.get("mount_path")
    if args:
        return args[0]
    try:
        import inspect as _sift_prefetch_inspect_v1
        sig = _sift_prefetch_inspect_v1.signature(original)
        for name in ("disk_mount", "mount_path"):
            param = sig.parameters.get(name)
            if param is not None and param.default is not _sift_prefetch_inspect_v1._empty:
                return param.default
    except Exception:
        pass
    return ""


def _sift_prefetch_has_pf_v1(disk_mount):
    from pathlib import Path as _SiftPath
    root = _SiftPath(str(disk_mount or ""))
    dirs = [
        root / "Windows" / "Prefetch",
        root / "WINDOWS" / "Prefetch",
    ]
    for d in dirs:
        try:
            if d.is_dir() and any(d.glob("*.pf")):
                return True
        except Exception:
            pass
    return False


from functools import wraps as _sift_prefetch_wraps_v1

if "_sift_parse_prefetch_without_zr_reason_v1" not in globals():
    _sift_parse_prefetch_without_zr_reason_v1 = parse_prefetch

    @_sift_prefetch_wraps_v1(_sift_parse_prefetch_without_zr_reason_v1)
    def parse_prefetch(*args, **kwargs):
        result = _sift_parse_prefetch_without_zr_reason_v1(*args, **kwargs)
        if not isinstance(result, dict) or _sift_prefetch_zr_count_v1(result) != 0:
            return result
        if _sift_prefetch_zr_has_reason_v1(result):
            return result

        disk_mount = _sift_prefetch_disk_mount_v1(
            _sift_parse_prefetch_without_zr_reason_v1, args, kwargs
        )
        if _sift_prefetch_has_pf_v1(disk_mount):
            return _sift_prefetch_zr_with_reason_v1(
                result,
                status="no_records",
                reason="Prefetch files were present but no Prefetch rows were parsed",
            )

        return _sift_prefetch_zr_with_reason_v1(
            result,
            status="not_applicable",
            reason="Windows Prefetch artifacts not found under mounted filesystem",
        )

