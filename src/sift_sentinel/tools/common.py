"""
Sentinel Qwen Ensemble - Shared helpers for tool modules.
Includes Task 1.5 invocation helpers: prepare_prompt, strip_markdown_fences,
run_tools_parallel.
"""

from __future__ import annotations

import csv
import datetime as _dt
import io
import ipaddress
import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from sift_sentinel.config import VOL_CMD

# SIFT_VOLATILITY_ARG_CONTRACT_IMPORT_V1
from sift_sentinel.analysis.volatility_arg_contract import resolve_volatility_image_path

logger = logging.getLogger(__name__)


# ── Cache provenance (evidence-bound cache reads/writes) ─────────────────
#
# Cached tool outputs are only safe to reuse across runs if they came from
# the *same* evidence image.  Every cache file on disk must have a sibling
# ``<cache>.meta.json`` recording the SHA256 of the evidence that produced
# it; ``load_cached`` rejects reads whose provenance does not match.


def _meta_path(cache_path: Path | str) -> Path:
    """Return the ``.meta.json`` sibling path for a cache file."""
    p = Path(cache_path)
    return p.with_name(p.name + ".meta.json")


def write_cached(
    cache_path: Path | str,
    data: Any,
    *,
    evidence_sha256: str,
    tool_name: str,
) -> Path:
    """Write ``data`` as JSON and a paired ``.meta.json`` with provenance.

    The sidecar records the evidence hash so future reads can reject stale
    or cross-image cache hits.  Both files are written atomically enough
    for the single-writer case we have (write cache first, then meta).
    """
    if not evidence_sha256:
        raise ValueError("write_cached requires non-empty evidence_sha256")

    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, default=str)

    if isinstance(data, list):
        records_count = len(data)
    elif isinstance(data, dict):
        records_count = len(data)
    else:
        records_count = 0

    meta = {
        "evidence_sha256": evidence_sha256,
        "tool": tool_name,
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "records_count": records_count,
    }
    with open(_meta_path(path), "w") as f:
        json.dump(meta, f)
    return path


def load_cached(
    cache_path: Path | str,
    *,
    evidence_sha256: str | None = None,
) -> Any | None:
    """Load JSON from *cache_path* with optional provenance enforcement.

    When *evidence_sha256* is supplied the ``<cache>.meta.json`` sidecar
    must exist and record the same hash; otherwise the cache is rejected
    (returns ``None``) so a stale cross-image hit cannot poison a run.
    When *evidence_sha256* is ``None`` the meta check is skipped (used by
    offline tooling that has no live image hash).
    """
    path = Path(cache_path)
    if not path.exists():
        return None

    if evidence_sha256 is not None:
        meta_path = _meta_path(path)
        if not meta_path.exists():
            logger.warning(
                "Cache rejected: evidence hash mismatch (missing meta) "
                "for %s", path,
            )
            return None
        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "Cache rejected: evidence hash mismatch (meta unreadable: "
                "%s) for %s", exc, path,
            )
            return None
        if meta.get("evidence_sha256") != evidence_sha256:
            logger.warning(
                "Cache rejected: evidence hash mismatch for %s "
                "(cache=%s, run=%s)",
                path,
                str(meta.get("evidence_sha256"))[:16],
                evidence_sha256[:16],
            )
            return None

    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cache load failed for %s: %s", path, exc)
        return None

# ── Vol3 subprocess timeouts (per-tool, seconds) ─────────────────────
#
# Heavy Vol3 plugins timed out at 90s under Step6 concurrency and then
# C29-retried. A generous, env-tunable ceiling lets them complete once;
# true hangs still surface as failure_mode=timeout. Lighter plugins keep
# the tighter default to catch hangs early.

VOL_TIMEOUT_HEAVY: int = int(os.environ.get("SIFT_VOL_HEAVY_TIMEOUT", "240"))
VOL_TIMEOUT_DEFAULT: int = 90


def _effective_vol_timeout(tool_name: str) -> int:
    """Per-tool Vol3 timeout, optionally capped by SIFT_REACT_TOOL_TIMEOUT.

    Default (env unset) = the normal per-tool timeout, unchanged. When the cap
    env is set (an operator opt-in for timing-sensitive runs, e.g. exported for
    the ReAct loop), a SLOW tool whose normal timeout exceeds the cap is bounded
    to the cap -- a fast tool (timeout already below the cap) is untouched.
    Universal: keyed on the timeout value, no case/tool name list."""
    base = VOL_TIMEOUTS.get(tool_name, VOL_TIMEOUT_DEFAULT)
    cap_raw = os.environ.get("SIFT_REACT_TOOL_TIMEOUT", "").strip()
    if cap_raw:
        try:
            cap = int(cap_raw)
            if cap > 0:
                return min(base, cap)
        except ValueError:
            pass
    return base

VOL_TIMEOUTS: dict[str, int] = {
    "vol_handles": VOL_TIMEOUT_HEAVY,
    "vol_malfind": VOL_TIMEOUT_HEAVY,
    "vol_filescan": VOL_TIMEOUT_HEAVY,
    # Pool scanners are inherently slow on large images; the heavy tier lets them
    # COMPLETE instead of timing out at the default and producing a "tool failure"
    # the model then writes junk findings about. Structural tier, no case data.
    "vol_psscan": VOL_TIMEOUT_HEAVY,
    "vol_netscan": VOL_TIMEOUT_HEAVY,
    "vol_psxview": VOL_TIMEOUT_HEAVY,
    # hollowprocesses walks every process VAD/PEB like its sibling malfind
    # (measured 3m04s live); on the 90s default it timed out with 0 records on
    # EVERY live run -- zero hollowing detection. Heavy tier lets it complete.
    "vol_hollowprocesses": VOL_TIMEOUT_HEAVY,
    # Fast-fail: vadinfo is a slow full-image corroborator; cap at 30s so the
    # D3-P1 timeout->inconclusive path fires quickly instead of burning 120s x N.
    "vol_vadinfo": 30,
}

# ── Volatility 3 plugin mapping ──────────────────────────────────────
# Dynamic-only resolution (Slot 31I-gamma):
#   Runtime discovery provides the plugin surface. The canonical alias
#   map below is a rename layer for discovered plugin paths only; it
#   does not advertise plugins absent from runtime discovery.


_VOL_CANONICAL_ALIASES: dict[str, str] = {
    "vol_pstree": "windows.pstree.PsTree",
    "vol_netscan": "windows.netscan.NetScan",
    "vol_malfind": "windows.malfind.Malfind",
    "vol_cmdline": "windows.cmdline.CmdLine",
    "vol_dlllist": "windows.dlllist.DllList",
    "vol_psscan": "windows.psscan.PsScan",
    "vol_handles": "windows.handles.Handles",
    "vol_envars": "windows.envars.Envars",
    "vol_getsids": "windows.getsids.GetSIDs",
    "vol_privileges": "windows.privileges.Privs",
    "vol_svcscan": "windows.svcscan.SvcScan",
    "vol_sessions": "windows.sessions.Sessions",
    "vol_ssdt": "windows.ssdt.SSDT",
    "vol_filescan": "windows.filescan.FileScan",
    "vol_reg_hivelist": "windows.registry.hivelist.HiveList",
    "vol_ldrmodules": "windows.malware.ldrmodules.LdrModules",
    "vol_hollowprocesses": "windows.malware.hollowprocesses.HollowProcesses",
    "vol_callbacks": "windows.callbacks.Callbacks",
    "vol_modscan": "windows.modscan.ModScan",
    "vol_vadinfo": "windows.vadinfo.VadInfo",
    "vol_mftscan": "windows.mftscan.MFTScan",
    "vol_netstat": "windows.netstat.NetStat",
    "vol_timers": "windows.timers.Timers",
}


def _discover_volatility_windows_plugins() -> dict[str, str]:
    """Parse `vol --help` to discover Vol3 plugins (all OS families).

    Despite the legacy name, now returns plugins across Windows, Linux,
    and Mac prefixes. Returns {} on any failure (binary missing, non-zero
    exit, timeout, I/O error, or opt-out via SIFT_ENABLE_VOL_DISCOVERY=0).
    The fixed-list fallback is the safety net -- see
    _build_volatility_plugins. Short timeout prevents import-time hangs.
    """
    if os.environ.get("SIFT_ENABLE_VOL_DISCOVERY", "1") != "1":
        logger.info(
            "Vol3 plugin discovery disabled via SIFT_ENABLE_VOL_DISCOVERY=0"
            " -- fixed-list fallback in use",
        )
        return {}
    try:
        result = subprocess.run(
            [*VOL_CMD, "--help"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
        logger.info(
            "Vol3 plugin discovery failed (%s) -- fixed-list fallback",
            exc,
        )
        return {}
    if result.returncode != 0:
        logger.info(
            "Vol3 plugin discovery: `vol --help` rc=%d -- fixed-list fallback",
            result.returncode,
        )
        return {}
    _OS_PREFIXES = ("windows.", "linux.", "mac.")
    discovered: dict[str, str] = {}
    for raw_line in result.stdout.splitlines():
        stripped = raw_line.strip()
        if not any(stripped.startswith(p) for p in _OS_PREFIXES):
            continue
        plugin = stripped.split()[0]
        parts = plugin.split(".")
        if len(parts) < 2:
            continue
        short = parts[-2].replace("_", "")
        vol_name = f"vol_{short}"
        discovered.setdefault(vol_name, plugin)
    return discovered


VOL3_DISCOVERY_ACTIVE: bool = False
VOL3_DISCOVERED_PLUGIN_COUNT: int = 0
VOL3_ALIAS_FALLBACK_COUNT: int = 0


def _discover_vol_plugin_paths() -> list[str]:
    """Return every runtime-discovered Vol3 plugin path from ``vol --help``.

    This parses raw help text instead of the short-name map because the
    short-name map de-duplicates cross-platform collisions. Canonical
    alias selection needs the complete raw path set.
    """
    if os.environ.get("SIFT_ENABLE_VOL_DISCOVERY", "1") != "1":
        return []

    try:
        if isinstance(VOL_CMD, (list, tuple)):
            cmd = [*VOL_CMD, "--help"]
        else:
            cmd = [VOL_CMD, "--help"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - host/tool dependent
        logger.debug("Vol3 plugin path discovery unavailable: %s", exc)
        return []

    if result.returncode != 0:
        logger.debug(
            "Vol3 plugin path discovery rc=%d", result.returncode,
        )
        return []

    raw = f"{result.stdout or ''}\n{result.stderr or ''}"
    paths: set[str] = set()
    for match in re.finditer(r"\b(?:windows|linux|mac)\.[A-Za-z0-9_.]+\b", raw):
        paths.add(match.group(0))

    return sorted(paths)


VOL3_DISCOVERY_ACTIVE: bool = False
VOL3_DISCOVERED_PLUGIN_COUNT: int = 0
VOL3_ALIAS_FALLBACK_COUNT: int = 0


def _build_volatility_plugins() -> dict[str, str]:
    """Derive the Vol3 plugin surface from runtime discovery only.

    The surface is what runtime discovery reports. Canonical aliases are
    applied only to plugin paths that were actually discovered. No
    undiscovered Vol3 plugin is advertised to MCP or Inv1.

    Canonical aliases are inserted before remaining discovered plugins so
    Windows canonical names win over cross-platform short-name collisions
    such as ``vol_pstree``.
    """
    global VOL3_DISCOVERY_ACTIVE, VOL3_DISCOVERED_PLUGIN_COUNT
    global VOL3_ALIAS_FALLBACK_COUNT

    discovered = _discover_volatility_windows_plugins()
    raw_paths = _discover_vol_plugin_paths()

    if not discovered or not raw_paths:
        VOL3_DISCOVERY_ACTIVE = False
        VOL3_DISCOVERED_PLUGIN_COUNT = 0
        VOL3_ALIAS_FALLBACK_COUNT = 0
        logger.warning(
            "Vol3 dynamic discovery unavailable -- no undiscovered "
            "plugins will be advertised."
        )
        return {}

    raw_path_set = set(raw_paths)

    surface: dict[str, str] = {}
    seen_paths: set[str] = set()

    # Canonical aliases first. This preserves stable Windows names when
    # another platform exposes the same short name.
    for canonical_name, plugin_path in sorted(_VOL_CANONICAL_ALIASES.items()):
        if plugin_path not in raw_path_set:
            continue
        surface[canonical_name] = plugin_path
        seen_paths.add(plugin_path)

    # Remaining runtime-discovered plugins. Never overwrite a canonical
    # alias name, and never advertise a duplicate plugin path.
    for discovered_name, plugin_path in sorted(discovered.items()):
        if plugin_path in seen_paths:
            continue
        if discovered_name in surface:
            continue
        surface[discovered_name] = plugin_path
        seen_paths.add(plugin_path)

    VOL3_DISCOVERY_ACTIVE = True
    VOL3_DISCOVERED_PLUGIN_COUNT = len(surface)
    VOL3_ALIAS_FALLBACK_COUNT = 0
    logger.info("Vol3 plugins: %d dynamically discovered", len(surface))
    return surface


VOLATILITY_PLUGINS: dict[str, str] = _build_volatility_plugins()


def _is_vol_os_incompat_v1(message) -> bool:
    """True when a Vol3 failure means the plugin cannot run on THIS evidence's
    OS/format (a capability fact, not a pipeline bug) -> classify not_applicable."""
    mm = str(message or "").lower()
    return any(s in mm for s in (
        "plugin incompatible with this memory image",
        "missing symbol table for this os version",
        "unable to identify memory image format",
        "required vol3 component not available",
        "no image path provided",
        "no volatility plugin mapped",
    ))


def _clean_vol3_error(tool_name: str, stderr: str) -> str:
    """Extract a clean one-liner from Vol3 stderr for user-facing logging.

    Raw Vol3 errors contain framework banners, stack traces, and automagic
    warnings that are confusing in judge-facing output.  The full detail is
    always logged at DEBUG level by the caller.
    """
    lower = stderr.lower()
    if "layerstacker" in lower or "automagic" in lower:
        return f"{tool_name}: plugin incompatible with this memory image"
    if "unsatisfied" in lower:
        return f"{tool_name}: missing symbol table for this OS version"
    if "no suitable address space" in lower:
        return f"{tool_name}: unable to identify memory image format"
    if "not available" in lower or "not found" in lower:
        return f"{tool_name}: required Vol3 component not available"
    return (f"{tool_name}: unavailable on this evidence "
            "(Vol3 plugin limitation -- not a pipeline error)")


# ── Live Volatility execution ────────────────────────────────────────


def _parse_vol_csv(raw_output: str) -> list[dict]:
    """Parse Volatility 3 CSV output generically.

    Skips preamble (``Volatility 3 Framework``, ``Progress:`` lines) and
    blank lines, then treats the first comma-containing line with 2+
    fields as the header row.  Works for *any* Vol3 plugin (SSDT,
    callbacks, etc.) -- no fixed-list column markers.
    """
    raw_lines = [l.rstrip("\r") for l in raw_output.splitlines() if l.strip()]

    for i, line in enumerate(raw_lines):
        if line.startswith(("Volatility 3 Framework", "Progress:")):
            continue
        if "," not in line:
            continue
        # Candidate header found -- collect remaining non-preamble lines
        cleaned = [
            l for l in raw_lines[i:]
            if not l.startswith("Volatility 3 Framework")
            and not l.startswith("Progress:")
        ]
        reader = csv.reader(io.StringIO("\n".join(cleaned)))
        headers = next(reader, None)
        if not headers or len(headers) < 2:
            continue
        width = len(headers)
        rows: list[dict] = []
        for row in reader:
            if not row:
                continue
            # Pad short rows, collapse overflow into last column
            if len(row) < width:
                row += [""] * (width - len(row))
            elif len(row) > width:
                row = row[:width - 1] + [",".join(row[width - 1:])]
            rows.append(dict(zip(headers, row)))
        return rows
    return []


def _flatten_vol_tree(records: list[dict]) -> list[dict]:
    """Flatten Vol3 JSON tree output (e.g. pstree __children) to flat list."""
    flat: list[dict] = []
    def _walk(node: dict, depth: int = 0) -> None:
        entry = {k: v for k, v in node.items() if k != "__children"}
        entry["TreeDepth"] = depth
        flat.append(entry)
        for child in node.get("__children", []):
            _walk(child, depth + 1)
    for record in records:
        if "__children" in record:
            _walk(record)
        else:
            flat.append(record)
    return flat


class VolatilityTimeout(Exception):
    """Raised when a Volatility 3 plugin subprocess exceeds its timeout.

    Intentionally NOT a subclass of RuntimeError so wrapper-level
    `except RuntimeError` clauses do not swallow it. Propagates to
    coordinator for typed failure_mode classification.
    """
    pass


# Run-level result cache: a Volatility plugin is deterministic for a given
# (tool, image), so a ReAct re-run of e.g. vol_malfind per PID need not
# re-execute the ~30s plugin + CSV retry. Keyed on (tool_name, image_path);
# only SUCCESSFUL results are stored, so a timeout/failure stays retryable.
# Per-process (the MCP server that serves ReAct calls). Kill-switch
# SIFT_TOOL_MEMO=0. Returns are isolated copies so a caller cannot mutate the
# cache. Universal: idempotent tool call, no detection change.
_TOOL_RESULT_CACHE: dict[tuple[str, str], list] = {}


def clear_tool_result_cache() -> None:
    """Drop all memoized tool results (test isolation / new run)."""
    _TOOL_RESULT_CACHE.clear()


def _copy_records(result):
    if isinstance(result, list):
        return [dict(r) if isinstance(r, dict) else r for r in result]
    return result


def run_volatility(tool_name: str, image_path: str) -> list[dict]:
    """Memoizing wrapper around the live Volatility runner (see
    _run_volatility_impl). Identical (tool, image) re-runs return the cached
    result instead of re-executing. SIFT_TOOL_MEMO=0 disables."""
    if os.environ.get("SIFT_TOOL_MEMO", "1") == "0":
        return _run_volatility_impl(tool_name, image_path)
    key = (str(tool_name), str(image_path))
    if key in _TOOL_RESULT_CACHE:
        return _copy_records(_TOOL_RESULT_CACHE[key])
    result = _run_volatility_impl(tool_name, image_path)   # may raise -> not cached
    _TOOL_RESULT_CACHE[key] = _copy_records(result)
    return _copy_records(result)


def _run_volatility_impl(tool_name: str, image_path: str) -> list[dict]:
    """Run Volatility 3 plugin live and return parsed JSON output.

    Raises VolatilityTimeout on subprocess timeout. Raises RuntimeError
    on non-zero exit or bad JSON. Callers distinguish tool failure from
    "0 records found" via exception type.
    """
    # SIFT_VOLATILITY_ARG_CONTRACT_COMMON_INJECTION_V1
    _sift_resolved_vol_image_path = resolve_volatility_image_path(
        tool_name=str(locals().get("tool_name") or locals().get("name") or ""),
        plugin_name=str(locals().get("plugin_name") or locals().get("plugin") or locals().get("vol_plugin") or ""),
        explicit_path=image_path,
        locals_map=locals(),
    )
    if _sift_resolved_vol_image_path:
        image_path = _sift_resolved_vol_image_path
    if not image_path:
        raise RuntimeError(
            f"{tool_name}: no image path provided (Vol3 requires -f <path>)")

    plugin = VOLATILITY_PLUGINS.get(tool_name)
    if not plugin:
        raise ValueError(f"No Volatility plugin mapped for {tool_name}")

    # SIFT_REACT_OS_COMPAT_RUNTIME_PLUGIN_GUARD_V1
    try:
        from sift_sentinel.analysis.react_os_tool_compat import resolve_vol_plugin as _sift_resolve_vol_plugin_v1
        _sift_l_v1 = locals()
        _sift_tool_v1 = (
            _sift_l_v1.get("tool_name")
            or _sift_l_v1.get("name")
            or _sift_l_v1.get("tool")
            or _sift_l_v1.get("tool_slug")
            or _sift_l_v1.get("vol_tool")
        )
        _sift_plugin_v1 = (
            _sift_l_v1.get("plugin")
            or _sift_l_v1.get("plugin_name")
            or _sift_l_v1.get("vol_plugin")
            or _sift_l_v1.get("plugin_path")
            or _sift_l_v1.get("volatility_plugin")
        )
        _sift_mount_v1 = (
            _sift_l_v1.get("disk_mount")
            or _sift_l_v1.get("mount")
            or _sift_l_v1.get("mount_path")
            or _sift_l_v1.get("disk_mount_path")
        )
        _sift_decision_v1 = _sift_resolve_vol_plugin_v1(
            tool_name=_sift_tool_v1,
            plugin_name=_sift_plugin_v1,
            disk_mount=_sift_mount_v1,
        )
        if _sift_decision_v1.get("action") == "replace":
            _sift_new_plugin_v1 = _sift_decision_v1.get("plugin")
            if "plugin" in _sift_l_v1:
                plugin = _sift_new_plugin_v1
            if "plugin_name" in _sift_l_v1:
                plugin_name = _sift_new_plugin_v1
            if "vol_plugin" in _sift_l_v1:
                vol_plugin = _sift_new_plugin_v1
            if "plugin_path" in _sift_l_v1:
                plugin_path = _sift_new_plugin_v1
            if "volatility_plugin" in _sift_l_v1:
                volatility_plugin = _sift_new_plugin_v1
            try:
                logger.warning(
                    "REACT_OS_COMPAT_TOOL_GATE=REWRITE tool=%s old_plugin=%s new_plugin=%s os=%s",
                    _sift_decision_v1.get("tool"),
                    _sift_decision_v1.get("old_plugin"),
                    _sift_decision_v1.get("plugin"),
                    _sift_decision_v1.get("evidence_os"),
                )
            except Exception:
                pass
        elif _sift_decision_v1.get("action") == "block":
            try:
                logger.warning(
                    "REACT_OS_COMPAT_TOOL_GATE=BLOCK tool=%s plugin=%s os=%s reason=%s",
                    _sift_decision_v1.get("tool"),
                    _sift_decision_v1.get("old_plugin"),
                    _sift_decision_v1.get("evidence_os"),
                    _sift_decision_v1.get("reason"),
                )
            except Exception:
                pass
            return {
                "status": "unavailable_wrong_os_tool",
                "records": [],
                "tool": _sift_decision_v1.get("tool"),
                "plugin": _sift_decision_v1.get("old_plugin"),
                "reason": _sift_decision_v1.get("reason"),
                "evidence_os": _sift_decision_v1.get("evidence_os"),
                "can_support_finding": False,
            }
    except Exception as _sift_compat_e_v1:
        try:
            logger.warning("REACT_OS_COMPAT_TOOL_GATE=ERROR %s", _sift_compat_e_v1)
        except Exception:
            pass

    logger.info("LIVE VOL: Running %s (%s) on %s",
                tool_name, plugin, image_path)
    try:
        timeout_s = _effective_vol_timeout(tool_name)
        result = subprocess.run(
            [*VOL_CMD, "-f", image_path, "-r", "json", plugin],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        raise VolatilityTimeout(
            f"{tool_name} timed out after {timeout_s}s") from exc

    if result.returncode != 0:
        logger.debug("Vol3 detail for %s (rc=%d): %s",
                      tool_name, result.returncode, result.stderr.strip())
        raise RuntimeError(_clean_vol3_error(tool_name, result.stderr))

    # rc=0 with EMPTY stdout = the plugin ran and found nothing = 0 records,
    # NOT a failure. Some vol3 plugins (e.g. windows.mftscan) emit empty stdout
    # instead of "[]" on an empty result set; json.loads("") then raised a
    # JSONDecodeError and the tool was wrongly marked failed. rc!=0 is already
    # handled above, so here rc==0 -> a genuinely empty scan. Universal across
    # every vol_* tool (they all run through this path); dataset-agnostic.
    if not (result.stdout or "").strip():
        logger.info("LIVE VOL: %s returned 0 records (empty result set)", tool_name)
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.debug("Vol3 JSON parse detail for %s: %s", tool_name, exc)
        raise RuntimeError(
            f"{tool_name}: output not parseable (Vol3 JSON error)") from exc

    # Flatten nested tree output (e.g. pstree __children)
    if isinstance(data, list) and any(
        isinstance(r, dict) and "__children" in r for r in data
    ):
        data = _flatten_vol_tree(data)
        logger.info("LIVE VOL: %s flattened tree to %d records",
                     tool_name, len(data))

    # CSV fallback: some plugins return [] in JSON mode
    _KNOWN_LEGITIMATELY_EMPTY = {"vol_hollowprocesses", "vol_svcdiff"}
    if isinstance(data, list) and len(data) == 0 and tool_name not in _KNOWN_LEGITIMATELY_EMPTY:
        logger.info("LIVE VOL: %s JSON empty, retrying with CSV", tool_name)
        try:
            csv_result = subprocess.run(
                [*VOL_CMD, "-f", image_path, "-r", "csv", plugin],
                capture_output=True, text=True, timeout=timeout_s,
            )
            if csv_result.returncode == 0 and csv_result.stdout.strip():
                data = _parse_vol_csv(csv_result.stdout)
                logger.info(
                    "LIVE VOL: %s CSV fallback returned %d records",
                    tool_name, len(data),
                )
        except (subprocess.TimeoutExpired, Exception) as exc:
            logger.debug("Vol3 CSV fallback detail for %s: %s",
                          tool_name, exc)
            logger.warning(
                "LIVE VOL: %s CSV fallback also unavailable", tool_name)

    logger.info("LIVE VOL: %s returned %d records",
                 tool_name, len(data) if isinstance(data, list) else 1)
    return data


def make_envelope(tool_name: str, evidence_path: str,
                  output, start_ms: int) -> dict:
    """Build the standard tool response envelope.
    output can be a list (record_count = len) or a dict (record_count from caller)."""
    elapsed = int((time.monotonic() * 1000) - start_ms)
    if isinstance(output, list):
        record_count = len(output)
    elif isinstance(output, dict) and "entries" in output:
        record_count = len(output["entries"])
    elif isinstance(output, dict) and "events" in output:
        record_count = len(output["events"])
    else:
        record_count = 0
    return {
        "tool_name": tool_name,
        "execution_time_ms": max(elapsed, 0),
        "evidence_path": evidence_path,
        "record_count": record_count,
        "output": output,
    }


def start_timer() -> int:
    """Return current monotonic time in ms for envelope timing."""
    return int(time.monotonic() * 1000)


def check_disk_path(disk_path: str) -> None:
    """Validate disk_path for disk forensic tools."""
    if not disk_path or not isinstance(disk_path, str):
        raise FileNotFoundError(f"Invalid disk path: {disk_path}")
    p = Path(disk_path)
    if not p.is_absolute():
        raise FileNotFoundError(f"Disk path must be absolute: {disk_path}")
    if not p.exists() and os.environ.get("SIFT_DRY_RUN") != "1":
        raise FileNotFoundError(f"Disk path not found: {disk_path}")


# ── Task 1.5: Invocation helpers ──────────────────────────────────────

# Tool priority for prepare_prompt: higher = included first when trimming.
# Based on Hunt Evil poster importance and forensic value.
_TOOL_PRIORITY = {
    "vol_malfind": 100,     # injected code -- highest signal
    "vol_cmdline": 95,      # attacker intent in args
    "vol_pstree": 90,       # parent-child = Hunt Evil question
    "vol_netscan": 85,      # C2 connections
    "get_amcache": 80,      # execution proof + SHA1
    "vol_ssdt": 75,         # kernel integrity
    "extract_mft_timeline": 70,  # timestomp detection
    "vol_psscan": 65,       # hidden process detection
    "parse_event_logs": 60,
    "parse_registry": 55,
    "vol_dlllist": 50,      # large, lower priority
    "vol_filescan": 40,     # very large
    "vol_handles": 30,      # massive, lowest priority
}
_DEFAULT_PRIORITY = 45


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return len(text) // 4


def strip_markdown_fences(raw_output: str) -> str:
    """Remove ```json``` or ``` ``` wrappers from LLM output.
    Handles leading text and multiple fence blocks (uses the last block)."""
    stripped = raw_output.strip()
    if not stripped:
        return ""
    # Find ALL opening fences; use the LAST one (handles multi-block output)
    matches = list(re.finditer(r"```(?:json)?\s*\n", stripped))
    if matches:
        start = matches[-1].end()
        # Find the FIRST closing fence after the last opening fence
        end = stripped.find("```", start)
        if end != -1:
            return stripped[start:end].strip()
    return stripped


def _extract_first_json_object(text: str) -> str:
    """Return the first complete JSON object from *text*.

    Strips markdown fences (``` or ```json) and ignores anything after the
    first balanced closing brace. Tolerates:
      - trailing prose ({"a":1}\\n\\nthanks!)
      - back-to-back objects ({"a":1}{"b":2})
      - braces inside strings ({"a":"x}y"} extra)
      - nested objects/arrays

    If no complete object is found, returns the original text so that
    json.loads raises a standard JSONDecodeError rather than masking it.
    """
    if not text:
        return ""
    t = text.strip()
    for fence in ("```json", "```"):
        if t.startswith(fence):
            t = t[len(fence):].lstrip()
            break
    if t.endswith("```"):
        t = t[:-3].rstrip()
    # If there is preamble before the first {, skip ahead to the brace.
    first_brace = t.find("{")
    if first_brace > 0 and not t.startswith(("[", "{")):
        t = t[first_brace:]
    depth = 0
    end = -1
    in_string = False
    escape = False
    for i, ch in enumerate(t):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    return t[:end] if end > 0 else t


def prepare_prompt(tool_outputs: dict[str, dict],
                   token_budget: int) -> str:
    """Filter and trim tool outputs to fit within token budget.
    Prioritizes high-value tools (malfind, cmdline, pstree) and truncates
    large outputs (dlllist, handles) to stay within context limits.

    Returns a formatted string ready for Invocation 2 system prompt."""
    if not tool_outputs:
        return ""

    # Sort tools by priority (highest first)
    sorted_tools = sorted(
        tool_outputs.items(),
        key=lambda kv: _TOOL_PRIORITY.get(kv[0], _DEFAULT_PRIORITY),
        reverse=True,
    )

    sections: list[str] = []
    tokens_used = 0
    # Reserve 500 tokens for framing text
    effective_budget = token_budget - 500

    for tool_name, tool_data in sorted_tools:
        output = tool_data.get("output", [])
        record_count = tool_data.get("record_count", 0)

        # Serialize the output
        serialized = json.dumps(output, separators=(",", ":"))
        output_tokens = _estimate_tokens(serialized)

        # Calculate remaining budget for this tool
        remaining = effective_budget - tokens_used
        if remaining <= 0:
            break

        if output_tokens <= remaining:
            # Fits entirely
            section = (f"=== {tool_name} ({record_count} records) ===\n"
                       f"{serialized}")
        else:
            # Truncate: take records until we hit budget
            section = _truncate_output(
                tool_name, output, record_count, remaining
            )

        section_tokens = _estimate_tokens(section)
        if section_tokens > remaining:
            # Even truncated section is too large, try minimal header
            if remaining > 100:
                section = (f"=== {tool_name} ({record_count} records) "
                           f"[TRUNCATED -- {output_tokens} tokens, "
                           f"budget exhausted] ===")
            else:
                break

        sections.append(section)
        tokens_used += _estimate_tokens(section)

    return "\n\n".join(sections)


def _truncate_output(tool_name: str, output: Any,
                     record_count: int, token_budget: int) -> str:
    """Truncate a tool's output to fit within token_budget tokens."""
    header = f"=== {tool_name} ({record_count} records) [TRUNCATED] ===\n"
    header_tokens = _estimate_tokens(header)
    data_budget = token_budget - header_tokens

    if isinstance(output, list):
        # Take records from the front until budget hit
        kept: list = []
        used = 0
        for record in output:
            chunk = json.dumps(record, separators=(",", ":"))
            chunk_tokens = _estimate_tokens(chunk)
            if used + chunk_tokens > data_budget:
                break
            kept.append(record)
            used += chunk_tokens
        serialized = json.dumps(kept, separators=(",", ":"))
        return header + serialized
    elif isinstance(output, dict):
        # For dict outputs (amcache, mft), truncate inner lists
        trimmed = {}
        used = 0
        for key, val in output.items():
            if isinstance(val, list):
                kept_items: list = []
                for item in val:
                    chunk = json.dumps(item, separators=(",", ":"))
                    chunk_tokens = _estimate_tokens(chunk)
                    if used + chunk_tokens > data_budget:
                        break
                    kept_items.append(item)
                    used += chunk_tokens
                trimmed[key] = kept_items
            else:
                trimmed[key] = val
        serialized = json.dumps(trimmed, separators=(",", ":"))
        return header + serialized
    else:
        serialized = json.dumps(output, separators=(",", ":"))
        return header + serialized[:data_budget * 4]


# ── Ollama-specific prompt builder ─────────────────────────────────────

_OLLAMA_KEY_FIELDS = (
    "PID", "PPID", "ImageFileName", "Owner", "LocalAddr",
    "ForeignAddr", "State", "CreateTime", "executable",
    "path", "Name", "Offset(V)", "CommandLine",
)


_SAFE_PROCESSES = frozenset({
    "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "RuntimeBroker.exe", "SearchUI.exe", "ShellExperienceHost.exe",
    "sihost.exe", "taskhostw.exe", "fontdrvhost.exe", "WmiPrvSE.exe",
    "spoolsv.exe", "dllhost.exe", "conhost.exe", "SearchIndexer.exe",
    "SecurityHealthService.exe", "MsMpEng.exe", "NisSrv.exe", "msdtc.exe",
    "LogonUI.exe", "MemCompression", "Registry", "Idle", "vmmem",
})

_SAFE_NETSCAN_STATES = frozenset({"CLOSED", "CLOSE_WAIT", "TIME_WAIT"})

_SECURITY_EVENT_IDS = frozenset({4624, 4625, 4688, 7045, 4103, 4104})

_SAFE_AMCACHE_PREFIXES = (
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
    "c:\\program files\\", "c:\\program files (x86)\\",
)


def _summarise_processes(records: list, count: int) -> tuple[str, list[str]]:
    """Summarise pstree/psscan: non-safe processes first, count of safe."""
    safe_count = 0
    interesting: list[dict] = []
    for rec in records if isinstance(records, list) else []:
        if not isinstance(rec, dict):
            continue
        name = rec.get("ImageFileName", "")
        if name in _SAFE_PROCESSES:
            safe_count += 1
        else:
            interesting.append(rec)
    other_count = count - safe_count
    header = f"{count} processes ({safe_count} known Windows, {other_count} OTHER)"
    lines: list[str] = []
    for rec in interesting:
        parts = [f"{k}={rec[k]}" for k in _OLLAMA_KEY_FIELDS if k in rec]
        if parts:
            lines.append("  " + ", ".join(parts))
    return header, lines


def _addr_scope(addr: str) -> str:
    """RFC1918/loopback/link-local/reserved -> 'internal'; public -> 'external'; unknown/wildcard -> ''. Dataset-agnostic (no literals)."""
    a = (addr or "").strip()
    if not a or a in ("*", "0.0.0.0", "::"):
        return ""
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return ""
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
        return "internal"
    return "external"


def _summarise_netscan(records: list, count: int) -> tuple[str, list[str]]:
    """Summarise netscan: ESTABLISHED/LISTENING/UDP first, skip CLOSED, external first."""
    active: list[dict] = []
    for rec in records if isinstance(records, list) else []:
        if not isinstance(rec, dict):
            continue
        state = rec.get("State", "")
        if state in _SAFE_NETSCAN_STATES:
            continue
        active.append(rec)
    # Sort: external IPs first (not 127.0.0.1, 0.0.0.0, *), then by state
    def _sort_key(r: dict) -> tuple:
        foreign = r.get("ForeignAddr", "")
        is_local = (foreign.startswith("127.") or foreign in ("0.0.0.0", "", "*"))
        state = r.get("State", "")
        state_rank = 0 if state == "ESTABLISHED" else (1 if state == "LISTENING" else 2)
        return (is_local, state_rank)
    active.sort(key=_sort_key)
    skipped = count - len(active)
    header = f"{count} connections ({len(active)} active, {skipped} closed/inactive)"
    lines: list[str] = []
    for rec in active:
        pid = rec.get("PID", "?")
        owner = rec.get("Owner", rec.get("ImageFileName", "?"))
        state = rec.get("State", "")
        local = rec.get("LocalAddr", "?")
        local_port = rec.get("LocalPort", "")
        foreign = rec.get("ForeignAddr", "?")
        foreign_port = rec.get("ForeignPort", "")
        local_str = f"{local}:{local_port}" if local_port else local
        foreign_str = f"{foreign}:{foreign_port}" if foreign_port else foreign
        # UDP listeners have empty State
        label = state if state else "UDP"
        if label in ("LISTENING", "UDP"):
            lines.append(f"  PID {pid} {owner} {label} {local_str}")
        else:
            _scope = _addr_scope(foreign)
            _tag = f" [{_scope}]" if _scope else ""
            lines.append(f"  PID {pid} {owner} {label} {local_str} -> {foreign_str}{_tag}")
    return header, lines


def _summarise_amcache(records: list, count: int) -> tuple[str, list[str]]:
    """Summarise amcache: skip known Windows system paths."""
    interesting: list[dict] = []
    safe_count = 0
    for rec in records if isinstance(records, list) else []:
        if not isinstance(rec, dict):
            continue
        path = (rec.get("path", "") or rec.get("Path", "") or "").lower()
        if any(path.startswith(p) for p in _SAFE_AMCACHE_PREFIXES):
            safe_count += 1
        else:
            interesting.append(rec)
    header = f"{count} entries ({safe_count} Windows system, {len(interesting)} OTHER)"
    lines: list[str] = []
    for rec in interesting:
        parts = [f"{k}={rec[k]}" for k in _OLLAMA_KEY_FIELDS if k in rec]
        if parts:
            lines.append("  " + ", ".join(parts))
    return header, lines


_SAFE_PREFETCH = frozenset({
    n.upper() for n in _SAFE_PROCESSES
    if not n.endswith(("Compression", "Registry", "Idle", "vmmem"))
}) | frozenset({
    "AUDIODG.EXE", "BACKGROUNDTASKHOST.EXE", "BACKGROUNDTRANSFERHOST.EXE",
    "COMPATTELRUNNER.EXE", "CONSENT.EXE", "CTFMON.EXE", "DEFRAG.EXE",
    "DEVICECENSUS.EXE", "DISMHOST.EXE", "MICROSOFTEDGE.EXE",
    "MICROSOFTEDGECP.EXE", "MOBSYNC.EXE", "MPCMDRUN.EXE", "MSASCUIL.EXE",
    "MSCORSVW.EXE", "NGEN.EXE", "NGENTASK.EXE", "OPENWITH.EXE",
    "SEARCHFILTERHOST.EXE", "SEARCHPROTOCOLHOST.EXE", "SPLWOW64.EXE",
    "TIWORKER.EXE", "TRUSTEDINSTALLER.EXE", "UNREGMP2.EXE",
    "USERINIT.EXE", "VSSVC.EXE", "WERFAULT.EXE", "WMIADAP.EXE",
    "WMIPRVSE.EXE", "APPLICATIONFRAMEHOST.EXE", "ACCOUNTSCONTROLHOST.EXE",
    "SYSTEMSETTINGS.EXE", "SYSTEMSETTINGSADMINFLOWS.EXE",
})


def _summarise_prefetch(records: list, count: int) -> tuple[str, list[str]]:
    """Summarise prefetch: filter safe Windows executables, show interesting ones."""
    interesting: list[str] = []
    safe_count = 0
    seen: set[str] = set()  # deduplicate by executable name
    for rec in records if isinstance(records, list) else []:
        if isinstance(rec, dict):
            name = rec.get("executable_name",
                           rec.get("executable",
                           rec.get("Name",
                           rec.get("ImageFileName", "?"))))
            name_upper = (name or "?").upper()
            if name_upper in _SAFE_PREFETCH:
                safe_count += 1
                continue
            if name_upper in seen:
                safe_count += 1
                continue
            seen.add(name_upper)
            run_count = rec.get("run_count", rec.get("RunCount", "?"))
            last_runs = rec.get("last_run_times", None)
            if isinstance(last_runs, list) and last_runs:
                last_run = last_runs[0]
            else:
                last_run = rec.get("last_run", rec.get("LastRun",
                           rec.get("CreateTime", "?")))
            interesting.append(f"  {name} (run count: {run_count}, last: {last_run})")
        elif isinstance(rec, str):
            interesting.append(f"  {rec[:120]}")
    header = f"{count} entries ({safe_count} known Windows, {len(interesting)} OTHER)"
    return header, interesting


def _summarise_event_logs(records: list, count: int) -> tuple[str, list[str]]:
    """Summarise event logs: prioritize security event IDs."""
    priority: list[dict] = []
    other_count = 0
    for rec in records if isinstance(records, list) else []:
        if not isinstance(rec, dict):
            continue
        eid = rec.get("EventId", rec.get("EventID", rec.get("event_id", None)))
        try:
            eid_int = int(eid) if eid is not None else None
        except (ValueError, TypeError):
            eid_int = None
        if eid_int in _SECURITY_EVENT_IDS:
            priority.append(rec)
        else:
            other_count += 1
    header = f"{count} events ({len(priority)} security, {other_count} routine)"
    lines: list[str] = []
    for rec in priority:
        parts = [f"{k}={rec[k]}" for k in _OLLAMA_KEY_FIELDS if k in rec]
        if parts:
            lines.append("  " + ", ".join(parts))
    if other_count:
        lines.append(f"  ... and {other_count} routine events omitted")
    return header, lines


def _summarise_generic(records: list, count: int) -> tuple[str, list[str]]:
    """Default summariser: first 10 records with key fields."""
    header = f"{count} records"
    lines: list[str] = []
    for rec in (records[:10] if isinstance(records, list) else []):
        if isinstance(rec, dict):
            parts = [f"{k}={rec[k]}" for k in _OLLAMA_KEY_FIELDS if k in rec]
            if parts:
                lines.append("  " + ", ".join(parts))
        elif isinstance(rec, str):
            lines.append("  " + rec[:100])
    if count > 10:
        lines.append(f"  ... and {count - 10} more records")
    return header, lines


# Map tool name prefixes to specialised summarisers
_TOOL_SUMMARISERS: dict[str, Callable] = {
    "vol_pstree": _summarise_processes,
    "vol_psscan": _summarise_processes,
    "vol_netscan": _summarise_netscan,
    "get_amcache": _summarise_amcache,
    "parse_prefetch": _summarise_prefetch,
    "parse_event_logs": _summarise_event_logs,
}


def build_ollama_inv2_prompt(
    all_outputs: dict[str, Any],
    *,
    tool_failures: list[dict] | None = None,
    max_data_chars: int = 18000,
) -> str:
    """Build a data-first Inv2 prompt optimised for Ollama/Qwen models.

    Qwen returns ``{}`` when instructions dominate and tool data is truncated
    out.  This builder puts concise, plain-text tool summaries FIRST, then
    appends minimal schema instructions.  Smart filtering prioritises
    suspicious data over known-good Windows noise.

    ``max_data_chars`` budgets the tool-summary blob only. The surrounding
    schema, citation rules (Fix A), ATT&CK granularity block (Fix B, CC#17b
    expanded to all 10 tactics), and known-good list add ~6k characters on
    top, keeping the composed prompt under the 25k upper bound that Qwen
    can handle reliably.
    """
    sections: list[str] = []
    # Deduplicate pstree/psscan: if both present, prefer psscan (flat list).
    seen_process_tool = False
    for tname, tdata in all_outputs.items():
        if isinstance(tdata, dict):
            records = tdata.get("output", [])
            count = tdata.get("record_count",
                              len(records) if isinstance(records, list) else 0)
        elif isinstance(tdata, list):
            records = tdata
            count = len(records)
        else:
            continue
        if count == 0:
            continue
        # Unwrap nested output formats (e.g. amcache: output={"entries": [...]})
        if isinstance(records, dict):
            # Try common nested keys
            for key in ("entries", "results", "items", "data"):
                if key in records and isinstance(records[key], list):
                    records = records[key]
                    break
            else:
                continue  # dict output with no recognisable list key
        # Deduplicate: only include one of pstree/psscan
        if tname in ("vol_pstree", "vol_psscan"):
            if seen_process_tool:
                continue
            seen_process_tool = True
        summariser = _TOOL_SUMMARISERS.get(tname, _summarise_generic)
        header, lines = summariser(records, count)
        sections.append(f"\n{tname} ({header}):")
        sections.extend(lines)

    tool_text = "\n".join(sections)
    if len(tool_text) > max_data_chars:
        tool_text = tool_text[:max_data_chars] + "\n... (truncated)"

    # Import locally to avoid a circular import during module load (tools
    # common.py is imported by known_good.py consumers).
    from sift_sentinel.known_good import render_known_good_block
    from sift_sentinel.prompts import (
        render_attack_granularity,
        render_citation_rules,
    )
    prompt = (
        "You are a DFIR analyst. Analyze this forensic tool output "
        "and return structured findings.\n\n"
        "TOOL OUTPUTS:\n" + tool_text + "\n\n"
        + render_citation_rules() + "\n"
        + render_attack_granularity() + "\n"
        + render_known_good_block() + "\n"
        'Return ONLY valid JSON: {"findings": [...]}\n'
        "Each finding must have:\n"
        "- finding_id (F followed by a zero-padded sequence number)\n"
        "- artifact (what you found, plain English)\n"
        "- confidence (HIGH, MEDIUM, or LOW)\n"
        "- claims: array of claims, each with type (pid/path/connection/hash),\n"
        "  the value, and source_tools array\n"
        "- source_tools: which tools provided the evidence\n\n"
        "CRITICAL: Each finding MUST have 2+ claims from DIFFERENT tools.\n"
        "Use exact PIDs, IPs, filenames from the data above.\n\n"
        "CRITICAL RULES:\n"
        "1. Every PID claim MUST include the exact PID number from the tool data above.\n"
        '   WRONG: {"type": "pid", "pid": null, "process": "find.exe"}\n'
        '   RIGHT: {"type": "pid", "pid": <PID_FROM_DATA>, "process": "<NAME_FROM_DATA>"}\n'
        "2. If you cannot find an exact PID in the data, do NOT make a PID claim.\n"
        "3. Every value in your claims must appear EXACTLY in the tool output above.\n"
        "4. Do NOT invent, guess, or reference example PIDs.\n"
    )
    if tool_failures:
        fail_names = [f.get("tool", "unknown") for f in tool_failures]
        prompt += f"\nFailed tools (no data): {', '.join(fail_names)}\n"
    return prompt


def run_tools_parallel(
    tasks: dict[str, tuple[Callable, tuple]],
    max_workers: int = 8,
) -> dict[str, dict]:
    """Run tool functions in parallel using ThreadPoolExecutor.
    tasks: {name: (callable, args_tuple)}
    Returns: {name: result_dict} -- failed tools get {"error": str}."""
    if not tasks:
        return {}

    results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {
            executor.submit(fn, *args): name
            for name, (fn, args) in tasks.items()
        }
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {
                    "tool_name": name,
                    "error": f"{type(exc).__name__}: {exc}",
                }

    return results

# SIFT_SSDT_RUNTIME_GUARD_V2_INSTALL
try:
    from sift_sentinel.analysis.ssdt_runtime_guard import install as _sift_install_ssdt_runtime_guard_v2
    _sift_install_ssdt_runtime_guard_v2()
except Exception:
    pass



# SIFT_CI_PATH_RESOLVER_V1
def resolve_path_ci(base, *parts):
    """Case-insensitive path resolution under *base*.

    Walks each segment, matching the on-disk name case-insensitively so
    'Windows' resolves 'WINDOWS', 'System32' resolves 'system32', etc.
    Returns the resolved Path when every segment is found; otherwise returns
    the naive join so callers' .exists()/.is_dir() checks behave exactly as
    before. Dataset-agnostic: encodes no fixed path, resolves whatever casing
    the mounted image uses.
    """
    from pathlib import Path as _P
    cur = _P(base)
    for part in parts:
        if part in (None, ""):
            continue
        direct = cur / part
        if direct.exists():
            cur = direct
            continue
        match = None
        try:
            target = str(part).lower()
            for child in cur.iterdir():
                if child.name.lower() == target:
                    match = child
                    break
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            match = None
        cur = match if match is not None else direct
    return cur
