"""
SIFT Sentinel - MCP Server.
Exposes forensic tools as typed MCP functions via dynamic registration
from _TOOL_REGISTRY plus 9 hardcoded meta/orphan tools.

ZERO bash access. 100% typed functions. AI never constructs command syntax.

MCP surface: 186 registry-driven + 9 hardcoded = 195 tools.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import pathlib
import sys
from typing import Optional

from sift_sentinel.shutdown_util import is_benign_shutdown_exc
from sift_sentinel.tools.parse_registry_persistence import parse_registry_persistence
from sift_sentinel.tools.parse_scheduled_tasks_disk import parse_scheduled_tasks_disk
from sift_sentinel.tools.extract_network_iocs import extract_network_iocs

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    class FastMCP:  # type: ignore[no-redef]
        def __init__(self, name: str, instructions: str = "") -> None:
            self.name = name
            self.instructions = instructions
            self._tool_manager = type(
                "TM", (),
                {"_tools": {}, "add_tool": lambda *a, **k: None},
            )()

        def tool(self, *args, **kwargs):
            def _decorator(fn):
                return fn
            return _decorator

        def run(self, *args, **kwargs) -> None:
            raise RuntimeError(
                "mcp package not installed; cannot run MCP server. "
                "Install with: pip install mcp>=1.0"
            )

# Trigger _TOOL_REGISTRY population BEFORE dynamic registration loop (gate 6a.5.14)
import sift_sentinel.coordinator
from sift_sentinel.coordinator import _TOOL_REGISTRY, new_tool_health

# Commit 26: Initialize per-subprocess tool health tracker.
# MCP server runs as subprocess spawned by mcp_client.py; Python
# subprocesses do not inherit module globals from parent process.
# Without this call, run_tool() dispatch at coordinator.py:1073 raises:
#   RuntimeError: new_tool_health() must be called at pipeline start.
# Tools with dedicated functions (arg_type: memory/standalone/disk_mft)
# bypass run_tool() and worked previously. This fix unblocks the ~160
# tools that route through run_tool() dispatch for vol_generic and
# ez_tools arg_types. Rule 5 "no persistent memory" remains enforced:
# subprocess dies with pipeline run, tracker dies with it.
new_tool_health()

# Orphan tool imports (kept hardcoded, no registry equivalent)
from sift_sentinel.tools.disk_extended import parse_shellbags
from sift_sentinel.tools.generic import (
    run_volatility_plugin,
    list_volatility_plugins,
    run_sleuthkit,
    run_log2timeline,
    run_regripper,
)
from sift_sentinel.tools.tool_catalog import (
    get_categories,
    get_tools_for_category,
    recommend_tools,
)
from sift_sentinel.config import DISK_MOUNT_PATH  # noqa: F401

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "sift-sentinel",
    instructions=(
        "SIFT Sentinel forensic MCP server. "
        "All tools return typed JSON with standard envelope: "
        "tool_name, execution_time_ms, evidence_path, record_count, output. "
        "No shell access. No raw command construction. "
        "172 forensic plugins via single-source registry, plus 9 meta and orphan tools."
    ),
)


# Docstring sources: curated > vol_help_cache > fn.__doc__ > fallback

_HERE = pathlib.Path(__file__).parent

try:
    _CURATED_DOCSTRINGS = json.loads((_HERE / "curated_docstrings.json").read_text())
except (FileNotFoundError, json.JSONDecodeError) as exc:
    logger.warning("curated_docstrings.json missing or invalid: %s", exc)
    _CURATED_DOCSTRINGS = {}

try:
    _VOL_HELP_CACHE_RAW = json.loads((_HERE / "vol_help_cache.json").read_text())
    _VOL_HELP_CACHE = {
        k: (v.get("description") if isinstance(v, dict) else str(v))
        for k, v in _VOL_HELP_CACHE_RAW.items()
    }
except (FileNotFoundError, json.JSONDecodeError) as exc:
    logger.warning("vol_help_cache.json missing or invalid: %s", exc)
    _VOL_HELP_CACHE = {}


def _resolve_docstring(tool_name: str, fn) -> str:
    if tool_name in _CURATED_DOCSTRINGS:
        return _CURATED_DOCSTRINGS[tool_name]
    if tool_name in _VOL_HELP_CACHE:
        return _VOL_HELP_CACHE[tool_name]
    if fn is not None and fn.__doc__:
        return fn.__doc__
    return f"{tool_name}: forensic tool (no description available)"


_DISPATCH_ARG_TYPES = frozenset({"vol_generic", "sift_native", "ez_tools", "sleuthkit"})


def _make_wrapper(tool_name: str, fn, arg_type: str, docstring: str):
    if fn is not None:
        @functools.wraps(fn)
        def _real_wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        _real_wrapper.__doc__ = docstring
        return _real_wrapper

    assert arg_type in _DISPATCH_ARG_TYPES, (
        f"Unexpected arg_type={arg_type!r} for fn=None tool {tool_name!r}. "
        f"Registry invariant: fn=None implies dispatch via coordinator.run_tool "
        f"(allowed arg_types: {sorted(_DISPATCH_ARG_TYPES)})."
    )

    def _dispatch_wrapper(
        image_path: str = "",
        disk_path: str = "",
        mft_start: str = "",
        mft_end: str = "",
        tool_args: list | None = None,
        evidence_type: str | None = None,
        disk_mount: str = "",
    ) -> dict:
        try:
            kwargs = {
                "tool_name": tool_name,
                "image_path": image_path,
                "disk_path": disk_path,
            }
            if mft_start:
                kwargs["mft_start"] = mft_start
            if mft_end:
                kwargs["mft_end"] = mft_end
            if tool_args is not None:
                kwargs["tool_args"] = tool_args
            if evidence_type is not None:
                kwargs["evidence_type"] = evidence_type
            if disk_mount:
                kwargs["disk_mount"] = disk_mount
            result = sift_sentinel.coordinator.run_tool(**kwargs)
            if not isinstance(result, dict):
                return {
                    "tool_name": tool_name,
                    "output": [],
                    "record_count": 0,
                    "failure_mode": "non_dict_return",
                    "error": f"run_tool returned {type(result).__name__}, expected dict",
                }
            return result
        except Exception as exc:
            return {
                "tool_name": tool_name,
                "output": [],
                "record_count": 0,
                "failure_mode": "dispatch_exception",
                "error": f"{type(exc).__name__}: {exc}",
            }
    _dispatch_wrapper.__name__ = f"tool_{tool_name}"
    _dispatch_wrapper.__doc__ = docstring
    return _dispatch_wrapper


# Dynamic registration loop

_REGISTERED_COUNT = 0
_FAILED_REGISTRATIONS: list[tuple[str, str]] = []

for _tool_name, (_fn, _arg_type) in _TOOL_REGISTRY.items():
    try:
        _doc = _resolve_docstring(_tool_name, _fn)
        _wrapper = _make_wrapper(_tool_name, _fn, _arg_type, _doc)
        _exposed_name = f"tool_{_tool_name}"
        mcp._tool_manager.add_tool(_wrapper, name=_exposed_name, description=_doc)
        setattr(sys.modules[__name__], _exposed_name, _wrapper)
        _REGISTERED_COUNT += 1
    except Exception as _exc:
        _FAILED_REGISTRATIONS.append((_tool_name, f"{type(_exc).__name__}: {_exc}"))
        logger.warning("Failed to register %s: %s", _tool_name, _exc)

logger.info(
    "MCP dynamic registration: %d / %d tools registered (%d failed)",
    _REGISTERED_COUNT, len(_TOOL_REGISTRY), len(_FAILED_REGISTRATIONS),
)


# Hardcoded orphan tools (9 total: 3 forensic + 6 meta)

@mcp.tool()
def tool_parse_shellbags(csv_path: str = "") -> dict:
    """Shellbags: folder access history, user activity timeline from pre-extracted shellbags CSV."""
    return parse_shellbags(csv_path)


@mcp.tool()
def tool_run_log2timeline(image_path: str, output_file: str = "/tmp/plaso.dump") -> dict:
    """Run log2timeline (Plaso) to generate super-timeline from evidence."""
    return run_log2timeline(image_path, output_file)


@mcp.tool()
def tool_run_regripper(hive_path: str, plugin: Optional[str] = None) -> dict:
    """Run RegRipper on a registry hive, optionally with a specific plugin."""
    return run_regripper(hive_path, plugin)


@mcp.tool()
def tool_get_investigation_categories() -> dict:
    """Returns 8 DFIR investigation categories for tool discovery."""
    return get_categories()


@mcp.tool()
def tool_get_tools_for_category(category: str) -> dict:
    """Returns list of tools for a given DFIR investigation category."""
    return get_tools_for_category(category)


@mcp.tool()
def tool_recommend_tools(question: str) -> dict:
    """Natural-language tool recommendation across the forensic tool catalog."""
    return recommend_tools(question)


@mcp.tool()
def tool_run_volatility(image_path: str, plugin: str) -> dict:
    """Generic Vol3 dispatcher. Runs any Volatility 3 plugin by plugin name."""
    return run_volatility_plugin(image_path, plugin)


@mcp.tool()
def tool_list_volatility_plugins() -> dict:
    """Returns list of available Volatility 3 plugins."""
    return list_volatility_plugins()


@mcp.tool()
def tool_run_sleuthkit(disk_path: str, command: str, args: Optional[list] = None) -> dict:
    """Generic Sleuthkit dispatcher. Runs any Sleuthkit command (fls, icat, mmls, ...) by name."""
    return run_sleuthkit(command, disk_path, args=args or [])


if __name__ == "__main__":
    # Reconcile the counts so '184 registered' and the 193-tool Inv1 catalog don't
    # read as a mismatch: total advertised = dynamic forensic + hardcoded core/meta.
    try:
        _total_adv = len(getattr(mcp._tool_manager, "_tools", {})) or _REGISTERED_COUNT
        _hardcoded = max(0, _total_adv - _REGISTERED_COUNT)
        logger.info(
            "MCP server advertises %d tools total (%d dynamic forensic + "
            "%d hardcoded core/meta)",
            _total_adv, _REGISTERED_COUNT, _hardcoded,
        )
    except Exception:
        pass

    # Backstop: if our parent (run_pipeline) dies abruptly (kill -9 / crash) before it can
    # reap us, take this whole detached session down too. We are spawned start_new_session,
    # so we LEAD our own process group -> killpg(our group) reaps us AND the Volatility
    # children we launched, without touching the launcher (a different group). This also
    # fires when run_pipeline reaps us with SIGTERM, so our vol children never orphan.
    def _install_pdeath_groupkill():
        import signal as _sig

        def _grp_kill(signum=None, frame=None):
            try:
                if os.getpgrp() == os.getpid():   # only if we truly lead our own group
                    os.killpg(os.getpgrp(), _sig.SIGKILL)
            except Exception:
                pass
            os._exit(143)

        try:
            import ctypes
            # PR_SET_PDEATHSIG = 1 -> deliver SIGTERM to us when our parent thread dies.
            ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, _sig.SIGTERM)
        except Exception:
            pass
        for _s in (_sig.SIGTERM, _sig.SIGHUP):
            try:
                _sig.signal(_s, _grp_kill)
            except Exception:
                pass

    try:
        _install_pdeath_groupkill()
    except Exception:
        pass

    # Graceful Ctrl-C: SIGINT reaches the whole foreground process group, so this MCP
    # subprocess gets it at the same instant as the launcher (step0_onboard), which owns
    # the user-facing "cleaning up / Goodbye". anyio surfaces the shutdown as a
    # KeyboardInterrupt or a BaseExceptionGroup of closed-pipe/cancelled errors -- swallow
    # those quietly so we do not dump a traceback over the launcher's message; re-raise
    # anything genuinely unexpected.
    try:
        mcp.run()
    except BaseException as _exc:  # noqa: BLE001 -- shutdown gate, re-raises non-benign
        if not is_benign_shutdown_exc(_exc):
            raise
    finally:
        # Pre-empt the interpreter-exit "Exception ignored in <stdout>: BrokenPipeError"
        # by pointing the std fds at /dev/null before the final buffer flush runs.
        try:
            _devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(_devnull, sys.stdout.fileno())
            os.dup2(_devnull, sys.stderr.fileno())
        except Exception:
            pass
