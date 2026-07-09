"""
Sentinel Qwen Ensemble - MCP Client.
Thin client that starts server.py as a subprocess and calls tools
through the MCP protocol via stdio transport.
"""

import asyncio
import json
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)


def _flatten_exc(exc: BaseException) -> str:
    """Unwrap ExceptionGroup so the real error messages are visible."""
    if hasattr(exc, "exceptions"):
        return "; ".join(_flatten_exc(e) for e in exc.exceptions)
    return str(exc)


# 31D-STEP6-TIMEOUT: explicit Vol3 execution-timeout text classifier.
# C29 was a defensive retry for transient MCP/stdio glitches. Heavy Vol3
# plugins that legitimately timed out at 90s also triggered C29, wasting
# another full window before surfacing as failure. Explicit timeout text
# returns a degraded envelope immediately; non-timeout malformed text
# still gets the C29 retry it was designed for.
_SIFT_MCP_TIMEOUT_RE = re.compile(
    r"\btimed\s+out\s+after\s+\d+\s*s\b",
    re.IGNORECASE,
)


def _sift_mcp_explicit_timeout_text(raw: str) -> bool:
    """True iff *raw* clearly reports a subprocess execution timeout.

    Matches things like "vol_malfind timed out after 150s" and
    "Error executing tool tool_vol_handles: vol_handles timed out after 90s".
    Returns False for benign mentions of timeout (e.g. "timeout budget
    configured") and for any normal JSON payload.
    """
    if not raw or not isinstance(raw, str):
        return False
    return bool(_SIFT_MCP_TIMEOUT_RE.search(raw))


def _sift_mcp_build_timeout_envelope(tool_name: str, raw: str) -> dict:
    """Standard degraded-timeout envelope for an explicit Vol3 timeout."""
    compact = (raw or "").strip()
    if len(compact) > 500:
        compact = compact[:500]
    return {
        "tool_name": tool_name,
        "output": [],
        "record_count": 0,
        "error": compact or "timed out",
        "failure_mode": "timeout",
        "degraded": True,
        "retry_attempted": False,
    }


async def _call_tool(tool_name: str, arguments: dict, _is_retry: bool = False) -> dict:
    """Call a tool on the MCP server via stdio transport."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server_py = os.path.join(os.path.dirname(__file__), "..", "server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_py],
        env={**os.environ, "SIFT_MCP_SERVER_PROC": "1"},  # SIFT_EVTX_TRANSPORT_GATE_V1
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments=arguments)
            # Extract text content from result
            if hasattr(result, "content") and result.content:
                for block in result.content:
                    if hasattr(block, "text"):
                        try:
                            return json.loads(block.text)
                        except (json.JSONDecodeError, ValueError) as exc:
                            raw_text = block.text or ""
                            raw_preview = raw_text[:500]
                            logger.warning(
                                "Tool %s returned invalid JSON (len=%d): %s | raw[:500]=%r",
                                tool_name, len(raw_text), exc, raw_preview,
                            )
                            # 31D-STEP6-TIMEOUT: short-circuit C29 for explicit
                            # execution-timeout text. Retrying a 90s timeout
                            # just burned another 90s and still failed; return
                            # a degraded envelope immediately so Step6 sees
                            # failure_mode=timeout.
                            if _sift_mcp_explicit_timeout_text(raw_text):
                                logger.info(
                                    "MCP_TIMEOUT_NO_C29_RETRY=%s", tool_name,
                                )
                                return _sift_mcp_build_timeout_envelope(
                                    tool_name, raw_text,
                                )
                            # C29: Defensive retry ONCE with fresh MCP subprocess session.
                            # Handles transient failures (memory pressure, subprocess
                            # corruption, stdio frame desync) by restarting from scratch.
                            # Without this, single-shot failures silently drop tool data.
                            if not _is_retry:
                                logger.info(
                                    "Tool %s: C29 defensive retry 1/1 with fresh MCP session",
                                    tool_name,
                                )
                                await asyncio.sleep(2)  # brief backoff for subprocess cleanup
                                return await _call_tool(
                                    tool_name, arguments, _is_retry=True,
                                )
                            # Second failure -> return envelope as before
                            return {
                                "tool_name": tool_name,
                                "output": [],
                                "record_count": 0,
                                "failure_mode": "invalid_json_response",
                                "error": f"{type(exc).__name__}: {exc}",
                                "raw_text_len": len(raw_text),
                                "retry_attempted": True,
                            }
            return {
                "tool_name": tool_name,
                "output": [],
                "record_count": 0,
                "failure_mode": "no_content_returned",
                "error": "MCP server returned no content blocks",
            }



# SIFT_MCP_LOCAL_DISK_FALLBACK_V1C
# Some large disk parsers can outlive/crash the stdio MCP subprocess on
# corrupt EVTX/user trees. On transport failure, retry locally in the parent
# process so one closed MCP channel cannot zero a high-value evidence family.
# Tools routed local-first: skip the MCP stdio round-trip entirely. These are
# heavy disk parsers that deterministically outlive/crash the subprocess on real
# images, where the MCP attempt only burns ~2 min before the exception path
# re-parses everything locally anyway. The in-process call produces identical
# typed output. Tool-routing config (a tool name), not a case-specific value.
_SIFT_MCP_LOCAL_FIRST_TOOLS = frozenset({"parse_event_logs"})

def _local_first_proc_timeout_s() -> int:
    """Wall-clock budget for an isolated local-first parser child.

    Engine config (env), not case data. Defaults to the EVTX total budget
    plus margin so the parent only times out on a genuinely wedged child;
    the parser self-bounds well under this.
    """
    import os

    def _envint(key: str, default: int) -> int:
        try:
            return int(os.environ.get(key, str(default)))
        except (TypeError, ValueError):
            return default

    budget = _envint("SIFT_EVTX_TOTAL_BUDGET_S", 90)
    return _envint("SIFT_LOCAL_FIRST_PROC_TIMEOUT_S", max(120, budget + 60))


def _run_parser_in_process(parser_fn, arguments: dict, timeout_s) -> dict:
    """Run a GIL-heavy local-first parser in an isolated subprocess.

    Uses a dedicated worker module launched via subprocess -- NOT
    multiprocessing 'spawn', which re-imports the orchestrator __main__
    (run_pipeline.py is not import-safe and would re-run the whole pipeline,
    recursively). Fresh interpreter -> the parser's GIL hold cannot starve
    the parent Step-6 ThreadPool / asyncio MCP readers. Worker stderr
    (EVTX_FILE_RESULT/SUMMARY) is forwarded into our log. Returns the
    parser's own dict, or a degraded envelope (degrade-open). Engine config.
    """
    import os as _os
    import sys as _sys
    import json as _json
    import subprocess as _sp
    from pathlib import Path as _Path

    target = "%s.%s" % (getattr(parser_fn, "__module__", ""),
                        getattr(parser_fn, "__qualname__", ""))
    worker = _Path(__file__).resolve().parent / "tools" / "evtx_subprocess_worker.py"
    payload = _json.dumps({"target": target, "kwargs": dict(arguments or {})})

    try:
        proc = _sp.run(
            [_sys.executable, str(worker)],
            input=payload, text=True, capture_output=True,
            timeout=timeout_s, env=dict(_os.environ),
        )
    except _sp.TimeoutExpired:
        logger.error("Local-first parser %s exceeded %ss in subprocess; degrading open",
                     target, timeout_s)
        return {"output": [], "record_count": 0,
                "error": "isolated parser timeout after %ss" % timeout_s,
                "failure_mode": "timeout"}
    except Exception as exc:
        logger.error("Local-first subprocess launch failed for %s: %s",
                     target, _flatten_exc(exc))
        return {"output": [], "record_count": 0,
                "error": "subprocess launch failed: %s" % _flatten_exc(exc),
                "failure_mode": "subprocess_error"}

    if proc.stderr:
        for _line in proc.stderr.splitlines():
            if _line.strip():
                logger.info("[evtx-worker] %s", _line)

    _out = (proc.stdout or "").strip()
    if not _out:
        return {"output": [], "record_count": 0,
                "error": "worker produced no stdout (rc=%s)" % proc.returncode,
                "failure_mode": "no_output"}
    try:
        _result = _json.loads(_out)
    except Exception as exc:
        return {"output": [], "record_count": 0,
                "error": "worker bad json: %s" % _flatten_exc(exc),
                "failure_mode": "bad_json"}
    if isinstance(_result, dict):
        return _result
    return {"output": [], "record_count": 0,
            "error": "worker returned non-dict", "failure_mode": "bad_result"}


def _sift_local_disk_tool_fallback_v1c(tool_name: str, arguments: dict, reason: str):
    canonical = str(tool_name or "").removeprefix("tool_")
    try:
        if canonical == "parse_event_logs":
            from sift_sentinel.tools.disk_extended import parse_event_logs
            out = _run_parser_in_process(parse_event_logs, arguments, _local_first_proc_timeout_s())
        elif canonical == "parse_rdp_artifacts":
            from sift_sentinel.tools.parse_rdp_artifacts import parse_rdp_artifacts
            out = parse_rdp_artifacts(**dict(arguments or {}))
        else:
            return None

        if not isinstance(out, dict):
            return None
        out = dict(out)
        recs = out.get("output")
        if not isinstance(recs, list):
            recs = out.get("records")
        if isinstance(recs, list):
            out["record_count"] = len(recs)
        out.setdefault("sift_mcp_local_fallback", True)
        out.setdefault("fallback_reason", reason)
        return out
    except Exception as exc:
        logger.error(
            "MCP local fallback failed: %s(%s) -- %s",
            tool_name, arguments, _flatten_exc(exc)
        )
        return None

def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    """Synchronous wrapper for MCP tool call.

    C32: tracks dispatch in parent-process tool_health. MCP subprocess
    (src/server.py) imports sift_sentinel.coordinator, which creates
    its own _tool_health module global in subprocess memory. Python
    module globals are per-process. The MCP subprocess instance of
    _tool_health is therefore distinct from the parent's instance.
    Any mark_* calls inside run_tool at coordinator.py:1073 update
    the subprocess tracker only. Parent reads its own tracker at
    summary time via get_tool_health().summary() in run_pipeline.py.

    Wrapping dispatch here ensures parent-side tracking on every tool
    call regardless of which run_pipeline.py call site invoked us.
    Lazy import of get_tool_health preserves zero-circular-import
    contract (mcp_client.py has no sift_sentinel imports at module
    scope).

    Classification from response envelope:
      - result has "error" OR "failure_mode" key -> mark_failure
      - neither present -> mark_success
      record_count is informational, not a failure signal.
    """
    from sift_sentinel.coordinator import get_tool_health
    health = get_tool_health()
    health.mark_attempt(tool_name)
    # SIFT_MCP_LOCAL_FIRST: parse_event_logs deterministically outlives/crashes
    # the stdio MCP subprocess on real images (100s of EVTX). The exception path
    # below would then re-parse everything locally -- a wasted ~2min MCP attempt
    # + double parse + a misleading "Connection closed" error. Route this one
    # known-fragile heavy parser local-first; the in-process parser already
    # yields identical typed output. Degrade-open: a non-dict result falls
    # through to the normal MCP attempt.
    _canonical_lf = str(tool_name or "").removeprefix("tool_")
    if _canonical_lf in _SIFT_MCP_LOCAL_FIRST_TOOLS:
        _lf = _sift_local_disk_tool_fallback_v1c(
            tool_name, arguments, "local_first_heavy_parser"
        )
        if isinstance(_lf, dict):
            _rc = int(_lf.get("record_count") or len(_lf.get("output") or _lf.get("records") or []))
            if _rc > 0 and not _lf.get("error") and not _lf.get("failure_mode"):
                health.mark_success(tool_name)
            else:
                health.mark_failure(tool_name, "local_first_heavy_parser", "local_first_zero")
            return _lf
    try:
        result = asyncio.run(_call_tool(tool_name, arguments))
    except Exception as exc:
        msg = _flatten_exc(exc)
        logger.error(
            "MCP tool call failed: %s(%s) -- %s", tool_name, arguments, msg
        )
        _fallback = _sift_local_disk_tool_fallback_v1c(tool_name, arguments, msg)
        if isinstance(_fallback, dict):
            _rc = int(_fallback.get("record_count") or len(_fallback.get("output") or _fallback.get("records") or []))
            if _rc > 0 and not _fallback.get("error") and not _fallback.get("failure_mode"):
                health.mark_success(tool_name)
            else:
                health.mark_failure(tool_name, msg, "exception_local_fallback_zero")
            return _fallback
        health.mark_failure(tool_name, msg, "exception")
        return {"error": msg, "output": [], "record_count": 0}
    # 31R: not_applicable is capability/coverage absence, not failure.
    # Some wrappers keep an error/reason string for operator visibility;
    # do not let that reason poison ToolHealth as a failed tool.
    _na_mode = str(result.get("failure_mode") or "").lower()
    _na_status = str(result.get("status") or "").lower()
    _na_kind = str(result.get("kind") or "").lower()
    if any(_x == "not_applicable" for _x in (_na_mode, _na_status, _na_kind)):
        return result

    if result.get("error") or result.get("failure_mode"):
        err = str(result.get("error") or result.get("failure_mode"))
        mode = result.get("failure_mode", "unknown")
        health.mark_failure(tool_name, err, mode)
    else:
        health.mark_success(tool_name)
    return result


async def _list_tools() -> list[dict]:
    """Ask the MCP server what tools are available."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server_py = os.path.join(os.path.dirname(__file__), "..", "server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_py],
        env={**os.environ, "SIFT_MCP_SERVER_PROC": "1"},  # SIFT_EVTX_TRANSPORT_GATE_V1
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            tools = result.tools
            return [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "parameters": t.inputSchema if hasattr(t, "inputSchema") else {},
                }
                for t in tools
            ]


def list_mcp_tools() -> list[dict]:
    """Synchronous wrapper. Returns list of available tools."""
    try:
        return asyncio.run(_list_tools())
    except Exception as exc:
        logger.error("MCP list_tools failed: %s", _flatten_exc(exc))
        return []
