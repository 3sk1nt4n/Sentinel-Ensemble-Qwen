from __future__ import annotations

import ast
import textwrap
from pathlib import Path


_HELPERS = {
    "_slot31c4_short_name",
    "_slot31c4_mcp_name",
    "_slot31c4_not_applicable",
    "_slot31k_evidence_context_args",
    "_slot31v_path_or_empty",
    "_slot31k_coordinator_dispatch_args",
    "_slot31c4_legacy_args",
    "_slot31c4_dispatch_one",
}


def _load_step6_helpers() -> dict:
    src = Path("run_pipeline.py")
    text = src.read_text(errors="replace")
    tree = ast.parse(text)
    nodes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in _HELPERS:
            nodes.append(node)
    found = {node.name for node in nodes}
    missing = _HELPERS - found
    assert not missing, f"missing nested helpers: {sorted(missing)}"
    nodes.sort(key=lambda n: n.lineno)

    ns = {
        "IMAGE_PATH": Path("/cases/evidence/memory.img"),
        "DISK_PATH": Path("/cases/evidence/disk.E01"),
        "DISK_MOUNT": Path("/mnt/rd01_part"),
        "MFT_START": "2015-01-01",
        "MFT_END": "2025-12-31",
        "_SLOT31C4_EXTERNAL_GENERIC_MCP": {
            "run_evtxecmd",
            "run_mftecmd",
            "run_amcacheparser",
            "run_appcompatcacheparser",
            "run_lecmd",
            "run_recmd",
        },
        "logger": type("Logger", (), {"info": lambda *args, **kwargs: None})(),
    }

    for node in nodes:
        segment = ast.get_source_segment(text, node)
        assert segment, f"no source segment for {node.name}"
        exec(textwrap.dedent(segment), ns)
    return ns


def test_sleuthkit_fls_legacy_mcp_args_include_disk_context() -> None:
    ns = _load_step6_helpers()
    args = ns["_slot31c4_legacy_args"]("sleuthkit_fls", "sleuthkit_fls")

    assert args["image_path"] == "/cases/evidence/memory.img"
    assert args["disk_path"] == "/cases/evidence/disk.E01"
    assert args["disk_mount"] == "/mnt/rd01_part"
    assert "tool_args" not in args


def test_sleuthkit_tsk_recover_resolver_output_dir_becomes_tool_args() -> None:
    ns = _load_step6_helpers()
    captured = {}

    def fake_resolver(short: str, **kwargs):
        captured["resolver_short"] = short
        captured["resolver_kwargs"] = kwargs
        return {
            "kind": "mcp_call",
            "tool_name": "sleuthkit_tsk_recover",
            "args": {"output_dir": "/tmp/sift-out"},
        }

    def fake_call_mcp_tool(name: str, args: dict):
        captured["mcp_name"] = name
        captured["mcp_args"] = dict(args)
        return {"tool_name": "sleuthkit_tsk_recover", "record_count": 0, "records": []}

    ns["resolve_high_value_tool_invocation"] = fake_resolver
    ns["call_mcp_tool"] = fake_call_mcp_tool

    short, result = ns["_slot31c4_dispatch_one"]("tool_sleuthkit_tsk_recover")

    assert short == "sleuthkit_tsk_recover"
    assert result["tool_name"] == "sleuthkit_tsk_recover"
    assert captured["mcp_name"] == "tool_sleuthkit_tsk_recover"
    assert captured["mcp_args"]["image_path"] == "/cases/evidence/memory.img"
    assert captured["mcp_args"]["disk_path"] == "/cases/evidence/disk.E01"
    assert captured["mcp_args"]["disk_mount"] == "/mnt/rd01_part"
    assert captured["mcp_args"]["tool_args"] == ["/tmp/sift-out"]
    assert "output_dir" not in captured["mcp_args"]


def test_memprocfs_resolver_schema_is_not_polluted_with_disk_context() -> None:
    ns = _load_step6_helpers()
    captured = {}

    def fake_resolver(short: str, **kwargs):
        return {
            "kind": "mcp_call",
            "tool_name": "run_memprocfs",
            "args": {"memory_image_path": "/cases/evidence/memory.img"},
        }

    def fake_call_mcp_tool(name: str, args: dict):
        captured["mcp_name"] = name
        captured["mcp_args"] = dict(args)
        return {"tool_name": "run_memprocfs", "record_count": 1, "records": ["x"]}

    ns["resolve_high_value_tool_invocation"] = fake_resolver
    ns["call_mcp_tool"] = fake_call_mcp_tool

    short, result = ns["_slot31c4_dispatch_one"]("tool_run_memprocfs")

    assert short == "run_memprocfs"
    assert result["record_count"] == 1
    assert captured["mcp_args"] == {"memory_image_path": "/cases/evidence/memory.img"}


def test_external_generic_resolver_keeps_wrapper_compatible_full_context() -> None:
    ns = _load_step6_helpers()
    captured = {}

    def fake_resolver(short: str, **kwargs):
        return {
            "kind": "mcp_call",
            "tool_name": "run_mftecmd",
            "args": {"mft_path": "/mnt/rd01_part/$MFT"},
        }

    def fake_call_mcp_tool(name: str, args: dict):
        captured["mcp_name"] = name
        captured["mcp_args"] = dict(args)
        return {"tool_name": "run_mftecmd", "record_count": 0, "records": []}

    ns["resolve_high_value_tool_invocation"] = fake_resolver
    ns["call_mcp_tool"] = fake_call_mcp_tool

    short, _ = ns["_slot31c4_dispatch_one"]("tool_run_mftecmd")

    assert short == "run_mftecmd"
    assert captured["mcp_name"] == "tool_run_mftecmd"
    assert captured["mcp_args"]["image_path"] == "/cases/evidence/memory.img"
    assert captured["mcp_args"]["disk_path"] == "/cases/evidence/disk.E01"
    assert captured["mcp_args"]["disk_mount"] == "/mnt/rd01_part"
    assert "mft_path" not in captured["mcp_args"]
