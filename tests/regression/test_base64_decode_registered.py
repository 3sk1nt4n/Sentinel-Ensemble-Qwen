"""Slot 31I-alpha-b64: real, registered, non-fake base64 decoder.

Proves BASE64_DECODE_REGISTERED_GATE: the decoder is a genuine
registered tool with a capability, resolves to the required semantic
buckets, actually decodes base64 payloads, and is not a phantom in the
Inv1 catalog. No hardcoded evidence paths / PIDs / hashes / answers.
"""

import base64
import re

import sift_sentinel.coordinator as c
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tools.decode_base64_strings import decode_base64_strings
from sift_sentinel.tool_semantics import (
    get_tool_semantics,
    format_grouped_inv1_tool_catalog,
    estimate_catalog_tokens,
)
from sift_sentinel.runtime.high_value_tool_args import (
    HIGH_VALUE_TOOLS,
    resolve_high_value_tool_invocation,
)

TOOL = "decode_base64_strings"
_REQUIRED_BUCKETS = {
    "base64_decode", "string_decode", "powershell_decode",
    "string_analysis", "network_ioc", "malware_triage",
}
_RECORD_KEYS = {
    "source_tool", "source_record", "original_preview",
    "decoded_preview", "encoding", "suspicious_keywords", "confidence",
}
_CATALOG_LINE = re.compile(r"(?m)^- (\S+) — .*\| platform=")


def test_decoder_is_registered_and_capable():
    assert TOOL in c._TOOL_REGISTRY
    assert get_capability(TOOL) is not None
    assert c._is_registered(TOOL) is True
    fn, arg_type = c._TOOL_REGISTRY[TOOL]
    assert callable(fn)
    assert arg_type == "runtime_tool_outputs"


def test_decoder_semantic_buckets_cover_required_set():
    sem = get_tool_semantics(
        TOOL, c._TOOL_REGISTRY[TOOL], get_capability(TOOL),
    )
    assert _REQUIRED_BUCKETS.issubset(set(sem["buckets"]))


def test_run_strings_not_tagged_base64_decode():
    sem = get_tool_semantics(
        "run_strings", c._TOOL_REGISTRY["run_strings"],
        get_capability("run_strings"),
    )
    assert "base64_decode" not in sem["buckets"]


def test_decoder_actually_decodes_utf8_utf16_ascii():
    payloads = {
        "p_utf8": "Invoke-Expression downloadstring http://host",
        "p_ascii": "benign filler text long enough to scan ok",
    }
    enc = {
        "a": base64.b64encode(payloads["p_utf8"].encode("utf-8")).decode(),
        "b": base64.b64encode(
            "cmd.exe /c whoami extra".encode("utf-16-le")).decode(),
        "c": base64.b64encode(payloads["p_ascii"].encode("ascii")).decode(),
    }
    out = decode_base64_strings(
        {"src_tool": {"output": list(enc.values())}}
    )
    assert out["tool_name"] == TOOL
    assert out["record_count"] >= 3
    decoded = {r["decoded_preview"] for r in out["output"]}
    assert payloads["p_utf8"] in decoded
    assert payloads["p_ascii"] in decoded
    assert any("whoami" in d for d in decoded)


def test_decoder_record_schema_and_scoring():
    token = base64.b64encode(
        b"powershell -enc Invoke-Expression http://x").decode()
    out = decode_base64_strings({"t": {"output": [token]}})
    assert out["output"], "expected at least one decode record"
    rec = out["output"][0]
    assert set(rec) == _RECORD_KEYS
    assert isinstance(rec["suspicious_keywords"], list)
    assert rec["suspicious_keywords"]  # known indicators present
    assert rec["confidence"] in {"low", "medium", "high"}
    assert rec["encoding"] in {"utf-8", "utf-16-le", "ascii"}


def test_decoder_handles_empty_and_non_container_inputs():
    for bad in (None, "", [], {}, 123):
        out = decode_base64_strings(bad)
        assert out["tool_name"] == TOOL
        assert out["record_count"] == 0
        assert out["output"] == []


def test_decoder_is_high_value_and_resolves():
    assert TOOL in HIGH_VALUE_TOOLS
    na = resolve_high_value_tool_invocation(TOOL)
    assert na["kind"] == "not_applicable"
    ok = resolve_high_value_tool_invocation(
        TOOL, tool_outputs={"t": {"output": ["aGVsbG8gd29ybGQgbG9uZw=="]}},
    )
    assert ok["kind"] == "mcp_call"
    assert ok["tool_name"] == TOOL


def test_decoder_advertised_and_not_a_phantom():
    selectable = (
        set(c._TOOL_REGISTRY) - c._NON_WINDOWS_TOOLS - {"vol_mftscan"}
    )
    reg = {n: c._TOOL_REGISTRY[n] for n in selectable}
    cat = format_grouped_inv1_tool_catalog(reg, get_capability)
    advertised = set(_CATALOG_LINE.findall(cat))
    assert TOOL in advertised
    assert advertised <= set(c._TOOL_REGISTRY)
    assert estimate_catalog_tokens(cat) < 10000
