"""Slot 31D-STEP6C-LOCAL regression tests.

Pins:
  - PURE_DERIVED_LOCAL_TOOLS allow-lists extract_network_iocs and
    decode_base64_strings.
  - run_pure_derived_local dispatches both tools in-process and the
    envelope shape matches the underlying tool's contract.
  - Unsupported tools raise PureDerivedLocalUnsupported so callers can
    fall back to the MCP path without noise.
  - A raising tool surfaces as PureDerivedLocalError so callers can
    catch it and fall back, without crashing the run.
  - JSON round-trip equivalence: the local path (in-memory Python
    objects, e.g. tuples) produces the same record_count and the same
    set of IOC indicators / decoded values as the MCP path (which
    serializes tool_outputs to JSON over stdio).

The MCP path effectively round-trips tool_outputs through
``json.loads(json.dumps(...))`` (tuples become lists, sets disappear,
etc.). This file pins that the local path is shape-compatible: we
compare ``direct_result`` against ``json_shape_result`` for both
allow-listed tools using a synthetic, dataset-agnostic tool_outputs
fixture.

This test MUST NOT import run_pipeline.py (top-level argparse + side
effects execute on import).
"""
from __future__ import annotations

import base64
import json

import pytest

from sift_sentinel import derived_local
from sift_sentinel.derived_local import (
    PURE_DERIVED_LOCAL_TOOLS,
    PureDerivedLocalError,
    PureDerivedLocalUnsupported,
    run_pure_derived_local,
)


def _synthetic_outputs() -> dict:
    """Dataset-agnostic tool_outputs fixture.

    Carries:
      * an IPv4 and a URL that ``extract_network_iocs`` should pick up
      * an embedded tuple value (which JSON serialisation would
        flatten to a list) so equivalence catches list/tuple drift
      * a base64-encoded ASCII payload with a generic indicator token
        that ``decode_base64_strings`` should decode
    """
    decoded_plaintext = "powershell -enc placeholder"
    b64_token = base64.b64encode(decoded_plaintext.encode("ascii")).decode("ascii")
    return {
        "vol_synthetic": {
            "tool_name": "vol_synthetic",
            "records": [
                {
                    "pid": 4242,
                    "remote_ip": "203.0.113.42",
                    "remote_port": 4444,
                    "url": "http://example.invalid/path?q=1",
                    "extras": ("ignored-tuple-item-1", "ignored-tuple-item-2"),
                },
            ],
            "record_count": 1,
        },
        "vol_strings_synthetic": {
            "tool_name": "vol_strings_synthetic",
            "records": [
                {"value": f"prefix {b64_token} suffix"},
            ],
            "record_count": 1,
        },
    }


def _network_indicator_keys(envelope: dict) -> set[tuple]:
    records = envelope.get("records")
    if not isinstance(records, list):
        records = envelope.get("output", [])
    keys: set[tuple] = set()
    if not isinstance(records, list):
        return keys
    for rec in records:
        if not isinstance(rec, dict):
            continue
        keys.add((
            rec.get("indicator_type"),
            rec.get("value"),
            rec.get("ioc_type"),
        ))
    return keys


def _decoded_preview_set(envelope: dict) -> set[str]:
    records = envelope.get("output")
    if not isinstance(records, list):
        records = envelope.get("records", [])
    out: set[str] = set()
    if not isinstance(records, list):
        return out
    for rec in records:
        if isinstance(rec, dict):
            preview = rec.get("decoded_preview")
            if isinstance(preview, str):
                out.add(preview)
    return out


def test_pure_derived_local_allowlist_contents():
    assert "extract_network_iocs" in PURE_DERIVED_LOCAL_TOOLS
    assert "decode_base64_strings" in PURE_DERIVED_LOCAL_TOOLS
    assert isinstance(PURE_DERIVED_LOCAL_TOOLS, frozenset)


def test_run_pure_derived_local_extract_network_iocs_envelope_shape():
    outputs = _synthetic_outputs()
    result = run_pure_derived_local(
        "extract_network_iocs", tool_outputs=outputs,
    )
    assert isinstance(result, dict)
    assert result.get("tool_name") == "extract_network_iocs"
    # record_count must be an int and reflect the indicators list.
    assert isinstance(result.get("record_count"), int)
    assert result["record_count"] >= 1


def test_run_pure_derived_local_decode_base64_strings_envelope_shape():
    outputs = _synthetic_outputs()
    result = run_pure_derived_local(
        "decode_base64_strings", tool_outputs=outputs,
    )
    assert isinstance(result, dict)
    assert result.get("tool_name") == "decode_base64_strings"
    assert isinstance(result.get("record_count"), int)
    assert result["record_count"] >= 1


def test_run_pure_derived_local_strips_tool_prefix():
    outputs = _synthetic_outputs()
    result = run_pure_derived_local(
        "tool_extract_network_iocs", tool_outputs=outputs,
    )
    assert result.get("tool_name") == "extract_network_iocs"


def test_run_pure_derived_local_unsupported_tool_raises():
    with pytest.raises(PureDerivedLocalUnsupported):
        run_pure_derived_local("vol_pstree", tool_outputs={})


def test_run_pure_derived_local_empty_inputs_do_not_crash():
    # Both tools must return an envelope with record_count==0 (or
    # equivalent not_found / ok status) when given no useful input.
    empty_net = run_pure_derived_local(
        "extract_network_iocs", tool_outputs={},
    )
    assert isinstance(empty_net, dict)
    assert empty_net.get("record_count", 0) == 0

    empty_b64 = run_pure_derived_local(
        "decode_base64_strings", tool_outputs={},
    )
    assert isinstance(empty_b64, dict)
    assert empty_b64.get("record_count", 0) == 0


def test_run_pure_derived_local_propagates_tool_exception(monkeypatch):
    # Replace the loader so the target raises -> caller sees
    # PureDerivedLocalError and can fall back to the MCP path.
    def _boom(_short):
        def _raise(*_args, **_kwargs):
            raise RuntimeError("synthetic local failure")
        return _raise

    monkeypatch.setattr(derived_local, "_load_tool_callable", _boom)

    with pytest.raises(PureDerivedLocalError):
        run_pure_derived_local(
            "extract_network_iocs", tool_outputs={"vol_x": {"records": []}},
        )


def test_run_pure_derived_local_rejects_non_dict_return(monkeypatch):
    monkeypatch.setattr(
        derived_local,
        "_load_tool_callable",
        lambda _short: (lambda **_kwargs: ["not", "a", "dict"]),
    )
    with pytest.raises(PureDerivedLocalError):
        run_pure_derived_local(
            "decode_base64_strings", tool_outputs={},
        )


@pytest.mark.parametrize(
    "short, comparator",
    [
        ("extract_network_iocs", _network_indicator_keys),
        ("decode_base64_strings", _decoded_preview_set),
    ],
)
def test_json_roundtrip_equivalence(short, comparator):
    """The MCP path JSON-serialises tool_outputs across stdio.

    Local dispatch hands the Python object straight through. Pin that
    tuple/list/string coercion doesn't change the extracted indicator
    set or the decoded payload set.
    """
    outputs = _synthetic_outputs()
    json_shape_outputs = json.loads(json.dumps(outputs))

    direct = run_pure_derived_local(short, tool_outputs=outputs)
    json_shape = run_pure_derived_local(short, tool_outputs=json_shape_outputs)

    assert direct.get("record_count") == json_shape.get("record_count")
    assert comparator(direct) == comparator(json_shape)


def test_test_file_does_not_import_run_pipeline():
    # Self-referential guard: importing run_pipeline.py triggers
    # argparse / side effects at module import time. This regression
    # file MUST stay import-safe. Check actual import statements
    # (not substring matches in docstrings / prose).
    import ast

    tree = ast.parse(open(__file__, "r", encoding="utf-8").read())
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "run_pipeline":
                    bad.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "run_pipeline":
                bad.append(f"from {node.module} import ...")
    assert not bad, f"this test file must not import run_pipeline: {bad}"
