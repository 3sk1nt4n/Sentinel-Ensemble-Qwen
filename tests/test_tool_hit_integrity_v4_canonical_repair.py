from pathlib import Path
import json
import subprocess
import sys

from sift_sentinel.analysis.tool_hit_integrity import build_hit_maps, canonical_tool_name

def test_appcompat_alias_canonicalizes_to_run_tool():
    assert canonical_tool_name("tool_parse_appcompatcacheparser") == "run_appcompatcacheparser"
    assert canonical_tool_name("parse_appcompatcacheparser") == "run_appcompatcacheparser"
    assert canonical_tool_name("run_appcompatcacheparser") == "run_appcompatcacheparser"

def test_zero_tool_removed_and_alias_preserved(tmp_path: Path):
    state = tmp_path
    (state / "all_outputs.json").write_text(json.dumps({
        "get_amcache": {"status": "not_applicable", "records": []},
        "run_appcompatcacheparser": {"status": "ok", "records": [{"x": 1}]},
        "vol_pstree": {"status": "ok", "records": [{"PID": 10, "ImageFileName": "x.exe"}]},
    }))
    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "suspicious_needs_review": [{
            "id": "F001",
            "title": "mixed provenance",
            "source_tools": ["get_amcache", "parse_appcompatcacheparser", "vol_pstree"],
            "tools_hit": ["tool_get_amcache", "parse_appcompatcacheparser"],
            "claims": [
                {"type": "raw", "source_tool": "get_amcache"},
                {"type": "pid", "pid": 10, "process": "x.exe", "source_tool": "vol_pstree"},
            ],
        }],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "confirmed_malicious_atomic": [],
        "synthesis_narrative": [],
    }))

    proc = subprocess.run(
        [sys.executable, "scripts/check_tool_hit_integrity_gate.py", str(state), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert "TOOL_HIT_INTEGRITY_GATE=PASS" in proc.stdout

    repaired = json.loads((state / "finding_disposition_buckets.json").read_text())
    finding = repaired["suspicious_needs_review"][0]
    assert "get_amcache" not in json.dumps(finding)
    assert "tool_get_amcache" not in json.dumps(finding)
    assert "run_appcompatcacheparser" in json.dumps(finding)
    assert "parse_appcompatcacheparser" not in json.dumps(finding)

    contrib = subprocess.run(
        [sys.executable, "scripts/summarize_tool_contribution.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert contrib.returncode == 0, contrib.stdout
    assert "TOOL_CONTRIBUTION_GATE=PASS" in contrib.stdout
    assert "zero_refs=[]" not in contrib.stdout  # PASS line should omit failure details

def test_build_hit_maps_zero_status_wins_only_when_no_records():
    hit, zero = build_hit_maps({
        "tool_get_amcache": {"status": "not_applicable", "records": []},
        "tool_run_appcompatcacheparser": {"status": "ok", "records": [{"ok": True}]},
    })
    assert "get_amcache" in zero
    assert "run_appcompatcacheparser" in hit
