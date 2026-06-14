import json
import subprocess
import sys
from pathlib import Path


def test_repair_moves_zero_tool_audit_out_of_finding_object(tmp_path: Path):
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
            "removed_tool_refs": [{"canonical": "get_amcache", "raw": "get_amcache"}],
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
    dumped = json.dumps(finding)

    assert "get_amcache" not in dumped
    assert "tool_get_amcache" not in dumped
    assert "removed_tool_refs" not in dumped
    assert "run_appcompatcacheparser" in dumped
    assert "vol_pstree" in dumped
    assert finding["provenance_repair_removed_ref_count"] >= 1
    assert (state / "tool_hit_integrity_repair_audit.json").exists()
