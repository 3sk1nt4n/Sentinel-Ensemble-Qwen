from pathlib import Path
import json
import subprocess
import sys

def test_customer_table_zero_hit_tool_gate_blocks_tools_hit_column(tmp_path: Path):
    state = tmp_path
    (state / "tool_outputs").mkdir()

    (state / "all_outputs.json").write_text(json.dumps({
        "vol_pstree": {"status": "ok", "records": [{"PID": 10, "ImageFileName": "x.exe"}]},
        "get_amcache": {"status": "not_applicable", "records": []},
    }))

    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            {
                "id": "F001",
                "title": "generic review",
                "source_tools": ["vol_pstree", "get_amcache"],
                "tools_hit": ["vol_pstree", "get_amcache"],
                "claims": [{"type": "pid", "pid": 10, "process": "x.exe", "source_tool": "vol_pstree"}],
            }
        ],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "synthesis_narrative": [],
    }))

    (state / "findings_final.json").write_text(json.dumps([]))

    repair = subprocess.run(
        [sys.executable, "scripts/check_tool_hit_integrity_gate.py", str(state), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert repair.returncode == 0, repair.stdout

    gate = subprocess.run(
        [sys.executable, "scripts/check_customer_table_zero_hit_tools_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert gate.returncode == 0, gate.stdout
    assert "CUSTOMER_TABLE_ZERO_HIT_TOOL_GATE=PASS" in gate.stdout
