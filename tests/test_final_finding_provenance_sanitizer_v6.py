import json
import subprocess
import sys
from pathlib import Path


def test_final_finding_sanitizer_removes_zero_and_non_tool_refs_from_findings(tmp_path: Path):
    state = tmp_path
    (state / "all_outputs.json").write_text(json.dumps({
        "zero_tool": {"status": "not_applicable", "records": []},
        "producer_tool": {"status": "ok", "records": [{"x": 1}]},
    }))

    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "suspicious_needs_review": [{
            "id": "F001",
            "title": "zero_tool appeared with typed_evidence_db and check_ancestry",
            "source_tools": ["zero_tool", "producer_tool", "typed_evidence_db"],
            "tools_hit": ["tool_zero_tool", "producer_tool"],
            "removed_tool_refs": [{"raw": "zero_tool"}],
            "claims": [
                {"type": "raw", "source_tool": "zero_tool"},
                {"type": "pid", "pid": 1, "process": "x.exe", "source_tool": "producer_tool"},
            ],
        }],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "confirmed_malicious_atomic": [],
        "synthesis_narrative": [],
    }))

    proc = subprocess.run(
        [sys.executable, "scripts/check_final_finding_provenance_sanitizer_gate.py", str(state), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert "FINAL_FINDING_PROVENANCE_SANITIZER_GATE=PASS" in proc.stdout

    text = (state / "finding_disposition_buckets.json").read_text()
    assert "zero_tool" not in text
    assert "tool_zero_tool" not in text
    assert "typed_evidence_db" not in text
    assert "check_ancestry" not in text
    assert "producer_tool" in text
    assert (state / "final_finding_provenance_sanitization_audit.json").exists()
