import json
import subprocess
import sys
from pathlib import Path


def test_likely_indicates_is_blocked_and_repaired(tmp_path: Path):
    (tmp_path / "all_outputs.json").write_text(json.dumps({
        "producer_tool": {"status": "ok", "records": [{"x": 1}]},
        "zero_tool": {"status": "not_applicable", "records": []},
    }))
    (tmp_path / "finding_disposition_buckets.json").write_text(json.dumps({
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [{
            "id": "F001",
            "title": "This likely indicates intrusion",
            "source_tools": ["producer_tool"],
            "claims": [{"type": "raw", "source_tool": "producer_tool"}],
        }],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "synthesis_narrative": [],
    }))

    failed = subprocess.run(
        [sys.executable, "scripts/check_zero_inference_contract_gate.py", str(tmp_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert failed.returncode == 1, failed.stdout
    assert "ZERO_INFERENCE_CONTRACT_GATE=FAIL" in failed.stdout

    repaired = subprocess.run(
        [sys.executable, "scripts/check_zero_inference_contract_gate.py", str(tmp_path), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert repaired.returncode == 0, repaired.stdout
    buckets = json.loads((tmp_path / "finding_disposition_buckets.json").read_text())
    assert not buckets["suspicious_needs_review"]
    assert buckets["inconclusive_unresolved"][0]["id"] == "F001"


def test_final_sanitizer_removes_zero_and_internal_refs_from_final_objects(tmp_path: Path):
    (tmp_path / "all_outputs.json").write_text(json.dumps({
        "producer_tool": {"status": "ok", "records": [{"x": 1}]},
        "zero_tool": {"status": "not_applicable", "records": []},
    }))

    dirty = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [{
            "id": "F001",
            "title": "Observed process fact from zero_tool and typed_evidence_db",
            "source_tools": ["producer_tool", "zero_tool", "typed_evidence_db", "reference_set"],
            "tools_hit": ["tool_zero_tool", "producer_tool"],
            "_validation_telemetry": {
                "typed_evidence_db_used": True,
                "reference_set_fallback_matches": 0,
            },
            "claims": [
                {"type": "raw", "source_tool": "zero_tool"},
                {"type": "raw", "source_tool": "producer_tool"},
            ],
        }],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "synthesis_narrative": [],
    }

    for name in ("finding_disposition_buckets.json", "findings_final.json", "findings_validated.json"):
        (tmp_path / name).write_text(json.dumps(dirty))

    proc = subprocess.run(
        [sys.executable, "scripts/check_final_finding_provenance_sanitizer_gate.py", str(tmp_path), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert "FINAL_FINDING_PROVENANCE_SANITIZER_GATE=PASS" in proc.stdout

    for name in ("finding_disposition_buckets.json", "findings_final.json", "findings_validated.json"):
        text = (tmp_path / name).read_text()
        assert "zero_tool" not in text
        assert "typed_evidence_db" not in text
        assert "reference_set" not in text
        assert "producer_tool" in text

    assert (tmp_path / "final_finding_provenance_sanitizer_audit.json").exists()
