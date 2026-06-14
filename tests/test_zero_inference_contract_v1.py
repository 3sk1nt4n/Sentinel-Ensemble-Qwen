import json
import subprocess
import sys
from pathlib import Path


def _write_state(state: Path, buckets: dict):
    (state / "all_outputs.json").write_text(json.dumps({
        "producer_tool": {"status": "ok", "records": [{"x": 1}]},
        "zero_tool": {"status": "not_applicable", "records": []},
    }))
    (state / "finding_disposition_buckets.json").write_text(json.dumps(buckets))


def test_inference_language_in_promoted_finding_routes_to_inconclusive(tmp_path: Path):
    _write_state(tmp_path, {
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
    })

    fail = subprocess.run(
        [sys.executable, "scripts/check_zero_inference_contract_gate.py", str(tmp_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert fail.returncode == 1
    assert "ZERO_INFERENCE_CONTRACT_GATE=FAIL" in fail.stdout

    repair = subprocess.run(
        [sys.executable, "scripts/check_zero_inference_contract_gate.py", str(tmp_path), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert repair.returncode == 0, repair.stdout
    assert "ZERO_INFERENCE_CONTRACT_GATE=PASS" in repair.stdout

    buckets = json.loads((tmp_path / "finding_disposition_buckets.json").read_text())
    assert not buckets["suspicious_needs_review"]
    assert buckets["inconclusive_unresolved"][0]["id"] == "F001"


def test_promoted_finding_without_producer_tool_routes_to_inconclusive(tmp_path: Path):
    _write_state(tmp_path, {
        "confirmed_malicious_atomic": [{
            "id": "F002",
            "title": "Exact title but no producing tool",
            "source_tools": ["zero_tool"],
            "claims": [{"type": "raw", "source_tool": "zero_tool"}],
        }],
        "suspicious_needs_review": [],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "synthesis_narrative": [],
    })

    proc = subprocess.run(
        [sys.executable, "scripts/check_zero_inference_contract_gate.py", str(tmp_path), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    buckets = json.loads((tmp_path / "finding_disposition_buckets.json").read_text())
    assert not buckets["confirmed_malicious_atomic"]
    assert buckets["inconclusive_unresolved"][0]["id"] == "F002"


def test_exact_promoted_finding_with_producer_tool_passes(tmp_path: Path):
    _write_state(tmp_path, {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [{
            "id": "F003",
            "title": "Observed process ancestry mismatch",
            "source_tools": ["producer_tool"],
            "claims": [{"type": "raw", "source_tool": "producer_tool"}],
        }],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "synthesis_narrative": [],
    })

    proc = subprocess.run(
        [sys.executable, "scripts/check_zero_inference_contract_gate.py", str(tmp_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert "ZERO_INFERENCE_CONTRACT_GATE=PASS" in proc.stdout
