import importlib
import json
import os
from pathlib import Path

def test_customer_table_export_exists_and_no_legacy_columns(capsys, tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [{"id": "F054", "title": "Unexpected process ancestry"}],
        "inconclusive_unresolved": [{"id": "F007", "title": "Unsupported temp executable claim"}],
        "benign_or_false_positive": [{"id": "F001", "title": "Benign RWX allocation"}],
        "synthesis_narrative": [{"id": "F053", "title": "Synthesis should not be promoted"}],
    }))
    (state / "findings_final.json").write_text("[]")
    monkeypatch.setenv("SIFT_LATEST_STATE_DIR", str(state))

    mod = importlib.import_module("sift_sentinel.reporting.customer_findings_table")
    assert hasattr(mod, "print_customer_findings_table")
    mod.print_customer_findings_table(state_dir=str(state))
    out = capsys.readouterr().out

    assert "Confirmed malicious findings" in out
    assert "Suspicious findings needing analyst review" in out
    assert "Self-correction / inconclusive / withheld" in out
    assert "Benign or false-positive findings" in out
    assert "Severity" not in out
    assert "Confidence" not in out
    assert out.find("Unexpected process ancestry") < out.find("Benign RWX allocation")
    assert out.find("Synthesis should not be promoted") < out.find("Benign RWX allocation")

def test_postrun_path_fidelity_gate_detects_stale_mount(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"evidence_path": "/mnt/windows_mount/Windows"}))
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "scripts/postrun_path_fidelity_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert "PATH_FIDELITY_GATE=FAIL" in result.stdout

def test_path_normalizers_are_importable_and_signatures_are_explicit():
    import inspect
    from sift_sentinel.tools.parse_powershell_transcripts import parse_powershell_transcripts
    from sift_sentinel.tools.parse_wmi_subscription import parse_wmi_subscription

    ps_sig = inspect.signature(parse_powershell_transcripts)
    wmi_sig = inspect.signature(parse_wmi_subscription)

    assert "args" not in ps_sig.parameters
    assert "kwargs" not in ps_sig.parameters
    assert "disk_mount" in ps_sig.parameters
    assert "image_path" in ps_sig.parameters

    assert "args" not in wmi_sig.parameters
    assert "kwargs" not in wmi_sig.parameters
    assert "disk_mount" in wmi_sig.parameters
    assert "image_path" in wmi_sig.parameters
