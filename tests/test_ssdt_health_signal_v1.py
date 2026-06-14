from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sift_sentinel.analysis.ssdt_health import classify_ssdt_output


def test_ssdt_page_error_is_unknown_and_non_supporting():
    obj = {
        "status": "error",
        "records": [],
        "stderr": "Volatility was unable to read a requested page: Page error 0x123",
    }
    h = classify_ssdt_output(obj)
    assert h["health_status"] == "unknown"
    assert h["can_support_finding"] is False


def test_ssdt_records_present_can_support_health_evidence():
    obj = {"status": "ok", "records": [{"Index": 1, "Module": "ntoskrnl.exe"}]}
    h = classify_ssdt_output(obj)
    assert h["health_status"] == "completed"
    assert h["can_support_finding"] is True


def test_failed_ssdt_removed_from_finding_on_repair(tmp_path: Path):
    state = tmp_path
    (state / "tool_outputs").mkdir()
    (state / "tool_outputs" / "vol_ssdt.json").write_text(json.dumps({
        "status": "error",
        "records": [],
        "stderr": "Page error",
    }))
    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [{
            "id": "F001",
            "title": "SSDT suspicious",
            "source_tools": ["vol_ssdt"],
            "claims": [{"type": "raw", "source_tool": "vol_ssdt"}],
        }],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "synthesis_narrative": [],
    }))

    fail = subprocess.run(
        [sys.executable, "scripts/check_ssdt_health_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert fail.returncode == 1
    assert "SSDT_HEALTH_GATE=FAIL" in fail.stdout

    ok = subprocess.run(
        [sys.executable, "scripts/check_ssdt_health_gate.py", str(state), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert ok.returncode == 0, ok.stdout
    assert "SSDT_HEALTH_GATE=PASS" in ok.stdout

    buckets = json.loads((state / "finding_disposition_buckets.json").read_text())
    blob = json.dumps(buckets)
    assert "vol_ssdt" not in blob
    assert buckets["inconclusive_unresolved"]
