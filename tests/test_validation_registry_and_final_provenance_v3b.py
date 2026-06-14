from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sift_sentinel.analysis.validation_family_registry import get_validation_family_registry


def test_validation_family_registry_has_only_fact_keys_and_powershell_family():
    reg = get_validation_family_registry()
    assert reg
    assert "parse_event_logs" not in reg
    assert "powershell_command_fact" in reg
    for family, spec in reg.items():
        assert family.endswith("_fact")
        assert spec.get("roles")
        assert spec.get("claim_types")


def test_final_finding_sanitizer_moves_internal_validation_provenance(tmp_path: Path):
    state = tmp_path
    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "confirmed_malicious_atomic": [{
            "id": "F001",
            "title": "confirmed",
            "source_tools": ["parse_event_logs", "typed_evidence_db", "reference_set"],
            "claim_tools": ["parse_event_logs", "check_ancestry"],
            "_validation_telemetry": {
                "typed_evidence_db_used": True,
                "reference_set_fallback_matches": 0,
            },
            "claims": [
                {"type": "raw", "source_tool": "typed_evidence_db"},
                {"type": "event_log", "source_tool": "parse_event_logs"},
            ],
        }],
        "suspicious_needs_review": [],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
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

    data = json.loads((state / "finding_disposition_buckets.json").read_text())
    text = json.dumps(data).lower()
    assert "typed_evidence_db" not in text
    assert "reference_set" not in text
    assert "check_ancestry" not in text
    assert "parse_event_logs" in text
    assert (state / "final_finding_provenance_sanitizer_audit.json").exists()
