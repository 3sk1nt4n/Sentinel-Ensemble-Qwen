"""Slot 31H-alpha -- synthetic fixture for the entity truth package.

dataset-agnostic by construction: every id/path/string here is a
synthetic ``syn_*`` token, never a real run finding id, PID, path,
hash or IP. There are no predetermined outputs -- the package is
derived purely from the synthetic run this builder writes.
"""
from __future__ import annotations

import json
from pathlib import Path

# Synthetic, obviously-fake tokens. Lower-case so canonical path
# normalization is identity.
SYN_CONFIRMED_FILE = "syn_confirmed_payload.dll"
SYN_CONFIRMED_FIDS = ("syn-c1", "syn-c2", "syn-c3")
SYN_SUSPICIOUS_FILE = "syn_suspicious_helper.dll"
SYN_SUSPICIOUS_FID = "syn-s1"
SYN_BENIGN_FILE = "syn_benign_tool.exe"
SYN_BENIGN_FID = "syn-b1"
SYN_CONFLICT_FILE = "syn_contradicted_artifact.bin"
SYN_CONFLICT_FID = "syn-x1"


def _finding(fid: str, file_name: str, sev: str = "high",
             conf: str = "high") -> dict:
    return {
        "finding_id": fid,
        "title": "synthetic observation %s" % fid,
        "file": file_name,
        "severity": sev,
        "confidence_level": conf,
        "claims": [],
    }


def make_synthetic_run(
    tmp_path: Path,
    *,
    with_conflict: bool = True,
    run_id: str | None = None,
) -> Path:
    """Write a synthetic run JSON + state dir. Returns the run JSON
    path. The state dir holds finding_disposition_buckets.json and an
    optional synthetic ReAct contradiction source."""
    state = Path(tmp_path) / "state"
    state.mkdir(parents=True, exist_ok=True)

    buckets = {
        "confirmed_malicious_atomic": [
            _finding(fid, SYN_CONFIRMED_FILE)
            for fid in SYN_CONFIRMED_FIDS
        ],
        "suspicious_needs_review": [
            _finding(SYN_SUSPICIOUS_FID, SYN_SUSPICIOUS_FILE),
        ],
        "benign_or_false_positive": [
            _finding(SYN_BENIGN_FID, SYN_BENIGN_FILE, "low", "low"),
        ],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    if with_conflict:
        buckets["suspicious_needs_review"].append(
            _finding(SYN_CONFLICT_FID, SYN_CONFLICT_FILE))
        # Two structured ReAct conclusions on the SAME file entity with
        # opposite verdicts -> a direct entity verdict contradiction.
        inv3 = [
            {
                "finding_id": SYN_CONFLICT_FID,
                "file": SYN_CONFLICT_FILE,
                "verdict": "malicious",
                "conclusion": "CONCLUDED -- malicious synthetic",
            },
            {
                "finding_id": SYN_CONFLICT_FID,
                "file": SYN_CONFLICT_FILE,
                "verdict": "benign",
                "is_false_positive": True,
                "conclusion": "CONCLUDED -- benign synthetic",
            },
        ]
        (state / "inv3_response.json").write_text(json.dumps(inv3))

    (state / "finding_disposition_buckets.json").write_text(
        json.dumps(buckets))

    run = {
        "state_dir": str(state),
        "run_id": run_id,
        "integrity_match": True,
        "disk_integrity": "verified",
        "memory_integrity": True,
        "db5_gates": {"SYN_DB5_GATE": "PASS"},
        "disposition_counts": {
            k: len(v) for k, v in buckets.items()
        },
    }
    run_json = Path(tmp_path) / "run_synth.json"
    run_json.write_text(json.dumps(run))
    return run_json
