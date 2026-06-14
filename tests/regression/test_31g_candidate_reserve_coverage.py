from pathlib import Path

from sift_sentinel.analysis.candidate_observations import (
    build_candidate_reserve_coverage,
)


def _payload():
    return {
        "candidates": [
            {
                "candidate_id": "cand-0101",
                "candidate_type": "high_risk_persistence",
                "score": 95,
                "entity_key": "registry:hklm/system/controlset001/control/safeboot/alternateshell",
                "validation_ready": True,
                "source_tools": ["parse_registry_persistence"],
                "fact_types": ["registry_persistence_fact"],
                "signals": ["high_risk_persistence"],
                "fact_ids": ["registry_persistence_fact-0001558"],
                "claim_templates": ["persistence"],
            },
            {
                "candidate_id": "cand-0049",
                "candidate_type": "suspicious_file_or_process_execution",
                "score": 245,
                "entity_key": "ip:172.16.7.11",
                "validation_ready": True,
                "source_tools": [
                    "extract_network_iocs",
                    "parse_event_logs",
                    "parse_powershell_transcripts",
                    "parse_rdp_artifacts",
                ],
                "fact_types": [
                    "event_log_fact",
                    "network_ioc_fact",
                    "powershell_command_fact",
                    "rdp_artifact_fact",
                ],
                "signals": [
                    "event_staging_path",
                    "rdp_target_reference",
                    "multi_source",
                    "multi_fact_type",
                ],
                "fact_ids": ["rdp_artifact_fact-0000001"],
                "claim_templates": ["remote_access_context"],
            },
            {
                "candidate_id": "cand-0956",
                "candidate_type": "high_risk_persistence",
                "score": 35,
                "entity_key": "task:wstask",
                "validation_ready": True,
                "source_tools": ["parse_scheduled_tasks_disk"],
                "fact_types": ["scheduled_task_fact"],
                "signals": ["hidden_scheduled_task"],
                "fact_ids": ["scheduled_task_fact-0000010"],
                "claim_templates": ["persistence"],
            },
        ]
    }


def test_reserve_coverage_marks_traceable_and_not_promoted():
    findings = [
        {
            "finding_id": "F900",
            "title": "SafeBoot AlternateShell persistence",
            "source_tools": ["parse_registry_persistence"],
            "raw_excerpt": (
                "candidate_id=cand-0101 "
                "fact_ids=registry_persistence_fact-0001558"
            ),
        }
    ]

    audit = build_candidate_reserve_coverage(_payload(), findings)

    assert audit["schema_version"] == "candidate_reserve_coverage_v1"
    assert audit["gate"] == "PASS"
    assert audit["reserved_count"] == 2
    assert audit["covered_count"] == 1
    assert audit["not_promoted_count"] == 1
    assert audit["covered_candidate_ids"] == ["cand-0101"]
    assert audit["not_promoted_candidate_ids"] == ["cand-0049"]

    rows = {row["candidate_id"]: row for row in audit["coverage"]}
    assert rows["cand-0101"]["status"] == "covered_traceable"
    assert rows["cand-0101"]["matching_finding_ids"] == ["F900"]
    assert rows["cand-0049"]["status"] == "not_promoted_reserved_for_review"
    assert "cand-0956" not in rows


def test_fact_id_match_counts_as_traceability_even_without_candidate_id():
    findings = [
        {
            "finding_id": "F901",
            "title": "RDP target corroborated staging access",
            "raw_excerpt": "supporting fact rdp_artifact_fact-0000001",
            "source_tools": ["parse_rdp_artifacts"],
        }
    ]

    audit = build_candidate_reserve_coverage(_payload(), findings)

    rows = {row["candidate_id"]: row for row in audit["coverage"]}
    assert rows["cand-0049"]["status"] == "covered_traceable"
    assert rows["cand-0049"]["matching_finding_ids"] == ["F901"]


def test_run_pipeline_freezes_candidate_reserve_coverage_into_report_truth():
    text = Path("run_pipeline.py").read_text()
    assert "build_candidate_reserve_coverage" in text
    assert '"candidate_reserve_coverage"' in text
    assert "CANDIDATE_RESERVE_COVERAGE" in text
