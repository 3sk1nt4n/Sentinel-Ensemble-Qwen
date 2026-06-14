from sift_sentinel.analysis.candidate_observations import (
    render_candidate_observations_for_prompt,
)


def _candidate(
    cid: str,
    *,
    tools: list[str],
    fact_types: list[str],
    signals: list[str],
    ctype: str,
    score: int,
    ready: bool = True,
    entity: str = "entity:generic",
) -> dict:
    return {
        "candidate_id": cid,
        "candidate_type": ctype,
        "score": score,
        "entity_key": entity,
        "validation_ready": ready,
        "signals": signals,
        "source_tools": tools,
        "fact_types": fact_types,
        "fact_ids": [f"{fact_types[0]}-0000001"] if fact_types else [],
        "supporting_facts": [],
        "disconfirming_facts": [],
        "suppression_reason": "",
        "claim_templates": [{"type": ctype, "source_tools": tools}],
    }


def _top_power_shell_candidates(n: int = 40) -> list[dict]:
    return [
        _candidate(
            f"cand-{i:04d}",
            tools=["parse_powershell_transcripts", "extract_network_iocs"],
            fact_types=["powershell_command_fact", "network_ioc_fact"],
            signals=[
                "powershell_encoded_command",
                "powershell_download_cradle",
                "multi_source",
            ],
            ctype="encoded_powershell_or_download_cradle",
            score=1000 - i,
            entity=f"ip:loopback-{i}",
        )
        for i in range(1, n + 1)
    ]


def test_registry_validation_ready_candidate_outside_top_n_is_reserved() -> None:
    registry_candidate = _candidate(
        "cand-0101",
        tools=["parse_registry_persistence"],
        fact_types=["registry_persistence_fact"],
        signals=["high_risk_persistence"],
        ctype="high_risk_persistence",
        score=95,
        entity="registry:generic/safeboot/alternateshell",
    )
    payload = {
        "candidates": _top_power_shell_candidates() + [registry_candidate],
        "corroborated_review_candidates": [],
    }

    text = render_candidate_observations_for_prompt(payload, top_n=40)

    assert "validation_ready_reserve_candidates" in text
    assert "candidate_id=cand-0101" in text
    assert "parse_registry_persistence" in text


def test_rdp_validation_ready_candidate_outside_top_n_is_reserved() -> None:
    rdp_candidate = _candidate(
        "cand-0049",
        tools=[
            "parse_rdp_artifacts",
            "parse_event_logs",
            "extract_network_iocs",
        ],
        fact_types=[
            "rdp_artifact_fact",
            "event_log_fact",
            "network_ioc_fact",
        ],
        signals=[
            "rdp_target_reference",
            "event_staging_path",
            "multi_source",
            "multi_fact_type",
        ],
        ctype="suspicious_file_or_process_execution",
        score=245,
        entity="host:rdp-target",
    )
    payload = {
        "candidates": _top_power_shell_candidates() + [rdp_candidate],
        "corroborated_review_candidates": [],
    }

    text = render_candidate_observations_for_prompt(payload, top_n=40)

    assert "validation_ready_reserve_candidates" in text
    assert "candidate_id=cand-0049" in text
    assert "parse_rdp_artifacts" in text


def test_hidden_only_scheduled_task_is_not_reserved() -> None:
    hidden_only_task = _candidate(
        "cand-0956",
        tools=["parse_scheduled_tasks_disk"],
        fact_types=["scheduled_task_fact"],
        signals=["hidden_scheduled_task"],
        ctype="high_risk_persistence",
        score=35,
        entity="task:generic-hidden-task",
    )
    payload = {
        "candidates": _top_power_shell_candidates(1) + [hidden_only_task],
        "corroborated_review_candidates": [],
    }

    text = render_candidate_observations_for_prompt(payload, top_n=1)

    assert "candidate_id=cand-0956" not in text


def test_suspicious_scheduled_task_action_is_reserved() -> None:
    suspicious_task = _candidate(
        "cand-0999",
        tools=["parse_scheduled_tasks_disk"],
        fact_types=["scheduled_task_fact"],
        signals=["scheduled_task_points_to_staging_path"],
        ctype="high_risk_persistence",
        score=95,
        entity="task:generic-staging-action",
    )
    payload = {
        "candidates": _top_power_shell_candidates() + [suspicious_task],
        "corroborated_review_candidates": [],
    }

    text = render_candidate_observations_for_prompt(payload, top_n=40)

    assert "validation_ready_reserve_candidates" in text
    assert "candidate_id=cand-0999" in text
    assert "parse_scheduled_tasks_disk" in text
