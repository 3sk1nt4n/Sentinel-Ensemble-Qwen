
"""31M-alpha.4: candidate queue should drive distinct validator-backed findings.

Synthetic only. Dataset-agnostic. No case facts.
"""

from pathlib import Path

from sift_sentinel.analysis.candidate_observations import render_candidate_observations_for_prompt


def test_candidate_renderer_contains_conversion_rules_and_candidate_id():
    payload = {
        "candidates": [
            {
                "candidate_id": "cand-0001",
                "candidate_type": "encoded_powershell_or_download_cradle",
                "score": 100,
                "entity_key": "synthetic:entity",
                "validation_ready": True,
                "source_tools": ["parse_powershell_transcripts"],
                "fact_types": ["powershell_command_fact"],
                "signals": ["powershell_ttp:encoded_command"],
                "fact_ids": ["powershell_command_fact-synthetic-1"],
                "claim_templates": ['{"type": "powershell_command", "ttp_tag": "encoded_command"}'],
            }
        ]
    }

    rendered = render_candidate_observations_for_prompt(payload)

    assert "Validation-ready candidate conversion rules" in rendered
    assert "candidate_id=cand-0001" in rendered
    assert "one finding per distinct validation-ready candidate" in rendered
    assert "If 20 or more validation-ready candidates" in rendered
    assert "Do NOT collapse unrelated candidates" in rendered
    assert '"type": "powershell_command"' in rendered
    assert "powershell_command_fact-synthetic-1" in rendered


def test_inv2_prompt_sources_no_longer_force_8_to_12_or_pid_primary_only():
    sources = [
        Path("run_pipeline.py").read_text(),
        Path("src/sift_sentinel/prompts.py").read_text(),
    ]

    for src in sources:
        assert "Use PID claims as your PRIMARY evidence" not in src
        assert "A finding with 2-3 PID claims and nothing else is EXCELLENT" not in src
        assert "On multi-stage intrusion with memory + disk evidence: 8-12 findings" not in src
        assert "attempt at least 20 distinct validator-backed findings" in src
        assert "candidate_id and fact_ids" in src
        assert "Do NOT collapse unrelated" in src
