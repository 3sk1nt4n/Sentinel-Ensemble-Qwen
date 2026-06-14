"""Commit 12: N12 date injection into Inv4 prompt header."""
from datetime import datetime, timezone
from pathlib import Path

from sift_sentinel.coordinator import build_inv4_prompt


def _minimal_findings() -> list[dict]:
    """Minimal findings list sufficient for build_inv4_prompt."""
    return [
        {"finding_id": "F001", "severity": "MEDIUM", "summary": "test finding"},
    ]


def test_inv4_prompt_contains_analysis_timestamp(tmp_path):
    """Prompt must contain explicit 'Analysis timestamp' label."""
    prompt_path = build_inv4_prompt(_minimal_findings(), tmp_path)
    text = prompt_path.read_text()
    assert "Analysis timestamp (UTC):" in text


def test_inv4_prompt_timestamp_is_iso8601_today(tmp_path):
    """Injected timestamp must be today's date in ISO 8601 UTC format."""
    prompt_path = build_inv4_prompt(_minimal_findings(), tmp_path)
    text = prompt_path.read_text()
    today_utc = datetime.now(timezone.utc).date().isoformat()
    assert today_utc in text, f"today {today_utc} not found in prompt"


def test_inv4_prompt_instructs_ai_to_use_exact_timestamp(tmp_path):
    """Prompt must instruct AI to use the given timestamp, not invent one."""
    prompt_path = build_inv4_prompt(_minimal_findings(), tmp_path)
    text = prompt_path.read_text()
    assert "Use this exact timestamp" in text
    assert "Do not invent" in text


def test_inv4_prompt_header_has_today_timestamp(tmp_path):
    """Timestamp header block must contain today's date.

    Findings section may contain other dates (evidence timestamps from
    file mtimes or event log entries). Only the header before '## Findings'
    is deterministic and assert-able.
    """
    prompt_path = build_inv4_prompt(_minimal_findings(), tmp_path)
    text = prompt_path.read_text()
    header = text.split("## Findings")[0]
    today = datetime.now(timezone.utc).date().isoformat()
    assert today in header, f"today {today} not in prompt header"
    assert "2025-07-14" not in header, "stale hallucinated date sentinel"
