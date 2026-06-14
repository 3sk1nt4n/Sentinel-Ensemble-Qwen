import json
from pathlib import Path

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    build_customer_findings_table,
    write_customer_findings_table,
)


def _buckets():
    return {
        "suspicious_needs_review": [
            {
                "finding_id": "F039",
                "title": "Needs review stays actionable",
                "source_tools": ["vol_pstree"],
                "claims": [{"type": "process_exists", "pid": 123, "process": "x.exe"}],
            }
        ],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "confirmed_malicious_atomic": [],
    }


def test_build_alias_exists_and_is_bucket_faithful():
    text = build_customer_findings_table(_buckets())
    actionable = text.split("## Actionable / Needs Review", 1)[1].split("## Self-Correction / Inconclusive", 1)[0]
    assert "F039" in actionable
    assert "Confidence" not in text
    assert "Severity" not in text


def test_write_alias_accepts_state_dir(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "finding_disposition_buckets.json").write_text(json.dumps(_buckets()))

    out = write_customer_findings_table(state)

    assert Path(out).exists()
    text = Path(out).read_text()
    assert "F039" in text


def test_write_alias_accepts_bucket_dict_and_output_path(tmp_path):
    out = tmp_path / "table.md"

    ret = write_customer_findings_table(_buckets(), out)

    assert Path(ret) == out
    text = out.read_text()
    assert "F039" in text
