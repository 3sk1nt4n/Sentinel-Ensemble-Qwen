from pathlib import Path
import json

from sift_sentinel.analysis.tool_hit_integrity import (
    build_hit_maps,
    check_state_dir_tool_hit_integrity,
    enforce_state_dir_tool_hit_integrity,
    sanitize_findings_inplace,
)


def test_zero_record_tool_removed_from_source_and_claim_tools():
    all_outputs = {
        "vol_pstree": {"status": "ok", "records": [{"PID": 1}]},
        "get_amcache": {"status": "not_applicable", "records": []},
        "parse_prefetch": {"status": "ok", "records": []},
    }
    hit_map, zero = build_hit_maps(all_outputs)
    assert "vol_pstree" in hit_map
    assert "get_amcache" in zero
    assert "parse_prefetch" in zero

    finding = {
        "id": "F900",
        "title": "generic summary",
        "source_tools": ["vol_pstree", "get_amcache", "parse_prefetch"],
        "claim_tools": ["tool_get_amcache", "vol_pstree"],
        "claims": [
            {"type": "pid", "pid": 1, "process": "x.exe", "source_tool": "get_amcache"},
            {"type": "pid", "pid": 1, "process": "x.exe", "source_tool": "vol_pstree"},
        ],
    }

    removed = sanitize_findings_inplace(finding, hit_map)
    assert removed >= 3
    assert finding["source_tools"] == ["vol_pstree"]
    assert finding["claim_tools"] == ["vol_pstree"]
    assert "source_tool" not in finding["claims"][0]
    assert finding["claims"][1]["source_tool"] == "vol_pstree"


def test_state_enforcer_removes_zero_hits_and_routes_nohit_actionable(tmp_path: Path):
    state = tmp_path
    (state / "tool_outputs").mkdir()

    (state / "all_outputs.json").write_text(json.dumps({
        "vol_pstree": {"status": "ok", "records": [{"PID": 10}]},
        "get_amcache": {"status": "not_applicable", "records": []},
        "parse_prefetch": {"status": "ok", "records": []},
    }))

    buckets = {
        "confirmed_malicious_atomic": [
            {
                "id": "F001",
                "title": "zero-only unsupported",
                "source_tools": ["get_amcache"],
                "claims": [{"type": "artifact", "source_tool": "get_amcache"}],
            }
        ],
        "suspicious_needs_review": [
            {
                "id": "F002",
                "title": "mixed evidence",
                "source_tools": ["vol_pstree", "parse_prefetch"],
                "claims": [{"type": "pid", "pid": 10, "process": "x.exe", "source_tool": "vol_pstree"}],
            }
        ],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    (state / "finding_disposition_buckets.json").write_text(json.dumps(buckets))
    (state / "findings_final.json").write_text(json.dumps(buckets["confirmed_malicious_atomic"] + buckets["suspicious_needs_review"]))

    result = enforce_state_dir_tool_hit_integrity(state, fail=True)
    assert result["status"] == "pass"
    assert result["removed_refs"] >= 2
    assert result["routed_nohit_to_inconclusive"] == 1

    fixed = json.loads((state / "finding_disposition_buckets.json").read_text())
    assert fixed["confirmed_malicious_atomic"] == []
    assert fixed["suspicious_needs_review"][0]["source_tools"] == ["vol_pstree"]
    assert fixed["inconclusive_unresolved"][0]["id"] == "F001"

    assert check_state_dir_tool_hit_integrity(state) is True


def test_tool_alias_tool_prefix_does_not_preserve_zero_tool():
    all_outputs = {
        "run_appcompatcacheparser": {"status": "ok", "records": [{"path": "x"}]},
        "get_amcache": {"status": "not_applicable", "records": []},
    }
    hit_map, _ = build_hit_maps(all_outputs)
    finding = {
        "id": "F003",
        "source_tools": ["tool_get_amcache", "tool_run_appcompatcacheparser"],
        "claims": [{"type": "path", "source_tools": ["tool_get_amcache", "tool_run_appcompatcacheparser"]}],
    }
    sanitize_findings_inplace(finding, hit_map)
    assert "tool_get_amcache" not in finding["source_tools"]
    assert "tool_run_appcompatcacheparser" in finding["source_tools"]
    assert "tool_get_amcache" not in finding["claims"][0]["source_tools"]
