from pathlib import Path

from sift_sentinel.analysis.zero_record_reasons import build_zero_record_audit


def test_zero_record_gate_classifies_actual_all_outputs_envelopes():
    selected = ["parse_prefetch", "vol_userassist", "run_srumecmd"]
    all_outputs = {
        "parse_prefetch": {
            "tool_name": "parse_prefetch",
            "status": "not_applicable",
            "kind": "not_applicable",
            "reason": "artifact class absent on mounted evidence",
            "records": [],
            "record_count": 0,
        },
        "run_srumecmd": {
            "tool_name": "run_srumecmd",
            "status": "not_applicable",
            "kind": "not_applicable",
            "reason": "required source artifact absent",
            "records": [],
            "record_count": 0,
        },
        "vol_userassist": {
            "tool_name": "vol_userassist",
            "output": [],
            "record_count": 0,
        },
    }

    audit = build_zero_record_audit(selected, all_outputs, disk_mount=None, env={})
    by_tool = {row["tool"]: row for row in audit["zero_record_tools"]}

    assert audit["gate"] == "PASS"
    assert len(audit["zero_record_tools"]) == 3
    assert audit["missing_reason_tools"] == []

    assert by_tool["parse_prefetch"]["status"] == "not_applicable"
    assert by_tool["run_srumecmd"]["status"] == "not_applicable"
    assert by_tool["vol_userassist"]["status"] == "ok_no_records"
    assert "zero records" in by_tool["vol_userassist"]["reason"]


def test_run_pipeline_zero_record_gate_uses_all_outputs_not_registry_namespace():
    text = Path("run_pipeline.py").read_text(errors="replace")
    start = text.index("# ── ZERO_RECORD_REASON_GATE")
    end = text.index("\n# ═════════", start)
    block = text[start:end]

    assert "all_outputs" in block
    assert "source\": \"all_outputs\"" in block or '"source": "all_outputs"' in block
    assert "choose_tool_outputs_for_zero_audit" not in block
    assert "_choose_zero_record_outputs" not in block
    assert "namespace_scan:_TOOL_REGISTRY" not in block
