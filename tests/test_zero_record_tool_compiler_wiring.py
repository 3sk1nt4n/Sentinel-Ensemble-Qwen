def test_zero_record_selected_tools_have_compiler_or_reason_module():
    from sift_sentinel.analysis import evidence_db
    from sift_sentinel.analysis.zero_record_reasons import infer_zero_record_reason

    compilers = getattr(evidence_db, "_TOOL_COMPILERS", {})

    # If records ever exist, these must not become silent data drops.
    for tool in ("parse_prefetch", "sleuthkit_mactime", "run_srumecmd"):
        assert tool in compilers, f"{tool} missing EvidenceDB compiler mapping"

    # If records are absent, these must explain why.
    for tool in ("parse_prefetch", "sleuthkit_mactime", "run_srumecmd"):
        result = infer_zero_record_reason(tool, {"record_count": 0}, env={})
        assert result["status"] in {"not_applicable", "empty_valid", "error", "missing_reason"}


def test_run_pipeline_emits_zero_record_reason_gate():
    from pathlib import Path

    text = Path("run_pipeline.py").read_text()
    assert "ZERO_RECORD_REASON_GATE" in text
    assert "ZERO_RECORD_TOOL_RESULT" in text
    assert "zero_record_reasons.json" in text
