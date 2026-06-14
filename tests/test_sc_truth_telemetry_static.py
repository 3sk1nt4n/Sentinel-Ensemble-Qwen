from pathlib import Path


def test_step12_future_loop_has_finding_id_exception_and_summary_telemetry():
    text = Path("src/sift_sentinel/coordinator.py").read_text()
    assert "Step 12 SC: parallel correction failed" not in text
    assert 'logger.exception("Step 12 SC failed for finding=%s"' in text
    assert "SELF_CORRECTION_TRIGGERED" in text
    assert "SELF_CORRECTION_FINDING_RESULT" in text
    assert "SELF_CORRECTION_SUMMARY" in text
    assert "SELF_CORRECTION_EXECUTION_GATE" in text


def test_step12_exception_finding_id_handles_nested_tuple_items():
    text = Path("src/sift_sentinel/coordinator.py").read_text()
    assert "def _sc_item_finding_id(item)" in text
    assert 'for key in ("finding", "draft", "original", "finding_dict")' in text
    assert "isinstance(obj, (list, tuple))" in text
    assert "executor.submit(_correct_one, item): _sc_item_finding_id(item)" in text


def test_self_correction_not_needed_message_is_guarded_by_rejected_count():
    text = Path("run_pipeline.py").read_text()
    idx = text.index("Self-correction: not needed (all findings passed first attempt)")
    nearby = text[max(0, idx - 800):idx + 250]
    assert "_sc_rejected_count == 0" in nearby
    assert "attempted on %d rejected finding" in text


def test_sc_normalizes_prompt_without_replacing_original_finding_object():
    text = Path("src/sift_sentinel/correction/self_correct.py").read_text()
    assert "finding = normalize_sc_finding(finding)  # SC_SCHEMA_HARDENING" in text
    assert "SC_SCHEMA_HARDENING_SELF_CORRECT" not in text
    assert "strategy[\"template\"].format(" not in text
    assert "_safe_format_strategy_template(" in text
