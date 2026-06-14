from sift_sentinel.correction.self_correct import _safe_format_strategy_template


def test_safe_strategy_template_survives_literal_json_type_braces():
    template = 'Finding {finding_id}: return {"type":"pid","pid":123}; also {{ "type": "hash" }}'
    out = _safe_format_strategy_template(
        template,
        finding_id="F_SYN",
        validation_error="E",
        failed_claim="C",
        context_dossier="D",
    )
    assert "F_SYN" in out
    assert '{"type":"pid","pid":123}' in out
    assert '{ "type": "hash" }' in out
    assert "{{" not in out and "}}" not in out
