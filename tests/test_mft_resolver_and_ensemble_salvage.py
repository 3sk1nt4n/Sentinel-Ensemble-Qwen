from pathlib import Path

def test_mft_resolver_no_undefined_root():
    text = Path("src/sift_sentinel/runtime/high_value_tool_args.py").read_text()
    start = text.find("def _resolve_extract_mft_timeline")
    end = text.find("\ndef ", start + 1)
    block = text[start:end if end > start else len(text)]
    assert "str(root)" not in block

def test_mft_resolver_does_not_raise_nameerror(tmp_path):
    from sift_sentinel.runtime.high_value_tool_args import _resolve_extract_mft_timeline
    (tmp_path / "$MFT").write_text("synthetic", encoding="utf-8")
    try:
        result = _resolve_extract_mft_timeline(tmp_path, None)
    except NameError as exc:
        raise AssertionError(f"MFT resolver raised NameError: {exc}") from exc
    assert isinstance(result, dict)

def test_ensemble_lenient_json_salvages_extra_text():
    import sift_sentinel.ensemble as ensemble
    loader = getattr(ensemble, "_sift_ensemble_json_loads_lenient")
    assert loader('{"findings": []}\n\nextra text') == {"findings": []}
    assert loader('```json\n[{"id": "F001"}]\n```\ntrailing') == [{"id": "F001"}]
