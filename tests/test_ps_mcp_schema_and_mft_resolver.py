import inspect
from pathlib import Path

def test_powershell_parser_has_explicit_mcp_schema_signature():
    from sift_sentinel.tools.parse_powershell_transcripts import parse_powershell_transcripts
    sig = inspect.signature(parse_powershell_transcripts)
    assert "args" not in sig.parameters
    assert "kwargs" not in sig.parameters
    assert "image_path" in sig.parameters
    assert "disk_mount" in sig.parameters

def test_powershell_parser_accepts_image_path_but_uses_active_mount(monkeypatch, tmp_path):
    from sift_sentinel.tools.parse_powershell_transcripts import parse_powershell_transcripts
    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", str(tmp_path))
    result = parse_powershell_transcripts(image_path="/tmp/not-a-disk.img")
    assert result["evidence_path"] == str(tmp_path)
    assert result["status"] in {"not_applicable", "ok_no_records", "transcripts_parsed"}
    assert "/mnt/windows_mount" not in str(result)

def test_mft_resolver_does_not_pass_literal_mft_file():
    text = Path("src/sift_sentinel/runtime/high_value_tool_args.py").read_text()
    assert '{"disk_path": str(source)}' not in text
    assert '{"disk_path": str(mft)}' not in text

def test_isolated_runner_does_not_force_color_off():
    text = Path("scripts/run_live_pair_isolated_mount.sh").read_text()
    assert "export SIFT_FORCE_COLOR=0" not in text
    assert 'SIFT_FORCE_COLOR="${SIFT_FORCE_COLOR:-1}"' in text
