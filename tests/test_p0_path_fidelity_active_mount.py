import json
from pathlib import Path

def test_run_pipeline_sets_active_mount_after_disk_mount_assignment():
    text = Path("run_pipeline.py").read_text()
    assert 'DISK_MOUNT = _args.disk_mount or DISK_MOUNT_PATH' in text
    assert 'os.environ["SIFT_ACTIVE_DISK_MOUNT"] = str(DISK_MOUNT)' in text

def test_disk_tools_prefer_active_mount_before_global_default():
    ps = Path("src/sift_sentinel/tools/parse_powershell_transcripts.py").read_text()
    wmi = Path("src/sift_sentinel/tools/parse_wmi_subscription.py").read_text()
    assert "SIFT_ACTIVE_DISK_MOUNT" in ps
    assert "SIFT_ACTIVE_DISK_MOUNT" in wmi

def test_parse_powershell_no_arg_uses_active_mount_not_global(monkeypatch, tmp_path):
    from sift_sentinel.tools.parse_powershell_transcripts import parse_powershell_transcripts
    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", str(tmp_path))
    result = parse_powershell_transcripts()
    text = json.dumps(result, default=str)
    assert "/mnt/windows_mount" not in text
    assert str(tmp_path) in text

def test_parse_wmi_no_arg_uses_active_mount_not_global(monkeypatch, tmp_path):
    from sift_sentinel.tools.parse_wmi_subscription import parse_wmi_subscription
    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", str(tmp_path))
    result = parse_wmi_subscription()
    text = json.dumps(result, default=str)
    assert "/mnt/windows_mount" not in text
    assert str(tmp_path) in text

def test_extract_mft_timeline_direct_call_no_duplicate_disk_path(tmp_path):
    from sift_sentinel.tools import disk
    result = disk.extract_mft_timeline(str(tmp_path))
    assert isinstance(result, dict)
    assert result.get("status") in {"not_applicable", "no_records", "ok_no_records", "error"}
    assert result.get("reason") or result.get("zero_record_reason")
