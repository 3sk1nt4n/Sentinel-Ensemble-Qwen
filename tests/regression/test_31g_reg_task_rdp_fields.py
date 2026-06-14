from __future__ import annotations

from sift_sentinel.analysis.evidence_db import INDEX_NAMES, _TOOL_COMPILERS


def _emit(tool_name: str, record: dict) -> dict:
    compiler = _TOOL_COMPILERS[tool_name]
    emitted = list(compiler([record]))
    assert len(emitted) == 1
    idx, fact, reason = emitted[0]
    assert idx == 0
    assert reason is None
    assert fact is not None
    return fact


def test_registry_persistence_preserves_numeric_zero_value_data() -> None:
    fact = _emit(
        "parse_registry_persistence",
        {
            "tool": "parse_registry_persistence",
            "hive_type": "SYSTEM",
            "source_hive": "/mnt/Windows/System32/config/SYSTEM",
            "registry_path": r"HKLM\\SYSTEM\\ControlSet001\\Services\\AcmeDriver",
            "value_name": "Start",
            "value_data": 0,
            "value_type": "REG_DWORD",
            "persistence_type": "service",
            "service_name": "AcmeDriver",
            "control_set": "ControlSet001",
            "is_active_controlset": True,
            "last_write_time": "2018-01-01T00:00:00+00:00",
        },
    )

    fields = fact["fields"]
    assert fact["fact_type"] == "registry_persistence_fact"
    assert fields["value_data"] == 0
    assert fields["value_type"] == "REG_DWORD"
    assert fields["control_set"] == "ControlSet001"
    assert fields["is_active_controlset"] is True
    assert fields["source_hive"].endswith("SYSTEM")
    assert fact["index"]["by_service_name"] == ["acmedriver"]


def test_scheduled_task_preserves_action_details_and_task_metadata() -> None:
    fact = _emit(
        "parse_scheduled_tasks_disk",
        {
            "tool": "parse_scheduled_tasks_disk",
            "source_path": "/mnt/windows_mount/Windows/System32/Tasks/AcmeTask",
            "task_name": "AcmeTask",
            "task_path": "Microsoft/Windows/Acme/AcmeTask",
            "author": "DOMAIN\\User",
            "user_id": "S-1-5-18",
            "enabled": True,
            "hidden": True,
            "run_level": "HighestAvailable",
            "logon_type": "InteractiveToken",
            "created": "2018-01-01T00:00:00",
            "modified": "2018-01-02T00:00:00",
            "description": "Synthetic task",
            "triggers": [{"type": "LogonTrigger", "enabled": True}],
            "actions": [
                {
                    "type": "Exec",
                    "execute": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "arguments": "-EncodedCommand AAAA",
                    "working_directory": r"C:\\Windows\\Temp",
                },
                {
                    "type": "ComHandler",
                    "class_id": "{11111111-2222-3333-4444-555555555555}",
                    "data": "/RuntimeWide",
                },
            ],
        },
    )

    fields = fact["fields"]
    assert fact["fact_type"] == "scheduled_task_fact"
    assert fields["source_path"].endswith("/AcmeTask")
    assert fields["user_id"] == "S-1-5-18"
    assert fields["run_level"] == "HighestAvailable"
    assert fields["logon_type"] == "InteractiveToken"
    assert fields["created"] == "2018-01-01T00:00:00"
    assert fields["modified"] == "2018-01-02T00:00:00"
    assert fields["description"] == "Synthetic task"

    details = fields["action_details"]
    assert details[0]["type"] == "Exec"
    assert "powershell.exe" in details[0]["normalized_execute"]
    assert details[0]["arguments"] == "-EncodedCommand AAAA"
    assert details[1]["type"] == "ComHandler"
    assert details[1]["class_id"] == "{11111111-2222-3333-4444-555555555555}"

    assert "by_path" in fact["index"]
    if "by_class_id" in INDEX_NAMES:
        assert "by_class_id" in fact["index"]
    if "by_user" in INDEX_NAMES:
        assert fact["index"]["by_user"] == ["s-1-5-18"]


def test_rdp_artifact_preserves_structured_fields_and_indexes_target() -> None:
    fact = _emit(
        "parse_rdp_artifacts",
        {
            "type": "rdp_default_profile",
            "source_kind": "rdp_profile_file",
            "extraction_method": "rdp_profile_directive",
            "source_file": "/mnt/windows_mount/Users/spsql/Documents/Default.rdp",
            "record_id": "rdp_default_profile:/mnt/windows_mount/Users/spsql/Documents/Default.rdp",
            "raw_excerpt": "full address:s:172.16.7.11",
            "user": "DOMAIN\\spsql",
            "host_or_target": "172.16.7.11",
            "timestamp": "2018-01-12T14:51:23+00:00",
            "event_id": 21,
            "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
            "computer": "HOST-A",
        },
    )

    assert fact["fact_type"] == "rdp_artifact_fact"
    assert fact["canonical_entity_id"] == "rdp:172.16.7.11"
    fields = fact["fields"]
    assert fields["record_type"] == "rdp_default_profile"
    assert fields["source_kind"] == "rdp_profile_file"
    assert fields["host_or_target"] == "172.16.7.11"
    assert fields["user"] == "DOMAIN\\spsql"
    assert fields["event_id"] == 21
    assert fields["channel"].endswith("/Operational")
    assert fields["source_file"].endswith("Default.rdp")
    assert fact["index"]["by_ip"] == ["172.16.7.11"]
    if "by_host" in INDEX_NAMES:
        assert fact["index"]["by_host"] == ["172.16.7.11"]
    if "by_user" in INDEX_NAMES:
        assert fact["index"]["by_user"] == ["domain\\spsql"]
    if "by_event_id" in INDEX_NAMES:
        assert fact["index"]["by_event_id"] == ["21"]
