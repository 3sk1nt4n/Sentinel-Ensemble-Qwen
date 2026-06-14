"""Tests for the Ollama-specific Inv2 data-first prompt builder."""

import pytest

from sift_sentinel.tools.common import build_ollama_inv2_prompt


# ── Sample tool outputs (mimics real pipeline data) ────────────────────

SAMPLE_OUTPUTS = {
    "vol_pstree": {
        "record_count": 3,
        "output": [
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2018-11-15T00:00:00"},
            {"PID": 1234, "PPID": 4, "ImageFileName": "sqlsvc.exe", "CreateTime": "2018-11-15T10:00:00"},
            {"PID": 9004, "PPID": 1234, "ImageFileName": "rundll32.exe", "CreateTime": "2018-11-15T10:05:00"},
        ],
    },
    "vol_netscan": {
        "record_count": 2,
        "output": [
            {"PID": 1234, "LocalAddr": "192.0.2.111", "ForeignAddr": "192.0.2.129", "State": "ESTABLISHED", "Owner": "sqlsvc.exe"},
            {"PID": 9004, "LocalAddr": "192.0.2.111", "ForeignAddr": "10.0.0.1", "State": "CLOSED", "Owner": "rundll32.exe"},
        ],
    },
    "vol_malfind": {
        "record_count": 1,
        "output": [
            {"PID": 9004, "ImageFileName": "rundll32.exe", "Offset(V)": "0xfa801234"},
        ],
    },
}

EMPTY_OUTPUTS = {
    "vol_pstree": {"record_count": 0, "output": []},
    "vol_netscan": {"record_count": 0, "output": []},
}


class TestOllamaInv2PromptHasData:
    """Prompt must contain actual tool output text, not just instructions."""

    def test_contains_process_names(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "sqlsvc.exe" in prompt
        assert "rundll32.exe" in prompt

    def test_contains_pids(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        # PID format varies by tool type (PID=N for pstree, PID N for netscan)
        assert "1234" in prompt
        assert "9004" in prompt

    def test_contains_network_data(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "192.0.2.129" in prompt
        assert "ESTABLISHED" in prompt

    def test_netscan_skips_closed(self):
        """CLOSED connections should be filtered out of netscan summary."""
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        # The CLOSED connection for PID 9004 in netscan should be omitted
        # (but 9004 may appear via pstree or malfind)
        netscan_section = prompt[prompt.index("vol_netscan"):prompt.index("vol_malfind")]
        assert "CLOSED" not in netscan_section

    def test_pstree_filters_safe_processes(self):
        """Safe processes like System should be counted but not listed individually."""
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        pstree_section = prompt[prompt.index("vol_pstree"):prompt.index("vol_netscan")]
        assert "known Windows" in pstree_section
        assert "OTHER" in pstree_section
        # System is safe -- should appear in count, not as a line item
        assert "ImageFileName=System" not in pstree_section
        # sqlsvc.exe is NOT safe -- should appear
        assert "sqlsvc.exe" in pstree_section

    def test_tool_names_present(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "vol_pstree" in prompt
        assert "vol_netscan" in prompt
        assert "vol_malfind" in prompt

    def test_data_appears_before_instructions(self):
        """Tool data must appear BEFORE the JSON schema instructions."""
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        data_pos = prompt.index("sqlsvc.exe")
        schema_pos = prompt.index("finding_id")
        assert data_pos < schema_pos, "Data must come before schema instructions"


class TestOllamaInv2PromptUnder25k:
    """Prompt must fit within Qwen's effective token budget."""

    def test_small_outputs_under_limit(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert len(prompt) < 25000

    def test_large_outputs_truncated(self):
        """Even with many records, prompt stays under limit."""
        big_outputs = {
            "vol_pstree": {
                "record_count": 500,
                "output": [
                    {"PID": i, "PPID": i - 1, "ImageFileName": f"proc_{i}.exe",
                     "CreateTime": "2018-11-15T10:00:00", "CommandLine": "x" * 200}
                    for i in range(500)
                ],
            },
        }
        prompt = build_ollama_inv2_prompt(big_outputs)
        assert len(prompt) < 25000

    def test_empty_outputs_still_valid(self):
        prompt = build_ollama_inv2_prompt(EMPTY_OUTPUTS)
        assert len(prompt) < 25000
        assert "finding_id" in prompt


class TestOllamaInv2PromptHasSchema:
    """Prompt must contain the required schema field names."""

    def test_has_finding_id(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "finding_id" in prompt

    def test_has_claims(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "claims" in prompt

    def test_has_source_tools(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "source_tools" in prompt

    def test_has_confidence(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "confidence" in prompt

    def test_has_json_instruction(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "JSON" in prompt


class TestOllamaInv2ToolFailures:
    """Tool failures should be noted concisely."""

    def test_failures_included(self):
        failures = [{"tool": "get_amcache"}, {"tool": "vol_handles"}]
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS, tool_failures=failures)
        assert "get_amcache" in prompt
        assert "vol_handles" in prompt

    def test_no_failures_no_section(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "Failed tools" not in prompt

    def test_failures_none_no_section(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS, tool_failures=None)
        assert "Failed tools" not in prompt


class TestOllamaInv2CriticalRules:
    """CRITICAL RULES block must be present."""

    def test_has_critical_rules(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "CRITICAL RULES" in prompt

    def test_warns_against_null_pids(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert '"pid": null' in prompt  # the WRONG example

    def test_warns_against_inventing_pids(self):
        prompt = build_ollama_inv2_prompt(SAMPLE_OUTPUTS)
        assert "Do NOT invent" in prompt


class TestOllamaInv2SmartFiltering:
    """Smart per-tool filtering tests."""

    def test_amcache_filters_system_paths(self):
        outputs = {
            "get_amcache": {
                "record_count": 3,
                "output": [
                    {"path": "c:\\windows\\system32\\notepad.exe", "sha1": "aaa"},
                    {"path": "c:\\users\\admin\\desktop\\tool.exe", "sha1": "bbb"},
                    {"path": "c:\\program files\\firefox\\firefox.exe", "sha1": "ccc"},
                ],
            },
        }
        prompt = build_ollama_inv2_prompt(outputs)
        assert "tool.exe" in prompt
        assert "OTHER" in prompt

    def test_prefetch_shows_all(self):
        outputs = {
            "parse_prefetch": {
                "record_count": 2,
                "output": [
                    {"executable": "SPSQL.EXE", "run_count": 5, "last_run": "2018-09-06"},
                    {"executable": "CMD.EXE", "run_count": 12, "last_run": "2018-09-07"},
                ],
            },
        }
        prompt = build_ollama_inv2_prompt(outputs)
        assert "SPSQL.EXE" in prompt
        assert "CMD.EXE" in prompt
        assert "run count: 5" in prompt

    def test_event_logs_prioritise_security(self):
        outputs = {
            "parse_event_logs": {
                "record_count": 3,
                "output": [
                    {"EventId": 4624, "Name": "Logon"},
                    {"EventId": 1000, "Name": "AppError"},
                    {"EventId": 4688, "Name": "ProcessCreate"},
                ],
            },
        }
        prompt = build_ollama_inv2_prompt(outputs)
        assert "security" in prompt.lower()
        assert "routine" in prompt.lower()

    def test_netscan_external_before_local(self):
        """External IPs should sort before 127.0.0.1."""
        outputs = {
            "vol_netscan": {
                "record_count": 2,
                "output": [
                    {"PID": 100, "LocalAddr": "127.0.0.1", "ForeignAddr": "127.0.0.1",
                     "State": "ESTABLISHED", "Owner": "local.exe"},
                    {"PID": 200, "LocalAddr": "10.0.0.1", "ForeignAddr": "8.8.8.8",
                     "State": "ESTABLISHED", "Owner": "remote.exe"},
                ],
            },
        }
        prompt = build_ollama_inv2_prompt(outputs)
        remote_pos = prompt.index("remote.exe")
        local_pos = prompt.index("local.exe")
        assert remote_pos < local_pos, "External connections should appear first"
