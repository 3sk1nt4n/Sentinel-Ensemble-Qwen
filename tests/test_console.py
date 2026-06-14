"""Tests for the agentic DFIR terminal (console.py)."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sift_sentinel.console import (
    SIFTConsole,
    detect_evidence,
    count_tools,
    extract_followups,
    flatten_pstree,
    load_json,
    parse_args,
    render_welcome,
    _build_ai_prompt,
    _parse_thinking,
    _trim_context,
    _human_size,
)


# ── Fixtures ──────────────────────────────────────────────────────────

SAMPLE_PSTREE = [
    {
        "PID": 4, "PPID": 0, "ImageFileName": "System",
        "CreateTime": "2018-08-30T13:51:58+00:00", "Cmd": None,
        "__children": [
            {
                "PID": 388, "PPID": 4, "ImageFileName": "smss.exe",
                "CreateTime": "2018-08-30T13:52:00+00:00", "Cmd": None,
                "__children": [],
            },
        ],
    },
]

SAMPLE_NETSCAN = [
    {
        "PID": 556, "Owner": "svchost.exe", "Proto": "TCPv4",
        "LocalAddr": "0.0.0.0", "LocalPort": 49666,
        "ForeignAddr": "0.0.0.0", "ForeignPort": 0,
        "State": "LISTENING", "Created": "2018-08-30T13:52:22+00:00",
    },
    {
        "PID": 9001, "Owner": "sample_payload.exe", "Proto": "TCPv4",
        "LocalAddr": "192.0.2.111", "LocalPort": 50123,
        "ForeignAddr": "192.0.2.129", "ForeignPort": 443,
        "State": "ESTABLISHED", "Created": "2018-09-04T18:20:44+00:00",
    },
]


# ── parse_args ────────────────────────────────────────────────────────

class TestParseArgs:
    def test_default_offline(self):
        args = parse_args([])
        assert args.mode == "offline"

    def test_live_flag(self):
        args = parse_args(["--live"])
        assert args.mode == "live"

    def test_ollama_flag(self):
        args = parse_args(["--ollama"])
        assert args.mode == "ollama"

    def test_offline_explicit(self):
        args = parse_args(["--offline"])
        assert args.mode == "offline"


# ── Welcome screen ────────────────────────────────────────────────────

class TestWelcome:
    def test_renders_without_crash(self, capsys):
        """Welcome screen renders in all modes without exception."""
        for mode in ("offline", "ollama", "live"):
            render_welcome(mode)

    def test_renders_with_no_evidence(self, capsys):
        with patch("sift_sentinel.console.detect_evidence", return_value=[]):
            render_welcome("offline")


# ── Helpers ───────────────────────────────────────────────────────────

class TestHelpers:
    def test_human_size(self):
        assert "B" in _human_size(500)
        assert "KB" in _human_size(2048)
        assert "GB" in _human_size(3_000_000_000)

    def test_flatten_pstree(self):
        flat = flatten_pstree(SAMPLE_PSTREE)
        assert len(flat) == 2
        assert flat[0]["PID"] == 4
        assert flat[0]["depth"] == 0
        assert flat[1]["PID"] == 388
        assert flat[1]["depth"] == 1

    def test_flatten_empty(self):
        assert flatten_pstree([]) == []

    def test_count_tools(self):
        specific, generic = count_tools()
        assert specific >= 15
        assert generic >= 30

    def test_trim_context_short(self):
        data = {"a": 1}
        result = _trim_context(data, 1000)
        assert "truncated" not in result

    def test_trim_context_long(self):
        data = {"key": "x" * 5000}
        result = _trim_context(data, 100)
        assert result.endswith("...(truncated)")


# ── AI prompt/response parsing ────────────────────────────────────────

class TestAIParsing:
    def test_parse_thinking_with_tag(self):
        resp = "<thinking>I see PID 9001</thinking>This process is suspicious."
        thinking, answer = _parse_thinking(resp)
        assert "PID 9001" in thinking
        assert "suspicious" in answer
        assert "<thinking>" not in answer

    def test_parse_thinking_without_tag(self):
        resp = "This is a plain answer."
        thinking, answer = _parse_thinking(resp)
        assert thinking == ""
        assert answer == "This is a plain answer."

    def test_build_prompt_includes_question(self):
        prompt = _build_ai_prompt("What is PID 4?", "context data", [])
        assert "What is PID 4?" in prompt
        assert "context data" in prompt

    def test_build_prompt_includes_history(self):
        history = [{"q": "prior question", "a": "prior answer"}]
        prompt = _build_ai_prompt("new q", "ctx", history)
        assert "prior question" in prompt


# ── Follow-up extraction ─────────────────────────────────────────────

class TestFollowups:
    def test_extracts_pids(self):
        text = "Process PID 9001 connected to 192.0.2.129 on port 443."
        followups = extract_followups(text)
        assert any("9001" in s for s in followups)

    def test_extracts_ips(self):
        text = "C2 callback to 192.0.2.129 from PID 9001."
        followups = extract_followups(text)
        assert any("192.0.2.129" in s for s in followups)

    def test_filters_localhost(self):
        text = "Listening on 127.0.0.1 and 0.0.0.0"
        followups = extract_followups(text)
        assert not any("127.0.0.1" in s for s in followups)
        assert not any("0.0.0.0" in s for s in followups)

    def test_extracts_hashes(self):
        text = "SHA1: 6f9d6ec7aa2ffaddb33fac59f674fdb0afdc2fbb"
        followups = extract_followups(text)
        assert any("6f9d6ec7" in s for s in followups)

    def test_max_three(self):
        text = ("PID 100 PID 200 PID 300 PID 400 "
                "1.2.3.4 5.6.7.8 198.51.100.12")
        followups = extract_followups(text)
        assert len(followups) <= 3


# ── Command dispatch ──────────────────────────────────────────────────

class TestDispatch:
    def setup_method(self):
        self.sc = SIFTConsole(mode="offline")

    def test_exit_returns_false(self):
        assert self.sc.dispatch("exit") is False
        assert self.sc.dispatch("quit") is False

    def test_empty_returns_true(self):
        assert self.sc.dispatch("") is True
        assert self.sc.dispatch("   ") is True

    def test_help_runs(self, capsys):
        assert self.sc.dispatch("help") is True

    def test_numbered_shortcuts(self):
        """Numbered commands dispatch without crash."""
        with patch.object(self.sc, "cmd_analyze"):
            self.sc.dispatch("1")
            self.sc.cmd_analyze.assert_called_once()

    def test_shortcut_4_findings(self):
        with patch.object(self.sc, "cmd_findings"):
            self.sc.dispatch("4")
            self.sc.cmd_findings.assert_called_once()

    def test_unknown_goes_to_ai(self):
        with patch.object(self.sc, "ask_ai") as mock_ai:
            self.sc.dispatch("what processes are suspicious?")
            mock_ai.assert_called_once_with("what processes are suspicious?")

    def test_show_with_arg(self):
        with patch.object(self.sc, "cmd_show") as mock_show:
            self.sc.dispatch("show F001")
            mock_show.assert_called_once_with("F001")

    def test_investigate_with_arg(self):
        with patch.object(self.sc, "cmd_investigate") as mock:
            self.sc.dispatch("investigate 9001")
            mock.assert_called_once_with("9001")

    def test_connections_with_arg(self):
        with patch.object(self.sc, "cmd_connections") as mock:
            self.sc.dispatch("connections 192.0.2.129")
            mock.assert_called_once_with("192.0.2.129")

    def test_analyze_live(self):
        with patch.object(self.sc, "cmd_analyze") as mock:
            self.sc.dispatch("analyze --live")
            mock.assert_called_once_with(live=True)

    def test_shortcut_3_with_question(self):
        with patch.object(self.sc, "ask_ai") as mock:
            self.sc.dispatch("3 what happened?")
            mock.assert_called_once_with("what happened?")


# ── Offline mode rejects AI ───────────────────────────────────────────

class TestOfflineMode:
    def test_ask_ai_offline_rejects(self, capsys):
        sc = SIFTConsole(mode="offline")
        sc.ask_ai("what happened?")
        # Should not crash, just print guidance


# ── Investigate with cached data ──────────────────────────────────────

class TestInvestigate:
    def test_investigate_loads_pstree(self):
        sc = SIFTConsole(mode="offline")
        sc._pstree_flat = flatten_pstree(SAMPLE_PSTREE)
        sc._netscan = SAMPLE_NETSCAN
        with patch("sift_sentinel.console.load_json", return_value=None):
            sc.cmd_investigate("4")

    def test_investigate_invalid_pid(self, capsys):
        sc = SIFTConsole(mode="offline")
        sc.cmd_investigate("notanumber")

    def test_investigate_pid_not_found(self):
        sc = SIFTConsole(mode="offline")
        sc._pstree_flat = []
        sc._netscan = []
        with patch("sift_sentinel.console.load_json", return_value=None):
            sc.cmd_investigate("99999")


# ── Connections filter ────────────────────────────────────────────────

class TestConnections:
    def test_filters_by_ip(self, capsys):
        sc = SIFTConsole(mode="offline")
        sc._netscan = SAMPLE_NETSCAN
        sc.cmd_connections("192.0.2.129")

    def test_no_match(self, capsys):
        sc = SIFTConsole(mode="offline")
        sc._netscan = SAMPLE_NETSCAN
        sc.cmd_connections("10.0.0.1")

    def test_connections_real_cached_data(self):
        """If cached netscan exists, connections command works on it."""
        data = load_json("vol_netscan")
        if data is None:
            pytest.skip("No cached netscan data")
        sc = SIFTConsole(mode="offline")
        sc._netscan = data
        sc.cmd_connections("0.0.0.0")


# ── Commands with real cached data ────────────────────────────────────

class TestWithCachedData:
    """Integration-style tests using actual cached_outputs/ if present."""

    def test_processes_renders(self):
        data = load_json("vol_pstree")
        if data is None:
            pytest.skip("No cached pstree data")
        sc = SIFTConsole(mode="offline")
        sc.cmd_processes()

    def test_timeline_renders(self):
        data = load_json("vol_pstree")
        if data is None:
            pytest.skip("No cached pstree data")
        sc = SIFTConsole(mode="offline")
        sc.cmd_timeline()

    def test_ancestry_renders(self):
        data = load_json("vol_pstree")
        if data is None:
            pytest.skip("No cached pstree data")
        sc = SIFTConsole(mode="offline")
        sc.cmd_ancestry()


# ── Conversation memory ──────────────────────────────────────────────

class TestConversationMemory:
    def test_history_appends(self):
        sc = SIFTConsole(mode="ollama")
        with patch("sift_sentinel.console.query_ollama",
                    return_value="Test answer"):
            with patch("sift_sentinel.console.load_json", return_value=None):
                sc.ask_ai("question one")
        assert len(sc.history) == 1
        assert sc.history[0]["q"] == "question one"

    def test_history_in_prompt(self):
        sc = SIFTConsole(mode="ollama")
        sc.history = [{"q": "prior", "a": "answer"}]
        with patch("sift_sentinel.console.query_ollama",
                    return_value="<thinking>reasoning</thinking>Final.") as mock:
            with patch("sift_sentinel.console.load_json", return_value=None):
                sc.ask_ai("follow up")
        call_prompt = mock.call_args[0][0]
        assert "prior" in call_prompt
