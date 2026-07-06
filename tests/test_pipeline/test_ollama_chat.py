"""Tests: Ollama must use /api/chat endpoint with think=False (qwen3 requirement)."""

import ast
import textwrap

import pytest


class TestOllamaUsesChat:
    """Verify run_pipeline.py configures Ollama for /api/chat, not /api/generate."""

    @pytest.fixture(autouse=True)
    def _parse_source(self):
        """Parse run_pipeline.py source to inspect Ollama config."""
        from pathlib import Path
        self.source = Path("run_pipeline.py").read_text()

    def test_ollama_url_ends_with_api_chat(self):
        assert "/api/chat" in self.source
        assert "/api/generate" not in self.source

    def test_ollama_model_is_qwen3(self):
        assert "qwen3:14b" in self.source

    def test_ollama_think_false_in_request(self):
        """Request body must include 'think': False for qwen3 thinking mode control."""
        assert '"think": False' in self.source or "'think': False" in self.source

    def test_ollama_uses_messages_not_prompt(self):
        """Chat endpoint requires 'messages' key, not 'prompt'."""
        # Find the Ollama POST block — it should have "messages" not "prompt"
        # The old format was: json={"model": ..., "prompt": prompt, ...}
        # The new format is: json={"model": ..., "messages": [...], ...}
        assert '"messages"' in self.source or "'messages'" in self.source

    def test_ollama_response_uses_message_content(self):
        """Chat endpoint returns message.content, not response."""
        assert '.get("message", {}).get("content"' in self.source


class TestConsolesUseChat:
    """Both console.py files (src + scripts/, the legacy console) must also use /api/chat."""

    @pytest.fixture(autouse=True)
    def _parse_sources(self):
        from pathlib import Path
        self.src_console = Path("src/sift_sentinel/console.py").read_text()
        self.root_console = Path("scripts/console.py").read_text()

    def test_src_console_uses_chat(self):
        assert "/api/chat" in self.src_console
        assert "/api/generate" not in self.src_console

    def test_root_console_uses_chat(self):
        assert "/api/chat" in self.root_console
        assert "/api/generate" not in self.root_console

    def test_src_console_think_false(self):
        assert "think" in self.src_console

    def test_root_console_think_false(self):
        assert "think" in self.root_console
