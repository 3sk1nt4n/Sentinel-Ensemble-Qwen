"""Pluggable LLM provider -- Qwen Cloud (Alibaba Cloud / DashScope) or Anthropic.

Global AI Hackathon with Qwen Cloud -- Track 4 (Autopilot Agent).

This module is the single seam that lets the whole 16-step pipeline run on
**Qwen models hosted on Alibaba Cloud** instead of Anthropic, WITHOUT touching
the LLM call sites or the `create_message_temp_resilient` wrapper.

How it works
------------
Every call site builds a client with `make_llm_client()` and then calls
`client.messages.create(**request_kwargs)`. For the Qwen provider we return a
thin adapter (`QwenClient`) that:

  * accepts the SAME Anthropic-style `request_kwargs`
    (model, max_tokens, messages, temperature, timeout, optional system),
  * calls Alibaba Cloud's **DashScope OpenAI-compatible** Chat Completions API
    over the standard library (no extra dependency -- matches the project's
    stdlib-only client ethos), and
  * returns a duck-typed response exposing exactly the fields the pipeline
    reads: `.content[i].text` and
    `.usage.{input_tokens, output_tokens,
             cache_read_input_tokens, cache_creation_input_tokens}`.

Provider + model are chosen entirely by environment (ZEROFAKE: no model literal
is hardcoded -- `model_roles.py` already resolves model ids from env):

    SIFT_LLM_PROVIDER   = qwen | anthropic        (default: anthropic)
    DASHSCOPE_API_KEY   = <your Qwen Cloud key>    (or QWEN_API_KEY)
    DASHSCOPE_BASE_URL  = <override endpoint>      (default: intl compatible-mode)
    SIFT_DEFAULT_MODEL  = qwen-max                 (model_roles resolves this)

This is also the repository's **Proof of Alibaba Cloud usage** file: it issues
live HTTPS requests to the Alibaba Cloud DashScope API.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

# DashScope OpenAI-compatible Chat Completions endpoint (Alibaba Cloud).
# International (Singapore) region by default; override via DASHSCOPE_BASE_URL
# for the mainland-China endpoint
# (https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions).
_DEFAULT_BASE_URL_INTL = (
    "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions"
)

_QWEN_PROVIDERS = {"qwen", "dashscope", "alibaba", "qwencloud"}


def active_provider() -> str:
    """The configured LLM provider id (lowercased). Default 'anthropic'."""
    return (os.environ.get("SIFT_LLM_PROVIDER") or "anthropic").strip().lower()


def is_qwen() -> bool:
    """True when the Qwen Cloud (DashScope) provider is selected."""
    return active_provider() in _QWEN_PROVIDERS


# ── duck-typed response objects (mirror the Anthropic SDK surface) ──────────
class _TextBlock:
    __slots__ = ("type", "text")

    def __init__(self, text: str):
        self.type = "text"
        self.text = text or ""


class _Usage:
    __slots__ = (
        "input_tokens", "output_tokens",
        "cache_read_input_tokens", "cache_creation_input_tokens",
    )

    def __init__(self, input_tokens: int, output_tokens: int):
        self.input_tokens = int(input_tokens or 0)
        self.output_tokens = int(output_tokens or 0)
        # The pipeline reads these for Anthropic prompt-cache accounting. Qwen's
        # caching is server-side / billed differently, so 0 is the honest value.
        self.cache_read_input_tokens = 0
        self.cache_creation_input_tokens = 0


class _Response:
    __slots__ = ("content", "usage", "stop_reason", "model")

    def __init__(self, text, usage, model="", stop_reason="end_turn"):
        self.content = [_TextBlock(text)]
        self.usage = usage
        self.stop_reason = stop_reason
        self.model = model


# ── content / message translation (Anthropic -> OpenAI-compatible) ─────────
def _flatten_content(content) -> str:
    """Anthropic `content` (str OR list of text blocks) -> a plain string.

    Drops `cache_control` (Anthropic-only metadata) and concatenates text
    blocks. Dataset-agnostic: structural only, never inspects the text.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(block.get("text", "") or "")
            else:
                parts.append(getattr(block, "text", "") or "")
        return "".join(parts)
    return str(content)


def _to_openai_messages(messages, system=None) -> list:
    """Translate Anthropic-style messages to OpenAI-compatible messages."""
    out = []
    if system:
        out.append({"role": "system", "content": _flatten_content(system)})
    for m in messages or []:
        if isinstance(m, dict):
            role = m.get("role") or "user"
            content = m.get("content")
        else:
            role, content = "user", m
        out.append({"role": role, "content": _flatten_content(content)})
    return out


# ── the Qwen Cloud (DashScope) client ──────────────────────────────────────
class _Messages:
    def __init__(self, parent: "QwenClient"):
        self._parent = parent

    def create(self, **kwargs):
        return self._parent._create(**kwargs)


class QwenClient:
    """Anthropic-`messages.create`-compatible client for Alibaba Cloud DashScope.

    The API key is read from DASHSCOPE_API_KEY (or QWEN_API_KEY) at call time,
    so the client object itself never holds a secret longer than a request.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (
            base_url
            or os.environ.get("DASHSCOPE_BASE_URL")
            or _DEFAULT_BASE_URL_INTL
        )
        self._api_key = api_key
        self.messages = _Messages(self)

    def _key(self) -> str:
        key = (
            self._api_key
            or os.environ.get("DASHSCOPE_API_KEY")
            or os.environ.get("QWEN_API_KEY")
            or ""
        ).strip()
        if not key:
            raise OSError(
                "Qwen provider selected but no DASHSCOPE_API_KEY / "
                "QWEN_API_KEY is set"
            )
        return key

    def _create(
        self,
        *,
        model,
        messages=None,
        max_tokens=4096,
        temperature=None,
        timeout=120,
        system=None,
        # thinking / tools / cache hints etc. are Anthropic-specific and unused
        # by this text-JSON pipeline -- accept and ignore them gracefully.
        **_ignored,
    ):
        body = {
            "model": model,
            "messages": _to_openai_messages(messages, system),
            "max_tokens": int(max_tokens) if max_tokens else 4096,
        }
        if temperature is not None:
            body["temperature"] = temperature
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base_url, data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self._key()}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:   # 4xx/5xx -- OSError subclass
            detail = b""
            try:
                detail = exc.read()[:300]
            except Exception:  # noqa: BLE001
                pass
            raise OSError(f"DashScope HTTP {exc.code}: {detail!r}") from exc
        # OpenAI-compatible response shape
        choices = payload.get("choices") or []
        text = ""
        if choices:
            msg = choices[0].get("message") or {}
            text = msg.get("content") or ""
        usage = payload.get("usage") or {}
        return _Response(
            text,
            _Usage(
                usage.get("prompt_tokens", 0),
                usage.get("completion_tokens", 0),
            ),
            model=payload.get("model", model) or model,
        )


# ── the factory every call site uses ───────────────────────────────────────
def make_llm_client():
    """Return the active LLM client.

    Qwen provider  -> DashScope adapter (Alibaba Cloud).
    anything else  -> the real Anthropic SDK client (default; unchanged).
    """
    if is_qwen():
        return QwenClient()
    import anthropic   # lazy: only needed for the Anthropic path
    return anthropic.Anthropic()
