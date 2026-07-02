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

    SIFT_LLM_PROVIDER   = qwen | anthropic        (qwen for this submission; unset falls back to anthropic)
    DASHSCOPE_API_KEY   = <your Qwen Cloud key>    (or QWEN_API_KEY)
    DASHSCOPE_BASE_URL  = <override endpoint>      (default: intl compatible-mode)
    SIFT_DEFAULT_MODEL  = qwen3.7-max              (model_roles resolves this)

This is also the repository's **Proof of Alibaba Cloud usage** file: it issues
live HTTPS requests to the Alibaba Cloud DashScope API.
"""
from __future__ import annotations

import json
import os
import time
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

# Transient DashScope statuses worth retrying (the Anthropic SDK retries these
# by default; the stdlib path must do it explicitly so one 429/5xx blip does
# not hard-fail a pipeline step).
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3


def _retry_delay(retry_after, attempt: int) -> float:
    """Backoff seconds: honor Retry-After when present, else exponential."""
    if retry_after:
        try:
            return min(30.0, max(0.0, float(retry_after)))
        except (TypeError, ValueError):
            pass
    return min(8.0, 0.5 * (2 ** attempt))


def active_provider() -> str:
    """The configured LLM provider id (lowercased). Set 'qwen' for Qwen
    Cloud; unset falls back to 'anthropic' (documented fallback)."""
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

    def __init__(self, input_tokens: int, output_tokens: int,
                 cache_read: int = 0, cache_creation: int = 0):
        self.input_tokens = int(input_tokens or 0)
        self.output_tokens = int(output_tokens or 0)
        # Qwen/DashScope does AUTOMATIC prefix caching and reports the cached
        # subset in usage.prompt_tokens_details.cached_tokens. We surface it as
        # cache_read so the pipeline's cache accounting + cache-aware pricing
        # credit it, exactly like the Anthropic path. input_tokens here is the
        # UNCACHED remainder (cost_usd treats total_input as uncached). Qwen's
        # implicit cache bills no separate "write", so cache_creation stays 0.
        self.cache_read_input_tokens = int(cache_read or 0)
        self.cache_creation_input_tokens = int(cache_creation or 0)


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
        timeout=None,
        system=None,
        # thinking / tools / cache hints etc. are Anthropic-specific and unused
        # by this text-JSON pipeline -- accept and ignore them gracefully.
        **_ignored,
    ):
        # Read timeout. qwen3.7-max with reasoning + a large evidence context can
        # take well over the old 120s default (the whole 4-member ensemble timed
        # out at 120s on a paired memory+disk case). Env-tunable; default 120s
        # keeps the lighter models' behaviour unchanged.
        if timeout is None:
            try:
                timeout = int(os.environ.get("SIFT_HTTP_TIMEOUT") or 120)
            except (TypeError, ValueError):
                timeout = 120
        # DashScope rejects max_tokens above a model's per-model output cap
        # (several Qwen text models cap around 8192) with a 400 that the
        # temperature self-heal does NOT catch -- clamp to a safe ceiling.
        # Raise it via SIFT_MAX_OUTPUT_TOKENS once you confirm the model's cap.
        try:
            cap = int(os.environ.get("SIFT_MAX_OUTPUT_TOKENS") or 8192)
        except (TypeError, ValueError):
            cap = 8192
        requested = int(max_tokens) if max_tokens else 4096
        body = {
            "model": model,
            "messages": _to_openai_messages(messages, system),
            "max_tokens": max(1, min(requested, cap)),
        }
        if temperature is not None:
            body["temperature"] = temperature
        data = json.dumps(body).encode("utf-8")

        # Bounded retry on transient 429/5xx + transport errors, mirroring the
        # Anthropic SDK's default resilience. 4xx (auth / bad-request) are not
        # retried so a real config error surfaces immediately.
        payload = None
        for attempt in range(_MAX_ATTEMPTS):
            req = urllib.request.Request(self.base_url, data=data, method="POST")
            req.add_header("Authorization", f"Bearer {self._key()}")
            req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:   # 4xx/5xx -- OSError subclass
                if exc.code in _RETRY_STATUS and attempt < _MAX_ATTEMPTS - 1:
                    ra = exc.headers.get("Retry-After") if exc.headers else None
                    time.sleep(_retry_delay(ra, attempt))
                    continue
                detail = b""
                try:
                    # capture enough body that error keywords (temperature,
                    # max_tokens, ...) survive for the self-heal classifiers
                    detail = exc.read()[:2000]
                except Exception:  # noqa: BLE001
                    pass
                raise OSError(f"DashScope HTTP {exc.code}: {detail!r}") from exc
            except TimeoutError as exc:             # socket READ timed out
                # A timeout during resp.read() raises a bare TimeoutError that is
                # NOT a urllib URLError, so it must be handled explicitly or it
                # escapes unretried (this silently zeroed the qwen3.7-max ensemble).
                if attempt < _MAX_ATTEMPTS - 1:
                    time.sleep(_retry_delay(None, attempt))
                    continue
                raise OSError(f"DashScope read timeout after {timeout}s: {exc}") from exc
            except urllib.error.URLError as exc:    # timeout / DNS / conn reset
                if attempt < _MAX_ATTEMPTS - 1:
                    time.sleep(_retry_delay(None, attempt))
                    continue
                raise OSError(f"DashScope transport error: {exc}") from exc
        if payload is None:   # defensive: the loop either breaks or raises
            raise OSError("DashScope: no response after retries")

        # OpenAI-compatible response shape
        choices = payload.get("choices") or []
        text = ""
        finish = "stop"
        if choices:
            msg = choices[0].get("message") or {}
            text = msg.get("content") or ""
            if not text:
                # reasoning models (qwen3 thinking / qwq-*) can return empty
                # content with the answer in reasoning_content.
                text = msg.get("reasoning_content") or ""
            finish = choices[0].get("finish_reason") or "stop"
        usage = payload.get("usage") or {}
        # Qwen auto-caches shared prefixes; the cached subset rides in
        # prompt_tokens_details.cached_tokens. Split prompt_tokens into the
        # uncached remainder (billed at base) + the cached read (billed at the
        # cache-read discount) so the pipeline credits the reuse.
        prompt_toks = int(usage.get("prompt_tokens", 0) or 0)
        details = usage.get("prompt_tokens_details") or {}
        cached = int(details.get("cached_tokens", 0) or 0)
        cached = max(0, min(cached, prompt_toks))
        uncached = prompt_toks - cached
        stop_reason = {"length": "max_tokens", "stop": "end_turn"}.get(
            finish, finish or "end_turn")
        return _Response(
            text,
            _Usage(
                uncached,
                usage.get("completion_tokens", 0),
                cache_read=cached,
                cache_creation=0,
            ),
            model=payload.get("model", model) or model,
            stop_reason=stop_reason,
        )


# ── the factory every call site uses ───────────────────────────────────────
def make_llm_client():
    """Return the active LLM client.

    Qwen provider  -> DashScope adapter (Alibaba Cloud).
    anything else  -> the real Anthropic SDK client (fallback; unchanged).
    """
    if is_qwen():
        return QwenClient()
    import anthropic   # lazy: only needed for the Anthropic path
    return anthropic.Anthropic()
