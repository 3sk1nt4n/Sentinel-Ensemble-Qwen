"""Optional AI advisor — an off-critical-path escape hatch (verify-before-act).

The deterministic onboarding pipeline never depends on this. The advisor is
consulted ONLY at deterministic-exhaustion points, and every suggestion it
returns MUST be confirmed by a real probe before it changes any state (see
``engine.consult_and_verify``). An unverified suggestion is logged and
discarded — it is never narrated as success.

Availability is fail-closed and fast:
  * no ``ANTHROPIC_API_KEY`` -> unavailable with NO network call;
  * kill switch ``SIFT_ONBOARD_AI=0`` (set by ``--no-ai``) -> unavailable;
  * otherwise a cached 1-token ping decides availability; a later 401/403 from
    ``advise`` invalidates the cache and rechecks once.
``advise`` makes ONE Haiku call and returns ``{}`` on ANY error/timeout/
non-200/parse failure. It never mutates state.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional

# NOTE: this optional onboarding advisor is an Anthropic-only OFF-PIPELINE helper
# (it does not run inside the 16-step investigation, which is fully provider-driven
# via model_roles + llm_provider). The hardcoded literal here is scoped to this
# advisor only and does not contradict the "no hardcoded model literal in the
# pipeline" claim; the advisor is skipped entirely when SIFT_ONBOARD_AI=0.
MODEL = "claude-haiku-4-5-20251001"
_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"
_PING_TIMEOUT = 8

SYSTEM_PROMPT = (
    "You are a DFIR onboarding advisor. Use ONLY the evidence provided. "
    "Propose the single best next action, choosing from `choices` if given. "
    "You are NOT permitted to invent facts not present in evidence. Respond "
    'with JSON only: {"suggestion":..., "rationale":..., "confidence":0..1}. '
    'If evidence is insufficient, set suggestion="insufficient_evidence".'
)


class AdvisorError(Exception):
    """Base class for advisor failures."""


class AdvisorAuthError(AdvisorError):
    """Raised internally on a 401/403 so the cache can be invalidated."""


def _kill_switched() -> bool:
    return os.environ.get("SIFT_ONBOARD_AI") == "0"


class Advisor:
    """Grounded, verify-before-act Haiku advisor. Stateless across calls
    except for the cached availability ping."""

    def __init__(self, model: str = MODEL) -> None:
        self.model = model
        self._ping_ok: Optional[bool] = None

    # -- availability --------------------------------------------------------
    def available(self) -> bool:
        if _kill_switched():
            return False
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:                       # FAST path: no key -> no network
            return False
        if self._ping_ok is None:
            self._ping_ok = self._ping(key)
        return bool(self._ping_ok)

    def _invalidate(self) -> None:
        self._ping_ok = None

    def _ping(self, key: str) -> bool:
        try:
            status, _ = self._post(
                key,
                {"model": self.model, "max_tokens": 1,
                 "messages": [{"role": "user", "content": "ping"}]},
                timeout=_PING_TIMEOUT,
            )
            return status == 200
        except Exception:
            return False

    # -- advice --------------------------------------------------------------
    def advise(self, question: str, evidence: dict,
               choices: Optional[list] = None, timeout: int = 30) -> dict:
        if not self.available():
            return {}
        try:
            return self._advise_once(question, evidence, choices, timeout)
        except AdvisorAuthError:
            self._invalidate()            # 401/403 -> recheck availability once
            if not self.available():
                return {}
            try:
                return self._advise_once(question, evidence, choices, timeout)
            except Exception:
                return {}
        except Exception:
            return {}

    def _advise_once(self, question, evidence, choices, timeout) -> dict:
        key = os.environ.get("ANTHROPIC_API_KEY") or ""
        user: dict = {"question": question, "evidence": evidence}
        if choices:
            user["choices"] = list(choices)
        body = {
            "model": self.model,
            "max_tokens": 256,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user",
                          "content": json.dumps(user, default=str)}],
        }
        status, payload = self._post(key, body, timeout=timeout)
        if status in (401, 403):
            raise AdvisorAuthError(f"auth {status}")
        if status != 200:
            return {}
        return self._parse(payload)

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _parse(payload: dict) -> dict:
        try:
            blocks = payload.get("content") or []
            text = "".join(b.get("text", "") for b in blocks
                           if isinstance(b, dict))
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end == -1 or end < start:
                return {}
            obj = json.loads(text[start:end + 1])
            if not isinstance(obj, dict) or "suggestion" not in obj:
                return {}
            return obj
        except Exception:
            return {}

    @staticmethod
    def _post(key: str, body: dict, timeout: int):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            _API_URL, data=data, method="POST",
            headers={"x-api-key": key, "anthropic-version": _API_VERSION,
                     "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return getattr(resp, "status", 200), json.loads(raw)
        except urllib.error.HTTPError as exc:
            return exc.code, {}


# ── Public module-level API (the stable names the rest of the system uses) ──
_DEFAULT = Advisor()


def available() -> bool:
    """True iff the advisor is usable (see Advisor.available). Fail-closed,
    fast, and makes NO network call when no key / kill switch is set."""
    return _DEFAULT.available()


def advise(question: str, evidence: dict, choices: Optional[list] = None) -> dict:
    """One grounded Haiku call; returns {} on any error. See Advisor.advise."""
    return _DEFAULT.advise(question, evidence, choices)
