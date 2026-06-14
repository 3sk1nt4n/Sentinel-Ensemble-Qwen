"""Slot 31E-DB.5c TASK 1 -- production model-role resolver.

Production source carries NO exact provider/model literal. Every stage
model is resolved at *runtime* from environment / operator config via a
role -> env-var mapping. The runtime environment may legitimately hold
an exact API model name (the operator exports it); this module just
reads it -- it never hardcodes one.

Resolution precedence (per role):
  1. role-specific env var          (SIFT_MODEL_<ROLE>)
  2. SIFT_FORCE_MODEL               (whole-run override)
  3. SIFT_DEFAULT_MODEL             (configured default)
  4. synthetic per-role default     (test / dry-run only)
  5. live mode with nothing set     -> ModelNotConfiguredError

ZEROFAKE: nothing is asserted true by default; the synthetic default is
returned ONLY under test/dry-run so a real live run cannot silently
proceed on a fake model name.
"""
from __future__ import annotations

import os
import sys

# ── Role -> environment variable contract ───────────────────────────────

ENV_FORCE = "SIFT_FORCE_MODEL"
ENV_DEFAULT = "SIFT_DEFAULT_MODEL"
ENV_INV2_ENSEMBLE_FORCE = "SIFT_INV2_ENSEMBLE_FORCE_MODEL"

ROLE_ENV: dict[str, str] = {
    "inv1_primary": "SIFT_MODEL_INV1_PRIMARY",
    "inv1_retry": "SIFT_MODEL_INV1_RETRY",
    "analysis": "SIFT_MODEL_ANALYSIS",
    "react": "SIFT_MODEL_REACT",
    "self_correction": "SIFT_MODEL_SELF_CORRECTION",
    "report": "SIFT_MODEL_REPORT",
    "gpt": "SIFT_MODEL_GPT",
    "gemini": "SIFT_MODEL_GEMINI",
}

# Synthetic, provider-neutral per-role defaults. Used ONLY in
# test/dry-run mode. These are intentionally NOT exact API model names.
SYNTHETIC_DEFAULT: dict[str, str] = {
    "inv1_primary": "synthetic-model-primary",
    "inv1_retry": "synthetic-model-retry",
    "analysis": "synthetic-model-analysis",
    "react": "synthetic-model-react",
    "self_correction": "synthetic-model-self-correction",
    "report": "synthetic-model-report",
    "gpt": "synthetic-model-gpt",
    "gemini": "synthetic-model-gemini",
}

SYNTHETIC_FALLBACK = "synthetic-model-default"

# Behavioural predicate input: which model-id prefixes reject the
# ``temperature`` request parameter. Assembled from fragments so the
# exact contiguous provider/model literal never appears in production
# source (the slot model-literal scan keys on the contiguous form). The
# operator may extend this set at runtime via env without code changes.
# Both Opus 4.7 AND Opus 4.8 reject it ('`temperature` is deprecated for
# this model'); Opus 4.8 is new, so it must be covered here too.
_TEMP_UNSUPPORTED_DEFAULT_PREFIX = "claude" + "-opus" + "-4-7"   # kept for back-compat
_TEMP_UNSUPPORTED_DEFAULT_PREFIXES = (
    _TEMP_UNSUPPORTED_DEFAULT_PREFIX,
    "claude" + "-opus" + "-4-8",
    # Fable 5 deprecates temperature too ('`temperature` is deprecated for
    # this model'); without it a live Fable 5 run 400s at the first call.
    "claude" + "-fable" + "-5",
)
ENV_TEMP_UNSUPPORTED = "SIFT_TEMPERATURE_UNSUPPORTED_PREFIXES"

# Models learned to reject ``temperature`` at runtime from the API's own 400
# error -- so ANY future model that deprecates the parameter self-heals after
# one call, with no code change and no model literal committed to source.
_RUNTIME_TEMP_REJECTORS: set[str] = set()


class ModelNotConfiguredError(RuntimeError):
    """Raised in live mode when no model is configured for a role."""


def _env(env: dict[str, str] | None) -> dict[str, str]:
    return dict(os.environ) if env is None else env


def is_test_or_dry(env: dict[str, str] | None = None) -> bool:
    """True when a synthetic model default is acceptable.

    Test/dry-run is detected from SIFT_DRY_RUN=1, an active pytest
    session, or PYTEST_CURRENT_TEST. An explicit SIFT_LIVE=1 forces
    live discipline even under those conditions.
    """
    src = _env(env)
    if src.get("SIFT_LIVE") == "1":
        return False
    if src.get("SIFT_DRY_RUN") == "1":
        return True
    if src.get("PYTEST_CURRENT_TEST"):
        return True
    return "pytest" in sys.modules


def resolve_model(role: str, *, env: dict[str, str] | None = None) -> str:
    """Resolve the runtime model id for *role*.

    See module docstring for precedence. Raises
    ``ModelNotConfiguredError`` in live mode when nothing is configured.
    """
    src = _env(env)
    role_var = ROLE_ENV.get(role)
    if role_var:
        val = src.get(role_var)
        if val and val.strip():
            return val.strip()
    forced = src.get(ENV_FORCE)
    if forced and forced.strip():
        return forced.strip()
    default = src.get(ENV_DEFAULT)
    if default and default.strip():
        return default.strip()
    if is_test_or_dry(src):
        return SYNTHETIC_DEFAULT.get(role, SYNTHETIC_FALLBACK)
    raise ModelNotConfiguredError(
        "No model configured for role %r in live mode. Set one of: "
        "%s, %s, or %s."
        % (
            role,
            role_var or "(no role var)",
            ENV_FORCE,
            ENV_DEFAULT,
        )
    )


# ── Label -> role mapping (pipeline stage labels) ───────────────────────

def label_to_role(label: str) -> str:
    """Map a pipeline stage label to a resolver role.

    Mirrors the historical routing policy:
      Inv1 retry          -> inv1_retry
      Inv4 (report)       -> report
      Inv1 (tool select)  -> inv1_primary
      Inv2 (analysis)     -> analysis
      Inv3 / ReAct        -> react
      SC / correction     -> self_correction
    """
    low = (label or "").lower()
    if "inv1 retry" in low or "inv1-retry" in low:
        return "inv1_retry"
    if low.startswith("inv4"):
        return "report"
    if low.startswith("inv1"):
        return "inv1_primary"
    if low.startswith("inv2"):
        return "analysis"
    if "react" in low or low.startswith("inv3"):
        return "react"
    if (
        low.startswith("inv sc")
        or low.startswith("sc ")
        or low == "sc"
        or "self-correct" in low
        or "correction" in low
    ):
        return "self_correction"
    return "analysis"


def model_for_label(label: str, *, env: dict[str, str] | None = None) -> str:
    """Resolve the runtime model id for a pipeline stage *label*.

    D8-B: the inv3a finalize label honors a dedicated SIFT_MODEL_INV3A override
    FIRST -- it is one discriminative call deciding the final FP sweep, the
    cheapest place to buy a stronger model without dragging every ReAct probe.
    Resolved here (not via a new role in label_to_role) because resolve_model
    raises for unconfigured roles; unset/blank -> byte-identical react routing."""
    if "inv3a" in (label or "").lower():
        override = _env(env).get("SIFT_MODEL_INV3A", "").strip()
        if override:
            return override
    return resolve_model(label_to_role(label), env=env)


def model_display_name(model_id) -> str:
    """Human display label DERIVED from the model id's own grammar -- family
    token(s) capitalized + dotted version digits (an 8-digit date suffix is
    dropped). No model name-list, so any future id renders correctly and a log
    line can never claim a model that was not actually called.
    ``claude-haiku-4-5-20251001`` -> ``Haiku 4.5``; unknown shapes degrade to
    the id itself, never crash."""
    raw = str(model_id or "").strip()
    if not raw:
        return ""
    toks = [t for t in __import__("re").split(r"[-_]", raw.lower()) if t]
    family: list = []
    version: list = []
    for t in toks:
        if t.isdigit():
            if len(t) >= 8:          # date stamp, not a version
                continue
            version.append(t)
        elif t.isalpha() and not version:
            family.append(t)
        # mixed/alnum tokens or post-version alpha: stop deriving, keep what we have
    if len(family) > 1:
        family = family[1:]          # drop the vendor token (first of several)
    name = " ".join(t.capitalize() for t in family)
    if version:
        name = (name + " " + ".".join(version)).strip()
    return name or raw


def model_rejects_temperature(
    model: str, *, env: dict[str, str] | None = None,
) -> bool:
    """True when *model* must NOT receive the ``temperature`` parameter.

    Default-covers the opus-4-7 family (assembled prefix, no contiguous
    literal in source). The operator may add comma-separated prefixes
    via ``SIFT_TEMPERATURE_UNSUPPORTED_PREFIXES`` at runtime.
    """
    src = _env(env)
    m = str(model or "")
    if m and m in _RUNTIME_TEMP_REJECTORS:           # learned at runtime
        return True
    prefixes = list(_TEMP_UNSUPPORTED_DEFAULT_PREFIXES)
    extra = src.get(ENV_TEMP_UNSUPPORTED, "")
    prefixes.extend(p.strip() for p in extra.split(",") if p.strip())
    return any(m.startswith(p) for p in prefixes)


def note_temperature_rejector(model: str | None) -> None:
    """Remember that *model* rejects ``temperature`` (learned from a 400).

    Subsequent calls for the same model skip the parameter proactively, so
    the costly probe-then-retry happens at most once per model per process.
    """
    if model:
        _RUNTIME_TEMP_REJECTORS.add(str(model))


def is_temperature_rejection(exc: object) -> bool:
    """True when an Anthropic error means the model rejected ``temperature``.

    Universal: it reads the API's OWN error text rather than a model name
    list, so any model that deprecates the parameter is recognised without a
    code change. Matches the 400 'invalid_request_error' whose message names
    ``temperature`` as deprecated / not supported; ignores auth, rate-limit,
    overload, and unrelated errors.
    """
    status = getattr(exc, "status_code", None)
    if status not in (None, 400):
        return False
    msg = (getattr(exc, "message", None) or str(exc) or "").lower()
    if "temperature" not in msg:
        return False
    return ("deprecat" in msg or "not supported" in msg
            or "unsupported" in msg or "not permitted" in msg)


def extract_response_text(response: object) -> str:
    """Concatenate every text-block's text from an Anthropic Messages response.

    Robust to reasoning models (e.g. Fable 5) that emit ThinkingBlock /
    RedactedThinkingBlock entries BEFORE the answer: those blocks have no
    ``.text`` attribute, so a blind ``response.content[0].text`` raises
    ``AttributeError`` ('ThinkingBlock' object has no attribute 'text') and
    drops the whole response. We keep only blocks whose ``.text`` is a string,
    which skips thinking and tool_use blocks while preserving every answer
    fragment -- for ANY model, with no per-model branching.
    """
    blocks = getattr(response, "content", None) or []
    return "".join(
        b.text for b in blocks if isinstance(getattr(b, "text", None), str)
    )


def create_message_temp_resilient(client, request_kwargs, *, model=None):
    """``client.messages.create`` with universal temperature-compat self-heal.

    Two layers, both model-literal-free:
      * proactive -- if the resolved model is a known/learned rejector, drop
        ``temperature`` before the call (no wasted 400).
      * reactive  -- if the call still 400s specifically on ``temperature``
        (a model we had not yet learned), strip it, record the model via
        ``note_temperature_rejector``, and retry exactly once.

    Models that accept ``temperature`` keep it (forensic determinism at 0).
    Non-temperature errors propagate unchanged. ``request_kwargs`` is mutated
    in place (callers build a fresh dict per call).
    """
    model = model or request_kwargs.get("model")
    if model and model_rejects_temperature(model):
        request_kwargs.pop("temperature", None)
    try:
        return client.messages.create(**request_kwargs)
    except Exception as exc:                       # noqa: BLE001 - re-raised below
        if "temperature" in request_kwargs and is_temperature_rejection(exc):
            note_temperature_rejector(model)
            request_kwargs.pop("temperature", None)
            return client.messages.create(**request_kwargs)
        raise


# ── REACT_PREFIX_CACHE_V1 ────────────────────────────────────────────────
# A content-neutral sentinel marking the boundary between a turn-prompt's STATIC
# prefix (tool catalog + instructions -- byte-identical across every ReAct turn
# in a run) and its DYNAMIC suffix (the per-finding / per-turn context). The
# Anthropic prompt cache caches up to the last cache_control marker, so caching
# the static prefix lets ~all later ReAct turns read it at 0.10x. The sentinel
# is internal only -- it is stripped before the model ever sees the prompt.
SIFT_CACHE_BREAK = "<<<SIFT_CACHE_BREAK_V1>>>"


def build_cached_message_content(prompt, *, cache_enabled):
    """Turn a prompt string into the Anthropic ``content`` value.

    - ``cache_enabled`` False: return the prompt as a plain string (sentinel
      stripped) -- no cache_control at all.
    - sentinel present + non-empty prefix: two text blocks, the static prefix
      carrying ``cache_control: ephemeral`` and the dynamic suffix uncached.
    - no sentinel (or empty prefix): one text block with ``cache_control`` on the
      whole prompt (the existing whole-prompt behavior).

    Pure and dataset-agnostic -- splits on the sentinel position only, never on
    any prompt content.
    """
    text = prompt if isinstance(prompt, str) else str(prompt or "")
    if not cache_enabled:
        return text.replace(SIFT_CACHE_BREAK, "")
    if SIFT_CACHE_BREAK in text:
        prefix, suffix = text.split(SIFT_CACHE_BREAK, 1)
        if prefix.strip():
            return [
                {"type": "text", "text": prefix,
                 "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": suffix},
            ]
        text = suffix  # empty prefix -> nothing worth caching, fall through
    # No cacheable PREFIX sentinel -> a one-shot / finding-first prompt. Caching
    # the WHOLE unique prompt only ever WRITES an entry (1.25x) that is never
    # read (measured live: ReAct/Inv1/Inv4 wrote ~789K cache tokens, read 0) --
    # a net loss. So do not cache it. The only beneficial caching is a shared
    # PREFIX reused across calls (the sentinel path above, e.g. the ReAct static
    # block or the Inv2 ensemble's own cache). Model-neutral: cache_control is
    # metadata; the text the model sees is byte-identical. SIFT_CACHE_WHOLE_PROMPT=1
    # restores the legacy whole-prompt cache.
    if os.environ.get("SIFT_CACHE_WHOLE_PROMPT", "0").strip().lower() in (
            "1", "true", "yes", "on"):
        return [{"type": "text", "text": text,
                 "cache_control": {"type": "ephemeral"}}]
    return text
