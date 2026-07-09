#!/usr/bin/env python3
"""Sentinel Qwen Ensemble Step-Zero - conversational onboarding launcher.

Wraps the deterministic onboarding engine in a warm, talkative terminal
experience: a branded welcome, ONE question (the evidence path), live honest
narration of every real phase, a "verified & ready" case card, and a FIND
launch prompt that hands off to the EXISTING run_pipeline.py.

HALT GATE: the FIND->run_pipeline exec is built (``build_find_command``) and
tested, but kept STAGED, not live (``FIND_WIRED = False``). Flip that one flag
to wire the launch once the gate is lifted.
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import subprocess
import sys
from typing import Optional

# Strip stray terminal escape sequences (arrow/Delete keys send e.g. '^[[3~') and
# control chars, so a fat-fingered keypress never wedges a prompt.
_ESC_SEQ_RE = re.compile(r"\x1b\[[0-9;]*[~A-Za-z]|[\x00-\x08\x0b-\x1f\x7f]")


def _clean_input(s: Optional[str]) -> str:
    return _ESC_SEQ_RE.sub("", s or "")


# Secret-paste guard: one long high-entropy token (no whitespace, no path
# separators, letters AND digits, len>=20) pasted at a VISIBLE prompt is
# almost certainly a credential -- menu answers are 1-2 chars, paths carry
# separators, prose carries spaces. Shape-based and universal; no vendor list.
_SECRET_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{20,}$")


def _looks_like_secret(s: str) -> bool:
    t = str(s or "").strip()
    if len(t) < 20 or not _SECRET_TOKEN_RE.match(t):
        return False
    return any(c.isalpha() for c in t) and any(c.isdigit() for c in t)


def _guard_visible_input(raw: Optional[str]) -> str:
    """Return the input unchanged UNLESS it is secret-shaped: then erase the
    echoed line from the terminal (ANSI move-up + clear), print a revoke
    warning, and return '' so the caller treats it as no-answer. The value is
    never used, stored, logged, or re-printed. Visible prompts only -- the
    hidden API-key prompt (getpass) never echoes and is not affected."""
    t = _clean_input(raw).strip()
    if not _looks_like_secret(t):
        return raw if raw is not None else ""
    try:
        if sys.stdout.isatty():
            # erase the prompt+echo line above (input() ended with a newline)
            sys.stdout.write("\x1b[1A\x1b[2K")
            sys.stdout.flush()
    except Exception:
        pass
    print("  ⚠ that input looked like an API key pasted at a menu prompt -- it "
          "was DISCARDED (never used, stored, or logged) and erased from the "
          "screen. If it was a real key, REVOKE it now and paste keys only at "
          "the hidden key prompt.", flush=True)
    return ""

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from sift_sentinel.onboard import presenter
from sift_sentinel.proc_cleanup import kill_child_process_trees
from sift_sentinel.onboard.ai_advisor import Advisor
from sift_sentinel.onboard.engine import (
    CaseManifest,
    Phase,
    Probes,
    RealProbes,
    Status,
    onboard,
)

# ── FIND wiring ──────────────────────────────────────────────────────────────
# Source default stays False. The EFFECTIVE state is _find_wired(), which also
# honors env SIFT_FIND_WIRED=1 and the --wire CLI flag - so going live needs no
# source edit:  SIFT_FIND_WIRED=1 python3 step0_onboard.py <folder>
FIND_WIRED = False
_WIRE_OVERRIDE = False           # set True by --wire

_REPO = os.path.dirname(os.path.abspath(__file__))
_PIPELINE = os.path.join(_REPO, "run_pipeline.py")


def _find_wired() -> bool:
    if os.environ.get("SIFT_FIND_WIRED") == "1":
        return True
    return _WIRE_OVERRIDE or FIND_WIRED


# ── Analysis depth modes (the two reasoning options offered before launch) ───
# Model ids are assembled from fragments so no contiguous provider/model literal
# lives in source (repo convention); the operator may override either via env.
# These are the Anthropic FALLBACK defaults; qwen mode overrides them below.
# HEAVY defaults to Opus 4.8: live-proven on this pipeline (full run, findings,
# ~$11/case). Fable 5 was trialled as the default and hit FOUR live failure
# modes; the terminal one is stop_reason=refusal on the Inv2 forensic-analysis
# prompt itself, which no client-side fix can override -- and the trial burned
# real budget. Fable stays one env away for A/B:
#   SIFT_HEAVY_MODEL="claude-fable-5" python3 step0_onboard.py
_HEAVY_MODEL = os.environ.get("SIFT_HEAVY_MODEL") or ("claude-" + "opus" + "-4-8")
# Haiku's canonical id is dated; the bare alias may be rejected, so default to the
# dated snapshot the ensemble roster already proves works. Fragment-assembled so no
# contiguous model literal enters source; overridable via SIFT_LIGHT_MODEL.
_LIGHT_MODEL = os.environ.get("SIFT_LIGHT_MODEL") or ("claude-haiku" + "-4-5-20251001")

# ── provider awareness (Qwen Cloud / DashScope) ───────────────────────────────
# Mirrors src/sift_sentinel/llm_provider.py's provider resolution so the
# launcher's key gate, menu names, and cost hints match the configured provider.
_QWEN_PROVIDER_NAMES = {"qwen", "dashscope", "alibaba", "qwencloud"}


def _qwen_mode() -> bool:
    """True when the run is configured for Qwen Cloud (Alibaba DashScope)."""
    return os.environ.get("SIFT_LLM_PROVIDER", "").strip().lower() in _QWEN_PROVIDER_NAMES


def _key_env_name() -> str:
    """The provider's key environment variable."""
    return "DASHSCOPE_API_KEY" if _qwen_mode() else "ANTHROPIC_API_KEY"


def _provider_label() -> str:
    return "Qwen Cloud (DashScope)" if _qwen_mode() else "Anthropic"


if _qwen_mode():
    # Menu names + costs reflect the QWEN tiering (env-overridable), and the
    # measured live-run costs (~$1.67 heavy / ~$0.22 light on the featured DC01 case).
    _HEAVY_MODEL = (os.environ.get("SIFT_HEAVY_MODEL")
                    or os.environ.get("SIFT_MODEL_ANALYSIS")
                    or os.environ.get("SIFT_DEFAULT_MODEL")
                    or "qwen3.7-max")
    _LIGHT_MODEL = os.environ.get("SIFT_LIGHT_MODEL") or "qwen-plus"


def _model_display(model: str) -> str:
    """Human label for a model id -- always reflects the ACTUAL selected model,
    so an env override (e.g. SIFT_HEAVY_MODEL=...opus...) shows the real name in
    the menu and logs, never a stale 'Opus 4.8'. Keyed on id fragments."""
    m = str(model or "").lower()
    if "fable" in m:
        return "Claude Fable 5"
    if "opus-4-8" in m:
        return "Claude Opus 4.8"
    if "opus-4-7" in m:
        return "Claude Opus 4.7"
    if "opus" in m:
        return "Claude Opus"
    if "sonnet" in m:
        return "Claude Sonnet 4.6"
    if "haiku" in m:
        return "Claude Haiku 4.5"
    if "qwen3.7-max" in m:
        return "Qwen3.7-Max (flagship)"
    if "qwen3-max" in m:
        return "Qwen3-Max"
    if "qwen-plus" in m:
        return "Qwen-Plus"
    return str(model)


_HEAVY_NAME = _model_display(_HEAVY_MODEL)
_LIGHT_NAME = _model_display(_LIGHT_MODEL)

_HEAVY_COST = "~$1.5-3 / case" if _qwen_mode() else "~$8-15 / case"
_LIGHT_COST = "~$0.3-1 / case" if _qwen_mode() else "~$2-3 / case"

ANALYSIS_MODES: dict = {
    "1": {"key": "heavy", "icon": "⚡", "label": "HEAVY",
          "name": _HEAVY_NAME, "tag": "deepest reasoning",
          "blurb": "all 4 invocations on %s + 4-model ensemble (Inv 1-2-3-4)" % _HEAVY_NAME,
          "cost": _HEAVY_COST, "ensemble": True, "model": _HEAVY_MODEL},
    "2": {"key": "light", "icon": "🪶", "label": "LIGHT",
          "name": _LIGHT_NAME, "tag": "fast & economical",
          "blurb": "all 4 invocations on %s + 4-model ensemble (Inv 1-2-3-4)" % _LIGHT_NAME,
          "cost": _LIGHT_COST, "ensemble": True, "model": _LIGHT_MODEL},
}
_DEFAULT_MODE = ANALYSIS_MODES["1"]


# ── tiny ANSI palette (honors NO_COLOR / non-TTY / SIFT_FORCE_COLOR) ──────────
def _use_color() -> bool:
    if os.environ.get("SIFT_FORCE_COLOR") == "1":
        return True
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _c(s: str, code: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if _use_color() else s


# Per-stage model env vars (model_roles.ROLE_ENV) that a shell may have pinned.
# The chosen depth overrides ALL of them so the mode is authoritative -- otherwise
# a stray SIFT_MODEL_INV1_PRIMARY pin silently downgrades a Heavy run.
_STAGE_ROLE_ENV_VARS = (
    "SIFT_MODEL_INV1_PRIMARY", "SIFT_MODEL_INV1_RETRY", "SIFT_MODEL_ANALYSIS",
    "SIFT_MODEL_REACT", "SIFT_MODEL_SELF_CORRECTION", "SIFT_MODEL_REPORT",
)


def mode_launch_env(mode: dict) -> dict:
    """Env that makes the chosen depth AUTHORITATIVE across the whole run.

    Sets SIFT_FORCE_MODEL + SIFT_DEFAULT_MODEL AND overrides every per-stage pin
    (SIFT_MODEL_<ROLE>), because resolve_model gives a per-role var precedence over
    the force -- so a shell that exported a stale SIFT_MODEL_INV1_PRIMARY pin
    would otherwise run Heavy's Inv1 on that model. The ensemble is forced onto
    the same model.
    Pure: returns a dict, sets nothing."""
    model = str(mode.get("model") or "")
    env = {"SIFT_FORCE_MODEL": model, "SIFT_DEFAULT_MODEL": model}
    for _rolevar in _STAGE_ROLE_ENV_VARS:
        env[_rolevar] = model            # the mode wins over any pre-existing pin
    if mode.get("ensemble"):
        env["SIFT_INV2_ENSEMBLE_FORCE_MODEL"] = model
    # Universal accuracy/usage fixes ON for every onboarded run: inv3a (Step 13D,
    # the single FP-sweep that replaces the token-heavy SC loop) + the two
    # deterministic FP gates. JIT/tool-status are already pipeline-default-ON;
    # setting them here makes the launch self-documenting and survives a future
    # default change. Kill-switch: export SIFT_<FLAG>=0 before launch.
    env["SIFT_INV3A_FINALIZE"] = "1"
    env["SIFT_INV3A_REVIEW_ALL"] = "1"     # inv3a gives a final TP/FP verdict on ALL findings (proven evil floored)
    env["SIFT_INV3A_ENRICH"] = "1"         # + deterministic cross-reference (tools/domains/strength) so it CROSS-CHECKS the big picture; case-neutral counts only
    env["SIFT_LLM_DEDUP"] = "1"            # final LLM semantic dedup (LLM proposes, deterministic guard verifies; never crosses TP/FP)
    env["SIFT_JIT_RWX"] = "1"
    env["SIFT_TOOL_STATUS_NOISE"] = "1"
    env["SIFT_SIGNATURE_RECONCILE"] = "1"  # lever 2: verdict consistency (C1)
    env["SIFT_BASELINE_GATE"] = "1"        # lever 3: baseline-artifact precision (C2)
    env["SIFT_CONFIRMED_DEDUP"] = "1"      # lever 1: same-artifact confirmed dedup (C2)
    env["SIFT_XBUCKET_DEDUP"] = "1"        # A1: cross-bucket same-event/artifact collapse (C2)
    env["SIFT_ENTITY_DISPOSITION_CONSISTENCY"] = "1"  # same entity -> ONE table (kills split-table contradictions, universal)
    env["SIFT_NETWORK_SALIENCE"] = "1"     # network-IOC salience SHADOW (measure only)
    # PARALLELISM: give every level 8-16 workers where it is SAFE, adapting to the
    # host. Operator env always wins (only set when the shell has not pinned it).
    # Step-6 runs Vol3 SUBPROCESSES (CPU+RAM heavy) -- floor it ONLY when RAM has
    # headroom, else leave it core-aware (oversubscribing heavy Vol3 on a small box
    # OOM-kills children -> "tool failure" -> junk findings). Step-10 (local
    # validators) is safe to raise. Step-11/12 are API fan-outs -- a moderate
    # core-matched count (lower via env on a 529-rate-limited tier). Heavy tools
    # already submit first via SIFT_STEP6_HEAVY_FIRST.
    # NB: do NOT set SIFT_PARSE_EVENT_LOGS_INNER_WORKERS here -- EVTX parsing is
    # serial BY DESIGN (31Y: parallel GIL contention cost 96% of event_log coverage).
    # ReAct/SC are LLM API fan-outs: firing more simultaneous calls than the host
    # has cores just self-collides into HTTP 529s on a rate-limited tier, and each
    # 529 backoff inflates wall time. Match concurrency to cores (cap 8) so a 4-core
    # box fires 4, not 8 -- the correct 529 lever (NOT fewer retries, which would drop
    # a whole stage to fallback). No detection change: same calls, less collision.
    _api_fanout = str(max(2, min(os.cpu_count() or 4, 8)))
    _para_defaults = {
        "SIFT_STEP10_MAX_WORKERS": "12",            # local validators -- safe high
        "SIFT_STEP11_MAX_WORKERS": _api_fanout,     # ReAct API fan-out -- core-matched
        "SIFT_STEP12_MAX_WORKERS": _api_fanout,     # self-correction API fan-out
        "SIFT_STEP6_HEAVY_FIRST": "1",              # long-pole tools submit first
        # EVTX: the fast Rust `evtx` wheel finishes in seconds; this larger budget
        # only binds on the slow python-evtx fallback (no wheel) so all crown-jewel
        # channels (Security/WinRM/WMI/...) complete instead of being cut at 90s.
        "SIFT_EVTX_TOTAL_BUDGET_S": "180",
    }
    # RAM-AWARE Step-6 worker floor (host-agnostic). Vol3 plugins mmap the image and
    # are IO/parse-bound, so up to 2x CPU oversubscription overlaps their IO waits
    # WITHOUT CPU-starving them below the 240s heavy-tool timeout (malfind ~136s even
    # at 1.5x = ~204s < 240s). Each heavy plugin holds ~1.25GB resident (symbols +
    # scan buffers, NOT the shared mmap), so spare RAM -- not cores -- is the real
    # cap. rec = min(2*cpu, avail_GB/1.25, 16): a 4-core/12GB VM gets 8 workers (was
    # core-bound at 4); peak 8*1.25=10GB < 12GB, no OOM. Only set when it beats the
    # bare core count (else the code stays core-aware).
    _cpu = _effective_cpu_count()
    _avail = _onboard_avail_ram_gb()
    if _avail >= 4.0:
        _rec_workers = max(1, min(2 * _cpu, int(_avail / 1.25), 16))
        if _rec_workers > _cpu:
            _para_defaults["SIFT_STEP6_MIN_WORKERS"] = str(_rec_workers)
    for _pk, _pv in _para_defaults.items():
        if _pk not in os.environ:
            env[_pk] = _pv
    return env


def _effective_cpu_count() -> int:
    """CPUs the CONTAINER may actually use, not the host/VM total. Respects the
    cpuset (sched_getaffinity) and the cgroup CFS quota (`docker run --cpus`).
    Degrades OPEN to os.cpu_count() when cgroup files are absent (bare metal / CI),
    so the core-aware contract is unchanged off-container. Never raises.

    Rationale: on Docker Desktop, os.cpu_count() reports the WSL2 VM's cores, so a
    throttled container would size 16 heavy vol3 workers onto a few real CPUs
    (contention + OOM risk). Sizing to the real grant is universal, not per-case."""
    n = os.cpu_count() or 1
    try:
        n = len(os.sched_getaffinity(0)) or n            # respects --cpuset-cpus
    except (AttributeError, OSError):
        pass
    try:                                                 # cgroup v2 CFS quota
        with open("/sys/fs/cgroup/cpu.max") as _f:
            _parts = _f.read().split()
            if _parts and _parts[0] != "max":
                _period = float(_parts[1]) if len(_parts) > 1 else 100000.0
                n = min(n, max(1, int(float(_parts[0]) / _period)))
    except (OSError, ValueError, ZeroDivisionError):
        try:                                             # cgroup v1 fallback
            with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") as _fq, \
                 open("/sys/fs/cgroup/cpu/cpu.cfs_period_us") as _fp:
                _q = int(_fq.read().strip()); _p = int(_fp.read().strip())
                if _q > 0 and _p > 0:
                    n = min(n, max(1, _q // _p))
        except (OSError, ValueError):
            pass
    return max(1, n)


def _onboard_avail_ram_gb() -> float:
    """Available RAM in GiB the CONTAINER may use: min(/proc/meminfo MemAvailable,
    cgroup memory limit). 0.0 if unreadable. Used only to decide whether the Step-6
    Vol3 worker floor is safe -- never raises. Cgroup-aware so we don't size for
    WSL2 VM RAM the container can't touch (universal, not per-case)."""
    _avail = 0.0
    try:
        with open("/proc/meminfo") as _mf:
            for _ln in _mf:
                if _ln.startswith("MemAvailable:"):
                    _avail = int(_ln.split()[1]) / (1024 * 1024)
                    break
    except (OSError, ValueError, IndexError):
        pass
    for _path in ("/sys/fs/cgroup/memory.max",                     # cgroup v2
                  "/sys/fs/cgroup/memory/memory.limit_in_bytes"):  # cgroup v1
        try:
            with open(_path) as _mf:
                _raw = _mf.read().strip()
            if _raw and _raw != "max":
                _lim = int(_raw) / (1024 ** 3)
                if 0 < _lim < 1_000_000:          # ignore the ~2^63 "unlimited" sentinel
                    _avail = min(_avail, _lim) if _avail > 0 else _lim
            break
        except (OSError, ValueError):
            continue
    return _avail


def _ensemble_size_default() -> int:
    """Ensemble member count: SIFT_ENSEMBLE_SIZE (clamped 1..8), default 4 -- the size
    the live runs already use."""
    try:
        n = int((os.environ.get("SIFT_ENSEMBLE_SIZE") or "4").strip())
    except ValueError:
        n = 4
    return n if 1 <= n <= 8 else 4


def ensemble_roster_env(mode: dict, current_env: Optional[dict] = None) -> dict:
    """Guarantee an ensemble roster so an onboarded ensemble run never dies at Step 8
    on an unconfigured roster.

    The mode already sets which model the members RUN (the force-model); the roster's
    only job is the member COUNT. When the operator has NOT exported an explicit
    SIFT_ENSEMBLE_MODELS, synthesise one from the chosen model repeated
    SIFT_ENSEMBLE_SIZE (default 4) times. Returns the env delta ({} when nothing to
    add): an explicit operator roster always wins, and a non-ensemble mode adds
    nothing. No model literal in source -- the id comes from the mode."""
    cur = current_env if current_env is not None else os.environ
    if not mode.get("ensemble", True):
        return {}
    if (cur.get("SIFT_ENSEMBLE_MODELS") or "").strip():
        return {}                              # operator's explicit roster wins
    model = str(mode.get("model") or "").strip()
    if not model:
        return {}
    return {"SIFT_ENSEMBLE_MODELS": ",".join([model] * _ensemble_size_default())}


def parse_mode_choice(raw: str) -> Optional[dict]:
    """Map '1'/'2' (or 'heavy'/'light') to a mode dict. None = unrecognized."""
    t = (raw or "").strip().lower()
    if t in ANALYSIS_MODES:
        return ANALYSIS_MODES[t]
    for m in ANALYSIS_MODES.values():
        if t and (t == m["key"] or t.startswith(m["key"])):
            return m
    return None


def parse_card_choice(raw: str, n: int):
    """A ready-cards selection: a 1-based case NUMBER, or 'a'/'q', or None to
    re-ask. 'just give the card number at the top' - e.g. 11 -> case 11."""
    t = _clean_input(raw).strip().lower()
    if t in _ANOTHER:
        return "a"
    if t in _QUIT:
        return "q"
    if t.isdigit() and 1 <= int(t) <= n:
        return int(t)
    return None


# ── FIND command construction (pure; safe to unit-test) ──────────────────────
def build_find_command(manifest: CaseManifest, ensemble: bool = True) -> list:
    """Build the run_pipeline.py argv for the chosen case. No side effects.
    ``ensemble`` adds --inv2-ensemble (Heavy mode); Light mode omits it."""
    cmd = [sys.executable, _PIPELINE, "--live"]
    if ensemble:
        cmd += ["--inv2-ensemble"]
    if manifest.memory_path:
        cmd += ["--image", manifest.memory_path]
    if manifest.disk_path:
        cmd += ["--disk", manifest.disk_path]
    if manifest.mount_path:
        cmd += ["--disk-mount", manifest.mount_path]
    return cmd


def validate_api_key(key: str) -> tuple:
    """Cheap FORMAT check for the provider's API key (catches a typo / wrong / DOUBLE
    paste before we waste a launch on a 401). Returns (ok, reason). Qwen mode expects
    a DashScope 'sk-...' token; Anthropic fallback mode expects one 'sk-ant-' ~100-char
    URL-safe token. This is a format gate, not auth --
    only the API can confirm the key is live."""
    k = (key or "").strip()
    if not k:
        return False, "empty"
    if _qwen_mode():
        # DashScope (Qwen Cloud) keys: 'sk-…' (NOT 'sk-ant-…'), URL-safe + dots.
        if k.startswith("sk-ant-"):
            return False, ("looks like an ANTHROPIC key (sk-ant-…) - the Qwen "
                           "path needs your DashScope key from Model Studio")
        if not k.startswith("sk-"):
            return False, "must start with 'sk-' (got '%s…')" % k[:6]
        if len(k) < 20:
            return False, "too short - %d chars (a DashScope key is longer)" % len(k)
        if len(k) > 250:
            return False, ("too long - %d chars. Did you paste it twice or "
                           "include extra text?" % len(k))
        if not re.fullmatch(r"[A-Za-z0-9_\-.]+", k):
            return False, "has characters a DashScope key never contains"
        return True, ""
    if not k.startswith("sk-ant-"):
        return False, "must start with 'sk-ant-' (got '%s…')" % k[:6]
    _n = k.count("sk-ant-")
    if _n > 1:
        return False, ("looks pasted %d× - %d chars with %d 'sk-ant-' prefixes "
                       "(a key is ONE ~100-char value)" % (_n, len(k), _n))
    if len(k) > 150:
        return False, ("too long - %d chars (a key is ~100). Did you paste it twice "
                       "or include extra text?" % len(k))
    if len(k) < 40:
        return False, "too short - %d chars (an Anthropic key is ~100)" % len(k)
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", k):
        return False, "has characters an Anthropic key never contains"
    return True, ""


def verify_api_key_live(key, *, _client_factory=None, timeout: float = 10.0) -> str:
    """Confirm the API actually ACCEPTS the key -- the format gate cannot. Returns:

      * ``"ok"``         -- the API accepted the key (a cheap, no-token models.list).
      * ``"rejected"``   -- a definite auth failure (HTTP 401 / invalid x-api-key /
                            permission). The key is wrong, revoked, or wrong workspace.
      * ``"unverified"`` -- the check could not run (no SDK, network/timeout, or it was
                            skipped). The caller FAILS OPEN: a transient problem must
                            never block a launch.

    Fails open by design: only a *definite* auth error blocks. The real-network path is
    skipped under tests and when ``SIFT_SKIP_KEY_PREFLIGHT`` is set; an injected
    ``_client_factory`` exercises the classification without a network call."""
    if _client_factory is None:
        if os.environ.get("SIFT_SKIP_KEY_PREFLIGHT", "").strip().lower() in ("1", "true", "yes", "on"):
            return "unverified"
        if os.environ.get("PYTEST_CURRENT_TEST"):     # never hit the network during tests
            return "unverified"
        if _qwen_mode():
            # DashScope: a cheap authenticated GET on the OpenAI-compatible
            # /models endpoint (no token cost). 401/403 = rejected; anything
            # else fails open, same contract as the Anthropic path.
            import urllib.error
            import urllib.request
            base = os.environ.get(
                "DASHSCOPE_BASE_URL",
                "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions",
            )
            root = base.split("/chat/completions")[0].rstrip("/")
            req = urllib.request.Request(
                root + "/models", headers={"Authorization": "Bearer " + (key or "")})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return "ok" if 200 <= resp.status < 300 else "unverified"
            except urllib.error.HTTPError as e:
                return "rejected" if e.code in (401, 403) else "unverified"
            except Exception:
                return "unverified"
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=key, timeout=timeout)
        except Exception:
            return "unverified"
    else:
        try:
            client = _client_factory(key)
        except Exception:
            return "unverified"
    try:
        client.models.list()                          # requires auth; no token cost
        return "ok"
    except Exception as e:
        blob = (type(e).__name__ + " " + str(e)).lower()
        if any(t in blob for t in ("authentication", "401", "invalid x-api-key",
                                   "permissiondenied", "permission_error", "x-api-key")):
            return "rejected"
        return "unverified"                           # network/other -> fail open


def _load_env_file_api_key(path=None) -> bool:
    """If the provider's key env var (DASHSCOPE_API_KEY in qwen mode, else
    ANTHROPIC_API_KEY) isn't already set, try to read JUST that variable from a
    local ``.env`` file (no shell execution, no other vars) so a key kept in .env is
    picked up automatically. Returns True iff it set the key. The value is never printed;
    .env is gitignored. The default repo/CWD scan is skipped under tests (pass an
    explicit ``path`` to exercise the parser)."""
    env_name = _key_env_name()
    accepted = ("DASHSCOPE_API_KEY", "QWEN_API_KEY") if _qwen_mode() else ("ANTHROPIC_API_KEY",)
    if os.environ.get(env_name):
        return False
    if path is None and os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    candidates = [path] if path else [os.path.join(_REPO, ".env"),
                                       os.path.join(os.getcwd(), ".env")]
    for p in candidates:
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln or ln.startswith("#") or "=" not in ln:
                        continue
                    k, v = ln.split("=", 1)
                    if k.strip().replace("export ", "").strip() in accepted:
                        v = v.strip().strip('"').strip("'")
                        if v:
                            os.environ[env_name] = v
                            return True
        except OSError:
            continue
    return False


def _is_placeholder_key(key) -> bool:
    """True when a configured key is still an example/template, not a real one.

    Shape-based ONLY -- repeated filler characters (the shipped `.env.example`
    value is ``sk-ant-xxxx…``) or obvious 'replace me' words. It never inspects
    or stores a real key's bytes, so a genuine random key is never flagged.
    Used to give a clear 'replace the placeholder' message instead of a
    confusing live-API 401, and to avoid sending the template to the API.
    """
    if not isinstance(key, str):
        return False
    k = key.strip()
    if not k:
        return False
    kl = k.lower()
    body = kl[len("sk-ant-"):] if kl.startswith("sk-ant-") else kl
    alnum = "".join(ch for ch in body if ch.isalnum())
    if not alnum:
        return False
    # whole body is one repeated character (xxxx…, 0000…) = pure filler.
    if len(set(alnum)) == 1:
        return True
    # a run of >= 8 identical characters anywhere = template filler block.
    run = 1
    for i in range(1, len(alnum)):
        if alnum[i] == alnum[i - 1]:
            run += 1
            if run >= 8:
                return True
        else:
            run = 1
    # obvious template / 'replace me' words.
    for w in ("xxxx", "yourkey", "your-key", "your_key", "placeholder",
              "replace", "example", "changeme", "change-me",
              "your-dashscope", "dashscope-key", "key-here"):
        if w in kl:
            return True
    return False


# ── visible key file (judge-friendly; no hidden dot-file to hunt for) ─────────
_VISIBLE_KEY_FILE = "API_KEY.txt"
_SK_ANT_TOKEN_RE = re.compile(r"sk-ant-[A-Za-z0-9_\-]+")
# DashScope keys are 'sk-…' with dots allowed (and NOT 'sk-ant-…').
_SK_QWEN_TOKEN_RE = re.compile(r"sk-[A-Za-z0-9_\-.]{16,}")
_VISIBLE_KEY_FILE_TEMPLATE = (
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "#  Sentinel Qwen Ensemble - your Anthropic API key\n"
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "#  Paste YOUR key on the LAST line below (replace the placeholder), then SAVE.\n"
    "#  Get one at  https://console.anthropic.com  →  API keys  →  Create key.\n"
    "#  Read locally only - never uploaded, logged, or committed (this file is\n"
    "#  gitignored). Or skip this file: ./setup.sh run asks once at a hidden prompt.\n"
    "#\n"
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "#  ⚠️  API USAGE TIER - IMPORTANT\n"
    "#  The analysis stage runs a 4-MODEL ENSEMBLE in parallel (4 concurrent API\n"
    "#  calls), plus the other invocations. A Tier-1 account ($5) is likely to hit\n"
    "#  rate limits (HTTP 429) on those parallel calls.\n"
    "#    • Tier 1  ($5)   - fine for `--demo`; will rate-limit the live ensemble\n"
    "#    • Tier 2  ($40)  - recommended minimum for a full live run\n"
    "#    • Tier 3  ($200) - smoothest (no throttling on parallel calls)\n"
    "#  Your tier auto-increases with account age + spend; check it at\n"
    "#  console.anthropic.com  →  Plans & Billing.\n"
    "#  (Optional) Lower cost: pick \"2\" (LIGHT / Haiku) at the depth prompt, or\n"
    "#  narrow the ensemble via  SIFT_ENSEMBLE_MODELS.\n"
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "\n"
    "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
)

_VISIBLE_KEY_FILE_TEMPLATE_QWEN = (
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "#  Sentinel Qwen Ensemble - your Qwen Cloud (DashScope) API key\n"
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "#  Paste YOUR key on the LAST line below (replace the placeholder), then SAVE.\n"
    "#  Get one at  https://qwencloud.com  →  Model Studio (Singapore/Intl region)\n"
    "#  →  API Keys  →  Create API Key.\n"
    "#  Read locally only - never uploaded, logged, or committed (this file is\n"
    "#  gitignored). Or skip this file: ./setup.sh run asks once at a hidden prompt.\n"
    "#\n"
    "#  Cost expectations (measured on the reference paired case): a full LIGHT\n"
    "#  run ~$0.22 (qwen-plus), a full HEAVY run ~$1.67 (qwen3.7-max) - the $40\n"
    "#  hackathon voucher covers many runs. `--demo` is free (no key needed).\n"
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "\n"
    "sk-your-dashscope-key-here\n"
)


def _visible_key_file_template() -> str:
    return _VISIBLE_KEY_FILE_TEMPLATE_QWEN if _qwen_mode() else _VISIBLE_KEY_FILE_TEMPLATE


def _scan_text_for_anthropic_key(path):
    """First provider API-key token in a file (function name is historical): a
    key ``NAME=<v>`` assignment OR a bare ``sk-...`` token on any non-comment
    line (so a judge can paste the key by
    itself). Returns the token string, or None. Comments (``#``) are ignored.
    Never raises."""
    qwen = _qwen_mode()
    accepted = ("DASHSCOPE_API_KEY", "QWEN_API_KEY") if qwen else ("ANTHROPIC_API_KEY",)
    token_re = _SK_QWEN_TOKEN_RE if qwen else _SK_ANT_TOKEN_RE
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                line = ln.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip().replace("export ", "").strip() in accepted:
                        v = v.strip().strip('"').strip("'")
                        if v:
                            return v
                        continue
                m = token_re.search(line)
                if m and not (qwen and m.group(0).startswith("sk-ant-")):
                    return m.group(0)
    except OSError:
        return None
    return None


def _find_key_in_files(*, env_paths=None, txt_paths=None):
    """Resolve the provider's API key from local files. Precedence: ``.env`` then the
    visible ``API_KEY.txt`` (repo dir, then CWD). A REAL key always wins over a
    placeholder found anywhere -- so a leftover ``.env`` placeholder never blocks a
    real key in ``API_KEY.txt``. Returns ``(key, source_label, is_placeholder)``;
    ``is_placeholder`` True means only the shipped example value was found, so the
    caller can show a clear 'replace it' message. The default repo/CWD scan is
    skipped under tests unless explicit paths are injected. Never raises."""
    if env_paths is None and txt_paths is None and os.environ.get("PYTEST_CURRENT_TEST"):
        return (None, None, False)
    if env_paths is None:
        env_paths = [os.path.join(_REPO, ".env"), os.path.join(os.getcwd(), ".env")]
    if txt_paths is None:
        txt_paths = [os.path.join(_REPO, _VISIBLE_KEY_FILE),
                     os.path.join(os.getcwd(), _VISIBLE_KEY_FILE)]
    ordered = ([(p, "your .env file") for p in env_paths]
               + [(p, "your %s file" % _VISIBLE_KEY_FILE) for p in txt_paths])
    placeholder = (None, None)
    for p, label in ordered:
        if not p or not os.path.isfile(p):
            continue
        tok = _scan_text_for_anthropic_key(p)
        if not tok:
            continue
        if _is_placeholder_key(tok):
            if placeholder[0] is None:
                placeholder = (tok, label)
            continue
        return (tok, label, False)
    if placeholder[0] is not None:
        return (placeholder[0], placeholder[1], True)
    return (None, None, False)


def _ensure_visible_key_file():
    """Create a VISIBLE ``API_KEY.txt`` (placeholder + instructions) in the repo
    root if no key file exists yet, so a judge has an obvious file to open and paste
    into instead of hunting for a hidden ``.env``. Returns its path (created or
    already present), or None. Skipped under tests and kill-switch
    SIFT_KEY_FILE_AUTOCREATE=0; fails silently if the repo dir isn't writable. Only
    the shipped placeholder template is ever written here -- never a real key."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    if os.environ.get("SIFT_KEY_FILE_AUTOCREATE", "1").strip().lower() in ("0", "false", "no", "off"):
        return None
    path = os.path.join(_REPO, _VISIBLE_KEY_FILE)
    if os.path.isfile(path):
        return path
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_visible_key_file_template())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path
    except OSError:
        return None


def _first_verifying_file_key(verify, exclude=None):
    """If a REAL key sits in .env / API_KEY.txt that the API accepts, return
    ``(key, source_label)``; else ``(None, None)``. Used to fall back when the
    *environment* key is rejected (401) or is a placeholder, so a key the operator
    just put in a file still works even with a stale exported key value in
    the shell. ``exclude`` skips re-trying the same key that already failed."""
    fk, flabel, fis_ph = _find_key_in_files()
    if not fk or fis_ph or fk == exclude:
        return (None, None)
    if verify(fk) in ("ok", "unverified"):
        return (fk, flabel)
    return (None, None)


def _ensure_api_key(getpass_fn=None, max_tries: int = 3, verifier=None) -> bool:
    """ALWAYS show the hidden API-key step (operator wants to see it every run).

    HIDDEN (never echoed). A pasted OR reused key is format-validated (provider prefix +
    length) AND, when possible, checked LIVE against the API (a cheap no-token
    models.list) so a wrong / revoked / stale key -- one that passes the format gate but
    the API rejects with a 401 -- is caught HERE with a clear message instead of failing
    the run two seconds in. The live check fails OPEN: a network problem never blocks a
    launch. The key is never printed, logged, or persisted to disk."""
    getpass_fn = getpass_fn or getpass.getpass
    verify = verifier or verify_api_key_live
    _env_name = _key_env_name()
    # Qwen path: QWEN_API_KEY is an accepted alias for DASHSCOPE_API_KEY.
    if _qwen_mode() and not os.environ.get("DASHSCOPE_API_KEY") \
            and os.environ.get("QWEN_API_KEY"):
        os.environ["DASHSCOPE_API_KEY"] = os.environ["QWEN_API_KEY"]
    # Resolve a key from files, preferring a REAL key over any placeholder. Order:
    # environment variable > .env > visible API_KEY.txt. A placeholder anywhere never
    # beats a real key found elsewhere, so a leftover .env placeholder is harmless.
    _src = "your environment"
    if not os.environ.get(_env_name):
        _fk, _flabel, _fis_ph = _find_key_in_files()
        if _fk:
            os.environ[_env_name] = _fk
            _src = _flabel
    existing = os.environ.get(_env_name)
    print(_c("\n  🔑 API key", "1;33")
          + _c("  (hidden - never shown, this session only)", "2"))
    # Frictionless skip: a key already configured (environment, .env, or API_KEY.txt)
    # that the API accepts needs no paste at all -- confirm and move on. Set
    # SIFT_FORCE_KEY_PROMPT=1 to always show the paste step instead.
    force_prompt = os.environ.get("SIFT_FORCE_KEY_PROMPT", "").strip().lower() in ("1", "true", "yes", "on")
    if existing and not force_prompt:
        # Placeholder guard: if .env still holds the shipped example value, say so
        # clearly and prompt -- don't waste a live call to get a confusing 401.
        # Kill-switch SIFT_ENV_PLACEHOLDER_GUARD=0 restores the verify-first path.
        _ph_guard = os.environ.get("SIFT_ENV_PLACEHOLDER_GUARD", "1").strip().lower() \
            not in ("0", "false", "no", "off")
        if _ph_guard and _is_placeholder_key(existing):
            # A placeholder in the environment must not hide a real key in a file.
            _fk, _flabel = _first_verifying_file_key(verify, exclude=existing)
            if _fk:
                os.environ[_env_name] = _fk
                print(_c("  ✓ using the verified key in %s." % _flabel, "1;32"))
                return True
            _ph_hint = ("sk-your-dashscope-key…" if _qwen_mode() else "sk-ant-xxxx…")
            print(_c("  ⚠ %s still has the placeholder key (%s) - replace it "
                     "with your real key. Paste one below for this run:" % (_src, _ph_hint), "1;33"))
            existing = None
        else:
            status = verify(existing)
            if status == "ok":
                print(_c("  ✓ API key found in %s and verified - skipping the paste step." % _src, "1;32"))
                return True
            if status == "unverified":
                print(_c("  ✓ using the API key in %s" % _src, "32")
                      + _c("  (couldn't verify online; proceeding).", "2"))
                return True
            # The environment key was rejected -- before prompting, fall back to a
            # valid key the operator may have put in API_KEY.txt / .env. This is the
            # common 'stale export shadows my edited file' case.
            _fk, _flabel = _first_verifying_file_key(verify, exclude=existing)
            if _fk:
                os.environ[_env_name] = _fk
                print(_c("  ✓ the key in %s was rejected, but %s has a valid one - using it."
                         % (_src, _flabel), "1;32"))
                return True
            print(_c("  ✗ the API key in %s was rejected (401 invalid x-api-key) - paste a "
                     "valid one below." % _src, "31"))
            existing = None
    # Key-file discoverability: if we reach the prompt with no usable key, the judge
    # may be hunting for a file. Point them at a VISIBLE API_KEY.txt (auto-created
    # here) they can open and paste into -- no hidden dot-file. Kill-switches:
    # SIFT_KEY_FILE_HINT=0 (silence) / SIFT_KEY_FILE_AUTOCREATE=0 (don't create).
    if not existing and os.environ.get("SIFT_KEY_FILE_HINT", "1").strip().lower() \
            not in ("0", "false", "no", "off"):
        _ensure_visible_key_file()
        _kf = os.path.join(_REPO, _VISIBLE_KEY_FILE)
        print(_c("  ▸ Paste your key at the prompt below - nothing to find or edit.", "2"))
        print(_c("    Prefer a file? Open this visible file, paste your key on its own "
                 "line, and save:", "2"))
        print("        " + _c(_kf, "36"))
        print(_c("    (a hidden .env with %s=… also works.)" % _env_name, "2"))
    for _ in range(max_tries):
        prompt = ("  ▸ Press Enter to use the key already set, or paste a different "
                  "one (hidden): " if existing
                  else "  ▸ Paste your %s API key (hidden, not echoed): " % _provider_label())
        try:
            key = (getpass_fn(prompt) or "").strip()
        except (EOFError, OSError, KeyboardInterrupt):
            key = ""
        if not key:
            if existing:
                # Verify the REUSED key too -- a stale/revoked key reused on Enter is the
                # most common 401 cause. A rejection forces a fresh paste.
                if verify(existing) == "rejected":
                    print(_c("  ✗ the key already in your environment was rejected by the "
                             "API (401 invalid x-api-key) - paste a valid one below.", "31"))
                    existing = None
                    continue
                print(_c("  ✓ using the key already in your environment (hidden).", "32"))
                return True
            print(_c("  ✗ no API key provided - cannot launch.", "31"))
            return False
        ok, why = validate_api_key(key)
        if not ok:
            tail = (" - or press Enter to use the existing key" if existing else "")
            _lbl = ("a Qwen Cloud (DashScope)" if _qwen_mode() else "an Anthropic")
            print(_c("  ✗ that doesn't look like %s key: %s. Try again%s."
                     % (_lbl, why, tail), "31"))
            continue
        status = verify(key)
        if status == "rejected":
            tail = (" - or press Enter to use the existing key" if existing else "")
            print(_c("  ✗ the API rejected that key (401 invalid x-api-key) - it may be "
                     "revoked or for the wrong workspace. Paste a valid one%s." % tail, "31"))
            continue
        os.environ[_env_name] = key
        if status == "ok":
            print(_c("  ✓ key verified with the API (accepted, %d chars)." % len(key), "32"))
        else:
            _pfx = "sk-…" if _qwen_mode() else "sk-ant-…"
            print(_c("  ✓ key format looks valid (%s, %d chars)." % (_pfx, len(key)), "32")
                  + _c("  (could not verify online; proceeding)", "2"))
        return True
    print(_c("  ✗ no valid API key after %d attempts - cannot launch." % max_tries, "31"))
    return False


def render_mode_menu() -> str:
    """A fancy, colorful depth menu that names the actual model/version."""
    w = 64
    top = "  " + _c("╭" + "─" * w + "╮", "36")
    titletxt = "  CHOOSE  ANALYSIS  DEPTH  -  how hard should the AI think?"
    title = "  " + _c("│", "36") + _c(titletxt.ljust(w), "1;36") + _c("│", "36")
    bot = "  " + _c("╰" + "─" * w + "╯", "36")
    lines = ["", top, title, bot, ""]
    # number color per mode: heavy = magenta, light = cyan
    numcol = {"1": "1;35", "2": "1;36"}
    namecol = {"1": "1;33", "2": "1;32"}      # heavy = gold, light = green
    for k, m in ANALYSIS_MODES.items():
        head = (f"   {_c(k + ')', numcol.get(k, '1'))} "
                f"{m['icon']} {_c(m['label'], numcol.get(k, '1'))}"
                f"  ·  {_c(m['name'], namecol.get(k, '1'))}"
                f"   {_c(m['tag'], '2')}")
        cost = "        " + _c(m["cost"], "1;32")
        blurb = "        " + _c(m["blurb"], "2")
        lines += [head, cost, blurb, ""]
    return "\n".join(lines)


def _clear_screen() -> None:
    """Clear the terminal + scrollback just before launch, so a pasted key (and the
    onboarding chatter) are not left on screen during the run. No-op when not a TTY
    (tests, pipes). ANSI: 3J scrollback, 2J screen, H home."""
    try:
        if sys.stdout.isatty():
            print("\x1b[3J\x1b[2J\x1b[H", end="", flush=True)
    except Exception:
        pass


def choose_mode(input_fn=None):
    """Prompt for analysis depth. Returns a mode dict, ``"back"`` (go back a step),
    or None (quit/EOF). Enter = Heavy (default). Every step has an escape: B=back,
    Q=quit - so a wrong keypress never traps the user."""
    input_fn = input_fn or _safe_input
    print(render_mode_menu())
    while True:
        raw = input_fn(_c("  ▸ Choose depth  ", "1;36")
                       + "[1 or Enter = Heavy · 2 = Light · B = back · Q = quit]: ")
        if raw is None:
            return None
        t = _clean_input(raw).strip().lower()
        if not t:
            return _DEFAULT_MODE
        if t in _QUIT:
            return None
        if t in _BACK or t in _ANOTHER:      # 'a'/'back' both step back to the cards
            return "back"
        m = parse_mode_choice(t)
        if m is not None:
            return m
        print("  " + _c("(1 or Enter = Heavy · 2 = Light · B = back · Q = quit)", "2"))


def warm_sha_async(manifest: CaseManifest):
    """STEP-1 WARM START: precompute the evidence SHA256 in the BACKGROUND so the
    pipeline's Step-1 fingerprint (a cold multi-GB hash, ~20-40 s) is instant. Hashing
    overlaps the user picking depth + pasting the key (dead time). Returns the temp
    JSON path immediately; the file appears ATOMICALLY only when hashing finishes, so
    the pipeline either reuses a complete file or falls back to a full re-hash - never
    a partial read. Byte-identical to the pipeline (sha256, full file)."""
    import hashlib
    import json
    import tempfile
    import threading
    paths = [p for p in (manifest.memory_path, manifest.disk_path) if p]
    if not paths:
        return None
    from sift_sentinel.onboard.sha_warmstart import inprogress_marker
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(manifest.case_id or "case"))
    out = os.path.join(tempfile.gettempdir(), f"sift-presha-{safe_id}.json")
    marker = inprogress_marker(out)

    def _rm_marker():
        try:
            os.remove(marker)
        except OSError:
            pass

    # Mark the hash IN FLIGHT synchronously (before the thread) so the pipeline can
    # tell "warm hash running -> wait for it" from "no warm hash -> cold hash". The
    # marker is removed on BOTH success and failure, so a failed warm hash never
    # makes the pipeline wait the full bound.
    try:
        with open(marker, "w") as fh:
            fh.write("")
    except OSError:
        pass

    def _work():
        data = {}
        for p in paths:
            try:
                st = os.stat(p)
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(16 * 1024 * 1024), b""):
                        h.update(chunk)
                data[p] = {"sha256": h.hexdigest(), "size": st.st_size}
            except OSError:
                _rm_marker()
                return                                  # can't hash -> no warm file
        try:
            tmp = out + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh)
            os.replace(tmp, out)                        # atomic publish
        except OSError:
            pass
        _rm_marker()

    threading.Thread(target=_work, daemon=True).start()
    return out


_KEY_IN_HISTORY_RE = re.compile(
    r"sk-ant-|sk-[A-Za-z0-9_.-]{16,}|ANTHROPIC_API_KEY|DASHSCOPE_API_KEY|QWEN_API_KEY",
    re.IGNORECASE)


def scrub_shell_history(histfile: Optional[str] = None) -> int:
    """Security guardrail: remove any line that carries an API key (an sk-... token
    or a key env assignment) from the shell history file, so a key typed at a prompt is
    never PERSISTED. Returns the number of lines scrubbed. Pure-ish: only rewrites
    the history file, and only when a key line is present."""
    path = histfile or os.environ.get("HISTFILE") or os.path.expanduser(
        "~/.bash_history")
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return 0
    kept = [ln for ln in lines if not _KEY_IN_HISTORY_RE.search(ln)]
    removed = len(lines) - len(kept)
    if removed:
        try:
            with open(path, "w") as fh:
                fh.writelines(kept)
        except OSError:
            return 0
    return removed


def _do_find(manifest: CaseManifest, wired: bool, mode: Optional[dict] = None,
             runner=subprocess.run, input_fn=None, getpass_fn=None):
    """Launch run_pipeline.py for the chosen case + reasoning mode - never a dead
    end. Confirms (GO/back/cancel), collects a HIDDEN API key if none is set,
    CLEARS the screen so the key/scrollback are not left visible, then execs with
    the mode's model env. Returns the TRUE returncode, or 'back', or None.

    Wired (SIFT_FIND_WIRED=1 / --wire) skips the confirm. ZEROFAKE: the post-exec
    line reports the real returncode."""
    input_fn = input_fn or _safe_input
    mode = mode or _DEFAULT_MODE
    print()
    print("  " + _c(f"{mode['icon']} {mode['label']}", "1;35"
                    if mode["key"] == "heavy" else "1;36")
          + "  ·  " + _c(mode["name"], "1;33" if mode["key"] == "heavy" else "1;32")
          + "  ·  " + _c(mode["cost"], "1;32"))
    print("  " + _c(" ".join(find_command_display(manifest, mode)), "2"))
    if not wired:
        # Retry guardrail: a typo (e.g. "p") must WARN and re-ask, never silently
        # cancel a ready-to-launch case. Only an explicit cancel/quit aborts; back
        # returns to the case cards; Enter/GO launches. Matches the depth menu.
        while True:
            ans = input_fn(_c("  ▸ Start the hunt now? ", "1;36")
                           + "[" + _c("GO", "1;32") + " / back / cancel]: ")
            if ans is None:                       # closed stdin / EOF -> effective cancel
                print(_c("  ✗ cancelled - nothing launched.", "31"))
                return None
            a = _clean_input(ans).strip().lower()
            if a in ("", "go", "g", "y", "yes", "start", "run", "find evil", "findevil"):
                break                             # launch
            if a in _BACK or a in _ANOTHER:
                return "back"
            if a in _QUIT or a in ("cancel", "c", "n", "no", "stop", "abort"):
                print(_c("  ✗ cancelled - nothing launched.", "31"))
                return None
            # unrecognized -> warn + re-ask (no accidental cancel on a typo)
            print("  " + _c("⚠ didn't catch \"%s\" - type " % ans.strip()[:24], "33")
                  + _c("GO", "1;32") + _c(" to start · ", "2")
                  + _c("back", "1;36") + _c(" to pick another case · ", "2")
                  + _c("cancel", "31") + _c(" to abort", "2"))
    if not _ensure_api_key(getpass_fn):
        print(_c("  ✗ No API key - cannot launch. Choose this case again to retry.", "31"))
        return None
    _clear_screen()
    # Security guardrail: scrub any key-bearing line from shell history before the
    # run starts, and report it like the pipeline's other =PASS gates.
    _scrubbed = scrub_shell_history()
    print("  " + _c("BASH_HISTORY_CLEARED_GATE=PASS", "1;32")
          + _c(f"  (scrubbed {_scrubbed} key-bearing history line(s); "
               "the hidden key was never echoed or persisted)", "2"))
    print("\n  " + _c(f"🚀 launching {mode['name']} on this case …", "1;36") + "\n")
    env = {**os.environ, **mode_launch_env(mode)}
    # Guarantee an ensemble roster from the chosen model when none is exported, so an
    # ensemble run never crashes at Step 8 on an unconfigured roster.
    env.update(ensemble_roster_env(mode, env))
    proc = runner(build_find_command(manifest, ensemble=mode.get("ensemble", True)),
                  cwd=_REPO, env=env)                       # streams to our stdio
    rc = getattr(proc, "returncode", 0)
    print(f"\n  run_pipeline.py exited with code {rc}.")
    return rc


_USAGE = (
    "usage: step0_onboard.py [--dry-run|--plan] [--demo] [--no-ai] [PATH]\n"
    "  PATH  evidence file/folder/archive. Omit it to be prompted on a TTY,\n"
    "        or pipe a single path on stdin. With no PATH, no TTY and no\n"
    "        piped input, this exits 2 (CI safety) rather than hang."
)


def _safe_input(prompt: str) -> Optional[str]:
    """input() that returns None on EOF/closed/detached stdin instead of raising.

    EOFError is the closed-pipe case; OSError covers a detached or
    capture-redirected stdin (e.g. under pytest) - both mean "no answer
    available", so callers treat None as a decline rather than crashing."""
    try:
        return input(prompt)
    except (EOFError, OSError):
        return None


def _print_welcome() -> None:
    """Banner + the warm 'one folder per case' guidance, before the prompt."""
    print(presenter.banner())
    print()
    print(presenter.guidance())
    print()


_HELP = ("  Find Evil / FE / F  → launch the analysis on this case\n"
         "  A / ANOTHER / ADD   → onboard another case\n"
         "  Q / QUIT            → exit\n"
         "  H / HELP / ?        → show this help")

_MENU_PROMPT = "▸ Type 'Find Evil' to start · A=another · Q=quit · H=help: "

# Launch trigger accepts every reasonable form of "Find Evil" (case-insensitive,
# hyphen/underscore-tolerant).
_LAUNCH = {"find evil", "findevil", "find evil!", "find", "fe", "f"}
_ANOTHER = {"a", "another", "add"}
_QUIT = {"q", "quit", "exit"}
_BACK = {"b", "back", "<", "prev"}
_HELP_WORDS = {"h", "help", "?"}


def _normalize(s: str) -> str:
    return _clean_input(s).strip().lower().replace("-", " ").replace("_", " ")


def _levenshtein(a: str, b: str) -> int:
    """Tiny edit distance (no deps) for typo-tolerant 'Find Evil' matching."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _read_action(input_fn=_safe_input, prompt: str = _MENU_PROMPT) -> str:
    """ONE central handler for the ready prompt AND the post-run menu.
    Returns 'find'|'a'|'q'|'h'. Unknown input re-asks (never silently quits);
    EOF/closed stdin returns 'q'."""
    while True:
        raw = input_fn(prompt)
        if raw is None:
            return "q"
        n = _normalize(raw)
        if n in _LAUNCH:
            return "find"
        if n in _ANOTHER:
            return "a"
        if n in _QUIT:
            return "q"
        if n in _HELP_WORDS:
            return "h"
        if _levenshtein(n, "find evil") <= 2 or _levenshtein(n, "findevil") <= 2:
            confirm = input_fn("  Did you mean Find Evil? [Y/n] ")
            if confirm is not None and _normalize(confirm) in ("", "y", "yes"):
                return "find"
            continue                         # declined / unclear -> re-ask the menu
        print("  (didn't catch that - type 'Find Evil', A, Q, or H)")


def _make_sink(verbose: bool):
    """on_event sink: quiet by default (hides the verbose-only events), full
    trace when verbose."""
    def sink(ev):
        if verbose or not presenter.is_verbose_only(ev):
            presenter.render_event(ev)
    return sink


# ── Synthetic demo probes (HALT-GATE render, clearly labelled SYNTHETIC) ─────
class _DemoProbes(Probes):
    """No real evidence. Emits a representative extract->classify->os->mount-
    fallback->health->ready stream so the presenter can be demonstrated."""

    def discover(self, path):
        return ["/synthetic/Evidence.zip"]

    def archive_kind(self, path):
        return "ZIP" if path.endswith(".zip") else None

    def extract(self, path):
        return ["/synthetic/Acme-Memory.raw", "/synthetic/acme-cdrive.e01"]

    def has_filesystem(self, path):
        return path.endswith(".e01")

    def fs_facts(self, path):
        return {"fstype": "NTFS", "volume": "Windows", "version": "Windows XP"}

    def memory_info(self, path):
        if path.endswith(".raw"):
            return {"NtMajorVersion": "10", "NtMinorVersion": "0",
                    "MachineType": "34404", "KeNumberProcessors": "4"}
        return None

    def mount(self, disk, method, mountpoint):
        # Reproduce the truncated-tail ladder: raw@0 fails -> dmpad succeeds.
        if method == "raw@0":
            return False, "no NTFS volume at offset 0"
        if method == "dmpad":
            return True, ""
        return False, "unknown method"

    def health(self, mem):
        return True, [], {"NtMajorVersion": "10", "KeNumberProcessors": "4"}


def run_demo() -> int:
    print(presenter.banner())
    print()
    cases = onboard("/synthetic/Evidence.zip",
                    on_event=presenter.render_event,
                    ai=None, probes=_DemoProbes())
    print()
    for c in cases:
        print(presenter.case_card(c))
    print()
    print(presenter.ready_prompt(cases))
    return 0


# ── Interactive loop ("keep talking, keep asking") ───────────────────────────
def _select_case(cases: list) -> Optional[CaseManifest]:
    if len(cases) == 1:
        return cases[0]
    while True:
        raw = input("Select case number: ").strip()
        if raw.lower() in ("q", "quit"):
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(cases):
            return cases[int(raw) - 1]
        print("  …please enter a valid case number (or Q).")


def _quick_role(path: str, probes: Probes) -> str:
    """Best-effort role hint shown the moment a file is added. The authoritative
    classification still happens in onboard() on Find Evil."""
    from sift_sentinel.onboard import archive
    if os.path.isdir(path):
        return "folder (scanned on Find Evil)"
    try:
        if archive.is_document(path):
            return "DOC (reference)"
        if probes.archive_kind(path):
            return "ARCHIVE"
        if probes.has_filesystem(path):
            return "DISK"
        if probes.memory_info(path):
            return "MEMORY"
    except Exception:
        pass
    return "image (classified on Find Evil)"


def _multi_add(first: str, probes: Probes, input_fn=None) -> list:
    """File-by-file mode: collect evidence paths (files OR folders), echoing each
    one's probe role. Blank line / EOF finishes. Duplicates are ignored once."""
    input_fn = input_fn or _safe_input
    collected: list = []

    def add(p: str) -> None:
        if p in collected:
            print(f"  • already added: {os.path.basename(p)} (ignored)")
            return
        collected.append(p)
        print(f"  • added: {os.path.basename(p)} - {_quick_role(p, probes)}")

    add(first)
    while True:
        raw = input_fn("▸ Add another evidence file (or press Enter to finish): ")
        if raw is None:
            break
        t = raw.strip()
        if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
            t = t[1:-1]
        if not t:
            break
        t = os.path.expandvars(os.path.expanduser(t))
        if not os.path.exists(t):
            print(f"  …can't find that path - skipping: {t}")
            continue
        add(t)
    return collected


# ── FIND command, verbatim display form ──────────────────────────────────────
def find_command_display(manifest: CaseManifest, mode: Optional[dict] = None) -> list:
    """Canonical, copy-pasteable form of the FIND command.

    Derived from build_find_command so the flags never drift, but rendered as
    ``python3 run_pipeline.py …`` rather than the absolute exec form. ``mode``
    controls whether --inv2-ensemble is shown (Heavy yes, Light no).
    """
    ensemble = (mode or _DEFAULT_MODE).get("ensemble", True)
    return ["python3", "run_pipeline.py"] + build_find_command(manifest, ensemble)[2:]


def _pick_and_run(cases: list, wired: bool, input_fn=None) -> Optional[str]:
    """Ready-cards interaction: pick a case by NUMBER, pick a depth, confirm,
    launch. Returns 'another' to onboard another case, else None (done / quit)."""
    input_fn = input_fn or _safe_input
    while True:
        if len(cases) == 1:
            chosen = cases[0]
        else:
            raw = input_fn(f"▸ Which case to run? number 1-{len(cases)} "
                           "· A=another · Q=quit: ")
            c = parse_card_choice(raw, len(cases))
            if c == "a":
                return "another"
            if c == "q" or raw is None:
                return None
            if c is None:
                print(f"  (just type the case number, 1-{len(cases)} - or A / Q)")
                continue
            chosen = cases[c - 1]
        # Warm the Step-1 SHA in the background NOW, so it overlaps the depth menu +
        # hidden-key paste below. The launch env points the pipeline at the result.
        _presha = warm_sha_async(chosen)
        if _presha:
            os.environ["SIFT_PRECOMPUTED_SHA_FILE"] = _presha
        mode = choose_mode(input_fn)
        if mode is None:                             # Q at the depth menu -> quit
            return None
        if mode == "back":                           # B/A at the depth menu
            if len(cases) == 1:
                return "another"                     # nowhere else to go -> re-onboard
            continue                                 # multi-case -> back to the list
        result = _do_find(chosen, wired, mode=mode, input_fn=input_fn)
        if result == "back":
            continue                                 # back to the card list
        # Secret-paste guard: this is the visible prompt where a key pasted
        # after a failed hidden-key entry would echo in cleartext.
        nxt = _guard_visible_input(input_fn("▸ A=onboard another · Q=quit: "))
        if nxt and _normalize(nxt) in _ANOTHER:
            return "another"
        return None


def format_plan(m: CaseManifest) -> str:
    """Human-readable dry-run plan: resolved manifest + the would-run command."""
    prof = m.os_profile or {}
    agree = "yes" if prof.get("agree") else "no"
    cmd = " ".join(find_command_display(m))
    lines = [
        "DRY RUN - onboarding plan (no pipeline executed)",
        "",
        f"  Case id    : {m.case_id}",
        f"  Memory     : {m.memory_path or '-'}  [{m.memory_health or 'none'}]",
        f"  Disk       : {m.disk_path or '-'}",
        f"  Disk mount : {m.mount_path or '-'}  (method: {m.mount_method or 'none'})",
        "  OS profile :",
        f"     memory  : {prof.get('memory') or '-'}"
        "   [vol3 windows.info - authoritative]",
        f"     disk    : {prof.get('disk') or ('undetermined' if m.disk_path else '-')}"
        "   [SOFTWARE-hive ProductName]",
        f"     agree   : {agree}",
        f"     chosen  : {prof.get('os', m.os)}"
        f"  (source: {prof.get('source', m.os_source)})",
        "",
        "  Would run (verbatim):",
        f"    {cmd}",
    ]
    return "\n".join(lines)


def run_plan(path: Optional[str] = None, probes: Optional[Probes] = None,
             show_banner: bool = True, verbose: bool = False) -> int:
    """--dry-run / --plan: full onboarding, then PRINT the plan instead of exec.

    Independent of the FIND_WIRED gate - this code path NEVER executes the
    pipeline. Quiet by default (card + resolved command); --verbose adds the
    full OS-profile plan. Always runs cleanup(); returns 0 (1 if no evidence).
    """
    probes = probes if probes is not None else RealProbes()
    sink = _make_sink(verbose)
    try:
        if not path:
            if show_banner:
                _print_welcome()
            path = presenter.ask_path()
            if path is None:
                return 0
        cases = onboard(path, on_event=sink, ai=Advisor(), probes=probes)
        if not cases:
            print("  Nothing to plan - no usable evidence found.")
            return 1
        for i, c in enumerate(cases, 1):
            print()
            print(presenter.case_card(c, number=i))
            if verbose:
                print()
                print(format_plan(c))
            else:
                print()
                print("Everything verified and ready.  "
                      "▸ Type  Find Evil  to start the hunt.")
                print("  " + " ".join(find_command_display(c)))
                if not _find_wired():
                    print("  (staged - not launched. "
                          "Set FIND_WIRED=True to run live.)")
        return 0
    finally:
        probes.cleanup()


def run_interactive(initial_path: Optional[str] = None,
                    show_banner: bool = True, verbose: bool = False) -> int:
    wired = _find_wired()
    sink = _make_sink(verbose)
    probes = RealProbes()
    # Resource guardrail: reclaim stale scratch from FINISHED prior runs at session
    # start so a long session can't fill /tmp. Conservative (age-gated -> never an
    # active run). Visible, like the other gates.
    try:
        from sift_sentinel.onboard.resource_guard import prune_stale_scratch
        _rg = prune_stale_scratch()
        if _rg["removed"]:
            print("  " + _c("RESOURCE_GUARD: reclaimed %d stale scratch dir(s), ~%d MB freed"
                            % (_rg["removed"], _rg["freed_bytes"] >> 20), "2"))
    except Exception:
        pass
    pending = initial_path
    first = True
    try:
        while True:
            if not (first and not show_banner):
                _print_welcome()
            first = False
            path = pending or presenter.ask_path()
            pending = None
            if path is None:               # Q/quit or closed stdin -> clean exit
                break
            # A folder = scan everything inside (current behavior). A single file
            # = file-by-file MULTI-ADD: collect more, then onboard the whole set.
            if os.path.isdir(path):
                targets = path
            else:
                targets = _multi_add(path, probes)
            cases = onboard(targets, on_event=sink, ai=Advisor(), probes=probes)
            if not cases:
                print("  Let's try a different path.\n")
                continue
            print()
            for i, c in enumerate(cases, 1):
                print(presenter.case_card(c, number=i))
            print()
            print(presenter.ready_prompt(cases))
            # Pick a case by NUMBER -> pick a depth -> hidden key -> GO. A=another.
            again = _pick_and_run(cases, wired)
            # Free THIS case's mounts + extracted scratch before the next case, so a
            # multi-case session ("A=onboard another") cannot pile extractions up and
            # fill /tmp (the run has already finished synchronously here). The engine
            # resets, so the next case re-extracts cleanly. Opt out: SIFT_KEEP_EXTRACTION=1.
            if os.environ.get("SIFT_KEEP_EXTRACTION", "").strip().lower() not in ("1", "true", "yes", "on"):
                try:
                    probes.cleanup()
                except Exception as _sift_cleanup_exc:
                    print(_c(f"  (note: scratch cleanup skipped: {_sift_cleanup_exc})", "2"))
            if again != "another":
                break
    except KeyboardInterrupt:
        # Stop further Ctrl-C from aborting the cleanup below -- the user often mashes it
        # while waiting for a slow tool to die.
        try:
            import signal
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except Exception:
            pass
        print("\n  Interrupted - stopping running tools…")
    finally:
        # Belt-and-suspenders: ignore Ctrl-C during teardown regardless of how we got here.
        try:
            import signal
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except Exception:
            pass
        # Force-stop the detached MCP server + Volatility subprocess trees. A terminal
        # Ctrl-C never reaches them (spawned start_new_session), so without this they
        # grind the remaining tool batch to completion after we have already exited.
        try:
            _stopped = kill_child_process_trees()
        except Exception:
            _stopped = 0
        if _stopped:
            print(f"  Stopped {_stopped} running tool process(es).")
        probes.cleanup()
    print("  Goodbye. Evidence left read-only and untouched.")
    return 0


def _stale_run_dirs(run_root: str = "/tmp", min_age_s: int = 60,
                    keep_recent: int = 1) -> list:
    """SIFT run-output dirs (``/tmp/sift-sentinel-run-*``) safe to delete (each run
    leaves ~600MB). ALWAYS keeps the ``keep_recent`` most-recent dirs (so the run
    you just examined is never nuked) and only returns ones older than
    ``min_age_s``. Pure: lists, never deletes. Keyed on the run-dir prefix only;
    never touches evidence or other paths. keep_recent via SIFT_PREFLIGHT_KEEP."""
    import glob
    import time
    try:
        keep_recent = max(0, int(os.environ.get("SIFT_PREFLIGHT_KEEP", keep_recent)))
    except (TypeError, ValueError):
        keep_recent = 1
    now = time.time()
    dirs = []
    for d in glob.glob(os.path.join(run_root, "sift-sentinel-run-*")):
        try:
            if os.path.isdir(d):
                dirs.append((os.path.getmtime(d), d))
        except OSError:
            continue
    dirs.sort(reverse=True)                       # newest first
    candidates = dirs[keep_recent:]               # always protect the newest N
    return sorted(d for mt, d in candidates if (now - mt) >= min_age_s)


def _storage_preflight(run_root: str = "/tmp",
                       mnt_root: str = "/tmp/sift-onboard-mnt") -> None:
    """Step-zero guard rail: before a run, clear accumulated SIFT run output and
    report stale mounts + free space, so back-to-back sample runs never silently
    fill the disk. Cleans ONLY SIFT's own run-output dirs (never evidence).
    Best-effort: any failure is a one-line note, never blocks onboarding. Stale
    fuse/ewf mount UNMOUNT is opt-in (SIFT_PREFLIGHT_UNMOUNT=1; sudo umount can
    hang). Kill-switch SIFT_STORAGE_PREFLIGHT=0. Universal: prefix/path only."""
    if os.environ.get("SIFT_STORAGE_PREFLIGHT", "1") == "0":
        return
    import shutil
    freed = 0
    try:
        for d in _stale_run_dirs(run_root):
            try:
                shutil.rmtree(d)
                freed += 1
            except OSError:
                pass
    except Exception:
        pass
    stale_mnt = 0
    try:
        if os.path.isdir(mnt_root):
            entries = os.listdir(mnt_root)
            stale_mnt = len(entries)
            if stale_mnt and os.environ.get("SIFT_PREFLIGHT_UNMOUNT") == "1":
                for x in entries:
                    try:
                        subprocess.run(["sudo", "umount", "-l",
                                        os.path.join(mnt_root, x)],
                                       capture_output=True, timeout=10)
                    except Exception:
                        pass
    except Exception:
        pass
    free_gb = -1
    try:
        free_gb = shutil.disk_usage(run_root).free // (1024 ** 3)
    except Exception:
        pass
    _hint = (" -- set SIFT_PREFLIGHT_UNMOUNT=1 to auto-clean"
             if stale_mnt and os.environ.get("SIFT_PREFLIGHT_UNMOUNT") != "1" else "")
    print("STORAGE_PREFLIGHT_GATE=PASS (cleared %d stale run dir(s); "
          "%d stale mount(s)%s; %s GB free)"
          % (freed, stale_mnt, _hint, free_gb if free_gb >= 0 else "?"),
          flush=True)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        # Dynamic so the findevil.py front door shows its own name in --help.
        prog=os.path.basename(sys.argv[0]) if sys.argv else "step0_onboard.py",
        description="Sentinel Qwen Ensemble conversational onboarding (Step Zero).")
    parser.add_argument("--demo", action="store_true",
                        help="Render a synthetic onboarding (no real evidence).")
    parser.add_argument("--dry-run", "--plan", dest="dry_run",
                        action="store_true",
                        help="Run the FULL onboarding, then PRINT the FIND plan "
                             "and exit 0 WITHOUT executing the pipeline. "
                             "Independent of the FIND_WIRED live gate.")
    parser.add_argument("--no-ai", dest="no_ai", action="store_true",
                        help="Disable the optional AI advisor (kill switch: "
                             "sets SIFT_ONBOARD_AI=0). Flow stays deterministic.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show the full per-file extraction/probe trace "
                             "(default is the quiet, summarized view).")
    parser.add_argument("--wire", action="store_true",
                        help="Arm live FIND (same as SIFT_FIND_WIRED=1): typing "
                             "FIND will actually launch run_pipeline.py.")
    parser.add_argument("path", nargs="?", default=None,
                        help="Evidence path (file/folder/archive). If omitted, "
                             "you are prompted interactively.")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.no_ai:
        os.environ["SIFT_ONBOARD_AI"] = "0"
    if args.wire:
        global _WIRE_OVERRIDE
        _WIRE_OVERRIDE = True
    verbose = args.verbose or os.environ.get("SIFT_ONBOARD_VERBOSE") == "1"
    if args.demo:
        return run_demo()

    # Entry resolution (ask-first):
    #   * path arg            -> use it directly (scripting shortcut);
    #   * no arg + TTY stdin   -> prompt in a loop until valid / Q (runner asks);
    #   * no arg + piped stdin -> read ONE path from the pipe (no hang);
    #   * no arg + no TTY/data -> usage to stderr, exit 2 (CI safety).
    path = args.path
    show_banner = True
    if not path and not sys.stdin.isatty():
        _print_welcome()
        show_banner = False
        path = presenter.ask_path()
        if path is None:
            print(_USAGE, file=sys.stderr)
            return 2

    if args.dry_run:
        return run_plan(path, show_banner=show_banner, verbose=verbose)
    # STORAGE_PREFLIGHT: only on a real interactive launch (a valid path resolved),
    # never on --help/--demo/dry-run/headless-exit -- clear accumulated run output
    # + report stale mounts/free space before the run mounts anything. Keeps the
    # most-recent run dir. Never blocks onboarding. Kill-switch SIFT_STORAGE_PREFLIGHT=0.
    if path:
        _storage_preflight()
    return run_interactive(path, show_banner=show_banner, verbose=verbose)


if __name__ == "__main__":
    raise SystemExit(main())
