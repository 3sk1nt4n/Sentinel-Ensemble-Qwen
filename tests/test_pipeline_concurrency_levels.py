"""Worker pools are env-configurable 8-16 at every level, defaults preserved.

The user wanted 8-16 parallel workers "at all levels". Safe answer (per the
adversarial OOM/timeout analysis): Step-6 Vol3 stays core-aware with an OPT-IN
floor (oversubscribing heavy Vol3 subprocesses OOMs a low-RAM box); the post-Step-6
pools (validation/ReAct/SC) get env knobs with their current default preserved.
"""
import importlib

import pytest

coord = importlib.import_module("sift_sentinel.coordinator")


# --- Step 6 floor (opt-in; unset MUST stay pure core-aware so the contract test holds) ---

def test_step6_floor_unset_is_pure_core_aware(monkeypatch):
    monkeypatch.delenv("SIFT_STEP6_MIN_WORKERS", raising=False)
    monkeypatch.delenv("SIFT_STEP6_MAX_WORKERS", raising=False)
    import os
    expected = max(1, min(int(os.cpu_count() or 1), 16))
    assert coord._step6_default_max_workers() == expected


def test_step6_floor_raises_low_core_boxes(monkeypatch):
    # a floor of 8 guarantees >=8 even where cpu_count would give fewer
    monkeypatch.setenv("SIFT_STEP6_MIN_WORKERS", "8")
    monkeypatch.delenv("SIFT_STEP6_MAX_WORKERS", raising=False)
    assert coord._step6_default_max_workers() >= 8


def test_step6_floor_clamped_to_ceiling(monkeypatch):
    monkeypatch.setenv("SIFT_STEP6_MIN_WORKERS", "999")
    monkeypatch.delenv("SIFT_STEP6_MAX_WORKERS", raising=False)
    assert coord._step6_default_max_workers() <= 16


def test_step6_floor_bad_value_ignored(monkeypatch):
    monkeypatch.setenv("SIFT_STEP6_MIN_WORKERS", "nope")
    monkeypatch.delenv("SIFT_STEP6_MAX_WORKERS", raising=False)
    import os
    assert coord._step6_default_max_workers() == max(1, min(int(os.cpu_count() or 1), 16))


# --- post-Step-6 pools ---

@pytest.mark.parametrize("fn,env_name,default", [
    (lambda e: coord.step10_max_workers(env=e), "SIFT_STEP10_MAX_WORKERS", 8),
    (lambda e: coord.step11_max_workers(env=e), "SIFT_STEP11_MAX_WORKERS", 8),
])
def test_pool_default_and_override(fn, env_name, default):
    assert fn({}) == default                         # unset -> default
    assert fn({env_name: "16"}) == 16                # raise
    assert fn({env_name: "1"}) == 1                  # serialize
    assert fn({env_name: "999"}) == default          # out of range -> default
    assert fn({env_name: "bad"}) == default          # invalid -> default


def test_step12_default_mirrors_caller():
    assert coord.step12_max_workers(default=8, env={}) == 8
    assert coord.step12_max_workers(default=3, env={}) == 3       # caller's value preserved
    assert coord.step12_max_workers(default=8, env={"SIFT_STEP12_MAX_WORKERS": "16"}) == 16


# --- hollow backfill constant (light high-value tools "instead of hollow") ---

def test_hollow_backfill_is_light_rootkit_tools():
    bf = coord.HOLLOW_BACKFILL_LIGHT_TOOLS
    assert bf[0] == "vol_modscan"                    # conclusive kernel-driver detector first
    assert "vol_callbacks" in bf
    assert "vol_hollowprocesses" not in bf           # never re-add the dropped pole
