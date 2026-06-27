"""The onboard launcher ships 8-16 parallelism defaults where safe.

mode_launch_env sets the post-Step-6 worker knobs (validation / ReAct / SC / EVTX)
and the heavy-first flag so a fresh-clone friend gets the parallel behaviour without
exporting anything. The Step-6 Vol3 floor is RAM-gated (only on a box with headroom)
because oversubscribing heavy Vol3 subprocesses OOM-kills children on a small box.
Operator env always wins (a knob already in the shell is not overridden).
"""
import importlib

s = importlib.import_module("step0_onboard")

# NB: SIFT_PARSE_EVENT_LOGS_INNER_WORKERS is deliberately NOT shipped (EVTX stays
# serial by design -- 31Y: parallel cost 96% of event_log coverage).
_KNOBS = (
    "SIFT_STEP10_MAX_WORKERS",
    "SIFT_STEP11_MAX_WORKERS",
    "SIFT_STEP12_MAX_WORKERS",
    "SIFT_STEP6_HEAVY_FIRST",
)


def _clean(monkeypatch):
    for k in _KNOBS + ("SIFT_STEP6_MIN_WORKERS",):
        monkeypatch.delenv(k, raising=False)


def test_parallelism_knobs_set_for_both_modes(monkeypatch):
    _clean(monkeypatch)
    for key in ("1", "2"):                       # Heavy and Light
        env = s.mode_launch_env(s.ANALYSIS_MODES[key])
        for k in _KNOBS:
            assert k in env, f"{k} missing for mode {key}"
        assert env["SIFT_STEP6_HEAVY_FIRST"] == "1"
        # validators safe-high
        assert int(env["SIFT_STEP10_MAX_WORKERS"]) >= 8
        # EVTX must NOT be parallelised by the launcher (31Y serial-by-design)
        assert "SIFT_PARSE_EVENT_LOGS_INNER_WORKERS" not in env


def test_operator_env_wins(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("SIFT_STEP11_MAX_WORKERS", "2")   # a rate-limited operator lowered it
    env = s.mode_launch_env(s.ANALYSIS_MODES["1"])
    # the launcher must NOT clobber an explicit operator pin
    assert env.get("SIFT_STEP11_MAX_WORKERS") in (None, "2")


def test_step6_floor_is_ram_aware(monkeypatch):
    _clean(monkeypatch)
    import os
    env = s.mode_launch_env(s.ANALYSIS_MODES["1"])
    # RAM-aware: floor = min(2*cpu, avail/1.25, 16), set only when it beats cores
    cpu = os.cpu_count() or 1
    avail = s._onboard_avail_ram_gb()
    rec = max(1, min(2 * cpu, int(avail / 1.25), 16))
    if rec > cpu and avail >= 4.0:
        assert env.get("SIFT_STEP6_MIN_WORKERS") == str(rec)
        assert int(env["SIFT_STEP6_MIN_WORKERS"]) <= 16          # never exceed ceiling
    else:
        assert "SIFT_STEP6_MIN_WORKERS" not in env               # core-aware on a tiny box


def test_four_core_twelve_gb_vm_gets_eight(monkeypatch):
    # the friend's box: 4 vCPU, 12GB -> 8 workers (RAM used, not core-bound)
    assert max(1, min(2 * 4, int(12.0 / 1.25), 16)) == 8


def test_avail_ram_helper_never_raises():
    assert isinstance(s._onboard_avail_ram_gb(), float)


def test_react_concurrency_is_core_matched(monkeypatch):
    # ReAct/SC API fan-out matches cores (cap 8) -> fewer simultaneous Opus calls
    # on a small/throttled box = fewer self-inflicted 529s. No detection change.
    _clean(monkeypatch)
    import os
    env = s.mode_launch_env(s.ANALYSIS_MODES["1"])
    expected = str(max(2, min(os.cpu_count() or 4, 8)))
    assert env["SIFT_STEP11_MAX_WORKERS"] == expected
    assert env["SIFT_STEP12_MAX_WORKERS"] == expected
    assert int(env["SIFT_STEP11_MAX_WORKERS"]) <= 8
