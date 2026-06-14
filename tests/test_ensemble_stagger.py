"""U2: Inv2 fan-out stagger so member 0's prompt-cache write is read by the
other members (cache reads bill 0.1x). Correctness must be unchanged: same
members, same results, only submission ordering differs. Mocked model calls
only -- never a real API.

INTENTIONAL CHANGE (2026-06-10, live-run timing review): the default is now
HEAD-START stagger -- member 0 fires, the rest follow after a short
SIFT_INV2_STAGGER_HEADSTART_S delay (cache is written at prompt INGESTION,
seconds, not at completion, ~60s). The legacy wait-for-completion mode is
preserved as SIFT_INV2_STAGGER=full; =0 stays fully parallel.
"""
from __future__ import annotations

import threading
import time

import sift_sentinel.ensemble as ens


def _stub_result(model):
    return {
        "model": model, "ok": True, "findings": [], "error": None,
        "input_tokens": 1, "output_tokens": 1, "duration_s": 0.0,
        "raw_text": "{\"findings\": []}",
    }


class _Recorder:
    def __init__(self, member0_sleep=0.05, rest_sleep=0.05):
        self.events = []
        self.lock = threading.Lock()
        self._m0 = member0_sleep
        self._rest = rest_sleep
        self._first = None

    def call(self, client, model, prompt, max_tokens):
        with self.lock:
            if self._first is None:
                self._first = model
            self.events.append(("start", model, time.monotonic()))
        time.sleep(self._m0 if model == self._first else self._rest)
        with self.lock:
            self.events.append(("end", model, time.monotonic()))
        return _stub_result(model)


def _run(monkeypatch, stagger, *, headstart=None, member0_sleep=0.05):
    rec = _Recorder(member0_sleep=member0_sleep)
    if stagger is None:
        monkeypatch.delenv("SIFT_INV2_STAGGER", raising=False)
    else:
        monkeypatch.setenv("SIFT_INV2_STAGGER", stagger)
    if headstart is None:
        monkeypatch.delenv("SIFT_INV2_STAGGER_HEADSTART_S", raising=False)
    else:
        monkeypatch.setenv("SIFT_INV2_STAGGER_HEADSTART_S", str(headstart))
    monkeypatch.setattr(ens, "_call_one_model", rec.call)
    monkeypatch.setattr(ens.anthropic, "Anthropic", lambda: object())
    out = ens.run_inv2_ensemble("synthetic prompt", max_tokens=16,
                                models=["model-a", "model-b", "model-c"])
    return rec, out


def test_default_headstart_rest_fire_before_member0_completes(monkeypatch):
    # Default = head-start: rest are delayed by the headstart, but must NOT
    # wait for member 0's completion (member 0 sleeps 0.5s; headstart 0.1s).
    rec, out = _run(monkeypatch, None, headstart=0.1, member0_sleep=0.5)
    starts = [(m, t) for kind, m, t in rec.events if kind == "start"]
    ends = {m: t for kind, m, t in rec.events if kind == "end"}
    t0 = starts[0][1]
    assert starts[0][0] == "model-a"
    for m, t in starts[1:]:
        assert t >= t0 + 0.1 - 0.02          # headstart honored
        assert t < ends["model-a"]           # NOT serialized behind member 0
    assert len(out["per_model"]) == 3


def test_stagger_1_is_headstart_too(monkeypatch):
    rec, out = _run(monkeypatch, "1", headstart=0.1, member0_sleep=0.5)
    starts = [(m, t) for kind, m, t in rec.events if kind == "start"]
    ends = {m: t for kind, m, t in rec.events if kind == "end"}
    for m, t in starts[1:]:
        assert t < ends["model-a"]
    assert len(out["per_model"]) == 3


def test_stagger_full_is_legacy_wait_for_completion(monkeypatch):
    rec, out = _run(monkeypatch, "full", member0_sleep=0.2)
    starts = [(m, t) for kind, m, t in rec.events if kind == "start"]
    ends = {m: t for kind, m, t in rec.events if kind == "end"}
    assert starts[0][0] == "model-a"
    for m, t in starts[1:]:
        assert t >= ends["model-a"]          # serialised after member 0
    assert len(out["per_model"]) == 3


def test_stagger_off_submits_all_up_front(monkeypatch):
    rec, out = _run(monkeypatch, "0")
    starts = [(m, t) for kind, m, t in rec.events if kind == "start"]
    ends = {m: t for kind, m, t in rec.events if kind == "end"}
    first_end = min(ends.values())
    assert len(starts) == 3
    assert all(t <= first_end for _, t in starts)
    assert len(out["per_model"]) == 3


def test_results_identical_shape_between_modes(monkeypatch):
    _, a = _run(monkeypatch, None, headstart=0.01)
    _, b = _run(monkeypatch, "0")
    _, c = _run(monkeypatch, "full")
    assert sorted(a["per_model"]) == sorted(b["per_model"]) == sorted(c["per_model"])
