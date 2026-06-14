"""Tests for the optional AI advisor — the off-critical-path escape hatch.

Guarantees proven here:
  * no key  -> available() is False instantly, with NO network call; a normal
    onboard run is fully deterministic and manifest.ai_consultations == [].
  * kill switch SIFT_ONBOARD_AI=0 -> available() False even with a key.
  * verify-before-act: a suggestion that FAILS its verifier is logged
    verified:False, never acted on, and never narrated as success; a
    suggestion that PASSES its verifier is acted on and logged verified:True.

advise() is never invoked against the real API: the no-key/kill-switch tests
short-circuit before any network call, and the verify tests inject a fake ai.
"""
from __future__ import annotations

import io

import pytest

from sift_sentinel.onboard.ai_advisor import Advisor
from sift_sentinel.onboard import presenter
from sift_sentinel.onboard.engine import (
    Phase,
    PhaseEvent,
    Probes,
    Status,
    consult_and_verify,
    onboard,
)


# ── Recorders / fakes ──────────────────────────────────────────────────────
class Recorder:
    def __init__(self):
        self.events: list[PhaseEvent] = []

    def __call__(self, ev: PhaseEvent):
        self.events.append(ev)

    def of(self, phase):
        return [e for e in self.events if e.phase == phase]

    def index_of(self, phase, status):
        for i, e in enumerate(self.events):
            if e.phase == phase and e.status == status:
                return i
        return -1


class FakeAdvisor:
    def __init__(self, suggestion="insufficient_evidence",
                 confidence=0.6, available=True):
        self._s, self._c, self._a = suggestion, confidence, available
        self.calls = []

    def available(self):
        return self._a

    def advise(self, question, evidence, choices=None, timeout=30):
        self.calls.append((question, evidence, choices))
        return {"suggestion": self._s, "rationale": "test", "confidence": self._c}


class FakeProbes(Probes):
    """One memory + one disk inside a ZIP; mount results are scriptable so the
    ladder can be made to exhaust."""

    def __init__(self, mount_results=None):
        self._mounts = mount_results or {}
        self.cleaned = False

    def discover(self, path):
        return ["/syn/Evidence.zip"]

    def archive_kind(self, path):
        return "ZIP" if path.endswith(".zip") else None

    def extract(self, path):
        return ["/syn/memory.raw", "/syn/disk.e01"]

    def has_filesystem(self, path):
        return path.endswith(".e01")

    def fs_facts(self, path):
        return {"fstype": "NTFS", "volume": "Windows", "version": "Windows XP"}

    def memory_info(self, path):
        if path.endswith(".raw"):
            return {"NtMajorVersion": "10", "NtMinorVersion": "0",
                    "KeNumberProcessors": "4"}
        return None

    def mount(self, disk, method, mountpoint):
        return self._mounts.get(method, (False, "no such method"))

    def health(self, mem):
        return True, [], {"KeNumberProcessors": "4"}

    def cleanup(self):
        self.cleaned = True


def _no_network(*_a, **_k):
    raise AssertionError("network call attempted when it must not be")


# ── available(): fail-closed, fast, no network without a key ───────────────
def test_no_key_available_is_false_and_no_network(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SIFT_ONBOARD_AI", raising=False)
    monkeypatch.setattr(Advisor, "_post", staticmethod(_no_network))
    a = Advisor()
    assert a.available() is False        # returns instantly; _post never called


def test_kill_switch_disables_even_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-used")
    monkeypatch.setenv("SIFT_ONBOARD_AI", "0")
    monkeypatch.setattr(Advisor, "_post", staticmethod(_no_network))
    a = Advisor()
    assert a.available() is False


# ── off the critical path: deterministic run logs zero consultations ───────
def test_no_key_run_is_deterministic_consultations_empty(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SIFT_ONBOARD_AI", raising=False)
    probes = FakeProbes(mount_results={"raw@0": (True, "")})
    cases = onboard("/syn/Evidence.zip", on_event=lambda e: None,
                    ai=Advisor(), probes=probes)
    assert cases[0].disk_mounted is True            # deterministic success
    assert cases[0].ai_consultations == []          # advisor never fired


# ── verify-before-act: PASS path ──────────────────────────────────────────
def test_mount_exhaustion_ai_suggestion_verified():
    rec = Recorder()
    probes = FakeProbes(mount_results={
        "raw@0": (False, "no NTFS at 0"), "dmpad": (False, "pad failed"),
        "try_offset:65536": (True, ""),  # the AI-suggested method works
    })
    ai = FakeAdvisor(suggestion="try_offset:65536", confidence=0.8)
    cases = onboard("/syn/Evidence.zip", on_event=rec, ai=ai, probes=probes)
    m = cases[0]
    assert m.disk_mounted is True
    assert m.mount_method == "try_offset:65536"
    assert len(m.ai_consultations) == 1
    c = m.ai_consultations[0]
    assert c["phase"] == "MOUNT"
    assert c["verified"] is True
    assert c["action_taken"] == "try_offset:65536"
    # Narration order: the verified MOUNT/OK only after the ADVISE/OK.
    assert rec.index_of(Phase.ADVISE, Status.OK) != -1
    assert rec.index_of(Phase.ADVISE, Status.OK) < rec.index_of(Phase.MOUNT, Status.OK)


# ── verify-before-act: FAIL path (no fake success) ─────────────────────────
def test_mount_exhaustion_ai_suggestion_unverified():
    rec = Recorder()
    probes = FakeProbes(mount_results={
        "raw@0": (False, "no NTFS at 0"), "dmpad": (False, "pad failed"),
    })  # no method (incl. the AI's) succeeds
    ai = FakeAdvisor(suggestion="apfs-fuse", confidence=0.5)
    cases = onboard("/syn/Evidence.zip", on_event=rec, ai=ai, probes=probes)
    m = cases[0]
    assert m.disk_mounted is False
    assert m.mount_method is None
    assert len(m.ai_consultations) == 1
    c = m.ai_consultations[0]
    assert c["verified"] is False
    assert c["action_taken"] is None
    # No fabricated success anywhere.
    assert rec.index_of(Phase.ADVISE, Status.OK) == -1
    assert rec.index_of(Phase.MOUNT, Status.OK) == -1
    assert rec.index_of(Phase.ADVISE, Status.FAIL) != -1
    # And the rendered FAIL line carries no success token.
    buf = io.StringIO()
    fail_ev = next(e for e in rec.of(Phase.ADVISE) if e.status == Status.FAIL)
    presenter.render_event(fail_ev, color=False, file=buf)
    out = buf.getvalue()
    assert "✓" not in out and "mounted via" not in out and "verified, applying" not in out


def test_insufficient_evidence_is_not_acted_on():
    rec = Recorder()
    probes = FakeProbes(mount_results={"raw@0": (False, "x"), "dmpad": (False, "x")})
    ai = FakeAdvisor(suggestion="insufficient_evidence")
    cases = onboard("/syn/Evidence.zip", on_event=rec, ai=ai, probes=probes)
    m = cases[0]
    assert m.disk_mounted is False
    assert len(m.ai_consultations) == 1
    assert m.ai_consultations[0]["verified"] is False
    assert rec.index_of(Phase.ADVISE, Status.OK) == -1


# ── consult_and_verify unit behavior ───────────────────────────────────────
def test_consult_and_verify_pass_records_verified():
    cons = []
    res = consult_and_verify(FakeAdvisor("X"), cons, "MOUNT", "q?", {}, ["X"],
                             lambda s: "MOUNTED" if s == "X" else None)
    assert res == "MOUNTED"
    assert cons[0]["verified"] is True and cons[0]["action_taken"] == "X"


def test_consult_and_verify_fail_records_unverified():
    cons = []
    res = consult_and_verify(FakeAdvisor("X"), cons, "MOUNT", "q?", {}, ["X"],
                             lambda s: None)
    assert res is None
    assert cons[0]["verified"] is False and cons[0]["action_taken"] is None


def test_consult_and_verify_unavailable_logs_nothing():
    cons = []
    res = consult_and_verify(FakeAdvisor("X", available=False), cons, "MOUNT",
                             "q?", {}, None, lambda s: "Y")
    assert res is None
    assert cons == []          # never consulted -> no audit record


def test_consult_and_verify_none_ai():
    cons = []
    res = consult_and_verify(None, cons, "MOUNT", "q?", {}, None, lambda s: "Y")
    assert res is None and cons == []
