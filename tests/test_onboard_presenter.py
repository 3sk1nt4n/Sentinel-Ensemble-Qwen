"""Tests for the SIFT-Sentinel conversational onboarding layer.

Covers the ZEROFAKE-UI guarantee (a FAIL event can never render a success
line), engine/presenter separation (the engine emits structured PhaseEvents;
the presenter only renders them), non-TTY degradation, ask_path hygiene, and
the honest mount-fallback narration (FAIL->WARN->OK without premature success).

All tests run with the AI advisor disabled and without sudo/real evidence:
the engine's I/O is injected via a FakeProbes seam.
"""
from __future__ import annotations

import io
import os

import pytest

from sift_sentinel.onboard.engine import (
    CaseManifest,
    InvalidPhaseEvent,
    MOUNT_LADDER,
    Phase,
    PhaseEvent,
    Probes,
    Status,
    detect_os,
    onboard,
)
from sift_sentinel.onboard import presenter
import step0_onboard


# ── A recording subscriber: proves narration maps 1:1 to engine state ──────
class Recorder:
    def __init__(self) -> None:
        self.events: list[PhaseEvent] = []

    def __call__(self, ev: PhaseEvent) -> None:
        assert isinstance(ev, PhaseEvent)
        self.events.append(ev)

    def phases(self) -> list[str]:
        return [e.phase for e in self.events]

    def of(self, phase: str) -> list[PhaseEvent]:
        return [e for e in self.events if e.phase == phase]


# ── A scriptable I/O seam so the engine runs headless, no sudo ─────────────
class FakeProbes(Probes):
    """Deterministic stand-in for RealProbes. Keyed by os.path.basename."""

    def __init__(
        self,
        *,
        discover_items: list[str],
        archives: dict[str, str] | None = None,
        extract_children: dict[str, list[str]] | None = None,
        filesystems: set[str] | None = None,
        memories: dict[str, dict] | None = None,
        mount_results: dict[str, tuple[bool, str]] | None = None,
        health_results: dict[str, tuple[bool, list, dict]] | None = None,
    ) -> None:
        self._discover = discover_items
        self._archives = archives or {}
        self._children = extract_children or {}
        self._fs = filesystems or set()
        self._mem = memories or {}
        self._mounts = mount_results or {}
        self._health = health_results or {}
        self.cleaned = False

    def discover(self, path: str) -> list[str]:
        return list(self._discover)

    def archive_kind(self, path: str) -> str | None:
        return self._archives.get(os.path.basename(path))

    def extract(self, path: str) -> list[str]:
        return list(self._children.get(os.path.basename(path), []))

    def has_filesystem(self, path: str) -> bool:
        return os.path.basename(path) in self._fs

    def fs_facts(self, path: str) -> dict:
        return {"fstype": "NTFS", "volume": "Windows", "version": "Windows XP"}

    def disk_os(self, mount_path):
        # Disk OS now comes from the SOFTWARE hive (here: a genuinely-XP disk),
        # NOT from fsstat's misleading "Version" line.
        return "Windows XP (NT 5.1)"

    def memory_info(self, path: str) -> dict | None:
        return self._mem.get(os.path.basename(path))

    def mount(self, disk: str, method: str, mountpoint: str) -> tuple[bool, str]:
        return self._mounts.get(method, (False, "no such method"))

    def health(self, mem: str) -> tuple[bool, list, dict]:
        return self._health.get(
            os.path.basename(mem), (True, [], {"NtMajorVersion": "10"})
        )

    def cleanup(self) -> None:
        self.cleaned = True


def _single_case_probes(*, raw_ok: bool = True) -> FakeProbes:
    """One memory image + one disk image inside a ZIP archive."""
    mounts = (
        {"raw@0": (True, "")}
        if raw_ok
        else {"raw@0": (False, "truncated tail"), "dmpad": (True, "")}
    )
    return FakeProbes(
        discover_items=["/syn/Evidence.zip"],
        archives={"Evidence.zip": "ZIP"},
        extract_children={"Evidence.zip": ["/syn/memory.raw", "/syn/disk.e01"]},
        filesystems={"disk.e01"},
        memories={"memory.raw": {"NtMajorVersion": "10", "NtMinorVersion": "0",
                                 "MachineType": "34404", "KeNumberProcessors": "4"}},
        mount_results=mounts,
        health_results={"memory.raw": (True, [], {"NtMajorVersion": "10",
                                                  "KeNumberProcessors": "4"})},
    )


def _strip_ansi(text: str) -> str:
    out, i = [], 0
    while i < len(text):
        if text[i] == "\x1b" and text[i:i + 2] == "\x1b[":
            j = text.find("m", i)
            i = (j + 1) if j != -1 else i + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _render(ev: PhaseEvent) -> str:
    buf = io.StringIO()
    presenter.render_event(ev, color=False, file=buf)
    return buf.getvalue()


# ── PhaseEvent contract ────────────────────────────────────────────────────
def test_phaseevent_rejects_unknown_phase():
    with pytest.raises(InvalidPhaseEvent):
        PhaseEvent("NOPE", Status.OK)


def test_phaseevent_rejects_unknown_status():
    with pytest.raises(InvalidPhaseEvent):
        PhaseEvent(Phase.MOUNT, "FINISHED")


def test_phaseevent_data_defaults_to_dict():
    ev = PhaseEvent(Phase.READY, Status.OK, "ready")
    assert ev.data == {}


# ── ZEROFAKE-UI: a FAIL/WARN event must never render success ───────────────
SUCCESS_TOKENS = ("✓", "mounted via", "HEALTHY", " OK")


def test_fail_event_never_renders_success():
    for phase in Phase.ALL:
        line = _strip_ansi(_render(PhaseEvent(phase, Status.FAIL,
                                              "it failed", {"reason": "x"})))
        for tok in SUCCESS_TOKENS:
            assert tok not in line, f"{phase}/FAIL leaked success token {tok!r}: {line!r}"


def test_mount_fail_does_not_claim_mounted():
    line = _strip_ansi(_render(
        PhaseEvent(Phase.MOUNT, Status.FAIL, "all methods exhausted",
                   {"method_tried": "dmpad", "reason": "bad superblock"})))
    assert "mounted via" not in line
    assert "bad superblock" in line


def test_health_fail_does_not_claim_healthy():
    line = _strip_ansi(_render(
        PhaseEvent(Phase.HEALTH, Status.FAIL, "image unusable",
                   {"reasons": ["missing_or_empty"]})))
    assert "HEALTHY" not in line
    assert "missing_or_empty" in line


def test_render_maps_real_values_only():
    line = _strip_ansi(_render(
        PhaseEvent(Phase.CLASSIFY, Status.OK, "",
                   {"name": "memory.raw", "role": "MEMORY", "probe": "vol3"})))
    assert "memory.raw" in line and "MEMORY" in line and "vol3" in line


def test_mount_warn_narrates_fallback():
    line = _strip_ansi(_render(
        PhaseEvent(Phase.MOUNT, Status.WARN, "",
                   {"method_tried": "raw@0", "reason": "truncated tail",
                    "next": "dmpad"})))
    assert "raw@0" in line and "truncated tail" in line and "dmpad" in line
    assert "✓" not in line


# ── Non-TTY / NO_COLOR degradation ─────────────────────────────────────────
def test_non_tty_emits_no_ansi():
    buf = io.StringIO()  # StringIO.isatty() is False
    presenter.render_event(
        PhaseEvent(Phase.OS_DETECT, Status.OK, "",
                   {"os": "Windows 10 / Server 2016+ (NT 10.0)",
                    "source": "memory", "agree": False}),
        file=buf,
    )
    assert "\x1b[" not in buf.getvalue()


def test_banner_no_ansi_when_color_off():
    assert "\x1b[" not in presenter.banner(color=False)


# ── ask_path hygiene: quotes, ~ expansion, env vars, re-ask, quit ──────────
def test_ask_path_strips_quotes_and_expands(tmp_path):
    target = str(tmp_path)
    answers = iter([f'"{target}"'])
    got = presenter.ask_path(input_fn=lambda _p: next(answers),
                             exists_fn=os.path.exists)
    assert got == target


def test_ask_path_reasks_on_missing_then_accepts(tmp_path):
    missing = str(tmp_path / "nope")
    good = str(tmp_path)
    answers = iter([missing, good])
    prompts: list[str] = []

    def fake_input(p):
        prompts.append(p)
        return next(answers)

    got = presenter.ask_path(input_fn=fake_input, exists_fn=os.path.exists)
    assert got == good
    assert len(prompts) == 2  # it re-asked


def test_ask_path_expands_tilde(tmp_path):
    answers = iter(["~"])
    got = presenter.ask_path(input_fn=lambda _p: next(answers),
                             exists_fn=lambda p: p == os.path.expanduser("~"))
    assert got == os.path.expanduser("~")


def test_ask_path_quit_returns_none():
    got = presenter.ask_path(input_fn=lambda _p: "Q", exists_fn=os.path.exists)
    assert got is None


# ── Engine: full headless sequence, AI disabled ────────────────────────────
def test_engine_emits_full_phase_sequence():
    rec = Recorder()
    cases = onboard("/syn/Evidence.zip", on_event=rec,
                    ai=None, probes=_single_case_probes())
    seq = rec.phases()
    # The engine must visit each milestone, in order.
    for phase in (Phase.DISCOVER, Phase.EXTRACT, Phase.CLASSIFY,
                  Phase.OS_DETECT, Phase.MOUNT, Phase.HEALTH,
                  Phase.MANIFEST, Phase.READY):
        assert phase in seq, f"missing {phase}"
    assert seq.index(Phase.CLASSIFY) < seq.index(Phase.MANIFEST)
    assert seq.index(Phase.READY) == len(seq) - 1
    assert len(cases) == 1


def test_engine_manifest_fields():
    cases = onboard("/syn/Evidence.zip", on_event=lambda e: None,
                    ai=None, probes=_single_case_probes())
    c = cases[0]
    assert isinstance(c, CaseManifest)
    assert "NT 10.0" in c.os
    assert c.os_source == "memory"
    assert os.path.basename(c.memory_path) == "memory.raw"
    assert c.memory_health == "HEALTHY"
    assert os.path.basename(c.disk_path) == "disk.e01"
    assert c.disk_mounted is True
    assert c.mount_method == "raw@0"


def test_engine_classifies_both_roles():
    rec = Recorder()
    onboard("/syn/Evidence.zip", on_event=rec, ai=None,
            probes=_single_case_probes())
    roles = {e.data.get("role") for e in rec.of(Phase.CLASSIFY)
             if e.status == Status.OK}
    assert roles == {"MEMORY", "DISK"}


# ── Engine: honest FAIL->WARN->OK mount fallback (truncated tail) ──────────
def test_engine_mount_fallback_is_honest():
    rec = Recorder()
    onboard("/syn/Evidence.zip", on_event=rec, ai=None,
            probes=_single_case_probes(raw_ok=False))
    mount_events = rec.of(Phase.MOUNT)
    statuses = [e.status for e in mount_events]
    # raw@0 must WARN before dmpad OK -- never an OK before the WARN.
    assert Status.WARN in statuses
    assert Status.OK in statuses
    assert statuses.index(Status.WARN) < statuses.index(Status.OK)
    warn = next(e for e in mount_events if e.status == Status.WARN)
    assert warn.data["method_tried"] == "raw@0"
    assert warn.data["next"] == "ntfs_offsets"   # ladder: raw@0 -> ntfs_offsets -> dmpad
    ok = next(e for e in mount_events if e.status == Status.OK)
    assert ok.data["method"] == "dmpad"          # the fake only mounts via dmpad here


def test_engine_emits_extract_for_archive():
    # Narration is collapsed (BUG: no per-child spam): one "extracting…" substep
    # plus an OK line carrying the child COUNT, not every child name.
    rec = Recorder()
    onboard("/syn/Evidence.zip", on_event=rec, ai=None,
            probes=_single_case_probes())
    extract = rec.of(Phase.EXTRACT)
    assert any(e.status == Status.SUBSTEP for e in extract)   # "X — ZIP → extracting…"
    ok = [e for e in extract if e.status == Status.OK]
    assert ok and ok[0].data.get("count", 0) >= 1             # collapsed count


def test_mount_ladder_has_dmpad_fallback():
    assert MOUNT_LADDER[0] == "raw@0"
    assert "dmpad" in MOUNT_LADDER


# ── Presenter: case card and FIND command construction ─────────────────────
def test_case_card_contains_real_facts():
    cases = onboard("/syn/Evidence.zip", on_event=lambda e: None,
                    ai=None, probes=_single_case_probes())
    card = _strip_ansi(presenter.case_card(cases[0], color=False))
    assert "NT 10.0" in card
    assert "HEALTHY" in card
    assert "memory.raw" in card
    assert "disk.e01" in card


def test_build_find_command_includes_disk_and_mount():
    m = CaseManifest(
        case_id="acme", os="Windows 10 (NT 10.0)", os_source="memory",
        memory_path="/syn/memory.raw", memory_health="HEALTHY",
        memory_health_facts={}, disk_path="/syn/disk.e01", disk_mounted=True,
        mount_method="raw@0", mount_path="/mnt/syn", reference_docs=[])
    cmd = step0_onboard.build_find_command(m)
    assert any(c.endswith("run_pipeline.py") for c in cmd)
    assert "--live" in cmd and "--inv2-ensemble" in cmd
    assert "--image" in cmd and "/syn/memory.raw" in cmd
    assert "--disk" in cmd and "/syn/disk.e01" in cmd
    assert "--disk-mount" in cmd and "/mnt/syn" in cmd


def test_build_find_command_omits_disk_when_memory_only():
    m = CaseManifest(
        case_id="memonly", os="Windows 10 (NT 10.0)", os_source="memory",
        memory_path="/syn/memory.raw", memory_health="HEALTHY",
        memory_health_facts={}, disk_path=None, disk_mounted=False,
        mount_method=None, mount_path=None, reference_docs=[])
    cmd = step0_onboard.build_find_command(m)
    assert "--image" in cmd and "/syn/memory.raw" in cmd
    assert "--disk" not in cmd
    assert "--disk-mount" not in cmd


def test_find_exec_is_not_wired_live():
    # HALT GATE: the FIND->run_pipeline exec must remain staged, not live.
    assert step0_onboard.FIND_WIRED is False


# ── detect_os: honest agreement (mismatch must NOT claim agreement) ────────
def test_detect_os_mismatch_does_not_claim_agreement():
    # Synthetic: disk family/version differs from memory family/version.
    prof = detect_os(memory_os="Windows 10 / Server 2016+ (NT 10.0)",
                     disk_os="Windows XP")
    assert prof["agree"] is False
    assert prof["memory"] == "Windows 10 / Server 2016+ (NT 10.0)"
    assert prof["disk"] == "Windows XP"
    # Memory is authoritative -> chosen OS + source come from memory, NOT a
    # fabricated "disk+memory" agreement.
    assert prof["os"] == "Windows 10 / Server 2016+ (NT 10.0)"
    assert prof["source"] == "memory"


def test_detect_os_agreement_same_family():
    prof = detect_os(memory_os="Windows 10 / Server 2016+ (NT 10.0)",
                     disk_os="Windows 10")
    assert prof["agree"] is True
    assert prof["source"] == "disk+memory"


def test_detect_os_agreement_same_nt_version():
    prof = detect_os(memory_os="Windows (NT 6.1)", disk_os="Windows 7 (NT 6.1)")
    assert prof["agree"] is True


def test_detect_os_memory_only():
    prof = detect_os(memory_os="Windows (NT 10.0)", disk_os=None)
    assert prof["source"] == "memory"
    assert prof["agree"] is False


def test_detect_os_none_signals():
    prof = detect_os(None, None)
    assert prof["os"] == "unknown"
    assert prof["source"] == "none"
    assert prof["agree"] is False


def test_engine_os_event_carries_both_sources():
    rec = Recorder()
    cases = onboard("/syn/Evidence.zip", on_event=rec, ai=None,
                    probes=_single_case_probes())
    os_ev = rec.of(Phase.OS_DETECT)[0]
    assert os_ev.data["memory"] is not None
    # Disk OS now comes from the SOFTWARE hive (here a genuinely-XP disk),
    # not fsstat's "Version" line — and it disagrees with the NT 10.0 memory.
    assert os_ev.data["disk"] == "Windows XP (NT 5.1)"
    assert os_ev.data["agree"] is False
    assert cases[0].os_profile["agree"] is False
    assert cases[0].os_profile["disk"] == "Windows XP (NT 5.1)"


# ── --dry-run / --plan: prints plan, never execs, independent of FIND_WIRED ─
def test_dry_run_plan_verbose_prints_full_plan(capsys):
    probes = _single_case_probes()
    rc = step0_onboard.run_plan(path="/syn/Evidence.zip", probes=probes,
                                verbose=True)
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY RUN" in out
    assert "agree   : no" in out                      # honest mismatch line
    assert "python3 run_pipeline.py --live --inv2-ensemble" in out
    assert "--image" in out and "memory.raw" in out
    assert "--disk" in out and "disk.e01" in out
    assert "--disk-mount" in out
    assert probes.cleaned is True                     # cleanup() always runs


def test_dry_run_quiet_is_clean(capsys):
    # Default (quiet) view: resolved command + staged note, NO verbose plan
    # block, NO document parts, NO advisor spam.
    probes = _single_case_probes()
    rc = step0_onboard.run_plan(path="/syn/Evidence.zip", probes=probes,
                                verbose=False)
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY RUN" not in out                       # verbose-only block hidden
    assert ".xml" not in out
    assert "asking the AI advisor" not in out
    assert "python3 run_pipeline.py --live --inv2-ensemble" in out
    assert "(staged — not launched" in out
    assert probes.cleaned is True


def test_dry_run_independent_of_find_wired(monkeypatch):
    # Even if the live gate were ON, dry-run must never spawn the pipeline.
    monkeypatch.setattr(step0_onboard, "FIND_WIRED", True)

    def boom(*a, **k):
        raise AssertionError("run_plan must not execute the pipeline")

    monkeypatch.setattr(step0_onboard.subprocess, "run", boom)
    rc = step0_onboard.run_plan(path="/syn/Evidence.zip",
                                probes=_single_case_probes())
    assert rc == 0


def test_find_command_display_is_verbatim_form():
    m = CaseManifest(
        case_id="acme", os="Windows 10 (NT 10.0)", os_source="memory",
        memory_path="/syn/memory.raw", memory_health="HEALTHY",
        memory_health_facts={}, disk_path="/syn/disk.e01", disk_mounted=True,
        mount_method="raw@0", mount_path="/mnt/syn", reference_docs=[])
    disp = step0_onboard.find_command_display(m)
    assert disp[0] == "python3"
    assert disp[1] == "run_pipeline.py"
    assert disp[2:5] == ["--live", "--inv2-ensemble", "--image"]
