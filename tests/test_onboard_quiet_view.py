"""Quiet (default) view shows ONLY memory/disk classifications + one 'set aside'
summary — never a per-file wall of documents/plaso/UNKNOWN noise. Verbose surfaces
the detail. Generic names only.
"""
import io
import re
import pytest
from sift_sentinel.onboard.engine import onboard, Probes, Phase, PhaseEvent, Status
from sift_sentinel.onboard import presenter

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class P(Probes):
    def discover(self, p):
        return ["/e/alpha-memory.img", "/e/alpha-cdrive.E01", "/e/notes.pdf",
                "/e/plaso_proto.000001", "/e/plaso_proto.000002", "/e/triage.mans",
                "/e/case-bodyfile", "/e/srum.db"]
    def archive_kind(self, p): return None
    def has_filesystem(self, p): return p.lower().endswith(".e01")
    def fs_facts(self, p): return {"fstype": "NTFS", "volume": "", "version": ""}
    def memory_info(self, p):
        return ({"NtMajorVersion": "10", "NtMinorVersion": "0"}
                if p.lower().endswith(".img") else None)
    def mount(self, d, m, mp): return (True, "") if m == "raw@0" else (False, "x")
    def health(self, mem): return True, [], {"KeNumberProcessors": "4"}
    def disk_os(self, mp): return None
    def cleanup(self): pass


def _quiet_render(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    buf = io.StringIO()

    def sink(ev):
        if not presenter.is_verbose_only(ev):
            presenter.render_event(ev, color=False, file=buf)
    onboard("/e", on_event=sink, ai=None, probes=P())
    return _ANSI.sub("", buf.getvalue())


def test_quiet_shows_memory_and_disk(monkeypatch):
    out = _quiet_render(monkeypatch)
    assert "alpha-memory.img" in out and "MEMORY" in out
    assert "alpha-cdrive.E01" in out and "DISK" in out


def test_quiet_hides_all_noise(monkeypatch):
    out = _quiet_render(monkeypatch)
    for noise in ("plaso_proto", "notes.pdf", "triage.mans", "bodyfile",
                  "srum.db", "UNKNOWN", "could not classify",
                  "reference document"):
        assert noise not in out, noise


def test_quiet_shows_one_set_aside_summary(monkeypatch):
    out = _quiet_render(monkeypatch)
    assert out.count("set aside") == 1
    assert "not analyzed" in out


def test_verbose_only_filter_unit():
    def ev(role, status=Status.OK):
        return PhaseEvent(Phase.CLASSIFY, status, "x", {"role": role})
    # hidden in quiet:
    assert presenter.is_verbose_only(ev("DOC")) is True
    assert presenter.is_verbose_only(ev("UNKNOWN", Status.WARN)) is True
    assert presenter.is_verbose_only(ev("ARTIFACT")) is True
    # shown in quiet:
    assert presenter.is_verbose_only(ev("MEMORY")) is False
    assert presenter.is_verbose_only(ev("DISK")) is False
    assert presenter.is_verbose_only(ev("SETASIDE")) is False
