"""Single-source guardrails on the case card: a memory-only / disk-only case shows
its SCOPE (what it can't find) and never the misleading 'agree: no'; a PAIRED OS
mismatch is flagged with ⚠. Universal: keyed on which sources are present, no case
data. All OS strings are generic NT labels.
"""
import re
from sift_sentinel.onboard.engine import CaseManifest, Phase, PhaseEvent, Status
from sift_sentinel.onboard import presenter

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _card(**kw):
    base = dict(case_id="c", os="Windows 10 / Server 2016+ (NT 10.0)",
                os_source="memory", memory_path=None, memory_health=None,
                memory_health_facts={}, disk_path=None, disk_mounted=False,
                mount_method=None, mount_path=None, reference_docs=[],
                os_profile={})
    base.update(kw)
    return _ANSI.sub("", presenter.case_card(CaseManifest(**base), color=False))


def test_memory_only_shows_scope_not_agree():
    card = _card(memory_path="/e/h-memory.raw", memory_health="HEALTHY",
                 os_profile={"memory": "Windows 10 (NT 10.0)", "source": "memory",
                             "agree": False, "os": "Windows 10 (NT 10.0)"})
    assert "memory-only" in card
    assert "no disk artifacts" in card
    assert "agree: no" not in card                # single source != disagreement


def test_disk_only_shows_scope_not_agree():
    card = _card(disk_path="/e/h-cdrive.E01", disk_mounted=True, mount_method="raw@0",
                 os_source="disk",
                 os_profile={"disk": "Windows 7 (NT 6.1)", "source": "disk",
                             "agree": False, "os": "Windows 7 (NT 6.1)"})
    assert "disk-only" in card
    assert "no memory detections" in card
    assert "agree: no" not in card


def test_paired_agree_shows_agreement():
    card = _card(memory_path="/e/h-memory.raw", memory_health="HEALTHY",
                 disk_path="/e/h-cdrive.E01", disk_mounted=True, mount_method="raw@0",
                 os_profile={"memory": "Windows 10 (NT 10.0)",
                             "disk": "Windows 10 (NT 10.0)", "source": "disk+memory",
                             "agree": True, "os": "Windows 10 (NT 10.0)"})
    assert "disk+memory agree" in card
    assert "memory + disk — full analysis" in card


def test_paired_mismatch_trusts_memory_no_alarm():
    card = _card(memory_path="/e/h-memory.raw", memory_health="HEALTHY",
                 disk_path="/e/h-cdrive.E01", disk_mounted=True, mount_method="raw@0",
                 os_profile={"memory": "Windows 10 (NT 10.0)",
                             "disk": "Windows 7 (NT 6.1)", "source": "memory",
                             "agree": False, "os": "Windows 10 (NT 10.0)"})
    # memory is authoritative -> no alarm, shown as 'per memory (disk hive reads …)'
    assert "≠" not in card and "disk≠memory" not in card
    assert "per memory" in card
    assert "NT 10.0" in card and "NT 6.1" in card  # both still surfaced (advisory)


def test_multi_case_notice_mentions_host_pairing():
    import io
    buf = io.StringIO()
    presenter.render_event(
        PhaseEvent(Phase.DISCOVER, Status.WARN, "multiple cases detected",
                   {"multi_case": True, "memory": 5, "disk": 4, "cases": 5}),
        color=False, file=buf)
    out = buf.getvalue()
    assert "more than one case" in out and "5 memory" in out
    assert "5 case(s) by HOST NAME" in out
