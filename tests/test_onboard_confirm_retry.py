"""The 'Start the hunt now?' confirm must be a retry guardrail: a typo WARNS and
re-asks (never silently cancels a ready case), back returns to the cards, an
explicit cancel/quit aborts, and Enter/GO launches. Universal UX, no case data."""
import step0_onboard as s
from sift_sentinel.onboard.engine import CaseManifest


def _manifest():
    return CaseManifest(
        case_id="c", os="Windows 7", os_source="memory",
        memory_path="/e/m.img", memory_health="HEALTHY", memory_health_facts={},
        disk_path="/e/d.E01", disk_mounted=True, mount_method="raw@0",
        mount_path="/mnt/c", reference_docs=[], os_profile={}, documents=[])


def _run(inputs):
    seq = iter(inputs)
    called = []

    def runner(*a, **k):
        called.append(1)
        return type("P", (), {"returncode": 0})()

    rc = s._do_find(_manifest(), wired=False, runner=runner,
                    input_fn=lambda _p: next(seq, None),
                    getpass_fn=lambda _p: "sk-ant-" + "x" * 101)
    return rc, called


def test_typo_warns_and_retries_then_launches(capsys):
    rc, called = _run(["p", "go"])          # typo, then GO
    out = capsys.readouterr().out
    assert "didn't catch" in out             # warned, did not cancel
    assert called == [1]                     # launched after the retry


def test_explicit_cancel_aborts(capsys):
    rc, called = _run(["cancel"])
    out = capsys.readouterr().out
    assert rc is None and called == []
    assert "cancelled - nothing launched" in out


def test_back_returns_to_cards(capsys):
    rc, called = _run(["back"])
    assert rc == "back" and called == []


def test_enter_launches(capsys):
    rc, called = _run([""])                  # bare Enter = GO
    assert called == [1]


def test_eof_is_clean_cancel(capsys):
    rc, called = _run([None])                # closed stdin
    out = capsys.readouterr().out
    assert rc is None and called == []
    assert "cancelled - nothing launched" in out
