"""FIND launch is self-explanatory + one-keypress, never a dead end.

Covers the additive launch behavior in step0_onboard.py:
  * unwired + ANTHROPIC_API_KEY + "Y"   -> exec run_pipeline.py with the
    resolved --image/--disk/--disk-mount argv (no real API spend: runner mocked)
  * unwired + NO key + "Y"              -> prints the export hint, does NOT exec,
    does NOT quit (returns to the menu)
  * unwired + "n" / closed stdin        -> keeps the staged line, no exec
  * wired (SIFT_FIND_WIRED=1)           -> no [Y/n] confirm; exec directly
  * "dind evil" / "fnd evil"            -> "Did you mean Find Evil?" -> launch
  * "banana"                            -> still "didn't catch that"
"""
from __future__ import annotations

import os

import pytest

import step0_onboard
from sift_sentinel.onboard.engine import CaseManifest


# ── helpers ────────────────────────────────────────────────────────────────
def _manifest(**kw):
    base = dict(
        case_id="case-x", os="Windows 10 / Server 2016+ (NT 10.0)",
        os_source="memory", memory_path="/ev/mem.raw",
        memory_health="HEALTHY", memory_health_facts={},
        disk_path="/ev/disk.e01", disk_mounted=True,
        mount_method="raw@0", mount_path="/mnt/case-x",
        reference_docs=[])
    base.update(kw)
    return CaseManifest(**base)


def _feed(seq):
    it = iter(seq)
    return lambda _prompt: next(it)


def _recording_feed(seq):
    """Like _feed, but records every prompt it was asked (the 'Did you mean…'
    question is issued as a real input() prompt, not a print)."""
    it = iter(seq)
    prompts = []

    def fn(prompt):
        prompts.append(prompt)
        return next(it)

    fn.prompts = prompts
    return fn


class _Proc:
    def __init__(self, rc=0):
        self.returncode = rc


# ── FIX 1: unwired Y/n flow ──────────────────────────────────────────────────
def test_unwired_with_key_and_yes_execs_with_resolved_argv(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured = {}

    def fake_runner(argv, **kw):
        captured["argv"] = argv
        return _Proc(0)

    m = _manifest()
    rc = step0_onboard._do_find(m, wired=False, runner=fake_runner,
                                input_fn=_feed(["Y"]), getpass_fn=lambda _p: "")
    assert rc == 0
    argv = captured["argv"]
    # The exec argv carries the resolved flags from build_find_command().
    assert argv == step0_onboard.build_find_command(m)
    assert "--image" in argv and "/ev/mem.raw" in argv
    assert "--disk" in argv and "/ev/disk.e01" in argv
    assert "--disk-mount" in argv and "/mnt/case-x" in argv
    out = capsys.readouterr().out
    assert "launching" in out and "run_pipeline.py" in out
    assert "exited with code 0" in out


def test_disk_only_launch_argv_has_no_image(monkeypatch, capsys):
    # A disk-only case (no memory) must launch with --disk/--disk-mount and NO
    # --image -- the argv shape run_pipeline.py now accepts (was a hard dead end).
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured = {}

    def fake_runner(argv, **kw):
        captured["argv"] = argv
        return _Proc(0)

    m = _manifest(memory_path=None, memory_health=None, os_source="disk")
    rc = step0_onboard._do_find(m, wired=False, runner=fake_runner,
                                input_fn=_feed(["Y"]), getpass_fn=lambda _p: "")
    assert rc == 0
    argv = captured["argv"]
    assert "--image" not in argv                      # no memory -> no --image
    assert "--disk" in argv and "/ev/disk.e01" in argv
    assert "--disk-mount" in argv and "/mnt/case-x" in argv


def test_memory_only_launch_argv_has_no_disk(monkeypatch):
    # Symmetric: a memory-only case launches with --image and NO --disk.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured = {}

    def fake_runner(argv, **kw):
        captured["argv"] = argv
        return _Proc(0)

    m = _manifest(disk_path=None, disk_mounted=False, mount_method=None,
                  mount_path=None, os_source="memory")
    step0_onboard._do_find(m, wired=False, runner=fake_runner,
                           input_fn=_feed(["Y"]), getpass_fn=lambda _p: "")
    argv = captured["argv"]
    assert "--image" in argv and "/ev/mem.raw" in argv
    assert "--disk" not in argv and "--disk-mount" not in argv


_VALID_KEY = "sk-ant-" + "A1b2C3d4" * 13   # sk-ant- prefix, ~110 chars, url-safe


def test_unwired_go_no_key_prompts_hidden_then_launches(monkeypatch, capsys):
    # GO + no key in env -> prompt for a HIDDEN, format-valid key, then launch.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    captured = {}
    rc = step0_onboard._do_find(
        _manifest(), wired=False,
        runner=lambda argv, **k: captured.setdefault("argv", argv) or _Proc(0),
        input_fn=_feed(["GO"]),
        getpass_fn=lambda _p: _VALID_KEY)
    out = capsys.readouterr().out
    assert "argv" in captured                            # launched after hidden key
    assert os.environ.get("ANTHROPIC_API_KEY") == _VALID_KEY
    assert _VALID_KEY not in out                         # key never echoed


def test_bad_format_key_is_rejected_no_launch(monkeypatch, capsys):
    # A wrong/garbage key (e.g. '88879') must be caught at paste time, not at a 401.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    called = []
    rc = step0_onboard._do_find(_manifest(), wired=False,
                                runner=lambda *a, **k: called.append(1),
                                input_fn=_feed(["GO"]),
                                getpass_fn=lambda _p: "88879")
    out = capsys.readouterr().out
    assert rc is None and called == []                   # never launched
    assert "doesn't look like an Anthropic key" in out
    assert "sk-ant-" in out                              # tells them the expected shape


def test_validate_api_key_unit():
    assert step0_onboard.validate_api_key("88879")[0] is False
    assert step0_onboard.validate_api_key("sk-ant-short")[0] is False     # too short
    assert step0_onboard.validate_api_key("plaintextkey" * 5)[0] is False  # no prefix
    assert step0_onboard.validate_api_key(_VALID_KEY)[0] is True


def test_unwired_empty_key_does_not_launch(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    called = []
    rc = step0_onboard._do_find(_manifest(), wired=False,
                                runner=lambda *a, **k: called.append(1),
                                input_fn=_feed(["GO"]),
                                getpass_fn=lambda _p: "")   # pasted nothing
    out = capsys.readouterr().out
    assert rc is None and called == []
    assert "No API key" in out                          # cannot launch without a key


def test_unwired_cancel_no_exec(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # key present, but cancelled
    called = []
    rc = step0_onboard._do_find(_manifest(), wired=False,
                                runner=lambda *a, **k: called.append(1),
                                input_fn=_feed(["cancel"]))
    out = capsys.readouterr().out
    assert rc is None and called == []
    assert "cancelled - nothing launched" in out
    assert "exited with code" not in out


def test_unwired_back_returns_back(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    called = []
    rc = step0_onboard._do_find(_manifest(), wired=False,
                                runner=lambda *a, **k: called.append(1),
                                input_fn=_feed(["back"]))
    assert rc == "back" and called == []                 # back to the card list


def test_closed_stdin_no_exec(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    called = []
    rc = step0_onboard._do_find(_manifest(), wired=False,
                                runner=lambda *a, **k: called.append(1),
                                input_fn=lambda _p: None)   # EOF / detached -> cancel
    out = capsys.readouterr().out
    assert rc is None and called == []
    assert "cancelled - nothing launched" in out


# ── FIX 1: wired fast path skips the confirm ─────────────────────────────────
def test_wired_skips_prompt_and_execs(capsys):
    captured = {}

    def fake_runner(argv, **kw):
        captured["argv"] = argv
        return _Proc(7)

    def no_prompt(_p):
        raise AssertionError("wired path must NOT prompt for confirmation")

    rc = step0_onboard._do_find(_manifest(), wired=True, runner=fake_runner,
                                input_fn=no_prompt, getpass_fn=lambda _p: _VALID_KEY)
    assert rc == 7
    assert "argv" in captured                            # exec happened directly
    out = capsys.readouterr().out
    assert "exited with code 7" in out
    assert "Launch now?" not in out                      # no [Y/n] confirm shown


# ── FIX 2: typo-help ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("typo", ["dind evil", "fnd evil", "findevl"])
def test_typo_offers_did_you_mean_and_launches(typo):
    # menu input is the typo, then "Y" confirms the "Did you mean Find Evil?".
    fn = _recording_feed([typo, "Y"])
    act = step0_onboard._read_action(fn)
    assert act == "find"                                 # routed to launch
    assert any("Did you mean Find Evil?" in p for p in fn.prompts)


def test_typo_confirm_empty_also_launches():
    fn = _recording_feed(["dind evil", ""])              # empty = default Yes
    assert step0_onboard._read_action(fn) == "find"
    assert any("Did you mean Find Evil?" in p for p in fn.prompts)


def test_typo_decline_reasks():
    # decline the "Did you mean" -> re-ask the menu, then Q quits cleanly.
    fn = _recording_feed(["fnd evil", "n", "q"])
    assert step0_onboard._read_action(fn) == "q"
    assert any("Did you mean Find Evil?" in p for p in fn.prompts)


def test_banana_still_didnt_catch_that(capsys):
    fn = _recording_feed(["banana", "q"])
    assert step0_onboard._read_action(fn) == "q"
    out = capsys.readouterr().out
    assert "didn't catch that" in out
    # banana is not a near-miss: no "Did you mean" prompt was ever issued.
    assert not any("Did you mean Find Evil?" in p for p in fn.prompts)


def test_double_pasted_key_rejected():
    one = "sk-ant-" + "A1b2C3d4" * 13          # ~111 chars, valid
    assert step0_onboard.validate_api_key(one)[0] is True
    doubled = one + one                          # pasted twice -> 222 chars, 2 prefixes
    ok, why = step0_onboard.validate_api_key(doubled)
    assert ok is False
    assert "pasted" in why and "sk-ant-" in why  # tells them it's a double paste


def test_overlong_key_rejected():
    long_no_double = "sk-ant-" + "A" * 200       # one prefix but absurdly long
    ok, why = step0_onboard.validate_api_key(long_no_double)
    assert ok is False
    assert "too long" in why


# ── bash-history scrub guardrail ────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _safe_histfile(tmp_path, monkeypatch):
    # protect the real ~/.bash_history: every test in this file scrubs a temp file
    monkeypatch.setenv("HISTFILE", str(tmp_path / ".bash_history"))


def test_scrub_removes_only_key_lines(tmp_path):
    h = tmp_path / "hist"
    h.write_text("ls -la\nexport ANTHROPIC_API_KEY=sk-ant-aaa\ncd /tmp\n"
                 "sk-ant-bbb-pasted\npwd\n")
    assert step0_onboard.scrub_shell_history(str(h)) == 2
    txt = h.read_text()
    assert "sk-ant-" not in txt and "ANTHROPIC_API_KEY" not in txt
    assert "ls -la" in txt and "pwd" in txt and "cd /tmp" in txt   # kept


def test_scrub_noop_when_no_key(tmp_path):
    h = tmp_path / "hist"
    h.write_text("ls\ncd /tmp\npwd\n")
    assert step0_onboard.scrub_shell_history(str(h)) == 0
    assert h.read_text() == "ls\ncd /tmp\npwd\n"                   # untouched


def test_scrub_missing_file_is_safe():
    assert step0_onboard.scrub_shell_history("/no/such/histfile") == 0


def test_do_find_prints_history_pass_gate(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", _VALID_KEY)
    step0_onboard._do_find(_manifest(), wired=False,
                           runner=lambda *a, **k: _Proc(0),
                           input_fn=_feed(["GO"]), getpass_fn=lambda _p: "")
    out = capsys.readouterr().out
    assert "BASH_HISTORY_CLEARED_GATE=PASS" in out                # gate-style PASS


# ── Step-1 SHA warm start ───────────────────────────────────────────────────
def test_warm_sha_async_matches_hashlib(tmp_path):
    import hashlib, json, time
    ev = tmp_path / "mem.img"
    content = b"forensic evidence bytes \x00\x01\x02" * 5000
    ev.write_bytes(content)
    m = _manifest(memory_path=str(ev), disk_path=None, disk_mounted=False,
                  mount_method=None, mount_path=None, case_id="warm test/1")
    out = step0_onboard.warm_sha_async(m)
    for _ in range(100):                       # wait for the atomic publish
        if out and os.path.exists(out):
            break
        time.sleep(0.05)
    data = json.loads(open(out).read())
    rec = data[str(ev)]
    assert rec["sha256"] == hashlib.sha256(content).hexdigest()   # pipeline-identical
    assert rec["size"] == len(content)                            # integrity field
    os.remove(out)


def test_warm_sha_async_no_evidence_returns_none():
    m = _manifest(memory_path=None, disk_path=None, disk_mounted=False,
                  mount_method=None, mount_path=None)
    assert step0_onboard.warm_sha_async(m) is None
