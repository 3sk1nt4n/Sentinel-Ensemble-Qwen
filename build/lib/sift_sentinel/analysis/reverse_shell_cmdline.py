"""Universal reverse-shell / C2 command-line SHAPE detector.

Why this exists: a literal reverse shell must confirm DETERMINISTICALLY on every run,
not only when the LLM ensemble happens to feel confident. This module recognises the
*grammar* of a remote-shell invocation and nothing else -- there is no list of binary
or malware NAMES here, so it generalises to a held-out evidence box.

Metamorphic invariance is the universality contract: relabel every IP / port / key
literal in a command line and the verdict is unchanged, because the literals are never
matched -- only the command-line structure (a listen flag bound to a port, an explicit
remote socket endpoint, netcat exec-redirection, the /dev/tcp bash idiom, or an encoded
PowerShell download one-liner).

FP discipline: a *bare* remote endpoint (a DB / monitoring client connecting to a
host:port) or a *plain* listener (a server bound to a port) is NOT confirm-grade on its
own -- only an unambiguous shell idiom, or the anomalous listen+remote-endpoint relay
combination, returns True. The disposition layer additionally requires C2 corroboration
(a real network connection) before any of this confirms, so the bar is intentionally
high.
"""
from __future__ import annotations

import re

# An explicit IPv4:port endpoint -- a process told to talk to a specific remote socket.
_IP_PORT_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}")
# A listen/bind flag immediately followed by a port: -l 4444, -p 8080, --listen 9001.
_LISTEN_PORT_RE = re.compile(r"(?:^|\s)(?:-l|-p|--listen|--lport|/l)[\s:=]+\d{1,5}\b", re.IGNORECASE)
# A remote-connect flag carrying an ip:port: -s 203.0.113.7:1337, --connect host:port.
_CONNECT_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-s|--connect|--rhost|-r)[\s:=]+(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}", re.IGNORECASE)
# netcat / ncat exec-redirection: the classic `nc -e /bin/sh host port` bind/reverse shell.
_NC_EXEC_RE = re.compile(
    r"\b(?:nc|ncat|netcat)(?:\.exe)?\b[^\n]{0,200}?(?:\s-e\b|--exec\b|--sh-exec\b)", re.IGNORECASE)
# bash / sh device reverse-shell idiom: /dev/tcp/<host>/<port>, /dev/udp/...
_DEVTCP_RE = re.compile(r"/dev/(?:tcp|udp)/[^/\s]+/\d{1,5}", re.IGNORECASE)
# PowerShell context + encoded payload, or a download cradle.
_PS_CTX_RE = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.IGNORECASE)
_PS_ENC_RE = re.compile(r"(?:-enc(?:odedcommand)?|-ec|-e)\b\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE)
_PS_IEX_RE = re.compile(r"(?:\bIEX\b|Invoke-Expression)", re.IGNORECASE)
_PS_NET_RE = re.compile(r"(?:Net\.WebClient|DownloadString|DownloadFile|DownloadData)", re.IGNORECASE)

# Idioms that are reverse/bind shells on their own (no corroboration needed to be SHAPE).
_STRONG_SIGNALS = frozenset({
    "netcat_exec_redirection",
    "dev_tcp_reverse_shell",
    "encoded_powershell_oneliner",
    "powershell_download_cradle",
})


def _as_text(cmdline) -> str:
    """Normalise str | argv-list | None to a single string."""
    if cmdline is None:
        return ""
    if isinstance(cmdline, (list, tuple)):
        return " ".join(str(p) for p in cmdline if p not in (None, ""))
    return str(cmdline)


def score_reverse_shell_cmdline(cmdline) -> dict:
    """Return {"score": int, "signals": [structural names]} for a command line.

    Signals are structural names only -- never a case value -- so the result is safe to
    surface in a report and is identical across metamorphic relabellings of the input.
    """
    text = _as_text(cmdline)
    signals: list[str] = []
    score = 0
    if not text.strip():
        return {"score": 0, "signals": signals}

    has_ps = bool(_PS_CTX_RE.search(text))

    # --- strong, stand-alone shell idioms ---
    if _NC_EXEC_RE.search(text):
        signals.append("netcat_exec_redirection")
        score += 5
    if _DEVTCP_RE.search(text):
        signals.append("dev_tcp_reverse_shell")
        score += 5
    if has_ps and _PS_ENC_RE.search(text):
        signals.append("encoded_powershell_oneliner")
        score += 5
    if has_ps and _PS_IEX_RE.search(text) and _PS_NET_RE.search(text):
        signals.append("powershell_download_cradle")
        score += 5

    # --- flag/endpoint primitives (confirm-grade only in the listen+endpoint combo) ---
    if _CONNECT_FLAG_RE.search(text):
        signals.append("remote_connect_flag")
        score += 4
    if _LISTEN_PORT_RE.search(text):
        signals.append("listen_port_flag")
        score += 2
    if _IP_PORT_RE.search(text):
        signals.append("remote_socket_endpoint")
        score += 2

    return {"score": score, "signals": signals}


def is_reverse_shell_shape(cmdline) -> bool:
    """True iff the command line is structurally a reverse/bind shell.

    Either an unambiguous shell idiom is present, OR a process both LISTENS on a port and
    carries an explicit remote socket endpoint (a bind+reverse relay). NOTE: that bare
    listen+endpoint combination is ALSO exhibited by legitimate remote-admin / DFIR agents
    (e.g. F-Response, Velociraptor, PsExec), so it is intentionally NOT used to gate
    confirm-eligibility -- use is_reverse_shell_strong_idiom for that. A lone endpoint or
    lone listener is deliberately NOT enough.
    """
    sigs = set(score_reverse_shell_cmdline(cmdline)["signals"])
    if sigs & _STRONG_SIGNALS:
        return True
    if "listen_port_flag" in sigs and "remote_socket_endpoint" in sigs:
        return True
    return False


def is_reverse_shell_strong_idiom(cmdline) -> bool:
    """True ONLY for an UNAMBIGUOUS reverse/bind-shell idiom: netcat exec-redirection
    (nc -e), the /dev/tcp bash idiom, or an encoded / download-cradle PowerShell one-liner.

    Unlike is_reverse_shell_shape this EXCLUDES the bare listen-flag + remote-endpoint
    combination, because that grammar (-l <port> -s <ip:port> -k <key>) is shared by
    legitimate remote-admin / DFIR agents and is therefore NOT confirm-grade on its own.
    This is the FP-safe predicate used to gate confirm-eligibility, so a legit tool is
    never flagged as a reverse shell.
    """
    return bool(set(score_reverse_shell_cmdline(cmdline)["signals"]) & _STRONG_SIGNALS)
