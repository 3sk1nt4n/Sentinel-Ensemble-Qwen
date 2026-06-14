"""D6: same-process+PID duplicate findings must merge -- but ONLY as a REFINED
identity, never on process identity alone.

Root cause (verified): ``entity_keys`` produces NO key for memory/PID findings
(no file hash, basename-only path, no event-id), so two findings about the same
injected process can never merge and both surface.

UNIVERSAL rule (adversarially adjusted): ``proc:{name}|{pid}|{behavior}`` is a
key only when the finding's behavior class is derivable, and two findings merge
ONLY if they share (name, pid, behavior class) AND carry no CONFLICTING peer-IP
claim. A single malicious PID legitimately hosts DISTINCT behaviors (injection
vs network vs ancestry) -- those must NEVER merge (mandatory negative guard).

Synthetic inputs only -- fabricated process names/PIDs/IPs; no case data.
Kill-switch SIFT_DEDUP_PROC_KEYS=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis import confirmed_dedup as cd  # noqa: E402


def _inj(fid, pid=4242, proc="fakeproc.exe", ip=None, tools=("vol_malfind",)):
    """A synthetic memory-injection finding: PID claim + injection tag, NO hash,
    NO full path, NO event-id -- the exact shape that today produces no key."""
    claims = [{"type": "pid", "pid": pid, "process": proc}]
    if ip:
        claims.append({"type": "connection", "pid": pid, "dst_ip": ip})
    return {
        "finding_id": fid,
        "title": "Process injection in %s (PID %d)" % (proc, pid),
        "description": "RWX VAD region in %s" % proc,
        "category": "memory_injection",
        "claims": claims,
        "source_tools": list(tools),
    }


def _netconn(fid, pid=4242, proc="fakeproc.exe", ip="203.0.113.77"):
    f = _inj(fid, pid=pid, proc=proc, ip=ip, tools=("vol_netscan",))
    f["category"] = "network_connection"
    f["title"] = "External connection from %s (PID %d)" % (proc, pid)
    return f


def test_same_proc_pid_same_behavior_merges():
    # the run-class bug: two injection findings on the same (proc, pid) -> ONE
    b = {cd.CONFIRMED: [_inj("S001"), _inj("S002", tools=("vol_malfind", "vol_pstree"))]}
    out, ledger = cd.dedup_confirmed(b)
    assert len(out[cd.CONFIRMED]) == 1
    assert len(ledger) == 1


def test_different_behavior_same_pid_never_merges():
    # MANDATORY negative guard: injection + network on the SAME pid are DISTINCT
    b = {cd.CONFIRMED: [_inj("S001"), _netconn("S002")]}
    out, ledger = cd.dedup_confirmed(b)
    assert len(out[cd.CONFIRMED]) == 2
    assert ledger == []


def test_conflicting_peer_ip_never_merges():
    # same (proc, pid, behavior) but DIFFERENT external peers -> two real targets
    b = {cd.CONFIRMED: [_inj("S001", ip="203.0.113.77"),
                        _inj("S002", ip="198.51.100.9")]}
    out, ledger = cd.dedup_confirmed(b)
    assert len(out[cd.CONFIRMED]) == 2
    assert ledger == []


def test_same_peer_ip_merges():
    # same (proc, pid, behavior) AND the SAME peer -> duplicate
    b = {cd.CONFIRMED: [_inj("S001", ip="203.0.113.77"),
                        _inj("S002", ip="203.0.113.77")]}
    out, ledger = cd.dedup_confirmed(b)
    assert len(out[cd.CONFIRMED]) == 1


def test_different_pid_never_merges():
    b = {cd.CONFIRMED: [_inj("S001", pid=1111), _inj("S002", pid=2222)]}
    out, ledger = cd.dedup_confirmed(b)
    assert len(out[cd.CONFIRMED]) == 2


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_DEDUP_PROC_KEYS", "0")
    b = {cd.CONFIRMED: [_inj("S001"), _inj("S002")]}
    out, _ = cd.dedup_confirmed(b)
    assert len(out[cd.CONFIRMED]) == 2          # legacy behavior restored


def test_representative_keeps_richest_tools():
    b = {cd.CONFIRMED: [_inj("S001", tools=("vol_malfind",)),
                        _inj("S002", tools=("vol_malfind", "vol_pstree", "vol_psscan"))]}
    out, _ = cd.dedup_confirmed(b)
    kept = out[cd.CONFIRMED][0]
    assert len(kept.get("source_tools") or []) == 3
