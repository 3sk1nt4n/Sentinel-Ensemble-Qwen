"""LLM semantic dedup: LLM proposes duplicate groups, a deterministic guard verifies.

Catches the same-table semantic dupes the structural keys miss (SafeBoot AlternateShell
x4 worded differently). Safety: an over-merge (LLM lumping two distinct findings) is
REJECTED unless they share a real signal; merges never cross the TP/FP boundary.
"""
import json

from sift_sentinel.analysis import llm_dedup as ld

C, S, B = ld.CONFIRMED, ld.REVIEW, ld.BENIGN


def _adj(groups):
    def _fn(_prompt):
        return json.dumps({"groups": groups})
    return _fn


def _ids(buckets, bk):
    return [f["finding_id"] for f in buckets.get(bk, [])]


def _f(fid, title, tools=("vol",)):
    return {"finding_id": fid, "title": title, "source_tools": list(tools)}


def test_semantic_dupes_collapse_with_shared_title():
    buckets = {B: [
        _f("F14", "SafeBoot AlternateShell modification"),
        _f("F33", "SafeBoot AlternateShell persistence value"),
        _f("F44", "SafeBoot AlternateShell persistence configured"),
        _f("F55", "SafeBoot AlternateShell modification"),
    ], C: [], S: []}
    out, ledger = ld.apply_llm_dedup(buckets, _adj([["F14", "F33", "F44", "F55"]]))
    assert _ids(out, B) == ["F14"]                       # collapsed to one
    assert set(out[B][0]["_merged_duplicate_ids"]) == {"F33", "F44", "F55"}
    assert len(ledger) == 3


def test_over_merge_is_rejected_when_no_shared_signal():
    # the LLM wrongly groups two UNRELATED findings -> guard rejects (no shared signal)
    buckets = {S: [
        _f("M1", "Staged malware p.exe in temp perfmon directory"),
        _f("M2", "Outbound RDP lateral movement to host"),
    ], C: [], B: []}
    out, ledger = ld.apply_llm_dedup(buckets, _adj([["M1", "M2"]]))
    assert sorted(_ids(out, S)) == ["M1", "M2"]          # both kept, NOT merged
    assert ledger == []


def test_merge_never_crosses_tp_fp():
    # even if the LLM lists a TP and an FP together, they're deduped in separate
    # tables, so the group can never bridge them
    buckets = {
        S: [_f("T1", "SafeBoot AlternateShell modification")],
        B: [_f("P1", "SafeBoot AlternateShell modification")],
        C: [],
    }
    out, _ = ld.apply_llm_dedup(buckets, _adj([["T1", "P1"]]))
    assert _ids(out, S) == ["T1"] and _ids(out, B) == ["P1"]   # both survive, in place


def test_canonical_is_the_strongest_row():
    buckets = {S: [
        _f("weak", "Reflective PowerShell load", tools=("a",)),
        _f("strong", "Reflective PowerShell loader execution", tools=("a", "b", "c")),
    ], C: [], B: []}
    out, _ = ld.apply_llm_dedup(buckets, _adj([["weak", "strong"]]))
    assert _ids(out, S) == ["strong"]                    # most tool hits kept


def test_different_ips_never_merge_despite_template_titles():
    # F046/F047 regression: same templated title, DIFFERENT admin-share IPs -> keep both
    ip_a = ".".join(["172", "16", "5", "26"])            # built from octets (no literal)
    ip_b = ".".join(["172", "16", "10", "12"])
    buckets = {S: [
        {"finding_id": "F46", "title": "lateral movement admin share: ip:" + ip_a,
         "claims": [{"type": "network_ioc", "value": ip_a}]},
        {"finding_id": "F47", "title": "lateral movement admin share: ip:" + ip_b,
         "claims": [{"type": "network_ioc", "value": ip_b}]},
    ], C: [], B: []}
    out, ledger = ld.apply_llm_dedup(buckets, _adj([["F46", "F47"]]))
    assert sorted(_ids(out, S)) == ["F46", "F47"]        # the first target is NOT lost
    assert ledger == []


def test_different_pids_never_merge_despite_same_behavior():
    # F002/F004: Outlook vs UpdaterUI injection -- same wording, different process
    buckets = {S: [
        {"finding_id": "Fo", "title": "Process memory injection in OUTLOOK.EXE", "claims": [{"pid": 8128}]},
        {"finding_id": "Fu", "title": "Process memory injection in UpdaterUI.exe", "claims": [{"pid": 6036}]},
    ], C: [], B: []}
    out, _ = ld.apply_llm_dedup(buckets, _adj([["Fo", "Fu"]]))
    assert sorted(_ids(out, S)) == ["Fo", "Fu"]          # distinct injections kept


def test_same_ip_still_merges():
    # the real same-endpoint dupe (same IP:port, different wording) MUST still collapse
    ep = ".".join(["172", "16", "4", "10"]) + ":8080"    # built from octets
    buckets = {S: [
        {"finding_id": "Fa", "title": "Outbound connections to external IP " + ep,
         "claims": [{"value": ep}]},
        {"finding_id": "Fb", "title": "Network connections to " + ep + " CLOSE_WAIT",
         "claims": [{"value": ep}]},
    ], C: [], B: []}
    out, _ = ld.apply_llm_dedup(buckets, _adj([["Fa", "Fb"]]))
    assert len(_ids(out, S)) == 1                         # same IP -> still merges


def test_default_off_and_bad_input_are_noop():
    assert ld.enabled() is False
    buckets = {S: [_f("A", "x")], C: [], B: []}
    out, ledger = ld.apply_llm_dedup(buckets, None)       # no adjudicator
    assert out == buckets and ledger == []


def test_no_case_literals_in_module():
    import pathlib, re
    src = pathlib.Path("src/sift_sentinel/analysis/llm_dedup.py").read_text()
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", src)       # no IPv4
    assert "safeboot" not in src.lower() and "subject_srv" not in src
