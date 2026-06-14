"""Tool-status-noise suppressor — universal, conservative, downgrade-only.

The live acme run emitted 6 non-findings that merely narrate a tool's own
execution status: four 'vol_hollowprocesses timed out' (F014/F025/F042/F051) and
two 'amcache empty' (F015/F026). A tool timeout / empty result is collection
metadata (already in TOOL HEALTH), not a forensic finding -- it shouldn't compete
with real malice in the table.

match_tool_status_noise fires ONLY when the finding's content is a tool-name +
status token (timeout/empty/failure) AND it carries NO real evidence (no file
path with an artifact extension, no hash, no real pid, no behavioral signal).
Universal: keys on the tool-name SHAPE + OS-agnostic status words, never a case
value. Downgrade-only -> benign (never deleted).
"""
from sift_sentinel.analysis.tool_status_noise import (
    match_tool_status_noise,
    apply_tool_status_noise,
)


def _f(fid, artifact, claims=None):
    return {"finding_id": fid, "title": artifact, "description": artifact,
            "claims": claims or [{"type": "raw", "value": artifact}]}


# ── the 6 live junk findings MUST match ──────────────────────────────────────
def test_hollowprocesses_timeout_variants_match():
    for art in (
        "vol_hollowprocesses_timeout",
        "vol_hollowprocesses timeout during analysis",
        "vol_hollowprocesses plugin timed out after 90 seconds",
        "pid:0 A - tool failure, not process; vol_hollowprocesses tool failure",
    ):
        hit, _ = match_tool_status_noise(_f("F", art))
        assert hit is True, art


def test_amcache_empty_variants_match():
    for art in ("amcache_empty; get_amcache", "AmCache execution registry - empty; Empty AmCache database"):
        hit, _ = match_tool_status_noise(_f("F", art))
        assert hit is True, art


# ── real findings MUST NOT match (conservative guards) ───────────────────────
def test_real_anti_forensics_with_hash_and_path_not_matched():
    f = _f("F44", "anti-forensics tool sdelete.exe",
           claims=[{"type": "path", "value": "users/jay-r/downloads/sdelete64.exe"},
                   {"type": "hash", "sha1": "7bcd946326b6aabbccddeeff00112233445566aa"}])
    assert match_tool_status_noise(f)[0] is False


def test_real_injection_with_pid_not_matched():
    f = _f("F1", "Memory injection in SearchApp.exe",
           claims=[{"type": "pid", "pid": 8312, "process": "SearchApp.exe"}])
    assert match_tool_status_noise(f)[0] is False


def test_real_exec_finding_mentioning_empty_word_not_matched():
    # a real exec finding that happens to contain the word 'empty' but has a real
    # path must NOT be suppressed (guard on real evidence).
    f = _f("F", "powershell.exe executed with empty command buffer",
           claims=[{"type": "path", "value": "windows/system32/windowspowershell/v1.0/powershell.exe"}])
    assert match_tool_status_noise(f)[0] is False


def test_behavioral_signal_finding_not_matched():
    f = _f("F52", "data exfiltration egress outlier",
           claims=[{"type": "raw", "value": "srum_egress_outlier behavioral anomaly"}])
    assert match_tool_status_noise(f)[0] is False


def test_plain_benign_text_not_matched():
    assert match_tool_status_noise(_f("F", "OneDrive.exe network connection"))[0] is False


# ── apply pass: flags + count, never mutates a real finding ──────────────────
def test_apply_flags_only_noise():
    findings = [
        _f("J1", "vol_hollowprocesses_timeout"),
        _f("J2", "amcache_empty; get_amcache"),
        _f("R1", "Memory injection", claims=[{"type": "pid", "pid": 8312}]),
    ]
    n = apply_tool_status_noise(findings)
    by = {f["finding_id"]: f for f in findings}
    assert n == 2
    assert by["J1"].get("_tool_status_noise") is True
    assert by["J2"].get("_tool_status_noise") is True
    assert by["R1"].get("_tool_status_noise") is not True


def test_apply_is_idempotent_and_pure_on_reals():
    f = _f("R", "sdelete.exe", claims=[{"type": "hash", "sha256": "a"*64}])
    apply_tool_status_noise([f])
    assert "_tool_status_noise" not in f


def test_flagged_finding_routes_to_benign():
    from sift_sentinel.analysis.disposition import derive_final_disposition, BUCKET_BENIGN
    f = _f("J", "vol_hollowprocesses_timeout")
    apply_tool_status_noise([f])
    assert f.get("_tool_status_noise") is True
    assert derive_final_disposition(f)[0] == BUCKET_BENIGN
