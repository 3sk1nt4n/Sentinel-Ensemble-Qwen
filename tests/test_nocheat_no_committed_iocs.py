"""The case-literal audit gate must be ENFORCED, not asserted -- and the public
repo must never ship the evaluation answer key.

Prior state: audit/nocheat.py pasted the rd-01 IOC blocklist as dead code
(defined after main(), never scanned) -- both unenforced AND a leak in a public
repo. Enforcement now lives in the gitignored audit/forbidden_tokens.local.txt,
scanned at runtime by audit_local_forbidden_tokens(). These tests lock in:
(1) no enforced answer-key token is committed in the audit source, (2) the
enforcement file stays gitignored.

This test contains NO IOC literals of its own (which would themselves trip the
gate); it reads the tokens from the gitignored local file. Universal: asserts the
absence of answer-key literals, never a detection value.
"""
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _local_tokens() -> list[str]:
    f = ROOT / "audit" / "forbidden_tokens.local.txt"
    if not f.exists():
        return []
    return [
        line.strip()
        for line in f.read_text(errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_nocheat_committed_source_ships_no_answer_key_token():
    tokens = _local_tokens()
    if not tokens:
        pytest.skip("no local forbidden-token file present (fresh checkout)")
    text = (ROOT / "audit" / "nocheat.py").read_text(errors="ignore")
    leaked = [t for t in tokens if t in text]
    assert not leaked, f"answer-key tokens committed in nocheat.py: {leaked}"


def test_forbidden_tokens_enforcement_file_is_gitignored():
    gi = (ROOT / ".gitignore").read_text(errors="ignore")
    assert "audit/forbidden_tokens.local.txt" in gi, \
        "the eval-answer enforcement file must stay gitignored"
