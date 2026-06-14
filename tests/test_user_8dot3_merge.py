"""D5 part 2: the aggregation-level 8.3 merge -- a short-name identity record
folds INTO its unambiguous long form so one human is reported once.

Safety rules (adversarially adjusted):
  * evidence (source_tools / event / ps / rdp records / paths) is unioned;
  * owned_pids are NOT unioned unless the records share a SID -- a wrong merge
    must never manufacture a malicious-PID attribution (it feeds risk Signal 1);
  * ambiguous tokens (collision / ordinal>1) stay separate (helper contract);
  * flag-gated SIFT_USER_8DOT3_CANON, default OFF (validate live first).
Fabricated identities only -- no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.user_account_synthesizer import merge_8dot3_users  # noqa: E402


def _info(tools=(), pids=(), sid=""):
    return {"username": "", "domain": "", "sid": sid,
            "source_tools": set(tools), "owned_pids": set(pids),
            "paths_seen": set(), "event_records": [],
            "powershell_records": [], "rdp_records": []}


def _users():
    return {
        ("corp", "foobarbaz"): _info(tools=("tool_a",), pids=(11,), sid="S-1-5-21-X-1001"),
        ("corp", "foobar~1"): _info(tools=("tool_b",), pids=(22,), sid=""),
        ("corp", "unrelated"): _info(tools=("tool_c",), pids=(33,)),
    }


def test_merge_off_by_default(monkeypatch):
    monkeypatch.delenv("SIFT_USER_8DOT3_CANON", raising=False)
    u = _users()
    assert set(merge_8dot3_users(u)) == set(u)      # untouched


def test_short_form_folds_into_long(monkeypatch):
    monkeypatch.setenv("SIFT_USER_8DOT3_CANON", "1")
    out = merge_8dot3_users(_users())
    assert ("corp", "foobar~1") not in out
    merged = out[("corp", "foobarbaz")]
    assert merged["source_tools"] == {"tool_a", "tool_b"}   # evidence unioned


def test_owned_pids_not_unioned_without_shared_sid(monkeypatch):
    monkeypatch.setenv("SIFT_USER_8DOT3_CANON", "1")
    out = merge_8dot3_users(_users())
    # the short form had no SID -> its pids must NOT transfer
    assert out[("corp", "foobarbaz")]["owned_pids"] == {11}


def test_owned_pids_unioned_with_shared_sid(monkeypatch):
    monkeypatch.setenv("SIFT_USER_8DOT3_CANON", "1")
    u = _users()
    u[("corp", "foobar~1")]["sid"] = "S-1-5-21-X-1001"      # same principal proven
    out = merge_8dot3_users(u)
    assert out[("corp", "foobarbaz")]["owned_pids"] == {11, 22}


def test_collision_stays_separate(monkeypatch):
    monkeypatch.setenv("SIFT_USER_8DOT3_CANON", "1")
    u = _users()
    u[("corp", "foobarqux")] = _info()                      # second prefix match
    out = merge_8dot3_users(u)
    assert ("corp", "foobar~1") in out                      # ambiguous -> unmerged


def test_cross_domain_never_merges(monkeypatch):
    monkeypatch.setenv("SIFT_USER_8DOT3_CANON", "1")
    u = {("corp", "foobarbaz"): _info(), ("other", "foobar~1"): _info()}
    out = merge_8dot3_users(u)
    assert ("other", "foobar~1") in out                     # domain scope respected
