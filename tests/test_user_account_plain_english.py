"""The compromised-user finding must read in plain English for a judge / junior
analyst: no raw internal 'risk N points' score, no 'see claims for typed
evidence' pointer, no bare PID / [Fxxx] jargon. Universal: keyed on the
structural signals + OS-token glosses, never case data.
"""
from sift_sentinel.analysis.user_account_synthesizer import (
    _humanize_signal,
    _user_account_description,
)


def test_description_has_no_internal_jargon():
    d = _user_account_description(
        "vibranium",
        ["owns 1 malicious PID(s) [F020]",
         "owns 1 persistence-indicator PID(s) [F033]"],
        "MEDIUM", False)
    low = d.lower()
    assert "risk points" not in low
    assert "see claims for typed evidence" not in low
    assert "pid(s)" not in low
    assert "[f020]" not in low
    # reads as plain explanation + actionable why-it-matters
    assert "may have been used by an attacker" in low
    assert "why it matters" in low
    assert "finding F020" in d


def test_singular_plural_is_clean():
    one = _user_account_description("u", ["owns 1 malicious PID(s) [F020]"],
                                    "MEDIUM", False)
    assert "1 malicious process " in one and "process(es)" not in one
    many = _user_account_description(
        "u", ["owns 3 malicious PID(s) [F020,F021,F022]"], "HIGH", False)
    assert "3 malicious processes" in many
    assert "findings F020, F021, F022" in many


def test_cryptic_event_ids_get_glossed():
    out = _humanize_signal("3× privileged logons (4672)", set())
    assert "admin-level rights" in out
    out2 = _humanize_signal("2× failed + 1× successful logons (4625→4624)",
                            set())
    assert "password guessing" in out2


def test_profile_only_is_softer_language():
    d = _user_account_description(
        "u", ["owns 1 process from \\Temp\\ staging"], "MEDIUM", True)
    assert "not confirmed compromise" in d.lower()


def test_gloss_applied_once_per_token():
    used = set()
    a = _humanize_signal("3× privileged logons (4672)", used)
    b = _humanize_signal("more 4672 logons (4672)", used)
    assert "admin-level rights" in a
    assert "admin-level rights" not in b  # not repeated
