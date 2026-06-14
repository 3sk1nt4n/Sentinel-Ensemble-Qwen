"""Secret-paste guard: an API key pasted at a VISIBLE prompt (a menu expecting
'a'/'q') echoes to the terminal and would land in any captured transcript. The
guard detects secret-shaped input at visible prompts, erases the echoed line
from the terminal, warns the operator to revoke, and never uses/stores/prints
the value.

UNIVERSAL: shape-based (one long high-entropy token, no whitespace -- menu
answers are 1-2 chars so collision is impossible); no vendor prefix list is
required for safety, though common key prefixes strengthen the signal.
Fabricated tokens only.
"""
import os
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

import step0_onboard as s  # noqa: E402


def test_secret_shapes_detected():
    assert s._looks_like_secret("sk-abc123-" + "x1" * 20) is True   # key-prefixed
    assert s._looks_like_secret("A1b2C3d4E5f6G7h8J9k0L1m2") is True  # bare token
    assert s._looks_like_secret("ghp_" + "Zz9" * 10) is True


def test_menu_answers_never_detected():
    for tok in ("a", "q", "A", "1", "2", "b", "yes", "another", ""):
        assert s._looks_like_secret(tok) is False, tok


def test_paths_and_sentences_never_detected():
    assert s._looks_like_secret("/cases/evidence/some-image.E01") is False  # has /
    assert s._looks_like_secret("hello world this is long input") is False  # spaces
    assert s._looks_like_secret("aaaaaaaaaaaaaaaaaaaaaaaaaa") is False      # no digits


def test_guarded_input_discards_secret_and_warns(capsys):
    out = s._guard_visible_input("sk-abc123-" + "x1" * 20)
    assert out == ""                                # secret never returned
    cap = capsys.readouterr().out
    assert "REVOKE" in cap.upper()
    assert "x1x1" not in cap                        # value never re-printed


def test_guarded_input_passes_normal_answers():
    assert s._guard_visible_input("a") == "a"
    assert s._guard_visible_input("Q") == "Q"
