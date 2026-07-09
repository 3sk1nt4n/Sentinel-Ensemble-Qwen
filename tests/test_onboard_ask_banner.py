"""The evidence-intake prompt is a fancy glowing-orange banner on a color TTY,
and a clean ANSI-free version when redirected (tests / pipes). Universal UI -
no case data, works for every case."""
import re

from sift_sentinel.onboard.presenter import build_ask_prompt

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def test_colored_banner_has_orange_and_title_and_guidance():
    p = build_ask_prompt(color=True)
    assert "38;5;208" in p                       # orange 256-color
    assert "ONBOARDING" in p and "EVIDENCE" in p  # the glowing header
    assert "folder" in p and "file" in p          # the folder/file guidance
    assert "\x1b[0m" in p                          # resets present (no bleed)
    # ends at the input prompt (after stripping ANSI + trailing space)
    assert _ANSI.sub("", p).rstrip().endswith("quit):")


def test_plain_banner_is_ansi_free_but_still_informative():
    p = build_ask_prompt(color=False)
    assert "\x1b[" not in p                         # NO ansi when redirected
    assert "ONBOARDING" in p and "EVIDENCE" in p
    assert "folder" in p and "file" in p
    assert "Q to quit" in p


def test_banner_is_case_neutral():
    # the banner must contain no case-specific value (only generic placeholders)
    p = build_ask_prompt(color=True).lower()
    for forbidden in ("jdoe", "alice", "acme", "rd01", "192.168", ".onion"):
        assert forbidden not in p


def test_ask_path_uses_the_banner_by_default():
    # ask_path with no explicit prompt should present the banner; q exits cleanly.
    from sift_sentinel.onboard.presenter import ask_path
    seen = {}

    def _in(prompt):
        seen["prompt"] = prompt
        return "q"

    assert ask_path(input_fn=_in, exists_fn=lambda p: True, color=False) is None
    assert "ONBOARDING" in seen["prompt"] and "EVIDENCE" in seen["prompt"]
