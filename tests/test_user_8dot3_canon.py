"""D5: Windows 8.3 short-name identities (FOOBAR~1) must collapse onto their
long form when -- and only when -- the match is unambiguous, so one human is
never reported as two users.

UNIVERSAL: the DOS 8.3 derivation is an OS primitive (strip spaces and
8.3-invalid chars incl. dots, uppercase, first 6 chars + ~ordinal). Rules
(adversarially adjusted):
  * ordinal must be 1 -- a ~2+ token means MULTIPLE identities shared the
    prefix at creation, so the target is unknowable: stay unmerged;
  * exactly ONE long-form candidate may derive the prefix -- a collision
    (two identities sharing the 6-char prefix) stays unmerged, never guessed;
  * matching is case-insensitive; non-tilde tokens pass through untouched.
All identities here are fabricated -- no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.user_account_synthesizer import (  # noqa: E402
    canonicalize_8dot3,
)


def test_unambiguous_short_name_collapses():
    assert canonicalize_8dot3("FOOBAR~1", {"foobarbaz", "otheruser"}) == "foobarbaz"
    assert canonicalize_8dot3("foobar~1", {"foobarbaz"}) == "foobarbaz"   # case-insensitive


def test_prefix_collision_stays_unmerged():
    # two long identities derive the same 6-char prefix -> never guess
    assert canonicalize_8dot3(
        "MARKET~1", {"marketing", "marketingadmin"}) == "MARKET~1"


def test_ordinal_above_one_stays_unmerged():
    # ~2 means >=2 candidates existed at creation -> target unknowable
    assert canonicalize_8dot3("ADMINI~2", {"administrator"}) == "ADMINI~2"


def test_dot_stripped_derivation_matches():
    # 8.3 derivation removes dots: a.bcdef -> ABCDEF
    assert canonicalize_8dot3("ABCDEF~1", {"a.bcdef"}) == "a.bcdef"


def test_non_tilde_token_passthrough():
    assert canonicalize_8dot3("plainuser", {"plainuser", "x"}) == "plainuser"


def test_no_candidate_stays_unmerged():
    assert canonicalize_8dot3("ZZZZZZ~1", {"unrelated"}) == "ZZZZZZ~1"
