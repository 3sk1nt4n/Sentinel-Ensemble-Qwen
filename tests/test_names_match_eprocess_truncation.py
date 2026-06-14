"""_names_match must honor the EPROCESS ImageFileName kernel truncation cap.

Live false-block: a finding was BLOCKED with "PID <n> is <14-char-name>, not
<full-name>.exe (typed cross-contamination)". The memory-side process name came
from _EPROCESS.ImageFileName -- a fixed 15-byte kernel buffer, so Volatility
renders at most ~14-15 visible chars -- while the claim carried the full name
from disk/event artifacts. Both _names_match copies allowed only a <=4-char
length difference (anticipating a dropped ".exe"), so any name longer than ~18
chars produced a false MISMATCH -> BLOCK -> the finding could never confirm.

Universal rule (OS primitive, no name lists): when the SHORTER string is at the
kernel cap (>= 14 chars) and the longer starts with it, the kernel cut the rest
-- ANY remainder length is possible -> MATCH. Short-name behavior (>=5 chars,
<=4 diff) is unchanged, so trivially-short prefixes still never match.

Both copies (validation/validator.py and validation/typed_validator.py) must
agree -- the typed and reference_set verdicts depend on identical semantics.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

import pytest  # noqa: E402

from sift_sentinel.validation import validator as v        # noqa: E402
from sift_sentinel.validation import typed_validator as tv  # noqa: E402

BOTH = pytest.mark.parametrize("nm", [v._names_match, tv._names_match],
                               ids=["validator", "typed_validator"])


@BOTH
def test_kernel_truncated_long_name_matches_full_name(nm):
    # 14-char EPROCESS render vs 20-char full name (diff 6 > legacy 4)
    assert nm("FrameworkServi", "FrameworkService.exe") is True
    assert nm("FrameworkService.exe", "FrameworkServi") is True  # symmetric


@BOTH
def test_fifteen_char_render_also_matches(nm):
    # some renders keep 15 visible chars
    assert nm("FrameworkServic", "FrameworkService.exe") is True


@BOTH
def test_legacy_dropped_extension_still_matches(nm):
    assert nm("longprocess.ex", "longprocess.exe") is True
    assert nm("svchost", "svchost.exe") is True


@BOTH
def test_different_names_still_mismatch(nm):
    assert nm("svchost.exe", "lsass.exe") is False
    assert nm("cmd.exe", "cmd2.exe") is False        # not a prefix -> mismatch
    # short prefixes below 5 chars never match
    assert nm("cmd", "cmdline-helper.exe") is False


@BOTH
def test_short_name_large_diff_still_mismatches(nm):
    # the cap rule must NOT loosen short names: 8-char prefix of a 20-char name
    assert nm("framewor", "FrameworkService.exe") is False


@BOTH
def test_empty_never_matches(nm):
    assert nm("", "svchost.exe") is False
