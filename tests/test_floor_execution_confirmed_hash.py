"""A4: an execution-history record (AppCompatCache 'Executed' / Amcache /
Prefetch) PLUS a file hash is concrete corroboration -- not 'purely historical'.

A live run demoted a staged credential-dumping tool to BENIGN with reason
'only weak or purely historical indicators, no independent corroboration' even
though AppCompatCache showed Executed=Yes with a confirmed SHA1. Execution +
identity (a hash) is two independent disk facts agreeing -> corroborated.

SAFETY: a hash is REQUIRED -- a staged finding with an execution-history tool
but NO hash stays floored (test_staging_no_hash_still_floored), preserving the
existing temp-staging-alone behaviour. Universal: tool-class + hash-shape, no
case data. Kill-switch SIFT_FLOOR_EXEC_HASH_CORROB=0.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.disposition import (  # noqa: E402
    weak_alone_only_uncorroborated,
    _confirmable_corroborator_present,
)

_TEMP = "executes_from_temp_path"
_SHA1 = "e78b845045f7522c02e463a9b22db48e61ec0e54"


def _f(**kw):
    base = {"finding_id": "F", "title": "t", "claims": [], "source_tools": []}
    base.update(kw)
    return base


def test_staging_with_executed_flag_and_hash_is_corroborated():
    f = _f(source_tools=["run_appcompatcacheparser", "get_amcache"],
           claims=[{"type": "file", "value": "tool.exe", "sha1": _SHA1}])
    assert _confirmable_corroborator_present(f, [_TEMP]) is True
    assert weak_alone_only_uncorroborated(f, [_TEMP]) is False


def test_hash_in_iocs_text_counts():
    f = _f(source_tools=["run_appcompatcacheparser"],
           iocs=[f"tool.exe (sha1:{_SHA1})"])
    assert _confirmable_corroborator_present(f, [_TEMP]) is True


def test_staging_no_hash_still_floored():
    # The existing temp-staging-alone behaviour MUST be preserved when no hash.
    f = _f(source_tools=["run_appcompatcacheparser", "extract_mft_timeline"])
    assert weak_alone_only_uncorroborated(f, [_TEMP]) is True


def test_hash_without_execution_tool_is_not_this_corroborator():
    # A hash alone, with no execution-history tool, is not this axis (other
    # corroborators may still apply, but not exec+hash).
    f = _f(source_tools=["run_strings"],
           claims=[{"type": "file", "sha1": _SHA1}])
    # run_strings is not an execution-history tool; this specific axis is off.
    # (Whether other axes fire is out of scope; assert the floor still holds
    #  when ONLY a hash+non-exec-tool is present and the signal is weak-alone.)
    assert weak_alone_only_uncorroborated(f, [_TEMP]) is True


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_FLOOR_EXEC_HASH_CORROB", "0")
    f = _f(source_tools=["run_appcompatcacheparser", "get_amcache"],
           claims=[{"type": "file", "sha1": _SHA1}])
    # With this axis off, exec+hash no longer corroborates a weak-alone finding.
    assert weak_alone_only_uncorroborated(f, [_TEMP]) is True
