"""UserAssist as a user-attribution source (DISK NTUSER.DAT).

Live gap (degraded-memory run): user attribution read only memory tools
(vol_pstree/cmdline/handles) + Event 4624 + RDP + amcache, but NOT userassist
-- the richest per-user DISK source, which ties a username to every program
that user launched, straight from their registry hive. On a corrupted-kernel
image the memory SIDs are unreadable, so 'no user identities extracted'. Adding
userassist recovers WHO from disk. Universal: the username is read from the
\\Users\\<name>\\NTUSER.DAT path SHAPE, never a hardcoded account list.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.user_account_synthesizer import (  # noqa: E402
    extract_user_account_facts,
)


def _env(tool, records):
    return {tool: {"output": records}}


def test_vol_userassist_hive_yields_user():
    facts = extract_user_account_facts(_env("vol_userassist", [
        {"Hive Name": "C:\\Users\\jdoe\\NTUSER.DAT", "Path": "C:\\tools\\x.exe", "Type": "Run"},
    ]))
    names = {f["username"] for f in facts}
    assert "jdoe" in names
    uf = next(f for f in facts if f["username"] == "jdoe")
    assert "vol_userassist" in uf["source_tools"]


def test_parse_userassist_disk_source_also_works():
    facts = extract_user_account_facts(_env("parse_userassist", [
        {"Hive Name": "C:\\Users\\asmith\\ntuser.dat", "Path": "x"},
    ]))
    assert "asmith" in {f["username"] for f in facts}


def test_pseudo_profiles_excluded():
    facts = extract_user_account_facts(_env("vol_userassist", [
        {"Hive Name": "C:\\Users\\Default\\NTUSER.DAT", "Path": "x"},
        {"Hive Name": "C:\\Users\\Public\\NTUSER.DAT", "Path": "x"},
    ]))
    assert all(f["username"] not in ("default", "public") for f in facts)


def test_userassist_path_field_fallback():
    # some parsers put the hive in 'Path' or 'hive_path'
    facts = extract_user_account_facts(_env("vol_userassist", [
        {"hive_path": "C:\\Users\\bob\\NTUSER.DAT", "Path": "x"},
    ]))
    assert "bob" in {f["username"] for f in facts}


def test_no_userassist_no_crash():
    assert isinstance(extract_user_account_facts({}), list)
