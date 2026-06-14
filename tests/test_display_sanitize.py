"""Render-time display hygiene: a finding's title/IOC must read cleanly, never
leak the tool's internal mount path or a raw JSON entity-key array.

Defect SHAPES from a live review (tokens genericized -- repo stays case-neutral):
  * a title leaked the SIFT mount prefix:
      path:tmp/sift-onboard-mnt/case-001/windows/prefetch/sdelete.exe-1a2b3c4d.pf
  * titles dumped a raw entity-key array:
      artifact:["\\"\\\\tsclient\\c\\users\\jdoe\\...\\sdelete64.exe\\" -z -c d:", ...]
      artifact:["{00000000-1111-2222-3333-444444444444}", "appid:1", ...]
  * details leaked raw candidate-id fragments: "Candidate_ids:,,,,.", "0148, 0149"

clean_display_text strips the run-local mount prefix (so a Windows-relative path
remains), collapses an entity-key array to its most recognizable token (a
filename, else a key:value like appid:1), and drops trailing candidate-id number
runs. Pure presentation -- never changes a verdict; fail-safe (returns the input
cleaned-or-unchanged, never raises). Universal: mount-path SHAPE + filename
grammar + number-run grammar, no case data. Kill-switch SIFT_DISPLAY_SANITIZE=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.reporting.display_sanitize import clean_display_text  # noqa: E402


def test_strips_sift_mount_prefix():
    s = "path:tmp/sift-onboard-mnt/case-001/windows/prefetch/sdelete.exe-1a2b3c4d.pf"
    out = clean_display_text(s)
    assert "sift-onboard-mnt" not in out
    assert "case-001" not in out
    assert "windows/prefetch/sdelete.exe-1a2b3c4d.pf" in out.lower()


def test_mount_prefix_anywhere_in_string():
    s = "defense evasion: /tmp/sift-onboard-mnt/case7/Windows/System32/x.exe ran"
    out = clean_display_text(s)
    assert "sift-onboard-mnt" not in out and "case7" not in out
    assert "windows/system32/x.exe".lower() in out.lower()


def test_artifact_array_collapses_to_filename():
    s = ('artifact:["\\"\\\\tsclient\\c\\users\\jdoe\\documents\\dept '
         'admin\\host-prep\\sdelete64.exe\\" -z -c d:", "", "", ""]')
    out = clean_display_text(s)
    assert "artifact:[" not in out
    assert out.lower().endswith("sdelete64.exe") or "sdelete64.exe" in out.lower()
    assert '\\"' not in out and "tsclient" not in out.lower()   # escaping noise gone


def test_artifact_array_with_label_keeps_label():
    s = 'defense evasion anti forensics: artifact:["...\\sdelete64.exe\\" -z -c d:"]'
    out = clean_display_text(s)
    assert out.lower().startswith("defense evasion anti forensics:")
    assert "sdelete64.exe" in out.lower()
    assert "artifact:[" not in out


def test_artifact_array_no_filename_uses_keyvalue_token():
    s = 'data exfiltration: artifact:["{00000000-1111-2222-3333-444444444444}", "appid:1", "", "srudb.dat"]'
    out = clean_display_text(s)
    assert "artifact:[" not in out
    # a recognizable token survives (srudb.dat filename or appid:1), GUID noise gone
    assert ("srudb.dat" in out.lower()) or ("appid:1" in out.lower())
    assert "00000000-1111" not in out


def test_strips_candidate_id_fragments():
    s = "GoogleCrashHandler holds SeDebug, SeImpersonate.0148, 0149"
    out = clean_display_text(s)
    assert out.rstrip().endswith("SeImpersonate")
    assert "0148" not in out and "0149" not in out


def test_strips_candidate_ids_label():
    s = "privileges enabled. Candidate_ids:,,,,., privilege, privilege"
    out = clean_display_text(s)
    assert "Candidate_ids" not in out
    assert "privileges enabled" in out


def test_clean_text_is_unchanged_for_normal_titles():
    for s in ("Anti-forensic tool execution: sdelete64.exe",
              "LOLBIN execution: rundll32.exe with SRUM network activity",
              "Service installation with non-standard path"):
        assert clean_display_text(s) == s


def test_real_path_with_legit_digits_not_over_stripped():
    # version-like / hash-like digits inside a real word must survive; only a
    # trailing bare candidate-id run is removed
    s = "MicrosoftEdgeUpdate.exe from Program Files (x86)\\Microsoft\\temp"
    assert clean_display_text(s) == s


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_DISPLAY_SANITIZE", "0")
    s = "path:tmp/sift-onboard-mnt/x/windows/prefetch/y.pf"
    assert clean_display_text(s) == s


def test_fail_safe_on_garbage():
    assert clean_display_text(None) in (None, "")
    assert clean_display_text(123) == clean_display_text(123)   # never raises
