"""Plain-English 'why it matters' significance -- junior/customer-friendly, keyed only
on universal OS primitives (RWX memory, IFEO Debugger, Event 5140 admin share, PowerShell
reflection, Run keys, services, ...). No case data, no tool/malware names (answer-key
risk). Never fabricates significance for an unrecognised finding.
"""
import inspect

from sift_sentinel.reporting.finding_significance import plain_significance
import sift_sentinel.reporting.finding_significance as _mod
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def test_rwx_injection_explained_in_plain_terms():
    f = {"title": "Memory injection detected",
         "description": "PAGE_EXECUTE_READWRITE RWX region with no module backing",
         "malicious_semantic_signals": ["rwx_memory_region_with_unusual_protection"]}
    s = plain_significance(f)
    assert s
    assert "memory" in s.lower()
    assert "jargon" not in s.lower()           # it explains, not restates


def test_ifeo_backdoor_explained():
    f = {"artifact": "Image File Execution Options sethc.exe Debugger"}
    s = plain_significance(f)
    assert "backdoor" in s.lower() and "registry" in s.lower()


def test_admin_share_lateral_movement_explained():
    f = {"description": "event 5140 network share accessed",
         "malicious_semantic_signals": ["admin_share_access"]}
    s = plain_significance(f)
    assert "share" in s.lower()
    assert any(w in s.lower() for w in ("attacker", "spreads", "lateral"))


def test_reflection_in_memory_explained():
    f = {"description": "PowerShell reflective load via GetProcAddress"}
    assert "memory" in plain_significance(f).lower()


def test_run_key_persistence_explained():
    f = {"artifact": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Thing"}
    assert "log" in plain_significance(f).lower()   # "...every time a user logs in..."


def test_unrecognised_finding_gets_no_fabricated_significance():
    f = {"title": "a generic observation", "description": "nothing matches any primitive"}
    assert plain_significance(f) == ""


def test_empty_finding_safe():
    assert plain_significance({}) == ""
    assert plain_significance(None) == ""


def test_most_severe_primitive_wins_when_several_present():
    # injection + temp-staging both present -> the injection explanation (more severe) wins
    f = {"description": "p.exe ran from c:/windows/temp/perfmon with an RWX injected region"}
    s = plain_significance(f)
    assert "memory" in s.lower()                 # injection, not the temp-staging line


def test_no_tool_or_malware_names_in_module_source():
    # keying on a specific tool/malware name would be an answer key -- forbidden.
    src = inspect.getsource(_mod).lower()
    # ban-list GUARD: these literals are deliberately case tokens (like the
    # agnostic-contract guards) -- they must NOT be renamed by neutralization
    # sweeps. "nfury" (not "alice") also avoids substring hits like "malice".
    for banned in ("mimikatz", "pwdump", "sdelete", "bleachbit", "psexesvc",
                   "cobalt", "metasploit", "rocba", "nromanoff", "nfury"):
        assert banned not in src, banned


def test_table_shows_why_it_matters():
    f = {"finding_id": "F1", "title": "Memory injection",
         "description": "RWX PAGE_EXECUTE_READWRITE region",
         "malicious_semantic_signals": ["rwx_memory_region_with_unusual_protection"],
         "claims": [{"type": "pid", "pid": 8712, "process": "x.exe"}]}
    out = render_findings_terminal({
        "confirmed_malicious_atomic": [f], "suspicious_needs_review": [],
        "benign_or_false_positive": [], "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    })
    assert "Why it matters" in out


def test_evidence_word_does_not_trigger_anti_forensics():
    # the common forensic word "evidence" must NOT read as log-clearing/anti-forensics
    f = {"description": "cmd.exe execution. Evidence of command-line shell invocation."}
    s = plain_significance(f)
    assert "clearing logs" not in s.lower()


def test_real_wiping_or_antiforensics_still_explained():
    f = {"description": "BC Wipe secure deletion tool executed",
         "malicious_semantic_signals": ["anti_forensics_execution"]}
    s = plain_significance(f)
    assert "clearing logs" in s.lower() or "wiping" in s.lower()


def test_lolbin_schtasks_reads_as_scheduled_task_not_antiforensics():
    f = {"title": "LOLBIN execution pattern: schtasks.exe, sc.exe, regsvr32.exe",
         "description": "AppCompatCache shows schtasks.exe (task creation), sc.exe, regsvr32.exe"}
    s = plain_significance(f).lower()
    assert "clearing logs" not in s          # no longer mis-tagged anti-forensics
    assert "scheduled task" in s             # schtasks -> scheduled-task significance


def test_lolbin_with_lateral_movement_phrase_not_tagged_admin_share():
    # the generic phrase "lateral movement" must NOT trigger the admin-share line
    f = {"title": "LOLBIN execution chain: schtasks.exe, sc.exe, rundll32.exe",
         "description": "binaries commonly used by attackers for lateral movement and persistence"}
    s = plain_significance(f).lower()
    assert "hidden administrative shares" not in s     # not mis-tagged admin-share
    assert "scheduled task" in s                        # schtasks -> scheduled-task


def test_real_admin_share_event_still_explained():
    f = {"description": "event 5140 network share accessed C$",
         "malicious_semantic_signals": ["admin_share_access"]}
    assert "administrative shares" in plain_significance(f).lower()


def test_fires_on_bare_structural_signal_no_description():
    # a terse/deterministic finding carrying ONLY the signal must still get significance
    for sig in ("rwx_memory_region_with_unusual_protection", "memory_injection_fact",
                "injected_pe_image_in_executable_memory"):
        s = plain_significance({"malicious_semantic_signals": [sig]})
        assert s and ("memory" in s.lower() or "injected" in s.lower()), sig


def test_staging_keyed_on_generic_temp_not_a_case_dir_name():
    # generic temp/staging path -> staging significance; no case-specific dir token needed
    assert "temporary or staging" in plain_significance(
        {"description": r"executed from D:\Obsidian\AppData\Local\Temp\q.exe"}).lower()


def test_table_finding_without_primitive_has_no_why_it_matters():
    f = {"finding_id": "F2", "title": "generic", "description": "nothing notable here",
         "claims": [{"type": "pid", "pid": 1, "process": "x.exe"}]}
    out = render_findings_terminal({
        "confirmed_malicious_atomic": [], "suspicious_needs_review": [f],
        "benign_or_false_positive": [], "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    })
    assert "Why it matters" not in out
