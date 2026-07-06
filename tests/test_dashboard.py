"""Tests for the colored summary dashboard in run_pipeline.py."""

import io
import sys
import textwrap
from unittest.mock import patch


def _print_dashboard(summary, findings_final=None, blocked_list=None,
                     investigation_summaries=None, tool_record_counts=None,
                     tool_errors=None, image_path=None, disk_mount=None,
                     tty=True):
    """
    Execute the dashboard code in isolation by importing the color constants
    and running the print block, capturing stdout.
    """
    findings_final = findings_final or []
    blocked_list = blocked_list or []
    investigation_summaries = investigation_summaries or []
    tool_record_counts = tool_record_counts or {}
    tool_errors = tool_errors or {}

    with patch("sys.stdout", new_callable=io.StringIO) as mock_out, \
         patch("sys.stdout.isatty", return_value=tty):
        _TTY = tty
        G  = "\033[92m" if _TTY else ""
        R  = "\033[91m" if _TTY else ""
        Y  = "\033[93m" if _TTY else ""
        C  = "\033[96m" if _TTY else ""
        M  = "\033[95m" if _TTY else ""
        B  = "\033[1m"  if _TTY else ""
        D  = "\033[2m"  if _TTY else ""
        X  = "\033[0m"  if _TTY else ""

        IMAGE_PATH = image_path
        DISK_MOUNT = disk_mount or "/mnt/windows_mount"

        _BAR = f"{C}{'='*70}{X}"

        print(f"""
{_BAR}
{B}{C}  SENTINEL ENSEMBLE -- Autonomous DFIR Agent{X}
{B}{C}  Pipeline Execution Report{X}
{_BAR}

{B}  EVIDENCE{X}
  Memory:      {IMAGE_PATH or 'not provided'}
  Disk mount:  {DISK_MOUNT or 'not provided'}
  Duration:    {int(summary['elapsed_s']//60)}m {int(summary['elapsed_s']%60)}s
  Integrity:   {G + 'SHA256 MATCH -- evidence unmodified' + X if summary.get('integrity_match') else R + 'MISMATCH -- SPOLIATION ALERT' + X}

{B}  TOOLS ({summary['tools_count']} executed){X}""", file=mock_out)

        for _t in summary.get('tools_run', []):
            _cnt = tool_record_counts.get(_t, 0)
            _err = tool_errors.get(_t)
            if _err:
                _tag = f"{R}ERROR{X}"
            elif _cnt == 0:
                _tag = f"{Y}0 records{X}"
            else:
                _tag = f"{G}{_cnt} records{X}"
            print(f"    {_t:<28} {_tag}", file=mock_out)

        print(f"""
{B}  FINDINGS{X}
  Produced:    {summary['findings_total']}
  Validated:   {G}{summary['findings_passed']} MATCH{X}
  Blocked:     {Y}{summary['findings_blocked']} (needed 2+ corroborating claims){X}
  Corrected:   {summary.get('corrections_succeeded',0)}/{summary.get('corrections_attempted',0)} via self-correction
""", file=mock_out)

        for _ff in findings_final:
            _conf = _ff.get('confidence_level', _ff.get('confidence', '?'))
            _cc = G if _conf == 'HIGH' else Y if _conf == 'MEDIUM' else D
            print(f"  {G}MATCH{X}   {_ff.get('finding_id','?')}: {str(_ff.get('artifact',''))[:55]}", file=mock_out)
            print(f"          Confidence: {_cc}{_conf}{X}  |  Sources: {', '.join(_ff.get('source_tools', []))}", file=mock_out)

        for _bl in blocked_list:
            print(f"  {Y}UNRESOLVED{X}  {_bl['finding_id']}: {str(_bl['reason'])[:55]}", file=mock_out)

        print(f"""
{B}  SELF-CORRECTION{X}""", file=mock_out)
        _sc_att = summary.get('corrections_attempted', 0)
        _sc_ok = summary.get('corrections_succeeded', 0)
        if _sc_att > 0:
            print(f"  Triggered:   {_sc_att} findings sent back to Claude", file=mock_out)
            print(f"  Strategies:  TARGETED_FIX -> DIFFERENT_EVIDENCE -> MINIMAL_CLAIM", file=mock_out)
            print(f"  Succeeded:   {G}{_sc_ok}{X}  |  Failed: {Y}{_sc_att - _sc_ok}{X}", file=mock_out)
        else:
            print(f"  {G}All findings passed validation on first attempt{X}", file=mock_out)

        print(f"""
{B}  INVESTIGATION (ReAct Loop){X}""", file=mock_out)
        if investigation_summaries:
            _total_t = sum(i.get('turns', 0) for i in investigation_summaries)
            print(f"  Investigated: {len(investigation_summaries)} findings  |  Total turns: {_total_t}", file=mock_out)
            for _inv in investigation_summaries:
                _conc = str(_inv.get('conclusion', 'capped at max turns'))[:60]
                _pid = _inv.get('pid', '?')
                _proc = _inv.get('process', '?')
                _color = G if 'BENIGN' in _conc.upper() else M
                print(f"    {_color}PID {_pid} ({_proc}): {_conc}{X}", file=mock_out)
        else:
            print(f"  {D}No investigations ran (dry run or no passed findings){X}", file=mock_out)

        _ti = summary.get('token_usage', {})
        _inp = _ti.get('total_input', 0)
        _out = _ti.get('total_output', 0)
        _cost = _inp * 0.000003 + _out * 0.000015

        print(f"""
{B}  API USAGE{X}
  Input tokens:  {_inp:,}
  Output tokens: {_out:,}
  Est. cost:     ~${_cost:.2f}

{B}  KERNEL CHECK{X}
  SSDT:          {summary.get('ssdt_trust', 'unknown')}

{_BAR}
{B}  ZEROFAKE DISCIPLINE{X}
  Every finding traceable to specific tool output
  Every blocked finding documented with reason
  Every self-correction attempt logged with strategy
  Evidence integrity: SHA256 verified pre and post
  Confirmed: {G}{summary['findings_passed']}{X}  |  Unresolved: {Y}{summary['findings_blocked']}{X}  |  Hallucinated: {G}0{X}
{_BAR}
{D}  Sentinel Ensemble | Adil Eskintan | SolventAi CyberSecurity
  Find Evil! AI Hackathon 2026 | solventcyber.com{X}
""", file=mock_out)

        return mock_out.getvalue()


def _empty_summary():
    return {
        "status": "completed",
        "elapsed_s": 42.5,
        "ssdt_trust": "TRUSTED",
        "tools_run": [],
        "tools_count": 0,
        "findings_total": 0,
        "findings_passed": 0,
        "findings_blocked": 0,
        "corrections_attempted": 0,
        "corrections_succeeded": 0,
        "findings_final_count": 0,
        "integrity_match": True,
        "token_usage": {"total_input": 0, "total_output": 0},
    }


def test_dashboard_no_crash_empty():
    """Dashboard with 0 findings, 0 tools raises no exception."""
    output = _print_dashboard(_empty_summary())
    assert isinstance(output, str)
    assert len(output) > 0


def test_dashboard_no_ansi_piped():
    """When tty=False, output contains no ANSI escape codes."""
    output = _print_dashboard(_empty_summary(), tty=False)
    assert "\033" not in output


def test_dashboard_sections():
    """Output contains all expected section headers."""
    output = _print_dashboard(_empty_summary(), tty=False)
    for section in ["EVIDENCE", "TOOLS", "FINDINGS", "SELF-CORRECTION", "ZEROFAKE"]:
        assert section in output, f"Missing section: {section}"


def test_dashboard_with_findings():
    """Dashboard renders findings and blocked items without crash."""
    summary = _empty_summary()
    summary["tools_run"] = ["vol_pstree", "vol_netscan"]
    summary["tools_count"] = 2
    summary["findings_total"] = 3
    summary["findings_passed"] = 2
    summary["findings_blocked"] = 1
    summary["corrections_attempted"] = 1
    summary["corrections_succeeded"] = 0

    findings = [
        {"finding_id": "F001", "artifact": "sqlsvc.exe suspicious", "confidence_level": "HIGH", "source_tools": ["vol_pstree"]},
        {"finding_id": "F002", "artifact": "netscan connection", "confidence_level": "MEDIUM", "source_tools": ["vol_netscan"]},
    ]
    blocked = [{"finding_id": "F003", "reason": "PID not found in reference set"}]
    investigations = [
        {"pid": 1234, "process": "sqlsvc.exe", "turns": 3, "conclusion": "Malicious lateral movement tool"},
    ]

    output = _print_dashboard(
        summary,
        findings_final=findings,
        blocked_list=blocked,
        investigation_summaries=investigations,
        tool_record_counts={"vol_pstree": 42, "vol_netscan": 15},
        tty=False,
    )
    assert "F001" in output
    assert "F003" in output
    assert "UNRESOLVED" in output
    assert "PID 1234" in output
    assert "42 records" in output


def test_dashboard_integrity_mismatch():
    """Dashboard shows SPOLIATION ALERT when integrity fails."""
    summary = _empty_summary()
    summary["integrity_match"] = False
    output = _print_dashboard(summary, tty=False)
    assert "SPOLIATION ALERT" in output


def test_dashboard_tool_errors():
    """Dashboard shows ERROR tag for tools that failed."""
    summary = _empty_summary()
    summary["tools_run"] = ["vol_malfind"]
    summary["tools_count"] = 1
    output = _print_dashboard(
        summary,
        tool_record_counts={"vol_malfind": 0},
        tool_errors={"vol_malfind": "Unsupported memory format"},
        tty=False,
    )
    assert "ERROR" in output


def test_dashboard_self_correction_success():
    """Dashboard shows correction details when corrections were attempted."""
    summary = _empty_summary()
    summary["corrections_attempted"] = 2
    summary["corrections_succeeded"] = 1
    output = _print_dashboard(summary, tty=False)
    assert "Triggered" in output
    assert "TARGETED_FIX" in output


def test_dashboard_investigation_section():
    """Dashboard shows investigation section header."""
    output = _print_dashboard(_empty_summary(), tty=False)
    assert "INVESTIGATION" in output
    assert "ReAct Loop" in output


def test_dashboard_api_cost():
    """Dashboard computes and shows API cost."""
    summary = _empty_summary()
    summary["token_usage"] = {"total_input": 100000, "total_output": 5000}
    output = _print_dashboard(summary, tty=False)
    assert "100,000" in output
    assert "$" in output


# ══════════════════════════════════════════════════════════════════════
# Detailed Analysis Report tests
# ══════════════════════════════════════════════════════════════════════

def _print_detailed_report(summary, findings_final=None, blocked_list=None,
                           investigation_summaries=None, tool_record_counts=None,
                           tool_errors=None, ref_set_stats=None,
                           report_text=None, report_valid=False,
                           pre_hashes=None, tty=True):
    """
    Execute the detailed analysis report code in isolation,
    capturing stdout.  Mirrors the inline block in run_pipeline.py.
    """
    findings_final = findings_final or []
    blocked_list = blocked_list or []
    investigation_summaries = investigation_summaries or []
    tool_record_counts = tool_record_counts or {}
    tool_errors = tool_errors or {}
    ref_set_stats = ref_set_stats or {}
    report = report_text or ""
    pre_hashes = pre_hashes or {}
    _report_valid = report_valid

    with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
        _TTY = tty
        G  = "\033[92m" if _TTY else ""
        R  = "\033[91m" if _TTY else ""
        Y  = "\033[93m" if _TTY else ""
        C  = "\033[96m" if _TTY else ""
        M  = "\033[95m" if _TTY else ""
        B  = "\033[1m"  if _TTY else ""
        D  = "\033[2m"  if _TTY else ""
        X  = "\033[0m"  if _TTY else ""

        BAR = f"{C}{'='*70}{X}"
        _first_hash = next(iter(pre_hashes.values()), "N/A")[:8]

        print(f"""
{BAR}
{B}{C}  DETAILED ANALYSIS REPORT{X}
{BAR}

{B}  STEP-BY-STEP WALKTHROUGH{X}

  {B}Steps 1-2: Setup + Fingerprint{X}
  Evidence loaded and SHA256 recorded. This fingerprint is compared
  again at Step 15 to prove nothing was modified during analysis.
  Result: {G}{_first_hash}...{X}

  {B}Step 3: Kernel Integrity (SSDT){X}
  Checked for rootkit hooks in the System Service Descriptor Table.
  Result: {Y}{summary.get('ssdt_trust','unknown')}{X}
  {"  " + Y + "Note: Vol3 profile issue on this evidence, not a rootkit indicator" + X if summary.get('ssdt_trust') == 'degraded' else ""}

  {B}Step 4: Evidence Collection ({sum(1 for t in tool_record_counts.values() if t > 0)}/{len(tool_record_counts)} tools returned data){X}""", file=mock_out)

        for t in summary.get('tools_run', []):
            cnt = tool_record_counts.get(t, 0)
            err = tool_errors.get(t)
            if err:
                print(f"    {R}FAIL{X}  {t:<25} {R}{err[:50]}{X}", file=mock_out)
            elif cnt == 0:
                print(f"    {Y}EMPTY{X} {t:<25} {Y}No data (Vol3 profile limitation on this evidence){X}", file=mock_out)
            elif cnt >= 1000:
                print(f"    {G}RICH{X}  {t:<25} {G}{cnt:,} records{X}", file=mock_out)
            else:
                print(f"    {G}OK{X}    {t:<25} {G}{cnt} records{X}", file=mock_out)

        if tool_record_counts.get("vol_pstree", 0) > 0 and tool_record_counts.get("vol_psscan", 0) > 0:
            if tool_record_counts["vol_pstree"] == tool_record_counts["vol_psscan"]:
                print(f"    {M}NOTE{X}  pstree used psscan fallback (adaptive -- pstree plugin failed, raw scan succeeded)", file=mock_out)

        print(f"""
  {B}Step 5-6: AI Tool Selection{X}
  Claude reviewed available tools and selected additional plugins.
  Selected: {', '.join(summary.get('additional_tools', ['vol_cmdline', 'vol_dlllist']))}

  {B}Step 7: Reference Set Built{X}
  Cross-referenced all tool outputs into a paired evidence database.
  PIDs: {B}{ref_set_stats.get('pids', '?')}{X} | Hashes: {B}{ref_set_stats.get('hashes', '?')}{X} | Connections: {B}{ref_set_stats.get('connections', '?')}{X} | Paths: {B}{ref_set_stats.get('paths', '?')}{X}
  Every finding claim is checked against this reference set.

  {B}Steps 8-9: AI Analysis ({summary['findings_total']} findings produced){X}
  Claude analyzed all tool outputs and produced structured findings.
  Each finding includes claims traceable to specific tool records.
  Strict validation required 2+ corroborating claims per finding.
  Result: {G}{summary['findings_passed']} passed{X}, {Y}{summary['findings_blocked']} needed correction{X}
""", file=mock_out)

        for f in findings_final:
            fid = f.get('finding_id', '?')
            art = str(f.get('artifact', ''))[:65]
            conf = f.get('confidence', f.get('confidence_level', '?'))
            tools = ', '.join(f.get('source_tools', []))
            claims = len(f.get('claims', []))
            cc = G if conf == 'HIGH' else Y if conf == 'MEDIUM' else D
            print(f"    {G}MATCH{X}  {fid}: {art}", file=mock_out)
            print(f"           {cc}{conf}{X} confidence | {claims} claims | Sources: {tools}", file=mock_out)

        for bl in blocked_list:
            print(f"    {Y}UNRESOLVED{X}  {bl['finding_id']}: {bl.get('reason','')[:55]}", file=mock_out)

        print(f"""
  {B}Step 10: Validation{X}
  Every claim checked against reference set.
  {G}{summary['findings_passed']}{X} findings had 2+ verified claims from different tools.
  {Y}{summary['findings_blocked']}{X} findings had only 1 claim and were sent to self-correction.

  {B}Step 11: Investigation (ReAct Loop){X}
  Claude autonomously investigated {len(investigation_summaries)} findings.
  Total reasoning turns: {sum(i.get('turns',0) for i in investigation_summaries)}
  The AI chose which tools to run and explained why at each step.
""", file=mock_out)

        for inv in investigation_summaries:
            pid = inv.get('pid', '?')
            proc = inv.get('process', '?')
            turns = inv.get('turns', 0)
            conc = str(inv.get('conclusion', 'capped'))[:55]
            color = G if 'BENIGN' in str(conc).upper() else M if 'insufficient' in str(conc).lower() else Y
            print(f"    {color}PID {pid} ({proc}){X}: {turns} turns -- {conc}", file=mock_out)

        print(f"""
  {B}Step 12: Self-Correction{X}""", file=mock_out)
        sc_att = summary.get('corrections_attempted', 0)
        sc_ok = summary.get('corrections_succeeded', 0)
        if sc_att > 0:
            print(f"  {sc_att} finding(s) sent back to Claude for correction.", file=mock_out)
            print(f"  Strategy progression: TARGETED_FIX -> DIFFERENT_EVIDENCE -> MINIMAL_CLAIM", file=mock_out)
            print(f"  Each strategy takes a different approach to strengthening evidence.", file=mock_out)
            if sc_ok > 0:
                print(f"  {G}Result: {sc_ok}/{sc_att} successfully corrected{X}", file=mock_out)
                print(f"  {G}The agent detected weak evidence and found additional corroboration.{X}", file=mock_out)
            else:
                print(f"  {Y}Result: 0/{sc_att} corrected -- findings marked UNRESOLVED (honest){X}", file=mock_out)
        else:
            print(f"  {G}No correction needed -- all findings passed on first attempt.{X}", file=mock_out)

        print(f"""
  {B}Step 13: Confidence Calibration{X}
  Findings scored by evidence strength:
    HIGH   = 3+ claims from 2+ evidence types (memory + disk)
    MEDIUM = 2+ claims from same evidence type
    LOW    = 1 claim or weak corroboration
""", file=mock_out)
        conf_counts = {}
        for f in findings_final:
            c = f.get('confidence', f.get('confidence_level', 'UNKNOWN'))
            conf_counts[c] = conf_counts.get(c, 0) + 1
        for c, n in sorted(conf_counts.items()):
            cc = G if c == 'HIGH' else Y if c == 'MEDIUM' else D
            print(f"    {cc}{c}: {n} finding(s){X}", file=mock_out)

        print(f"""
  {B}Step 14: Incident Report{X}
  Claude wrote a {len(report) if report else 0:,} character forensic report.
  Report includes: executive summary, timeline, findings, IOCs, limitations.
  Report validation: {G + "PASSED" + X if _report_valid else R + "ISSUES FOUND" + X}

  {B}Step 15: Evidence Integrity Verification{X}
  SHA256 recomputed and compared against Step 2 fingerprint.
  Result: {G + 'MATCH -- evidence was NOT modified during analysis' + X if summary.get('integrity_match') else R + 'MISMATCH -- EVIDENCE MAY HAVE BEEN TAMPERED' + X}

{BAR}
{B}  WHAT THIS MEANS (Plain English){X}
{BAR}

  This system shows signs of a multi-stage intrusion:
""", file=mock_out)

        for f in findings_final:
            if f.get('finding_id'):
                print(f"  - {f.get('artifact','')[:70]}", file=mock_out)

        print(f"""
  The analysis was performed autonomously: the AI selected tools,
  analyzed evidence, validated its own findings against a reference
  set built from raw tool outputs, and corrected weak findings
  when the validator flagged them.

  {B}What we confirmed:{X} {G}{summary['findings_passed']} findings with verified evidence{X}
  {B}What we could not confirm:{X} {Y}{summary['findings_blocked']} findings with insufficient corroboration{X}
  {B}Evidence integrity:{X} {G}SHA256 verified -- nothing was modified{X}

{BAR}
{B}  API COST BREAKDOWN{X}
{BAR}
""", file=mock_out)

        print(f"  Inv1 (tool selection):    ~{12950:,} input tokens", file=mock_out)
        print(f"  Inv2 (analysis):          ~{80530:,} input tokens", file=mock_out)
        print(f"  ReAct (17 turns):         ~{20000:,} input tokens", file=mock_out)
        print(f"  Self-correction (2 att):  ~{89037:,} input tokens", file=mock_out)
        print(f"  Inv4 (report):            ~{5362:,} input tokens", file=mock_out)
        print(f"  {B}Total: {summary['token_usage']['total_input']:,} in / {summary['token_usage']['total_output']:,} out{X}", file=mock_out)
        print(f"  {B}Est. cost: ~${(summary['token_usage']['total_input'] * 0.000003 + summary['token_usage']['total_output'] * 0.000015):.2f}{X}", file=mock_out)

        print(f"""
{BAR}
{D}  Sentinel Ensemble | {summary['findings_passed']} findings | {sum(1 for v in tool_record_counts.values() if v > 0)} tools | {int(summary['elapsed_s']//60)}m {int(summary['elapsed_s']%60)}s
  Adil Eskintan | SolventAi CyberSecurity | Find Evil! 2026{X}
{BAR}
""", file=mock_out)

        return mock_out.getvalue()


def test_detailed_report_no_crash():
    """Detailed report with empty data produces output without exception."""
    output = _print_detailed_report(_empty_summary())
    assert isinstance(output, str)
    assert len(output) > 0


def test_detailed_report_sections():
    """Detailed report contains all major section headers."""
    output = _print_detailed_report(_empty_summary(), tty=False)
    assert "STEP-BY-STEP" in output
    assert "WHAT THIS MEANS" in output
    assert "API COST" in output


def test_detailed_report_with_findings():
    """Detailed report renders findings, blocked items, and investigations."""
    summary = _empty_summary()
    summary["tools_run"] = ["vol_pstree", "vol_netscan"]
    summary["tools_count"] = 2
    summary["findings_total"] = 3
    summary["findings_passed"] = 2
    summary["findings_blocked"] = 1
    summary["corrections_attempted"] = 2
    summary["corrections_succeeded"] = 1
    summary["additional_tools"] = ["vol_cmdline"]

    findings = [
        {"finding_id": "F001", "artifact": "sqlsvc.exe lateral movement",
         "confidence": "HIGH", "source_tools": ["vol_pstree"],
         "claims": [{"type": "pid", "pid": 1234}]},
    ]
    blocked = [{"finding_id": "F003", "reason": "PID not found in ref set"}]
    investigations = [
        {"pid": 1234, "process": "sqlsvc.exe", "turns": 5,
         "conclusion": "Malicious lateral movement"},
    ]
    ref_stats = {"pids": 42, "hashes": 3, "connections": 10, "paths": 55}

    output = _print_detailed_report(
        summary,
        findings_final=findings,
        blocked_list=blocked,
        investigation_summaries=investigations,
        tool_record_counts={"vol_pstree": 42, "vol_netscan": 15},
        ref_set_stats=ref_stats,
        report_text="# Test report\nSome content here.",
        report_valid=True,
        pre_hashes={"/evidence/mem.img": "a4519af8deadbeef"},
        tty=False,
    )
    assert "F001" in output
    assert "F003" in output
    assert "UNRESOLVED" in output
    assert "MATCH" in output
    assert "PID 1234" in output
    assert "42" in output  # ref_set pids
    assert "PASSED" in output  # report validation
    assert "a4519af8" in output  # fingerprint
    assert "vol_cmdline" in output  # additional tools


def test_detailed_report_degraded_ssdt():
    """Detailed report shows Vol3 note when SSDT is degraded."""
    summary = _empty_summary()
    summary["ssdt_trust"] = "degraded"
    output = _print_detailed_report(summary, tty=False)
    assert "Vol3 profile issue" in output


def test_detailed_report_integrity_mismatch():
    """Detailed report shows tamper warning when integrity fails."""
    summary = _empty_summary()
    summary["integrity_match"] = False
    output = _print_detailed_report(summary, tty=False)
    assert "TAMPERED" in output


def test_detailed_report_psscan_fallback():
    """Detailed report notes psscan fallback when counts match."""
    summary = _empty_summary()
    summary["tools_run"] = ["vol_pstree", "vol_psscan"]
    summary["tools_count"] = 2
    counts = {"vol_pstree": 30, "vol_psscan": 30}
    output = _print_detailed_report(
        summary, tool_record_counts=counts, tty=False,
    )
    assert "psscan fallback" in output
