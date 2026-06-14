"""WHO-from-logons + SYSTEM/service execution-context labeling (universal).

Grounded in the REAL compiled shapes verified from Security.evtx output:
  * event_log_fact.raw_excerpt is EvtxECmd JSON; the 4624 ``Message`` is
    pipe-delimited ``... | TargetUserSid[4] | TargetUserName[5] |
    TargetDomainName[6] | TargetLogonId[7] | LogonType[8] | ...``.
  * sid_fact.artifact is ``[process, account_or_group, sid]`` with no PID.
No case data: Event-ID + SID class + LogonType grammar only.
"""
import json

from sift_sentinel.analysis.logon_actor import (
    parse_human_logons,
    build_process_identity_map,
    derive_execution_context,
    enrich_findings_with_logon_context,
    summarize_logon_context,
    build_logon_context_section,
    insert_logon_context_into_report,
    SERVICE_CONTEXT_LABEL,
)


def _logon_msg(target_sid, target_user, target_dom, logon_type, ip="-"):
    # SubjSid | SubjUser | SubjDom | SubjLogonId | TargetSid | TargetUser |
    # TargetDom | TargetLogonId | LogonType | LogonProc | AuthPkg | WorkstationName
    # | LogonGuid | TransmittedServices | LmPackage | KeyLength | ProcessId |
    # ProcessName | IpAddress | IpPort
    fields = [
        "S-1-0-0", "-", "-", "0x0", target_sid, target_user, target_dom,
        "0x1a2b", str(logon_type), "User32", "Negotiate", "HOSTA",
        "{guid}", "-", "-", "0", "0x0", "C:\\Windows\\System32\\winlogon.exe",
        ip, "0",
    ]
    return " | ".join(fields)


def _evt(event_id, msg, when="2026-06-09 12:00:00.000000+00:00"):
    return {
        "fact_type": "event_log_fact",
        "canonical_entity_id": str(event_id),
        "source_tool": "parse_event_logs",
        "raw_excerpt": json.dumps({
            "EventID": int(event_id), "TimeCreated": when,
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Channel": "Security", "Message": msg, "SourceFile": "Security.evtx",
        }),
    }


def _sid_fact(process, name, sid):
    return {"fact_type": "sid_fact", "pid": None,
            "artifact": [process, name, sid]}


def _db(event_facts=None, sid_facts=None):
    return {"typed_facts": {
        "event_log_fact": event_facts or [],
        "sid_fact": sid_facts or [],
    }}


# ── parse_human_logons ───────────────────────────────────────────────────────
def test_rdp_human_logon_is_extracted():
    db = _db(event_facts=[_evt("4624", _logon_msg(
        "S-1-5-21-111-222-333-1105", "jdoe", "CORP", 10, ip="203.0.113.50"))])
    logons = parse_human_logons(db)
    assert len(logons) == 1
    e = logons[0]
    assert e["user"] == "jdoe"
    assert e["domain"] == "CORP"
    assert e["logon_type"] == 10
    assert e["logon_type_name"] == "RemoteInteractive (RDP)"
    assert e["source_ip"] == "203.0.113.50"


def test_interactive_console_logon_is_extracted():
    db = _db(event_facts=[_evt("4624", _logon_msg(
        "S-1-5-21-1-2-3-500", "Administrator", "HOSTA", 2))])
    logons = parse_human_logons(db)
    assert len(logons) == 1 and logons[0]["logon_type_name"] == "Interactive"
    assert logons[0]["user"] == "Administrator"      # RID 500 is a human acct


def test_machine_account_logon_is_not_human():
    # network logon by the machine account -> not a person at the box
    db = _db(event_facts=[_evt("4624", _logon_msg(
        "S-1-5-18", "HOSTA$", "CORP", 3))])
    assert parse_human_logons(db) == []


def test_service_logon_is_not_human():
    db = _db(event_facts=[_evt("4624", _logon_msg(
        "S-1-5-18", "SYSTEM", "NT AUTHORITY", 5))])
    assert parse_human_logons(db) == []


def test_non_4624_event_is_ignored():
    db = _db(event_facts=[_evt("4672", _logon_msg(
        "S-1-5-21-1-2-3-1105", "jdoe", "CORP", 2))])
    assert parse_human_logons(db) == []


def test_logons_dedup_on_account_and_type():
    db = _db(event_facts=[
        _evt("4624", _logon_msg("S-1-5-21-1-2-3-1105", "jdoe", "CORP", 10),
             when="2026-06-09 10:00:00+00:00"),
        _evt("4624", _logon_msg("S-1-5-21-1-2-3-1105", "jdoe", "CORP", 10),
             when="2026-06-09 08:00:00+00:00"),
    ])
    logons = parse_human_logons(db)
    assert len(logons) == 1
    assert logons[0]["count"] == 2
    assert logons[0]["time"] == "2026-06-09 08:00:00+00:00"   # earliest kept


def test_kill_switch_disables_logon_parse(monkeypatch):
    monkeypatch.setenv("SIFT_LOGON_ACTOR", "0")
    db = _db(event_facts=[_evt("4624", _logon_msg(
        "S-1-5-21-1-2-3-1105", "jdoe", "CORP", 10))])
    assert parse_human_logons(db) == []


# ── build_process_identity_map ───────────────────────────────────────────────
def test_system_process_is_service_context():
    db = _db(sid_facts=[
        _sid_fact("smss.exe", "Local System", "S-1-5-18"),
        _sid_fact("smss.exe", "Administrators", "S-1-5-32-544"),
    ])
    m = build_process_identity_map(db)
    assert m["smss.exe"]["context"] == "system_service"
    assert m["smss.exe"]["user"] == ""


def test_user_process_resolves_account_by_process_name():
    # sid_fact has no PID -> resolution must key on process NAME
    db = _db(sid_facts=[
        _sid_fact("rdpclip.exe", "CORP\\jdoe", "S-1-5-21-1-2-3-1105"),
        _sid_fact("rdpclip.exe", "Everyone", "S-1-1-0"),
    ])
    m = build_process_identity_map(db)
    assert m["rdpclip.exe"]["user"] == "jdoe"
    assert m["rdpclip.exe"]["context"] == "user"


# ── derive_execution_context ─────────────────────────────────────────────────
def test_finding_on_system_process_labelled_service_context():
    db = _db(sid_facts=[_sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    m = build_process_identity_map(db)
    f = {"claims": [{"type": "pid", "pid": 612, "process": "lsass.exe"}]}
    assert derive_execution_context(f, m) == SERVICE_CONTEXT_LABEL


def test_finding_on_user_process_labelled_with_user():
    db = _db(sid_facts=[_sid_fact("powershell.exe", "CORP\\jdoe",
                                  "S-1-5-21-1-2-3-1105")])
    m = build_process_identity_map(db)
    f = {"description": "powershell.exe spawned an encoded command"}
    assert derive_execution_context(f, m) == "jdoe"


def test_finding_with_no_process_is_blank():
    db = _db(sid_facts=[_sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    m = build_process_identity_map(db)
    assert derive_execution_context({"description": "a registry key"}, m) == ""


def test_user_wins_over_service_when_both_present():
    db = _db(sid_facts=[
        _sid_fact("svc.exe", "Local System", "S-1-5-18"),
        _sid_fact("app.exe", "CORP\\jdoe", "S-1-5-21-1-2-3-1105"),
    ])
    m = build_process_identity_map(db)
    f = {"description": "svc.exe and app.exe both ran"}
    assert derive_execution_context(f, m) == "jdoe"


# ── summarize_logon_context ──────────────────────────────────────────────────
def test_summary_combines_logons_and_service_flag():
    db = _db(
        event_facts=[_evt("4624", _logon_msg(
            "S-1-5-21-1-2-3-1105", "jdoe", "CORP", 10))],
        sid_facts=[_sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    s = summarize_logon_context(db)
    assert s["logon_count"] == 1
    assert s["any_service_only"] is True
    assert s["human_logons"][0]["user"] == "jdoe"


# ── enrich_findings_with_logon_context (pipeline mutation) ───────────────────
def test_enrich_attaches_user_claim_and_service_context():
    db = _db(sid_facts=[
        _sid_fact("explorer.exe", "CORP\\jdoe", "S-1-5-21-1-2-3-1105"),
        _sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    findings = [
        {"finding_id": "FB", "description": "explorer.exe spawned cmd"},
        {"finding_id": "FA", "claims": [{"type": "pid", "pid": 1,
                                         "process": "lsass.exe"}]},
        {"finding_id": "FC", "description": "a registry Run key"},
    ]
    n_user, n_service = enrich_findings_with_logon_context(findings, db)
    assert n_user == 1 and n_service == 1
    assert any(c.get("type") == "user_account" and c.get("value") == "jdoe"
               for c in findings[0]["claims"])
    assert findings[1]["execution_context"] == SERVICE_CONTEXT_LABEL
    assert "execution_context" not in findings[2]      # no process -> blank


def test_enrich_does_not_overwrite_existing_actor():
    db = _db(sid_facts=[_sid_fact("explorer.exe", "CORP\\jdoe",
                                  "S-1-5-21-1-2-3-1105")])
    f = {"finding_id": "F", "description": "explorer.exe",
         "claims": [{"type": "user_account", "value": "someoneelse"}]}
    n_user, _ = enrich_findings_with_logon_context([f], db)
    assert n_user == 0                                 # already had an actor


# ── report section ───────────────────────────────────────────────────────────
def test_logon_section_renders_logons_owner_and_context():
    db = _db(
        event_facts=[_evt("4624", _logon_msg(
            "S-1-5-21-1-2-3-1105", "jdoe", "CORP", 10, ip="203.0.113.50"))],
        sid_facts=[
            _sid_fact("explorer.exe", "CORP\\jdoe", "S-1-5-21-1-2-3-1105"),
            _sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    sec = build_logon_context_section(db)
    assert sec.startswith("## Accounts & Logon Context")
    assert "RemoteInteractive (RDP)" in sec
    assert "203.0.113.50" in sec
    assert "jdoe" in sec and "explorer.exe" in sec
    assert "SYSTEM / service" in sec and "lsass.exe" in sec


def test_logon_section_empty_without_evidence():
    assert build_logon_context_section(_db()) == ""


def test_insert_logon_section_is_idempotent():
    db = _db(sid_facts=[_sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    base = "# Report\n\n## Key Findings\n\nstuff\n"
    md1, n1 = insert_logon_context_into_report(base, db)
    assert n1 > 0 and md1.count("## Accounts & Logon Context") == 1
    md2, _ = insert_logon_context_into_report(md1, db)
    assert md2.count("## Accounts & Logon Context") == 1     # replaced, not dup'd


def test_insert_anchors_after_per_user_attribution():
    db = _db(sid_facts=[_sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    base = ("# R\n\n## Per-User Attribution\n\nusers\n\n## Key Findings\n\nx\n")
    md, _ = insert_logon_context_into_report(base, db)
    assert md.index("## Per-User Attribution") < md.index(
        "## Accounts & Logon Context") < md.index("## Key Findings")


def test_insert_section_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_LOGON_ACTOR", "0")
    db = _db(sid_facts=[_sid_fact("lsass.exe", "Local System", "S-1-5-18")])
    md, n = insert_logon_context_into_report("# R\n", db)
    assert n == 0 and "Accounts & Logon Context" not in md
