"""WHO attribution from Security 4688 process-creation events.

Universal, dataset-agnostic: joins a still-blank disk-execution finding to the
launching user via NewProcessName basename -> SubjectUserName. No case literals.
"""
import json

import pytest

from sift_sentinel.analysis import logon_actor as la
from sift_sentinel.analysis.finding_actor_time import derive_actor


def _evt4688(subject_sid, subject_user, new_proc, ts="2021-09-16T03:07:00Z"):
    # EvtxECmd Message = ordered EventData pipe-join:
    # [0]SubjectUserSid [1]SubjectUserName [2]Domain [3]LogonId
    # [4]NewProcessId [5]NewProcessName [6]TokenElev [7]ProcessId [8]CommandLine
    msg = "|".join([subject_sid, subject_user, "CORP", "0x1a2b",
                    "0xabc", new_proc, "%%1936", "0x4", '"x" /run'])
    return {"canonical_entity_id": "4688",
            "raw_excerpt": json.dumps({"EventID": 4688, "Message": msg,
                                       "TimeCreated": ts})}


def _edb(*facts):
    return {"typed_facts": {"event_log_fact": list(facts)}}


_USER_SID = "S-1-5-21-1004336348-1177238915-682003330-1001"


def test_4688_maps_image_to_human_launcher():
    edb = _edb(_evt4688(_USER_SID, "jsmith", r"C:\Windows\System32\schtasks.exe"))
    m = la.build_launch_user_map_from_4688(edb)
    assert m == {"schtasks.exe": "jsmith"}


def test_4688_excludes_system_and_service_launchers():
    edb = _edb(
        _evt4688("S-1-5-18", "WKSTN$", r"C:\Windows\System32\svchost.exe"),
        _evt4688("S-1-5-19", "LOCAL SERVICE", r"C:\Windows\System32\sc.exe"),
    )
    assert la.build_launch_user_map_from_4688(edb) == {}


def test_4688_attributes_blank_disk_execution_finding():
    edb = _edb(_evt4688(_USER_SID, "jsmith", r"C:\Windows\System32\schtasks.exe"))
    f = {"id": "F022", "title": "System32 schtasks.exe execution evidence",
         "claims": [{"type": "path", "value": r"c:\windows\system32\schtasks.exe"}]}
    assert derive_actor(f) == ""
    assert la.resolve_actors_from_process_creation([f], edb) == 1
    assert derive_actor(f) == "jsmith"


def test_4688_never_overwrites_an_existing_actor():
    edb = _edb(_evt4688(_USER_SID, "jsmith", r"C:\Windows\System32\cmd.exe"))
    f = {"id": "F1", "title": "cmd.exe execution",
         "claims": [{"type": "user_account", "value": "administrator"},
                    {"type": "path", "value": r"c:\windows\system32\cmd.exe"}]}
    assert la.resolve_actors_from_process_creation([f], edb) == 0
    assert derive_actor(f) == "administrator"      # unchanged


def test_4688_no_match_stays_blank_no_fabrication():
    # 4688 names powershell.exe, but the finding is about a tool with no 4688 record.
    edb = _edb(_evt4688(_USER_SID, "jsmith", r"C:\Windows\System32\powershell.exe"))
    f = {"id": "F2", "title": "regsvr32.exe execution evidence",
         "claims": [{"type": "path", "value": r"c:\windows\syswow64\regsvr32.exe"}]}
    assert la.resolve_actors_from_process_creation([f], edb) == 0
    assert derive_actor(f) == ""                    # honest blank preserved


def test_4688_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_LOGON_ACTOR", "0")
    edb = _edb(_evt4688(_USER_SID, "jsmith", r"C:\Windows\System32\schtasks.exe"))
    assert la.build_launch_user_map_from_4688(edb) == {}
    f = {"id": "F3", "claims": [{"type": "path", "value": r"c:\windows\system32\schtasks.exe"}]}
    assert la.resolve_actors_from_process_creation([f], edb) == 0


def test_4688_ignores_non_4688_events():
    # a 4624 logon must not be mined by the 4688 pass
    edb = _edb({"canonical_entity_id": "4624",
                "raw_excerpt": json.dumps({"EventID": 4624,
                                           "Message": _USER_SID + "|jsmith|CORP|0x1"})})
    assert la.build_launch_user_map_from_4688(edb) == {}
