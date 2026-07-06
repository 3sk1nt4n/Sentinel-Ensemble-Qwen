"""EvtxECmd fast-engine for parse_event_logs (SIFT_EVTX_EZT).

Guards the byte-compatibility contract that lets the compiled EvtxECmd engine
substitute for python-evtx without changing what downstream (logon_actor,
evidence_db) sees: the 6-field record schema, and the pipe-delimited EventData
Message whose field positions logon_actor parses (TargetUserName=field[5],
LogonType=field[8]). Universal: no case data.
"""
import json

import pytest

from sift_sentinel.tools.disk_extended import (
    _evtxecmd_message,
    _parse_evtx_with_evtxecmd,
)


# A real rd01 4624 Payload shape (ordered EventData.Data), trimmed.
_4624_PAYLOAD = json.dumps({
    "EventData": {"Data": [
        {"@Name": "SubjectUserSid", "#text": "S-1-5-18"},
        {"@Name": "SubjectUserName", "#text": "WIN$"},
        {"@Name": "SubjectDomainName", "#text": "WORKGROUP"},
        {"@Name": "SubjectLogonId", "#text": "0x3e7"},
        {"@Name": "TargetUserSid", "#text": "S-1-5-21-1"},
        {"@Name": "TargetUserName", "#text": "tdungan"},
        {"@Name": "TargetDomainName", "#text": "CORP"},
        {"@Name": "TargetLogonId", "#text": "0x9a"},
        {"@Name": "LogonType", "#text": "3"},
    ]},
})


def test_message_field_positions_match_logon_actor_contract():
    # logon_actor reads TargetUserName=field[5], LogonType=field[8].
    fields = _evtxecmd_message(_4624_PAYLOAD).split(" | ")
    assert fields[5] == "tdungan"
    assert fields[8] == "3"


def test_message_capped_at_200_chars():
    big = json.dumps({"EventData": {"Data": [
        {"@Name": "x", "#text": "A" * 500}]}})
    assert len(_evtxecmd_message(big)) == 200


def test_message_handles_single_dict_and_bare_strings():
    single = json.dumps({"EventData": {"Data": {"@Name": "x", "#text": "solo"}}})
    assert _evtxecmd_message(single) == "solo"
    bare = json.dumps({"EventData": {"Data": ["a", "b"]}})
    assert _evtxecmd_message(bare) == "a | b"


def test_message_never_raises_on_garbage():
    for junk in ("", "not json", "[]", "{}", '{"EventData": null}',
                 '{"EventData": {"Data": null}}'):
        assert _evtxecmd_message(junk) == ""


def test_fast_engine_returns_none_when_evtxecmd_absent(monkeypatch, tmp_path):
    # Fall through to python-evtx when the binary is not on PATH.
    monkeypatch.setattr("shutil.which", lambda _n: None)
    assert _parse_evtx_with_evtxecmd(tmp_path, 50000) is None


def test_fast_engine_maps_records_when_binary_present(monkeypatch, tmp_path):
    # Simulate EvtxECmd on PATH writing one JSONL record; assert the 6-field
    # schema and the compatible Message come back.
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/local/bin/EvtxECmd")

    def _fake_run(cmd, **kw):
        # cmd = [EvtxECmd, -d, <dir>, --json, <out>, --jsonf, evtxecmd.json]
        out_dir = cmd[cmd.index("--json") + 1]
        fname = cmd[cmd.index("--jsonf") + 1]
        import os as _os
        with open(_os.path.join(out_dir, fname), "w") as fh:
            fh.write(json.dumps({
                "EventId": 4624, "TimeCreated": "2018-09-06T16:37:25.0Z",
                "Provider": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security", "Computer": "WIN.corp",
                "Payload": _4624_PAYLOAD,
            }) + "\n")

        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr("subprocess.run", _fake_run)
    res = _parse_evtx_with_evtxecmd(tmp_path, 50000)
    assert res is not None
    assert res["engine"] == "EvtxECmd"
    assert res["record_count"] == 1
    rec = res["output"][0]
    assert set(rec) == {"EventID", "TimeCreated", "Provider", "Channel",
                        "Computer", "Message"}
    assert rec["EventID"] == 4624
    assert rec["Channel"] == "Security"
    assert rec["Message"].split(" | ")[5] == "tdungan"


def test_fast_engine_falls_through_on_no_output(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/local/bin/EvtxECmd")

    def _fake_run(cmd, **kw):
        class _R:
            returncode = 1
        return _R()  # writes no file -> fall through

    monkeypatch.setattr("subprocess.run", _fake_run)
    assert _parse_evtx_with_evtxecmd(tmp_path, 50000) is None
