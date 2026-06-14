"""D3 (title): deterministic candidate findings whose entity key is the raw
``artifact:["7045", "provider", ...]`` fallback tuple must get a HUMAN title
derived from the tuple's structured parts via the Event-ID grammar -- never the
raw JSON array, and never a hardcoded category phrase (the glossary decides:
4104 is PowerShell scriptblock, not 'service event').

Tolerant by construction: the fallback entity key is TRUNCATED upstream, so
parsing is regex-based (first quoted digit-token = event id, second quoted
token = provider); any parse failure keeps the legacy title (fail-closed).
Synthetic tuples only. Kill-switch SIFT_TITLE_SANITIZE_V1=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.candidate_findings import _entity_title_label  # noqa: E402

_RAW = 'artifact:["7045", "fabricated provider", "system", "2099-01-01 00:00:00", "fakething | c:\\\\somewhere\\\\x'


def test_event_tuple_becomes_grammar_label():
    lbl = _entity_title_label(_RAW)
    assert "artifact:[" not in lbl
    assert "event:7045" in lbl
    assert "service installed" in lbl          # glossary, not hardcoded prefix
    assert "fabricated provider" in lbl        # provider from the tuple itself


def test_out_of_map_event_id_keeps_id_prefix():
    lbl = _entity_title_label('artifact:["31337", "fabricated provider", "x"]')
    assert "event:31337" in lbl
    assert "artifact:[" not in lbl


def test_powershell_event_not_mislabelled_service():
    lbl = _entity_title_label('artifact:["4104", "fabricated-ps", "ops"]')
    assert "PowerShell scriptblock logged" in lbl
    assert "service" not in lbl.lower()


def test_non_artifact_keys_pass_through():
    assert _entity_title_label("path:c:/fake/thing.exe") == "path:c:/fake/thing.exe"
    assert _entity_title_label("ip:203.0.113.7") == "ip:203.0.113.7"


def test_unparseable_artifact_fails_closed():
    raw = "artifact:not-a-tuple-at-all"
    assert _entity_title_label(raw) == raw


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_TITLE_SANITIZE_V1", "0")
    assert _entity_title_label(_RAW) == _RAW
