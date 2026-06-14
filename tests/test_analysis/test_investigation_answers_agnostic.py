"""Standing universality guards: the resolver may never bake in case data,
and with no evidence it must abstain rather than fabricate."""
from __future__ import annotations
import re
from pathlib import Path
import sift_sentinel.analysis.investigation_answers as _m
from sift_sentinel.analysis.investigation_answers import resolve

_SRC = Path(_m.__file__).read_text()


def test_no_hardcoded_ip_literals():
    ips = re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', _SRC)
    assert not ips, "resolver hardcodes IP literals: %s" % ips


def test_no_case_data_or_answer_key():
    low = _SRC.lower()
    for bad in ("answer_key", "answerkey", "cheat", "ground_truth",
                "groundtruth", "/cases/", "fredr", "rocba"):
        assert bad not in low, "resolver references case data: %s" % bad


def test_empty_evidence_abstains():
    a = resolve({"typed_facts": {}, "indexes": {}}, {})
    assert a["external_endpoints"] == [] and a["projects_files"] == []
    assert a["candidate_stolen"] == [] and a["activity_window"] is None
    assert a["principal"] is None
