"""Anti-forensics signal precision (alice inversion fix). The matcher must key on
a wiper/log-clear token in REAL execution evidence, never on:
  * a filesystem_timeline_fact field name ('timestomped': false -- a NEGATIVE),
  * a model-authored finding_excerpt ('(bcwipe)' annotating an installer).
And a MODEL declaration of anti_forensics is trusted only if the matcher fires;
a DETERMINISTIC finding's declaration is trusted by construction. Universal:
fact-type class + matcher structure, no case data.
"""
from sift_sentinel.analysis.malicious_semantics import (
    has_malicious_semantic,
    match_anti_forensics_execution as maf,
)


def test_real_wiper_event_fires():
    assert maf({"fact_type": "event_log_fact", "event_id": "7045",
                "message": "bcwipe service | c:\\program files"}) is True


def test_timestomped_false_field_does_not_fire():
    assert maf({"fact_type": "filesystem_timeline_fact",
                "timestomped": False, "path": "x"}) is False


def test_finding_excerpt_annotation_does_not_fire():
    assert maf({"fact_type": "finding_excerpt",
                "raw_excerpt_text": "installers; fact-0530 (bcwipe), 0216"}) is False


def test_real_wiper_cmdline_still_fires():
    assert maf({"fact_type": "process_cmdline_fact",
                "cmdline": "sdelete -z c:"}) is True


def test_model_declaration_dropped_when_matcher_does_not_fire():
    # model finding declares anti_forensics, but its facts (an installer excerpt)
    # never fire the matcher -> declaration dropped
    f = {"finding_id": "F010", "title": "installer executions",
         "malicious_semantic_signals": ["anti_forensics_execution"],
         "claims": [{"type": "path", "value": "Windows\\Temp\\vcredist_x86.exe"}],
         "raw_excerpt": "vcredist_x86.exe, setup.exe (bcwipe) cross-ref"}
    hs, sigs = has_malicious_semantic(f)
    assert "anti_forensics_execution" not in sigs


def test_deterministic_declaration_is_trusted():
    f = {"finding_id": "F041", "title": "anti forensics",
         "deterministic_finding": True,
         "malicious_semantic_provenance": True,
         "malicious_semantic_signals": ["anti_forensics_execution"],
         "claims": [{"type": "path", "value": "x"}]}
    hs, sigs = has_malicious_semantic(f)
    assert "anti_forensics_execution" in sigs
