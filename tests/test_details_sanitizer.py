"""The customer-facing Details must read as plain English, never leak internal
pipeline vocabulary: candidate IDs (cand-0005), raw signal/fact identifiers
(srum_usage_context, file_execution_fact, admin_or_lolbin_artifact), or scores.

Universal: the glossary keys on OUR OWN signal category names (universal behavior
categories), never on a case value (no IP/hash/filename/username)."""
import re

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    _sanitize_details,
)

_INTERNAL_SUFFIX = re.compile(r"_(?:fact|signal|context|artifact|usage)\b", re.IGNORECASE)


def test_strips_candidate_ids_and_scores():
    raw = "rundll32.exe shows execution. Candidate cand-0005 indicates srum_usage_context with score 0.83."
    out = _sanitize_details(raw)
    assert "cand-" not in out.lower()
    assert "score" not in out.lower()
    assert "srum_usage_context" not in out
    assert "SRUM" in out                      # translated, meaning preserved


def test_translates_staging_jargon_and_consumes_trailing_signal_word():
    raw = "Candidate cand-0018 indicates execution_from_staging_path signal with network telemetry."
    out = _sanitize_details(raw)
    assert "execution_from_staging_path" not in out
    assert "staging" in out.lower() or "temporary" in out.lower()
    assert "signal" not in out.lower()        # the dangling jargon word is consumed


def test_translates_admin_lolbin_artifact():
    raw = "Candidate cand-0029 indicates admin_or_lolbin_artifact with multi-source evidence."
    out = _sanitize_details(raw)
    assert "admin_or_lolbin_artifact" not in out
    assert "living-off-the-land" in out.lower() or "built-in windows" in out.lower()


def test_preserves_real_paths_and_binaries():
    raw = "Execution from C:\\Windows\\Temp\\stage\\tool.exe via file_execution_fact."
    out = _sanitize_details(raw)
    assert "tool.exe" in out
    assert "C:\\Windows\\Temp\\stage\\tool.exe" in out
    assert "file_execution_fact" not in out


def test_no_leftover_internal_suffix_tokens():
    raw = "Detected ssdt_integrity_fact and rdp_artifact_fact in evidence."
    out = _sanitize_details(raw)
    assert not _INTERNAL_SUFFIX.search(out)


def test_empty_and_clean_text_are_safe():
    assert _sanitize_details("") == ""
    # already-clean prose is left essentially intact
    clean = "A built-in tool ran from a temporary folder and made outbound connections."
    assert "temporary folder" in _sanitize_details(clean).lower()


# Regression: a plural "Candidates cand-X through cand-Y" range citation must be
# consumed whole, not left as the orphan "Candidates through."
def test_plural_candidate_range_citation_is_removed_whole():
    raw = "Execution recorded in AppCompatCache. Candidates cand-0009 through cand-0021. Evidence of staging."
    out = _sanitize_details(raw)
    assert "cand-" not in out.lower()
    assert "candidates" not in out.lower()          # no orphan "Candidates through"
    assert "through." not in out.lower()
    assert "AppCompatCache" in out and "Evidence of staging" in out


def test_comma_separated_candidate_citation_is_removed_whole():
    raw = "from System32/SysWOW64. Candidates cand-0003, cand-0027 through cand-0032, cand-0056."
    out = _sanitize_details(raw)
    assert "cand-" not in out.lower()
    assert "candidates" not in out.lower()
    assert "System32/SysWOW64" in out
    assert ",." not in out and " ," not in out      # no orphan punctuation


def test_factids_citation_is_removed():
    raw = "Staging detected. fact_ids: appcompatcache_execution_fact multiple."
    out = _sanitize_details(raw)
    assert "fact_id" not in out.lower()
    assert "_fact" not in out
    assert "Staging detected" in out


# Regression (rd01 run): the "Candidate ID: cand-X, cand-Y" connector form left
# an orphan "ID:,." / "ID: through." after bare-token stripping.
def test_candidate_id_connector_citation_removed():
    raw = "PWDumpX is a credential extraction tool. Candidate ID: cand-0025, cand-0087."
    out = _sanitize_details(raw)
    assert "candidate" not in out.lower()
    assert "id:" not in out.lower()
    assert "cand-" not in out.lower()
    assert "credential extraction tool" in out


def test_candidate_id_range_connector_removed():
    raw = "Lateral movement preparation. Candidate ID: cand-0033 through cand-0041."
    out = _sanitize_details(raw)
    assert "candidate" not in out.lower()
    assert "through." not in out.lower()
    assert "Lateral movement preparation" in out
