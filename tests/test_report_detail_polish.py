"""Deterministic report-detail polish fixes (universal, no case data), TDD'd against the
actual artifacts seen in a live base-hosta-01 report:

  BUG 1  empty candidate-id leak:  "... Candidate_id=." / "Candidate_id=,."
  BUG 2  missing space after a period before a sentence-continuation word:
         "paths.indicate", "staging.supports", "bindings.indicates"
  BUG 3  "Why it matters" significance keying on a tangential signal instead of the
         finding's primary nature (service finding mislabelled RWX; "staging server"
         mislabelled "staging folder").

All inputs are invented placeholders -- universal, swap-test holds on any box.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import _sanitize_details
from sift_sentinel.reporting.finding_significance import plain_significance


# ── BUG 1 ─────────────────────────────────────────────────────────────────
def test_empty_candidate_id_is_stripped():
    for s in ("rundll32 execution evidence. Candidate_id=.",
              "schtasks execution. Candidate_id=,.",
              "Candidate_id= indicates WSM provider execution."):
        out = _sanitize_details(s)
        assert "andidate_id" not in out.lower(), out


# ── BUG 2 ─────────────────────────────────────────────────────────────────
def test_run_on_join_words_get_a_space():
    # a space is inserted after the period (the sentence-case step then capitalises it)
    assert ". indicate" in _sanitize_details("multi-source filesystem paths.indicate evidence").lower()
    assert ". support" in _sanitize_details("from staging.supports network usage").lower()
    assert ". indicate" in _sanitize_details("port bindings.indicates a listener").lower()


def test_file_extensions_versions_ips_are_not_broken():
    # the fix must never insert a space inside cmd.exe / v1.0 / an IP / a decimal
    for s in ("C:\\Windows\\System32\\cmd.exe ran", "powershell v1.0 here",
              "peer 172.16.5.20 contacted", "9.9 GB egress observed"):
        out = _sanitize_details(s)
        assert "cmd. exe" not in out and "v1. 0" not in out
        assert "172.16. 5" not in out and "9. 9" not in out


# ── BUG 3 ─────────────────────────────────────────────────────────────────
def test_significance_uses_primary_nature_not_a_tangential_signal():
    # service-execution finding; a tangential 'rwx' SIGNAL must not make it "RWX injection"
    f = {"title": "Suspicious service binary execution from non-standard path",
         "description": "process ran as a service from C:\\windows with a remote server reference",
         "malicious_semantic_signals": ["rwx_memory", "process_injection"]}
    sig = plain_significance(f)
    assert "writable and executable" not in sig, sig      # NOT the RWX significance
    assert "service" in sig.lower(), sig                  # the primary nature


def test_staging_server_is_not_called_a_staging_folder():
    f = {"title": "Network connection to internal staging server on port 443",
         "description": "outbound connection from a system service to a remote peer"}
    sig = plain_significance(f)
    assert "temporary or staging folder" not in sig, sig  # network != ran-from-temp


def test_real_temp_execution_still_gets_its_significance():
    # a genuine ran-from-temp finding must KEEP the staging-folder significance
    f = {"title": "Execution from temp staging directory",
         "description": "setup.exe ran from C:\\Windows\\Temp\\cr_x.tmp"}
    sig = plain_significance(f)
    assert "temporary or staging folder" in sig, sig


# ── WHO attribution (track 2): surface the actor, not just the time ───────
def test_who_surfaces_from_user_path_and_never_fabricated():
    from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
        render_findings_terminal,
    )

    def _render(f):
        return render_findings_terminal({
            "confirmed_malicious_atomic": [f], "suspicious_needs_review": [],
            "benign_or_false_positive": [], "inconclusive_unresolved": [],
            "synthesis_narrative": [],
        })

    # a finding whose evidence sits under a user profile -> WHO is that user
    u = _render({"finding_id": "F1", "title": "Execution from user profile",
                 "description": r"C:\Users\jdoe\AppData\Local\Temp\x.exe ran",
                 "claims": [{"type": "path", "value": r"C:\Users\jdoe\AppData\Local\Temp\x.exe"}]})
    assert "Who: jdoe" in u
    # WHO-FIRST (2026-06-10, intentional): a finding with no derivable user and
    # no execution_context now leads with an explicit honest 'not attributed'
    # rather than a silent blank -- every row starts with an identity. The user
    # is still never FABRICATED (it's the literal 'not attributed' label).
    s = _render({"finding_id": "F2", "title": "svchost listener",
                 "description": "svchost.exe SYSTEM service listening on 5985",
                 "claims": [{"type": "connection", "value": "5985", "timestamp": "2021-09-15T17:50:04"}]})
    assert "Who: not attributed" in s
    assert "Who: jdoe" not in s          # no fabricated user
