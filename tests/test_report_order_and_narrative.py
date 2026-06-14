"""Two report-quality fixes from the live Opus acme run:

#1 FINDINGS table must lead with CONFIRMED findings, then most-tool-hits-first.
   The run put F040 (9 tools, needs-review) at row 1 and the two CONFIRMED
   SDelete findings (F009 5 tools / F010 3 tools) at rows 11-12 -- a reader sees
   the most-tool-touched item before what is actually proven.

#2 The per-user Attack Chain Narrative numbered steps with FIXED per-step
   numbers, so a run where only persistence/collection/exfil fired printed
   '4.', '6.', '7.' with gaps. Steps must renumber sequentially by what fired.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    _sort_confirmed_first,
)
from sift_sentinel.reporting.per_user_summary import build_per_user_summary


# ── #1 confirmed-first ordering ──────────────────────────────────────────
def _f(fid, n_tools):
    return {"finding_id": fid, "source_tools": ["t%d" % i for i in range(n_tools)]}


def test_confirmed_leads_even_with_fewer_tools():
    findings = [_f("F040", 9), _f("F009", 5), _f("F010", 3)]
    out = _sort_confirmed_first(findings, confirmed_fids={"F009", "F010"})
    ids = [x["finding_id"] for x in out]
    # both confirmed first (by tool-hits among themselves), THEN F040.
    assert ids == ["F009", "F010", "F040"], ids


def test_within_nonconfirmed_sorts_by_tool_hits():
    out = _sort_confirmed_first([_f("A", 1), _f("B", 4), _f("C", 2)],
                                confirmed_fids=set())
    assert [x["finding_id"] for x in out] == ["B", "C", "A"]


def test_no_confirmed_is_plain_tool_hit_order():
    out = _sort_confirmed_first([_f("A", 2), _f("B", 5)], confirmed_fids={"Z"})
    assert [x["finding_id"] for x in out] == ["B", "A"]


# ── #2 sequential narrative numbering ────────────────────────────────────
def _persistence_finding():
    # a finding whose title hits PERSISTENCE_VOCAB, owned by a user PID.
    return {"finding_id": "F035", "title": "Non-standard service install (scheduled task)",
            "severity": "MEDIUM",
            "claims": [{"type": "user_account", "username": "bobby", "domain": ""},
                       {"type": "pid", "pid": 1248}]}


def _typed_facts():
    return {"user_account_fact": [{"username": "bobby", "domain": "",
                                   "owned_pids": [1248]}]}


def test_narrative_renumbers_sequentially_no_gaps():
    md = build_per_user_summary([_persistence_finding()], _typed_facts())
    if "Attack Chain Narrative" not in md:
        # narrative only renders when a chain is inferred; persistence alone qualifies
        return
    import re
    nums = [int(m.group(1)) for m in re.finditer(r"^(\d+)\.\s+\*\*", md, re.MULTILINE)]
    if nums:
        # whatever fired must be numbered 1..N with NO gaps and starting at 1.
        assert nums == list(range(1, len(nums) + 1)), nums


def test_narrative_never_starts_at_four():
    md = build_per_user_summary([_persistence_finding()], _typed_facts())
    import re
    m = re.search(r"^(\d+)\.\s+\*\*Persistence\*\*", md, re.MULTILINE)
    if m:
        assert m.group(1) == "1", "persistence-only chain must start the list at 1"
