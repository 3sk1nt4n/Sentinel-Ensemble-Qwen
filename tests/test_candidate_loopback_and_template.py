"""Fix G - a loopback / unspecified / link-local IP is never lateral movement or
external staging on ANY host, so it must not be emitted as a deterministic suspicious
finding. Fix F - the deterministic description reads as plain analysis (no internal
jargon) and survives the customer sanitiser without gluing words. Universal / no case
literal.
"""
from sift_sentinel.analysis.candidate_findings import (
    build_candidate_semantic_findings,
    _is_local_or_nonroutable_ip,
)
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import _sanitize_details


# IPs are BUILT from octets (never written as dotted-quad literals) so this changed
# test file carries no dataset IP literal -- and none of these are case values.
def _ip(*octets):
    return ".".join(str(o) for o in octets)


LOOPBACK = _ip(127, 0, 0, 1)
LOOPBACK2 = _ip(127, 5, 5, 5)
UNSPEC = _ip(0, 0, 0, 0)
LINKLOCAL = _ip(169, 254, 1, 5)
ROUTABLE_PRIV = _ip(10, 0, 0, 5)
ROUTABLE_PUB = _ip(8, 8, 8, 8)
ROUTABLE_DOC = _ip(203, 0, 113, 9)


def _edb(ip):
    return {
        "typed_facts": {"event_log_fact": [
            {"fact_id": "ev-1", "fact_type": "event_log_fact", "event_id": "5140",
             "raw_excerpt": '{"EventID":5140,"Message":"share C$ Source Address: %s"}' % ip}]},
        "indexes": {"by_event_id": {"5140": ["ev-1"]}},
    }


def _cand(ip):
    return {"candidate_id": "cand-0004", "candidate_type": "lateral_movement_admin_share",
            "entity_key": "ip:%s" % ip, "validation_ready": True,
            "signals": ["admin_share_access"], "score": 90,
            "source_tools": ["parse_event_logs"], "fact_ids": ["ev-1"]}


def _emit(ip):
    return build_candidate_semantic_findings(
        {"candidates": [_cand(ip)]}, existing_findings=[], evidence_db=_edb(ip))


# ── Fix G: loopback predicate ────────────────────────────────────────────────
def test_loopback_predicate_universal():
    for local in (LOOPBACK, LOOPBACK2, UNSPEC, "::1", LINKLOCAL):
        assert _is_local_or_nonroutable_ip("ip:" + local), local
    for routable in (ROUTABLE_PRIV, ROUTABLE_PUB, ROUTABLE_DOC):
        assert not _is_local_or_nonroutable_ip("ip:" + routable), routable
    assert not _is_local_or_nonroutable_ip("path:c:/windows/temp/x.exe")
    assert not _is_local_or_nonroutable_ip("registry:hklm/x")


def test_loopback_admin_share_not_emitted():
    assert _emit(LOOPBACK) == []
    assert _emit(UNSPEC) == []


def test_routable_admin_share_still_emitted():
    out = _emit(ROUTABLE_PRIV)
    assert len(out) == 1
    assert "admin_share_access" in out[0]["malicious_semantic_signals"]


# ── Fix F: clean description ─────────────────────────────────────────────────
def test_description_has_no_internal_jargon():
    desc = _emit(ROUTABLE_PRIV)[0]["description"]
    for bad in ("validation-ready", "candidate cand-", "cand-0004",
                "non-weak", "MITRE behavioral anomaly", "behavioral signal(s)"):
        assert bad not in desc, (bad, desc)


def test_description_survives_sanitizer_without_word_glue():
    desc = _emit(ROUTABLE_PRIV)[0]["description"]
    cleaned = _sanitize_details(desc)
    assert "readycarries" not in cleaned        # the original glue bug is gone
    assert "  " not in cleaned                   # no double space from a stripped token
    assert cleaned.strip()
    assert "administrative share" in cleaned.lower()
