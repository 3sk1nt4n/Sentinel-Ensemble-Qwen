"""Cross-family entity resolution (Work Order #2, Task B).

Property: when one normalized identity (content hash, or a REMOTE FQDN) appears
in >=2 independent fact families, those facts must group into one candidate and
be recognised as corroborated (multi_fact_type) -- universal, dataset-agnostic
(keys on identity shape/field only), and bounded so ubiquitous/baseline
identities cannot manufacture false corroboration:

  - a file's content hash links facts about the same file across families even
    when their path representation differs;
  - a remote/destination FQDN links facts about the same external peer;
  - the LOCAL computer name is never keyed as a remote host (no over-link);
  - SIDs/usernames are deliberately NOT keyed (they are ubiquitous baseline
    identities -- e.g. S-1-5-18 / the interactive user SID appear in thousands
    of facts across families and would manufacture false corroboration).

Tests assert properties with synthetic values, never specific dataset values.
"""

from __future__ import annotations

import importlib


def _co():
    import sift_sentinel.analysis.candidate_observations as co

    return importlib.reload(co)


SHA = "a" * 64  # synthetic content hash (shape only)


def _fact(fact_id, fact_type, **fields):
    base = {"fact_id": fact_id, "fact_type": fact_type,
            "source_tool": fields.pop("source_tool", fact_type)}
    base.update(fields)
    return base


def test_hash_creates_shared_key_across_families():
    """The linking mechanism: the same content hash yields a shared hash: key
    even when the path representation differs across families."""
    co = _co()
    a = _fact("f1", "file_execution_fact", sha256=SHA, path="C:/users/x/a.exe", source_tool="amcache")
    b = _fact("f2", "filesystem_listing_fact", sha256=SHA, path="C:/some/other/copy.exe", source_tool="fls")
    ka, kb = co._entity_keys(a), co._entity_keys(b)
    assert f"hash:{SHA}" in ka and f"hash:{SHA}" in kb
    # Paths differ -> path: keys do NOT link them; only the hash does.
    assert not (set(k for k in ka if k.startswith("path:")) & set(k for k in kb if k.startswith("path:")))


def test_hash_links_two_families_into_one_corroborated_candidate():
    co = _co()
    # Same hash + a scoring signal (staging path) in two families, different
    # paths -> they group under the shared hash and are recognised corroborated.
    a = _fact("f1", "file_execution_fact", sha256=SHA,
              path="C:/Windows/Temp/a.exe", source_tool="amcache")
    b = _fact("f2", "appcompatcache_execution_fact", sha256=SHA,
              path="C:/Users/Public/copy.exe", source_tool="appcompat")
    db = {"typed_facts": {"file_execution_fact": [a], "appcompatcache_execution_fact": [b]}}
    payload = co.build_candidate_observations(db, max_candidates=100)
    by_hash = [c for c in payload["candidates"] if c.get("entity_key") == f"hash:{SHA}"]
    assert by_hash, "the two families must group under the shared hash"
    c = by_hash[0]
    assert len(c["fact_types"]) >= 2, "grouped across >=2 families => corroborated"
    assert "multi_fact_type" in (c.get("signals") or [])


def test_remote_fqdn_links_across_families():
    co = _co()
    fqdn = "pivot.corp.example.lan"
    a = _fact("r1", "rdp_artifact_fact", host_or_target=fqdn, raw_excerpt="EventID=1024")
    b = _fact("n1", "network_connection_fact", remote_host=fqdn, source_tool="netscan")
    ka, kb = co._entity_keys(a), co._entity_keys(b)
    assert f"host:{fqdn}" in ka and f"host:{fqdn}" in kb


def test_local_computer_is_not_keyed_as_remote_host():
    """A fact whose host_or_target equals its own computer (local host) must NOT
    produce a host: key -- otherwise every local-host fact over-links."""
    co = _co()
    f = _fact("e1", "event_log_fact", computer="WS01.corp.example.lan",
              host_or_target="WS01.corp.example.lan")
    keys = co._entity_keys(f)
    assert not any(k.startswith("host:") for k in keys)


def test_blob_hex_is_not_treated_as_a_hash():
    """A 32-hex GUID-ish token in free text (no dedicated hash field) must NOT
    create a hash: key (avoids false linking on coincidental hex)."""
    co = _co()
    f = _fact("g1", "filesystem_listing_fact",
              raw_excerpt="value=0123456789abcdef0123456789abcdef")
    keys = co._entity_keys(f)
    assert not any(k.startswith("hash:") for k in keys)


def test_sid_does_not_create_cross_family_linking():
    """Two facts in different families sharing ONLY a SID must NOT group --
    SIDs are ubiquitous baseline identities and are deliberately not keyed."""
    co = _co()
    sid = "S-1-5-21-111-222-333-1002"
    a = _fact("s1", "handle_fact", sid=sid, pid="100", raw_excerpt=sid)
    b = _fact("s2", "event_log_fact", sid=sid, raw_excerpt=sid)
    ka, kb = set(co._entity_keys(a)), set(co._entity_keys(b))
    assert not any(k.startswith("sid:") for k in ka | kb)
    # No shared non-trivial key from the SID alone.
    shared = ka & kb
    assert not any(sid.lower() in k for k in shared)
