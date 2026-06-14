"""Network-IOC salience gate -- cost down, quality up (SHADOW-safe).

``extract_network_iocs`` collects every connection / IOC (thousands of records); on
a real box only a handful are ever review-worthy. Loading all of them into the hot
path (evidence_db -> scoring -> prompt) bloats the DB, slows eligibility, and lets
benign vendor traffic weakly corroborate. A network fact earns a HOT-PATH slot only
when it carries a structural salience signal -- a public non-vendor peer, a
non-baseline high-port listener, a LOLBIN/admin-tool owner, or an encoded/download
URL. The full raw set stays in the tool envelope for audit; only the salient subset
needs to be indexed.

This module is SHADOW-SAFE: ``network_ioc_salient`` is a pure predicate and
``summarize_network_salience`` only MEASURES (kept/dropped). It changes no bucket and
no DB. Flipping it authoritative (actually trimming the DB) is a separate, gated step
taken ONLY after a shadow run proves zero finding loss -- and MUST first add the
entity-tie clause (keep any network fact whose owning process / peer carries another
signal) so internal lateral-movement / internal-C2 evidence is never dropped.

Universal: reuses the existing candidate-scoring predicates; no IP / port / case
literal, no allow/deny IP list.
"""
from __future__ import annotations

from sift_sentinel.analysis.candidate_observations import (
    _is_public_ip,
    _VENDOR_OR_UPDATE_RE,
    _LOLBIN_RE,
    _ENCODED_OR_DOWNLOAD_RE,
    _SENSITIVE_BASELINE_NAMES,
    _URL_RE,
    _IP_RE,
)

NETWORK_FACT_TYPES = ("network_connection_fact", "network_ioc_fact")


def _flat(fact) -> dict:
    out: dict = {}
    if not isinstance(fact, dict):
        return out
    for k, v in fact.items():
        if isinstance(v, (str, int, float, bool)):
            out[str(k).lower()] = v
    f = fact.get("fields")
    if isinstance(f, dict):
        for k, v in f.items():
            if isinstance(v, (str, int, float, bool)):
                out.setdefault(str(k).lower(), v)
    art = fact.get("artifact")
    if isinstance(art, (list, tuple)):
        out["_artifact_blob"] = " ".join(str(x) for x in art)
    return out


def network_ioc_salient(fact) -> tuple[bool, list[str]]:
    """``(salient, reasons)``. A salient network fact earns a hot-path slot; the rest
    stay in the raw tool envelope only. ``reasons`` lists the structural signals."""
    if not isinstance(fact, dict):
        return False, []
    ft = str(fact.get("fact_type") or fact.get("type") or "").lower()
    if ft not in NETWORK_FACT_TYPES:
        return False, []
    flat = _flat(fact)
    blob = " ".join(str(v) for v in flat.values())
    owner = str(flat.get("owner") or flat.get("process_name") or "").lower()
    dst = str(flat.get("dst_ip") or flat.get("faddr") or flat.get("foreignaddr") or "")
    state = str(flat.get("state") or "").upper()
    sport = str(flat.get("src_port") or flat.get("lport") or "")

    ips = _IP_RE.findall(blob)
    urls = _URL_RE.findall(blob)
    non_vendor_url = any(not _VENDOR_OR_UPDATE_RE.search(u) for u in urls)
    reasons: list[str] = []

    # public, non-vendor remote peer -> the external-C2 candidate
    if (_is_public_ip(dst) or any(_is_public_ip(ip) for ip in ips)) and (not urls or non_vendor_url):
        reasons.append("public_non_vendor_peer")
    # non-baseline high-port listener
    if "LISTEN" in (state or blob.upper()) and sport.isdigit() and int(sport) >= 1024 \
            and owner not in _SENSITIVE_BASELINE_NAMES:
        reasons.append("non_baseline_high_port_listener")
    # LOLBIN / admin tool making network activity
    if owner and _LOLBIN_RE.search(owner) and owner not in _SENSITIVE_BASELINE_NAMES:
        reasons.append("lolbin_owner_network")
    # encoded / download URL shape
    if _ENCODED_OR_DOWNLOAD_RE.search(blob.lower()) and (not urls or non_vendor_url):
        reasons.append("encoded_or_download_url")

    return (bool(reasons), reasons)


def iter_network_facts(evidence_db):
    """Yield every network fact from an evidence_db dict, de-duplicated by identity."""
    if not isinstance(evidence_db, dict):
        return
    containers = [evidence_db]
    tf = evidence_db.get("typed_facts")
    if isinstance(tf, dict):
        containers.append(tf)
    seen: set[int] = set()
    for container in containers:
        for v in container.values():
            if not isinstance(v, list):
                continue
            for f in v:
                if (isinstance(f, dict)
                        and str(f.get("fact_type") or f.get("type") or "").lower() in NETWORK_FACT_TYPES
                        and id(f) not in seen):
                    seen.add(id(f))
                    yield f


def summarize_network_salience(evidence_db) -> dict:
    """MEASURE ONLY: how many network facts the salience gate would keep vs drop.
    Returns ``{total, kept, dropped, by_reason}``. Changes nothing."""
    total = kept = 0
    by_reason: dict[str, int] = {}
    for f in iter_network_facts(evidence_db):
        total += 1
        salient, reasons = network_ioc_salient(f)
        if salient:
            kept += 1
            for r in reasons:
                by_reason[r] = by_reason.get(r, 0) + 1
    return {"total": total, "kept": kept, "dropped": total - kept, "by_reason": by_reason}
