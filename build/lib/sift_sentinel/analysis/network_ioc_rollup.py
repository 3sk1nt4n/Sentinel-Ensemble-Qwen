"""Universal Network Indicators (IOC) roll-up.

A consolidated, FACTUAL view of the system's EXTERNAL network footprint, built
purely from runtime evidence -- it answers "what did this box talk to, and which
of it looks algorithmic" with no IP/domain answer key:

  * Observed external connections -- from ``network_connection_fact``
    (vol_netscan): each socket whose remote peer is a PUBLIC IPv4 (RFC1918 /
    loopback / link-local / multicast / 0.x / x.0 excluded by octet shape), with
    the owning process, port and direction. These are real, observed sockets.
  * Suspicious (DGA) domains -- from ``network_ioc_fact``, scored by
    ``dga_detection``; only algorithmically-random labels are listed (a normal
    CDN/vendor domain is not), each with the structural reasons.
  * Other carved public IPs -- public IPv4 indicators seen only in carved strings
    (lower confidence), summarised with a sample.

Factual, NOT a verdict: a listed endpoint is "external", not "malicious" -- the
findings decide intent. Universal: public-IP octet shape + DGA structure +
socket grammar, no case data. Kill-switch ``SIFT_NETWORK_IOC=0``.
"""
from __future__ import annotations

import json
import os
import re

# Reuse the single public-IPv4 octet-shape gate (drops RFC1918 / loopback /
# link-local / multicast / 0.x / x.0 carving junk) so "public" means the same
# thing as the confirmed-bucket corroborator. One definition, no IP list.
from sift_sentinel.analysis.disposition import _ipv4_is_public


def _is_oid_or_version_carved(ip: str) -> bool:
    """#3a: a carve-ONLY dotted-quad whose first octet is <= 2 is overwhelmingly
    an ASN.1 OID arc (0=ITU-T, 1=ISO, 2=joint) or a 4-part version number carved
    from a cert/binary, NOT an external host. A host genuinely contacted in
    those ranges surfaces as a LIVE socket (which this never touches). Universal:
    first-octet shape, no IOC list. Kill-switch SIFT_CARVED_IP_OID_FILTER=0."""
    if os.environ.get("SIFT_CARVED_IP_OID_FILTER", "1") == "0":
        return False
    try:
        return int(str(ip).split(".", 1)[0]) <= 2
    except (ValueError, IndexError):
        return False


def _is_noncanonical_quad(ip: str) -> bool:
    """D1-residual (ADDITIVE to the OID filter, never replacing it): a dotted
    quad that is not a canonical IPv4 -- an octet > 255, or an octet written
    with a leading zero -- is carve junk (timestamps, serials, version
    strings), never a host. A real host renders canonically everywhere the OS
    prints it. Universal: octet grammar only; no example literals by policy.
    Kill-switch SIFT_CARVED_IP_CANON_FILTER=0."""
    if os.environ.get("SIFT_CARVED_IP_CANON_FILTER", "1") == "0":
        return False
    parts = str(ip or "").split(".")
    if len(parts) != 4:
        return True
    for p in parts:
        if not p.isdigit() or int(p) > 255 or (len(p) > 1 and p[0] == "0"):
            return True
    return False
from sift_sentinel.analysis.dga_detection import dga_score

_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_MAX_ROWS = 40                       # bounded table; overflow is summarised, not dropped
_DOMAIN_TYPES = frozenset({"domain", "fqdn", "hostname"})


def _enabled() -> bool:
    return os.environ.get("SIFT_NETWORK_IOC", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _facts(evidence_db, fam) -> list:
    return (((evidence_db or {}).get("typed_facts") or {}).get(fam) or [])


def _conn_fields(fact) -> tuple[str, str, str, str]:
    """(dst_ip, dst_port, process, direction) from a network_connection_fact, via
    named fields (preferred) or the artifact tuple
    ``[proto, local:port, foreign:port, state, process]``."""
    if not isinstance(fact, dict):
        return "", "", "", ""
    dst_ip = str(fact.get("dst_ip") or "").strip()
    dst_port = str(fact.get("dst_port") or "").strip()
    proc = str(fact.get("owner") or fact.get("process") or "").strip()
    direction = str(fact.get("direction") or "").strip()
    if not dst_ip:
        art = fact.get("artifact")
        if isinstance(art, (list, tuple)) and len(art) >= 5:
            foreign = str(art[2] or "")
            if ":" in foreign:
                dst_ip, _, dst_port = foreign.rpartition(":")
            else:
                dst_ip = foreign
            proc = proc or str(art[4] or "")
    return dst_ip, dst_port, proc, direction


def _ioc_fields(fact) -> tuple[str, str, str]:
    """(type, value, classification) from a network_ioc_fact artifact
    ``[type, value, port_or_None, classification]`` or the raw_excerpt JSON."""
    if not isinstance(fact, dict):
        return "", "", ""
    art = fact.get("artifact")
    if isinstance(art, (list, tuple)) and len(art) >= 2:
        t = str(art[0] or "").lower()
        val = str(art[1] or "")
        cls = str(art[3] or "").lower() if len(art) > 3 else ""
        return t, val, cls
    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw:
        try:
            o = json.loads(raw)
            return (str(o.get("type") or "").lower(), str(o.get("value") or ""),
                    str(o.get("classification") or "").lower())
        except Exception:
            pass
    return "", "", ""


def extract_network_iocs(evidence_db) -> dict:
    """Structured external network footprint. Returns
    ``{"observed_connections": [...], "suspicious_domains": [...],
    "carved_public_ips": [...]}``. Each observed connection is
    ``{ip, port, process, direction}``; each suspicious domain is
    ``{domain, score, reasons}``. Universal; ``{}`` empty lists when disabled."""
    empty = {"observed_connections": [], "suspicious_domains": [],
             "carved_public_ips": []}
    if not _enabled():
        return empty

    # 1. observed external connections (real sockets)
    seen_conn: set[tuple] = set()
    conns: list[dict] = []
    conn_ips: set[str] = set()
    for f in _facts(evidence_db, "network_connection_fact"):
        dst_ip, dst_port, proc, direction = _conn_fields(f)
        m = _IPV4_RE.search(dst_ip or "")
        if not m or not _ipv4_is_public(m.group(1)):
            continue
        ip = m.group(1)
        key = (ip, dst_port, proc.lower())
        if key in seen_conn:
            continue
        seen_conn.add(key)
        conn_ips.add(ip)
        conns.append({"ip": ip, "port": dst_port, "process": proc or "-",
                      "direction": direction or "-"})

    # 2. suspicious (DGA) domains
    # D1-residual provenance pre-pass: a domain that appears as the HOST of an
    # extracted URL has positive domain provenance ("url_host"); a bare carved
    # token does not ("carved"). Derived here from the url-type facts -- the
    # classification slot is left untouched (downstream C2 matchers key on it).
    url_hosts: set[str] = set()
    for f in _facts(evidence_db, "network_ioc_fact"):
        t, val, _cls = _ioc_fields(f)
        if t == "url" and val:
            try:
                from urllib.parse import urlsplit
                h = (urlsplit(val).hostname or "").strip().lower()
                if h:
                    url_hosts.add(h)
            except Exception:
                continue
    seen_dom: set[str] = set()
    domains: list[dict] = []
    carved: list[str] = []
    carved_seen: set[str] = set()
    for f in _facts(evidence_db, "network_ioc_fact"):
        t, val, cls = _ioc_fields(f)
        if not val:
            continue
        if t in _DOMAIN_TYPES or (t == "" and "." in val and not _IPV4_RE.fullmatch(val)):
            d = val.strip().lower()
            if d in seen_dom:
                continue
            seen_dom.add(d)
            _prov = "url_host" if d in url_hosts else "carved"
            # D1-final (UNIVERSAL, no extension list): a domain is a DGA network
            # IOC only with positive network provenance (seen as a URL host).
            # A carved-only token that merely looks domain-shaped -- a Windows
            # Update .cab, a DirectShow .ax, any file whose extension happens to
            # collide with a real TLD -- is not a network indicator. Real DGA C2
            # carries a beacon URL, so recall holds. SIFT_DGA_REQUIRE_PROVENANCE=0
            # restores legacy carved scoring.
            if (os.environ.get("SIFT_DGA_REQUIRE_PROVENANCE", "1") != "0"
                    and _prov != "url_host"):
                continue
            suspect, score, reasons = dga_score(d, provenance=_prov)
            if suspect:
                domains.append({"domain": d, "score": score, "reasons": reasons})
        elif t == "ipv4" or (t == "" and _IPV4_RE.fullmatch(val)):
            m = _IPV4_RE.search(val)
            if not m or not _ipv4_is_public(m.group(1)):
                continue
            ip = m.group(1)
            if ip in conn_ips or ip in carved_seen:
                continue
            if _is_oid_or_version_carved(ip):     # OID/version fragment, not a host
                continue
            if _is_noncanonical_quad(val.strip()):  # leading-zero / >255 carve junk
                continue
            carved_seen.add(ip)
            carved.append(ip)

    domains.sort(key=lambda d: d["score"], reverse=True)
    return {"observed_connections": conns, "suspicious_domains": domains,
            "carved_public_ips": carved}


# ── D2: IOC <-> finding correlation (verdict inheritance) ────────────────────
# An indicator alone is NOT an IOC -- it becomes one when BOUND to a finding.
# Join identity: the finding's OWN claims must carry the indicator's public
# IPv4 (dst_ip / value) or the domain token. NEVER process-name alone -- it is
# many-to-one against sockets on every Windows box (would false-merge a benign
# socket onto a malicious finding). Verdict = strongest related bucket.
_VERDICT_BY_BUCKET = (
    ("confirmed_malicious_atomic", "confirmed"),
    ("suspicious_needs_review", "suspect"),
)


def _correlate_enabled() -> bool:
    return os.environ.get("SIFT_IOC_CORRELATE", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _finding_network_tokens(f) -> set:
    """The network identity tokens a finding's OWN claims carry: public IPv4s
    (dst_ip/src_ip/value/ip fields) and lowercase domain-ish strings. Claim
    structure only -- never the process name."""
    toks: set = set()
    for c in (f.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for k in ("dst_ip", "src_ip", "ip", "value", "remote_ip", "address"):
            v = str(c.get(k) or "").strip()
            if not v:
                continue
            m = _IPV4_RE.search(v)
            if m and _ipv4_is_public(m.group(1)):
                toks.add(m.group(1))
            elif "." in v and not _IPV4_RE.fullmatch(v):
                toks.add(v.lower())
    return toks


def correlate_iocs_to_findings(ioc_data, buckets) -> list:
    """Bind each network indicator to its related finding(s) and inherit the
    verdict from the strongest related disposition bucket. Returns rows
    ``{indicator, kind, port, process, verdict, finding_ids}`` where verdict is
    confirmed | suspect | external. Universal: claim-token identity + bucket
    names only. Kill-switch SIFT_IOC_CORRELATE=0 (-> empty, legacy section)."""
    if not _correlate_enabled():
        return []
    ioc_data = ioc_data or {}
    # token -> [(finding_id, verdict_rank)] from the surfaced buckets
    tok_map: dict = {}
    for rank, (bucket, verdict) in enumerate(_VERDICT_BY_BUCKET):
        for f in ((buckets or {}).get(bucket) or []):
            if not isinstance(f, dict):
                continue
            fid = str(f.get("finding_id") or f.get("id") or "")
            for tok in _finding_network_tokens(f):
                tok_map.setdefault(tok, []).append((fid, rank, verdict))
    rows: list = []
    for c in (ioc_data.get("observed_connections") or []):
        ip = str(c.get("ip") or "")
        hits = sorted(tok_map.get(ip, []), key=lambda h: h[1])
        rows.append({
            "indicator": ip, "kind": "ip", "port": str(c.get("port") or ""),
            "process": str(c.get("process") or "-"),
            "verdict": hits[0][2] if hits else "external",
            "finding_ids": sorted({h[0] for h in hits if h[0]}),
        })
    for d in (ioc_data.get("suspicious_domains") or []):
        dom = str(d.get("domain") or "").lower()
        hits = sorted(tok_map.get(dom, []), key=lambda h: h[1])
        rows.append({
            "indicator": dom, "kind": "dga_domain", "port": "",
            "process": "-",
            "verdict": hits[0][2] if hits else "external",
            "finding_ids": sorted({h[0] for h in hits if h[0]}),
        })
    return rows


# ── report section: "Network Indicators (IOCs)" ──────────────────────────────
_NETIOC_SECTION_TITLE = "## Network Indicators (IOCs)"


def _render_correlated_tiers(rows, carved) -> list:
    """D2 verdict-tiered rendering: confirmed (block/hunt) -> suspect ->
    external/informational. Each row cites its related finding ids so every
    listed IOC is traceable to the evidence that made it one."""
    lines: list = []
    # FINDINGS-ONLY (default ON): an indicator with NO related finding is
    # observability, not an IOC -- the external tier and the carve footnote
    # collapse to count lines so the section contains ONLY indicators a real
    # finding proved. Kill-switch SIFT_IOC_FINDINGS_ONLY=0 restores the table.
    findings_only = os.environ.get(
        "SIFT_IOC_FINDINGS_ONLY", "1").strip().lower() not in (
        "0", "false", "no", "off")
    tiers = (
        ("confirmed", "**Confirmed-malicious network indicators "
                      "(recommended for blocking / hunting):**"),
        ("suspect", "**Suspicious indicators (tied to needs-review findings):**"),
        ("external", "**External / informational (no related malicious "
                     "finding):**"),
    )
    for verdict, heading in tiers:
        tier_rows = [r for r in rows if r.get("verdict") == verdict]
        if not tier_rows:
            continue
        if verdict == "external" and findings_only:
            lines.append(
                "_%d external endpoint(s) observed with no related finding "
                "(not IOCs; full detail in the evidence database)._"
                % len(tier_rows))
            lines.append("")
            continue
        lines.append(heading)
        lines.append("")
        lines.append("| Indicator | Type | Port | Process | Related findings |")
        lines.append("|---|---|---|---|---|")
        for r in tier_rows[:_MAX_ROWS]:
            fids = ", ".join(r.get("finding_ids") or []) or "-"
            lines.append("| %s | %s | %s | %s | %s |" % (
                r.get("indicator"), r.get("kind"), r.get("port") or "-",
                r.get("process") or "-", fids))
        if len(tier_rows) > _MAX_ROWS:
            lines.append("")
            lines.append("_(+%d more not shown)_" % (len(tier_rows) - _MAX_ROWS))
        lines.append("")
    if carved:
        if findings_only:
            lines.append(
                "_%d public IP(s) seen only in carved strings (no live socket, "
                "no related finding -- not IOCs)._" % len(carved))
        else:
            sample = ", ".join(carved[:12]) + (" + more" if len(carved) > 12 else "")
            lines.append("**Public IPs seen only in carved strings (no live "
                         "socket, no related finding -- lowest confidence):** "
                         "%d unique — %s." % (len(carved), sample))
        lines.append("")
    return lines


def build_network_ioc_section(evidence_db, buckets=None) -> str:
    """Markdown roll-up of the external network footprint. ``""`` when there is no
    external indicator (honest blank). With ``buckets`` (the disposition buckets),
    indicators are CORRELATED to findings and rendered in verdict tiers
    (confirmed -> suspect -> external) -- an indicator is called malicious only
    because a finding proved it, never from a list. Without buckets: legacy
    factual shape. Universal."""
    if not _enabled():
        return ""
    data = extract_network_iocs(evidence_db)
    conns = data["observed_connections"]
    domains = data["suspicious_domains"]
    carved = data["carved_public_ips"]
    if not conns and not domains and not carved:
        return ""

    if buckets is not None and _correlate_enabled():
        rows = correlate_iocs_to_findings(data, buckets)
        lines = [_NETIOC_SECTION_TITLE, ""]
        lines.append(
            "Network indicators correlated to the findings above: an indicator "
            "is listed as malicious ONLY because a related finding proved it "
            "(verdict inherited from the finding's disposition), never from an "
            "IOC list. Dataset-agnostic: live-socket + claim-identity join.")
        lines.append("")
        lines += _render_correlated_tiers(rows, carved)
        return "\n".join(lines).rstrip() + "\n"

    lines = [_NETIOC_SECTION_TITLE, ""]
    lines.append(
        "External network footprint observed on this system, from live sockets "
        "(vol_netscan), carved indicators and DGA scoring. Factual: an endpoint "
        "is listed because it is EXTERNAL, not because it is malicious — intent "
        "is decided by the findings above. Dataset-agnostic (public-IP octet "
        "shape + DGA structure, no IOC list).")
    lines.append("")

    if conns:
        lines.append("**Observed external connections (live sockets):**")
        lines.append("")
        lines.append("| Remote IP | Port | Process | Direction |")
        lines.append("|---|---|---|---|")
        for c in conns[:_MAX_ROWS]:
            lines.append("| %s | %s | %s | %s |" % (
                c["ip"], c["port"] or "-", c["process"], c["direction"]))
        if len(conns) > _MAX_ROWS:
            lines.append("")
            lines.append("_(+%d more external connections not shown)_"
                         % (len(conns) - _MAX_ROWS))
        lines.append("")

    lines.append("**Domains with DGA characteristics (algorithmically random):**")
    lines.append("")
    if domains:
        lines.append("| Domain | DGA score | Why flagged |")
        lines.append("|---|---|---|")
        for d in domains[:_MAX_ROWS]:
            lines.append("| %s | %.2f | %s |" % (
                d["domain"], d["score"], "; ".join(d["reasons"]) or "-"))
        if len(domains) > _MAX_ROWS:
            lines.append("")
            lines.append("_(+%d more flagged domains not shown)_"
                         % (len(domains) - _MAX_ROWS))
    else:
        lines.append("None detected — no domain showed algorithmic-randomness "
                     "structure.")
    lines.append("")

    if carved:
        sample = ", ".join(carved[:12]) + (" + more" if len(carved) > 12 else "")
        lines.append("**Other public IPs seen only in carved strings "
                     "(lower confidence):** %d unique — %s."
                     % (len(carved), sample))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def insert_network_ioc_into_report(report_md, evidence_db,
                                    buckets=None) -> tuple[str, int]:
    """Insert (or idempotently replace) the "## Network Indicators (IOCs)" section.
    Anchors after "## Accounts & Logon Context", else after "## Per-User
    Attribution", else after "## Attack Timeline", else before "## Key
    Findings"/"## MITRE", else appends. ``(report_md, 0)`` when no external
    indicator. With ``buckets``, the section is the D2 verdict-tiered correlated
    ledger. Universal; structural anchors only."""
    if not isinstance(report_md, str):
        report_md = str(report_md or "")
    section = build_network_ioc_section(evidence_db, buckets=buckets)
    if not section:
        return report_md, 0
    existing = re.search(
        r"(^##\s+Network Indicators \(IOCs\)\s*$)(.*?)(?=^##\s|\Z)",
        report_md, re.MULTILINE | re.DOTALL)
    if existing:
        new_md = (report_md[:existing.start()] + section.rstrip() + "\n\n"
                  + report_md[existing.end():])
        return new_md, len(section)
    for pat in (r"(^##\s+Accounts & Logon Context\s*$)(.*?)(?=^##\s|\Z)",
                r"(^##\s+Per-User Attribution\s*$)(.*?)(?=^##\s|\Z)",
                r"(^##\s+Attack Timeline\s*$)(.*?)(?=^##\s|\Z)"):
        m = re.search(pat, report_md, re.MULTILINE | re.DOTALL)
        if m:
            at = m.end()
            return (report_md[:at].rstrip() + "\n\n" + section.rstrip() + "\n\n"
                    + report_md[at:].lstrip()), len(section)
    for pat in (r"^##\s+Key Findings\s*$", r"^##\s+MITRE"):
        m = re.search(pat, report_md, re.MULTILINE)
        if m:
            return (report_md[:m.start()].rstrip() + "\n\n" + section.rstrip()
                    + "\n\n" + report_md[m.start():].lstrip()), len(section)
    return report_md.rstrip() + "\n\n" + section.rstrip() + "\n", len(section)
