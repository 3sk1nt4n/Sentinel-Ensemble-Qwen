"""DGA (Domain Generation Algorithm) detection -- universal, no domain blocklist.

Malware C2 frequently resolves algorithmically-generated domains (random-looking
labels like ``kq7zxvbnmlp`` or ``x7sf2kq9z``). These are distinguishable from real
domains by STRUCTURE alone -- no answer-key domain list, so it generalizes to any
held-out box:

  * low vowel ratio   -- English/brandable labels are ~30-40% vowels; DGA labels
    are often < 20% (the single strongest signal),
  * long consonant runs,
  * high digit ratio,
  * near-maximal Shannon entropy for the label length.

Conservative by design (high precision): a label is flagged only when the low-vowel
signal AND at least one corroborating signal fire, and only for labels long enough to
classify (>= 10 chars) -- so short brandable domains are never flagged. Pure function,
deterministic, no I/O, no case data.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter

_VOWELS = frozenset("aeiou")

# OS-file-type grammar (NOT a domain/case list): tokens whose final dotted
# segment is one of these are FILENAMES carved from the filesystem (Windows
# driver/config/system files), not domains -- so they must never be DGA-scored.
# A live run flagged 235 such driver filenames (*.ppd/*.inf/*.gpd/*.mof) as
# "DGA domains". Deliberately EXCLUDES extensions that are also real TLDs
# (app, dev, info, pro, zip, mov, ...) so a real domain is never suppressed.
_FILE_EXTENSIONS = frozenset({
    "inf", "pnf", "ppd", "gpd", "gdl", "cat", "man", "mof", "xrm", "types",
    "cdxml", "ptxml", "sys", "dll", "drv", "ocx", "cpl", "scr", "ax", "rll",
    "mui", "nls", "fon", "ttf", "cab", "msi", "etl", "evtx", "dat", "bin",
    "pf", "lnk", "admx", "adml", "pol", "cdf", "ini", "manifest",
})


def _is_filename_not_domain(domain: str) -> bool:
    """True when the final dotted segment is a known file extension (a filename
    like ``foo.ppd``), not a registrable TLD. Legacy blocklist path -- retained
    as the fallback when the TLD allowlist gate is off or unavailable. Kill-switch
    SIFT_DGA_FILE_EXT_FILTER=0."""
    if os.environ.get("SIFT_DGA_FILE_EXT_FILTER", "1") == "0":
        return False
    parts = [p for p in str(domain).lower().strip().strip(".").split(".") if p]
    return len(parts) >= 2 and parts[-1] in _FILE_EXTENSIONS


# UNIVERSAL domain gate (replaces the inherently-incomplete blocklist above): a
# token is scored only when its final label is a registered TLD (IANA allowlist).
from sift_sentinel.analysis.registrable_domain import (
    final_label_is_tld as _final_label_is_tld,
    gate_available as _tld_gate_available,
    needs_domain_provenance as _needs_domain_provenance,
)

# provenance values that prove a token was seen as a HOST (not a carved string)
_DOMAIN_PROVENANCE = frozenset({"url_host", "url", "host", "hostname", "dns"})


def _not_a_domain(domain: str, provenance: str = "") -> bool:
    """True when ``domain`` is NOT a registrable domain and must not be DGA-scored.
    Default path: the TLD allowlist (universal, bounded). For the bounded
    TLD∧file-extension COLLISION set (.zip/.sh/.py/...) a bare 2-label token
    additionally needs positive domain PROVENANCE (it was the host of a parsed
    URL) -- a random-stem carved FILE with such an extension is otherwise
    indistinguishable from a domain (proven leak). Kill-switches
    SIFT_DGA_TLD_GATE=0 (-> legacy blocklist) / SIFT_DGA_PROVENANCE_GATE=0
    (TLD gate only). Falls back to the blocklist if the TLD set is unreadable
    so detection is never silently disabled."""
    if os.environ.get("SIFT_DGA_TLD_GATE", "1") != "0" and _tld_gate_available():
        if not _final_label_is_tld(domain):
            return True
        if (os.environ.get("SIFT_DGA_PROVENANCE_GATE", "1") != "0"
                and _needs_domain_provenance(domain)
                and str(provenance or "").strip().lower() not in _DOMAIN_PROVENANCE):
            return True
        return False
    return _is_filename_not_domain(domain)
# RFC-1035 domain label: letters/digits/hyphen only. Anything else (e.g. a
# URL-encoded "%77%77" or carve punctuation) is not a domain label.
_VALID_LABEL_RE = re.compile(r"^[a-z0-9-]+$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _longest_consonant_run(label: str) -> int:
    best = run = 0
    for ch in label:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _registrable_label(domain: str) -> str:
    """The second-level label (where registrable C2 DGA randomness lives): ``evil``
    from ``www.evil.com``. Scoring the SLD (not a long structured subdomain like
    ``csc3-2010-crl``) keeps legit infrastructure subdomains from false-flagging."""
    parts = [p for p in str(domain).lower().strip().strip(".").split(".") if p]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def _is_carving_fragment(label_raw: str) -> bool:
    """bulk_extractor carve noise (e.g. ``u-l-c-6-e-p-a-a-0``) is a string of single
    characters joined by dashes -- not a real domain label. Reject it so it never
    counts as DGA."""
    segs = [s for s in label_raw.split("-") if s]
    if len(segs) < 3:
        return False
    single = sum(1 for s in segs if len(s) <= 1)
    return single / len(segs) >= 0.5


def dga_score(domain: str, provenance: str = "") -> tuple[bool, float, list[str]]:
    """Return (is_suspect, score_0_to_1, reasons) for a domain's registrable label.
    Universal structure only -- no domain list. Conservative: low-vowel + >=1 more,
    carving fragments rejected. ``provenance`` ("url_host"/"carved"/...) feeds the
    TLD∧file-extension collision discriminator -- see _not_a_domain."""
    if _not_a_domain(domain, provenance):   # not a domain (or carve-ambiguous) -> never score
        return False, 0.0, []
    label_raw = _registrable_label(domain)
    if not _VALID_LABEL_RE.match(label_raw) or _is_carving_fragment(label_raw):
        return False, 0.0, []
    label = label_raw.replace("-", "")
    L = len(label)
    if L < 10:                       # too short to classify reliably -> never DGA
        return False, 0.0, []
    alpha = [c for c in label if c.isalpha()]
    if not alpha:
        return False, 0.0, []
    vowel_ratio = sum(1 for c in alpha if c in _VOWELS) / len(alpha)
    digit_ratio = sum(1 for c in label if c.isdigit()) / L
    ent = _shannon_entropy(label)
    ent_ratio = ent / math.log2(L) if L > 1 else 0.0
    cons_run = _longest_consonant_run(label)

    reasons: list[str] = []
    if vowel_ratio <= 0.26:
        reasons.append("low_vowel_ratio")
    if cons_run >= 5:
        reasons.append("long_consonant_run")
    if digit_ratio >= 0.25:
        reasons.append("high_digit_ratio")
    if ent_ratio >= 0.90:
        reasons.append("near_max_entropy")

    # Conservative: the low-vowel signal is required, plus at least one corroborator.
    is_suspect = "low_vowel_ratio" in reasons and len(reasons) >= 2
    return is_suspect, round(len(reasons) / 4.0, 2), reasons


def flag_dga_domains(domains, max_items: int = 25) -> tuple[list[dict], int]:
    """Scan an iterable of domains -> (suspects, suspect_count). Each suspect is
    {domain, score, reasons}, ranked by score. ``domains`` may be plain strings or
    ``{"value": domain, "count": n}`` histogram dicts (count is preserved)."""
    try:
        cap = max(0, int(max_items))
    except (TypeError, ValueError):
        cap = 0
    suspects: list[dict] = []
    for d in domains or []:
        if isinstance(d, dict):
            dom = d.get("value") or ""
            freq = d.get("count")
        else:
            dom = d
            freq = None
        is_sus, score, reasons = dga_score(dom)
        if is_sus:
            entry = {"domain": dom, "score": score, "reasons": reasons}
            if freq is not None:
                entry["count"] = freq
            suspects.append(entry)
    suspects.sort(key=lambda e: e["score"], reverse=True)
    return suspects[:cap], len(suspects)


__all__ = ["dga_score", "flag_dga_domains"]
