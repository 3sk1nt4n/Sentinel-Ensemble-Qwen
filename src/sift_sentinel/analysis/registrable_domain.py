"""Shared, universal registrable-domain gate.

A token is a DOMAIN only when its final dotted label is a registered top-level
domain (the IANA / ICANN TLD set, vendored from the Mozilla Public Suffix List in
``data/iana_tlds.txt``). This is the deliberate INVERSION of a file-extension
blocklist:

  * a blocklist of file extensions is inherently case-specific and incomplete --
    it has to enumerate every non-TLD extension a given sample happens to carry
    (``.sqm``, ``.jrs``, ``.ttc``, ``.clb`` ...), so it always misses the next one;
  * the TLD ALLOWLIST is a bounded, universal public standard -- identical for
    every case on earth -- so it generalises to any held-out box. A real domain
    (including a brand-new gTLD like ``.zip`` / ``.mov``) is never dropped; a
    filename whose final label is not a TLD is never treated as a domain.

Pure, deterministic, no case data. One definition, reused by every consumer
(DGA scoring, the IOC roll-up, the EvidenceDB host index) so the four historic
ad-hoc blocklists collapse to a single authority.
"""
from __future__ import annotations

import functools
import os

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "iana_tlds.txt")


@functools.lru_cache(maxsize=1)
def tld_set() -> frozenset:
    """The vendored IANA/ICANN TLD set (lowercased, punycode for IDN). Empty
    frozenset if the data file cannot be read -- callers treat empty as
    'gate unavailable' and fall back, so a missing file never silently disables
    detection."""
    out: set = set()
    try:
        with open(_DATA, encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    out.add(s.lower())
    except OSError:
        pass
    return frozenset(out)


def _labels(token) -> list:
    return [p for p in str(token or "").strip().strip(".").lower().split(".") if p]


def is_known_tld(label) -> bool:
    """True when ``label`` (a single segment) is a registered TLD."""
    return str(label or "").strip().strip(".").lower() in tld_set()


def final_label_is_tld(token) -> bool:
    """True when ``token`` has >= 2 dotted labels AND its final label is a real
    TLD -- i.e. it is a plausible domain, not a filename or bare basename."""
    labels = _labels(token)
    return len(labels) >= 2 and labels[-1] in tld_set()


def is_registrable_domain(token) -> bool:
    """True when ``token`` looks like a registrable domain. Alias of
    :func:`final_label_is_tld`; universal TLD allowlist, no case data."""
    return final_label_is_tld(token)


def gate_available() -> bool:
    """True when the TLD set loaded (so the allowlist gate can be trusted).
    Callers fall back to legacy behaviour when this is False."""
    return bool(tld_set())


# Labels that are BOTH a delegated IANA TLD AND a common file extension on a
# modern system (archives / scripts / shared objects / media / docs). For these
# -- and ONLY these -- a bare 2-label token is ambiguous by nature, so callers
# require positive DOMAIN PROVENANCE (URL/host context or an explicit
# subdomain) before treating it as a domain. The set is the bounded
# intersection of two universal vocabularies (the IANA TLD list x file-format
# grammar), not a case blocklist. Deliberately EXCLUDES "com" (overwhelmingly
# the TLD; DOS .com carving is negligible and gating it would gut DGA recall).
TLD_FILE_EXT_COLLISIONS = frozenset({
    "zip", "mov", "app", "sh", "so", "py", "rs", "pl", "md",
    "cab", "man", "cat",
})


def needs_domain_provenance(token) -> bool:
    """True when ``token`` is a 2-label name whose final label is in the
    TLD∧file-extension collision set -- i.e. it can only be trusted as a domain
    with positive provenance (URL/host context). >=3 labels are domain-shaped
    on their own (explicit subdomain)."""
    labels = _labels(token)
    return len(labels) == 2 and labels[-1] in TLD_FILE_EXT_COLLISIONS


__all__ = ["tld_set", "is_known_tld", "final_label_is_tld",
           "is_registrable_domain", "gate_available"]
