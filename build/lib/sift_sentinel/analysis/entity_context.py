"""Entity-context propagation for finding presentation clustering.

Builds a per-finding context map that exposes entity overlap across
disposition buckets. Each finding gets:
  - entity_keys: canonical entity keys derived from claims
  - shares_entity_with: other findings sharing any entity key
  - entity_react_refuted_by: shared peers in benign_or_false_positive
    with a react_conclusion (ReAct cross-check FP'd them)
  - entity_react_confirmed_by: shared peers in confirmed_malicious_atomic

PURELY ADDITIVE: does not move findings between buckets, does not modify
validation, does not change report content unless report logic opts in.

DATASET-AGNOSTIC ABSOLUTE: derives keys only from claim values present.
No hardcoded PIDs/paths/IPs/hashes/fixtures.
"""
from __future__ import annotations

from typing import Any

BUCKET_BENIGN = "benign_or_false_positive"
BUCKET_CONFIRMED = "confirmed_malicious_atomic"


def _entity_keys_from_claims(claims):
    """Extract canonical entity keys from a finding's claims.

    Supported claim types:
      pid / process_exists -> "pid:N"   (from claim.pid or claim.value)
      path                 -> "path:<lower, kernel-prefix-stripped>"
      connection           -> "port:N" and/or "endpoint:host:port"
      hash                 -> "hash:<lower>"

    Sparse/unsupported claims contribute no keys.
    """
    keys = set()
    for c in (claims or []):
        if not isinstance(c, dict):
            continue
        ctype = c.get("type")
        if ctype in ("pid", "process_exists"):
            pid_val = c.get("pid")
            if pid_val is None:
                pid_val = c.get("value")
            if pid_val is not None:
                keys.add(f"pid:{pid_val}")
        elif ctype == "path":
            path_v = c.get("value") or c.get("artifact") or c.get("path")
            if isinstance(path_v, str) and path_v.strip():
                norm = path_v.strip().lower()
                for prefix in ("\\??\\", "\\\\?\\", "\\\\.\\"):
                    if norm.startswith(prefix.lower()):
                        norm = norm[len(prefix):]
                        break
                keys.add(f"path:{norm}")
        elif ctype == "connection":
            for k in ("local_port", "port", "src_port", "dst_port"):
                v = c.get(k)
                if v is not None:
                    keys.add(f"port:{v}")
            for k in ("remote", "remote_addr", "endpoint"):
                v = c.get(k)
                if isinstance(v, str) and v.strip():
                    keys.add(f"endpoint:{v.strip().lower()}")
        elif ctype == "hash":
            h = c.get("value") or c.get("hash")
            if isinstance(h, str) and h.strip():
                keys.add(f"hash:{h.strip().lower()}")
    return keys


def build_entity_context_map(disposition_buckets):
    """Build per-finding entity-context map.

    Args:
        disposition_buckets: bucket-name -> list of finding dicts (output
            of route_findings_for_report). Findings without a finding_id
            are silently skipped.

    Returns:
        dict[finding_id, {
            entity_keys: sorted list[str],
            shares_entity_with: sorted list[str],
            entity_react_refuted_by: sorted list[str],
            entity_react_confirmed_by: sorted list[str],
        }]
    """
    if not disposition_buckets:
        return {}

    fid_to_keys = {}
    fid_to_bucket = {}
    fid_to_finding = {}
    for bucket_name, items in disposition_buckets.items():
        if not isinstance(items, list):
            continue
        for f in items:
            if not isinstance(f, dict):
                continue
            fid = f.get("finding_id") or f.get("id")
            if not fid:
                continue
            fid_to_keys[fid] = _entity_keys_from_claims(f.get("claims") or [])
            fid_to_bucket[fid] = bucket_name
            fid_to_finding[fid] = f

    key_to_fids = {}
    for fid, keys in fid_to_keys.items():
        for k in keys:
            key_to_fids.setdefault(k, set()).add(fid)

    out = {}
    for fid, keys in fid_to_keys.items():
        shared = set()
        for k in keys:
            shared.update(key_to_fids.get(k, set()))
        shared.discard(fid)

        react_refuted = []
        react_confirmed = []
        for other_fid in shared:
            other_f = fid_to_finding.get(other_fid, {})
            other_bucket = fid_to_bucket.get(other_fid)
            if other_bucket == BUCKET_BENIGN and other_f.get("react_conclusion"):
                react_refuted.append(other_fid)
            elif other_bucket == BUCKET_CONFIRMED:
                react_confirmed.append(other_fid)

        out[fid] = {
            "entity_keys": sorted(keys),
            "shares_entity_with": sorted(shared),
            "entity_react_refuted_by": sorted(react_refuted),
            "entity_react_confirmed_by": sorted(react_confirmed),
        }
    return out
