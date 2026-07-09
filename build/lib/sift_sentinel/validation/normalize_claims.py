import copy
import ntpath
import os
import re

# A claim that names a Windows Event by ID (e.g. "Event 4688", "EventID: 1074")
# belongs to the validatable `event_log` claim type, not `path`. Windows Event
# IDs are OS-defined integers -> dataset-agnostic. Matched only on short,
# non-path-looking values (guarded below) so real filesystem paths are untouched.
_EVENT_ID_RE = re.compile(r"\bevent\s*(?:id)?\s*[:#]?\s*(\d{1,5})\b", re.IGNORECASE)

# Type alias remapping: map common AI-generated type names to validator types.
# Models often return near-miss type names; remap before type-specific handling.
_TYPE_ALIASES = {
    "process": "pid",
    "network": "connection",
    "execution": "timestamp",
    "file": "hash",
    "port": "connection",
    "ip": "connection",
    "address": "connection",
    "artifact": "path",
    "raw": "path",
}

# Claim types whose verdict hinges on a canonical ``value`` string. Used by the
# universal value-recovery pass: when one of these is missing ``value`` but carries
# the datum in another field, promote it. Identity-keyed types (pid/process) are
# excluded -- they validate on pid/process, not value.
_VALUE_BEARING_TYPES = frozenset({
    "path", "artifact", "raw", "hash", "connection", "url", "event_log",
    "srum_usage", "typed_fact",
})

# A Windows token privilege name (OS-defined constants -> dataset-agnostic):
# SeImpersonate, SeDebug, SeTcbPrivilege, SeChangeNotifyPrivilege, ... The camelCase
# `Se[A-Z]...` shape is specific enough to avoid 'Security'/'Service' path tokens.
_PRIVILEGE_RE = re.compile(r"\bSe[A-Z][A-Za-z]{2,}(?:Privilege)?\b")
# A process token (image name) carried in the artifact text.
_PROC_EXE_RE = re.compile(r"\b([A-Za-z0-9_.\-]+\.exe)\b", re.IGNORECASE)

# R1B bare-token / leading-token shapes. A single image-or-service-name-like
# token (letter-led, no separator, no space). Structural only -- no name list.
_BARE_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{2,31}$")
_LEAD_TOKEN_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-]{2,31})\b")


def _r1b_rescue_enabled() -> bool:
    """Kill-switch for the R1b claim-rescue family (default ON)."""
    return os.environ.get("SIFT_CLAIM_RESCUE_R1B", "1").strip().lower() \
        not in ("0", "false", "no", "off")


# A dotted-quad carried in a claim's prose value. The model sometimes emits a
# real external peer as a generic path claim (e.g. "network peer <ipv4>"); such
# a claim is really a network CONNECTION, validatable by_ip. Octet-range is
# enforced in _extract_ipv4 so a dotted version string is not mistaken for an
# IP. Dataset-agnostic: the IPv4 octet shape, never a literal address.
_IPV4_CAND_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Network cues that disambiguate an IP-as-peer from a dotted-quad inside a path.
_NET_CUE_RE = re.compile(
    r"\b(?:peer|ip|external|connection|c2|netscan|address|remote|inbound|"
    r"outbound|egress|beacon|host)\b", re.IGNORECASE)


def _extract_ipv4(text: str) -> str | None:
    """Return the first valid (octets 0-255) IPv4 in *text*, else None."""
    if not isinstance(text, str):
        return None
    for m in _IPV4_CAND_RE.finditer(text):
        if all(0 <= int(o) <= 255 for o in m.group(1).split(".")):
            return m.group(1)
    return None


def normalize_claims(findings: list[dict]) -> list[dict]:
    """Normalize AI-produced findings to match validator expected format.
    Deep copies -- never mutates originals."""
    result = copy.deepcopy(findings)
    _r1b_on = _r1b_rescue_enabled()
    for finding in result:
        if "claims" not in finding:
            continue
        # R1b context blob: finding-level prose used only to pick WHICH
        # validatable claim type a bare token is retyped to (cue words,
        # not case data). Lowercased once per finding.
        _fctx = " ".join(
            str(finding.get(_k) or "")
            for _k in ("title", "description", "artifact")).lower()
        normalized = []
        claims = finding.get("claims", [])
        for i in range(len(claims)):
            claim = claims[i]
            if not isinstance(claim, dict):
                if isinstance(claim, str):
                    claims[i] = {"type": "raw", "value": claim, "source_tools": []}
                    claim = claims[i]
                else:
                    continue
            ctype = claim.get("type", "")

            # Remap type aliases before type-specific normalization
            if ctype in _TYPE_ALIASES:
                ctype = _TYPE_ALIASES[ctype]
                claim["type"] = ctype

            # UNIVERSAL VALUE RECOVERY: a value-bearing claim whose canonical
            # ``value`` is missing but whose datum sits in another field
            # (registry_path / key / url / path / file / name / text ...) is
            # STRUCTURALLY valid -- recover it instead of dropping the finding as
            # "no recognized claim types". Keyed on field PRESENCE + value SHAPE,
            # never case data, so it works for any model emitting a near-miss claim
            # schema. NEVER clobbers an existing value (guarded) -> cannot regress a
            # well-formed claim.
            _value_present = (
                isinstance(claim.get("value"), str) and claim["value"].strip())
            # An explicit event_id field => really an event_log claim (Windows Event
            # IDs are OS-defined integers -> dataset-agnostic).
            if claim.get("event_id") and ctype in ("path", "raw", "artifact"):
                claim["type"] = ctype = "event_log"
                if not _value_present:
                    claim["value"] = "Event %s" % str(claim["event_id"]).strip()
                    _value_present = True
            if not _value_present and ctype in _VALUE_BEARING_TYPES:
                for _rf in ("registry_path", "key", "url", "path", "file",
                            "filename", "name", "text", "artifact"):
                    _rv = claim.get(_rf)
                    if isinstance(_rv, str) and _rv.strip():
                        claim["value"] = _rv.strip()
                        break

            # Event-ID rescue: a path/raw claim whose text names a Windows Event
            # ID is really an `event_log` claim (validatable by EID). Guard
            # against genuine paths: skip values containing a path separator or
            # an executable extension. Universal: EID is an integer, no case data.
            if ctype in ("path", "raw") and not claim.get("event_id"):
                for _src in (claim.get("value"), claim.get("artifact")):
                    if not isinstance(_src, str):
                        continue
                    low = _src.lower()
                    if "/" in low or "\\" in low or ".exe" in low:
                        continue
                    _m = _EVENT_ID_RE.search(_src)
                    if _m:
                        claim["type"] = "event_log"
                        claim["event_id"] = int(_m.group(1))
                        ctype = "event_log"
                        break

            # Privilege retype: a path/raw/artifact claim that structurally describes
            # "<process> privilege <SePrivilege> enabled/disabled" is really a
            # process_privilege_enabled claim (validatable against privilege_fact by
            # the existing typed checker), not a path. Keyed on the OS-defined Windows
            # privilege-name shape + a process token + the enabled/disabled context;
            # guarded so a real path is never retyped. Universal -- no case literal.
            if ctype in ("path", "raw", "artifact"):
                _pblob = " ".join(
                    str(claim.get(_k) or "")
                    for _k in ("value", "artifact", "text", "name", "title"))
                _plow = _pblob.lower()
                _pm = _PRIVILEGE_RE.search(_pblob)
                if _pm and ("privileg" in _plow or "enabled" in _plow
                            or "disabled" in _plow):
                    claim["type"] = ctype = "process_privilege_enabled"
                    claim.setdefault("privilege_name", _pm.group(0))
                    _pe = _PROC_EXE_RE.search(_pblob)
                    if _pe and not claim.get("process"):
                        claim["process"] = _pe.group(1)
                    if "enabled" not in claim:
                        claim["enabled"] = "disabled" not in _plow

            # IP rescue: a path/raw/artifact claim whose prose value carries an
            # IPv4 address is really a network CONNECTION (validatable by_ip via
            # _t_connection's pid-optional fallback). Guard against dotted-quad
            # version strings: rescue only when the text has a network cue OR the
            # value is essentially just the IP. Keyed on the IPv4 octet shape +
            # cue, never a literal address -> universal. Recovers real external
            # peers the model emitted as generic path claims.
            if ctype in ("path", "raw", "artifact") and not claim.get("foreign_addr"):
                _ipblob = " ".join(
                    str(claim.get(_k) or "")
                    for _k in ("value", "artifact", "text", "name"))
                _ip = _extract_ipv4(_ipblob)
                if _ip is not None:
                    _bare = str(claim.get("value") or "").strip() == _ip
                    if _bare or _NET_CUE_RE.search(_ipblob):
                        claim["type"] = ctype = "connection"
                        claim["foreign_addr"] = _ip
                        claim.setdefault("value", _ip)

            # R1B privilege process-recovery: a process_privilege* claim that
            # names a privilege but no process/pid ABSTAINS in the typed
            # checker (a privilege claim must identify a process context), so
            # the finding dies as "no recognized claim types". The process is
            # the LEADING image-name-shaped token of the claim text
            # ("<Proc> with SeXxx enabled") -- recover it structurally (token
            # shape, never a name list). Never clobbers an existing process.
            if (_r1b_on and ctype in ("process_privilege",
                                      "process_privilege_enabled")
                    and not claim.get("process")
                    and not claim.get("process_name")
                    and not claim.get("pid")):
                for _pf in ("value", "artifact", "text", "name"):
                    _pv = str(claim.get(_pf) or "").strip()
                    _pm2 = _LEAD_TOKEN_RE.match(_pv)
                    if _pm2 and not _PRIVILEGE_RE.match(_pm2.group(1)):
                        claim["process"] = _pm2.group(1)
                        break

            # R1B bare-token rescue (LAST resort): a path/raw/artifact claim
            # whose value is one bare extension-less token is not a filesystem
            # path and never binds by_path -> the finding is silently dropped
            # at Step 10. Retype by claim+finding CONTEXT: a service cue ->
            # `service` (binds by_service_name); otherwise `process_exists`
            # (binds the pid-less process-name scan). Both targets MATCH or
            # ABSTAIN -- a wrong retype cannot create a new MISMATCH block, it
            # leaves the finding exactly as dropped as before. Dotted tokens
            # (real filenames, versions) are excluded so existing path/hash
            # semantics are untouched. Shape-keyed, no case names.
            if (_r1b_on and ctype in ("path", "raw", "artifact")
                    and isinstance(claim.get("value"), str)):
                _bt = claim["value"].strip()
                if _BARE_TOKEN_RE.match(_bt):
                    _btctx = _fctx + " " + str(claim.get("artifact") or "").lower()
                    if "service" in _btctx:
                        claim["type"] = ctype = "service"
                        claim.setdefault("service_name", _bt)
                        claim["rescued_from"] = "bare_token_path"
                    elif any(_cue in _btctx for _cue in (
                            "process", "psxview", "pslist", "view",
                            "hiding", "hidden", "persistence")):
                        # Cue REQUIRED: a context-free bare token keeps the
                        # plain alias path type (pinned behavior) -- only an
                        # explicit process/view/persistence context earns the
                        # process_exists retype.
                        claim["type"] = ctype = "process_exists"
                        claim.setdefault("process", _bt)
                        claim["rescued_from"] = "bare_token_path"

            if ctype == "pid":
                if "process_name" in claim and "process" not in claim:
                    claim["process"] = claim.pop("process_name")
                if "process" in claim and isinstance(claim["process"], str):
                    claim["process"] = ntpath.basename(claim["process"])
                if "pid" in claim:
                    try:
                        claim["pid"] = int(claim["pid"])
                    except (ValueError, TypeError):
                        continue
                normalized.append(claim)

            elif ctype == "hash":
                if "hash" in claim and "sha1" not in claim:
                    claim["sha1"] = claim.pop("hash")
                # sha256 preserved as-is; do NOT relabel it as sha1
                if "path" in claim and "filename" not in claim:
                    claim["filename"] = claim.pop("path")
                if "file" in claim and "filename" not in claim:
                    claim["filename"] = claim.pop("file")
                if "filename" in claim and isinstance(claim["filename"], str):
                    claim["filename"] = ntpath.basename(claim["filename"])
                normalized.append(claim)

            elif ctype == "connection":
                # pid is OPTIONAL: _t_connection validates a no-pid connection
                # via by_ip on foreign_addr (CONNFIX_BY_IP_V1). Only drop a
                # connection that has NEITHER a usable pid NOR a foreign endpoint
                # -- otherwise a real external peer (owner=None on CLOSED/scanned
                # sockets, or an IP-rescued claim) would be silently lost.
                _pid_ok = False
                try:
                    claim["pid"] = int(claim.get("pid"))
                    _pid_ok = claim["pid"] != 0
                except (TypeError, ValueError):
                    claim.pop("pid", None)
                _has_addr = bool(
                    claim.get("foreign_addr") or claim.get("remote_addr")
                    or claim.get("foreign_ip") or claim.get("remote_ip")
                    or claim.get("foreign"))
                if not _pid_ok and not _has_addr:
                    continue
                if "process_name" in claim and "process" not in claim:
                    claim["process"] = claim.pop("process_name")
                if "foreign_ip" in claim and "foreign_addr" not in claim:
                    claim["foreign_addr"] = claim.pop("foreign_ip")
                if "remote_addr" in claim and "foreign_addr" not in claim:
                    claim["foreign_addr"] = claim.pop("remote_addr")
                # C27: bridge Inv2 prompt schema (remote_ip + remote_port)
                if "remote_ip" in claim and "foreign_addr" not in claim:
                    claim["foreign_addr"] = claim.pop("remote_ip")
                if "remote_port" in claim and "foreign_port" not in claim:
                    claim["foreign_port"] = claim.pop("remote_port")
                # C27: bridge SC strategies prompt schema (foreign: "ip:port")
                # 4-guard split: bracketed IPv6, IPv4 with port (non-empty addr),
                # bare address no colon, else skip (avoid empty/bare-IPv6 corruption).
                if "foreign" in claim and "foreign_addr" not in claim:
                    raw_foreign = claim.pop("foreign")
                    if isinstance(raw_foreign, str) and raw_foreign:
                        # Guard 1: bracketed IPv6 like [::1]:8080
                        if raw_foreign.startswith("[") and "]:" in raw_foreign:
                            addr, _, port = raw_foreign.partition("]:")
                            claim["foreign_addr"] = addr + "]"
                            try:
                                claim["foreign_port"] = int(port)
                            except (TypeError, ValueError):
                                pass
                        # Guard 2: IPv4 with single colon "ip:port", non-empty addr
                        elif ":" in raw_foreign and raw_foreign.count(":") == 1:
                            addr, _, port = raw_foreign.rpartition(":")
                            if addr:
                                claim["foreign_addr"] = addr
                                try:
                                    claim["foreign_port"] = int(port)
                                except (TypeError, ValueError):
                                    pass
                        # Guard 3: bare address (no colon) - IPv4 or hostname
                        elif ":" not in raw_foreign:
                            claim["foreign_addr"] = raw_foreign
                        # Guard 4 (else): bare IPv6 or multi-colon garbage - skip
                normalized.append(claim)

            elif ctype == "timestamp":
                if "value" in claim and "timestamp" not in claim:
                    claim["timestamp"] = claim.pop("value")
                normalized.append(claim)

            elif ctype == "path":
                # Canonicalize: lift the path value into `value` when the model
                # placed it under a synonym key (artifact/path/filename) -- this
                # also covers type:"artifact"/"raw" remapped to "path" above.
                # Every validator consumer already reads these keys
                # (validator._check_hash, _check_timestamp, typed _t_passthrough),
                # so this is validation-neutral; it fixes value-strict report/
                # audit renderers (e.g. the customer findings table `path` branch)
                # that have no artifact fallback. Never overwrites an existing
                # value. Universal: pure schema-key normalization, no case data.
                if not claim.get("value"):
                    for _k in ("artifact", "path", "filename"):
                        _pv = claim.get(_k)
                        if isinstance(_pv, str) and _pv.strip():
                            claim["value"] = _pv
                            break
                normalized.append(claim)

            else:
                normalized.append(claim)

        finding["claims"] = normalized
    return result
