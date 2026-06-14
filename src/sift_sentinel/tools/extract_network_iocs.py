"""Dataset-agnostic network IOC candidate extractor.

This module consumes already-provided runtime tool outputs. It does not read
from disk, run commands, or make network calls.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any


TOOL_NAME = "extract_network_iocs"
EVIDENCE_TYPE = "network_ioc_candidate"

CONTEXT_CHARS = 160
URL_CHARS = 2048
TRAILING_TOKEN_CHARS = ".,;:!?)]}\"'"

FILE_EXTENSION_TLDS = frozenset({
    "dll",
    "exe",
    "sys",
    "ini",
    "log",
    "json",
    "xml",
    "txt",
    "pdb",
    "bin",
    "dat",
    "tmp",
    "lib",
    "obj",
    "res",
    "rc",
    "h",
    "c",
    "cpp",
    "py",
    "js",
    "css",
    "html",
    "htm",
})

GENERIC_CONTAINER_KEYS = frozenset({
    "records",
    "output",
    "tool_outputs",
    "findings",
    "errors",
    "metadata",
    "record_count",
    "status",
    "tool",
    "tool_name",
    "source_tools",
    "sources",
})

PORT_FIELD_NAMES = frozenset({
    "port",
    "remote_port",
    "dst_port",
    "destination_port",
    "source_port",
    "src_port",
    "local_port",
    "foreign_port",
})

URL_RE = re.compile(r"\bhttps?://[^\s<>'\"\]\)\}]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_@:/\\.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}\b"
)
HOST_PORT_RE = re.compile(
    r"(?<![A-Za-z0-9_.:-])"
    r"(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)"
    r":(\d{1,5})(?!\d)"
)
PORT_LABEL_RE = re.compile(
    r"\b(?:remote_port|dst_port|source_port|destination_port|port)"
    r"\s*[:= ]\s*(\d{1,5})\b",
    re.IGNORECASE,
)
COLON_PORT_RE = re.compile(r"(?<![A-Za-z0-9_.\]-]):(\d{1,5})(?!\d)")
IPV6_TOKEN_RE = re.compile(r"(?<![0-9A-Fa-f])\[?[0-9A-Fa-f:]{2,45}\]?(?![0-9A-Fa-f])")


class _Accumulator:
    def __init__(self, max_records: int) -> None:
        self.max_records = max(0, int(max_records))
        self.records_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        self.order: list[tuple[str, str]] = []
        self.source_keys: dict[tuple[str, str], set[tuple[Any, ...]]] = {}
        self.capped = False
        self.candidate_seen = False

    def add(
        self,
        kind: str,
        value: str,
        original_value: str,
        classification: str,
        port: int | None,
        source: dict[str, Any],
    ) -> None:
        self.candidate_seen = True
        key = (kind, value)
        if key not in self.records_by_key:
            if len(self.order) >= self.max_records:
                self.capped = True
                return
            self.records_by_key[key] = {
                "type": kind,
                "value": value,
                "original_value": original_value,
                "classification": classification,
                "port": port,
                "source_tools": [],
                "sources": [],
                "count": 0,
                "evidence_type": EVIDENCE_TYPE,
            }
            self.source_keys[key] = set()
            self.order.append(key)

        record = self.records_by_key[key]
        record["count"] += 1
        source_tool = source["source_tool"]
        if source_tool not in record["source_tools"]:
            record["source_tools"].append(source_tool)
        source_key = (
            source["source_tool"],
            source["source_field"],
            source["source_index"],
            source["offset"],
        )
        if source_key not in self.source_keys[key]:
            self.source_keys[key].add(source_key)
            record["sources"].append(source)

    def records(self) -> list[dict[str, Any]]:
        return [self.records_by_key[key] for key in self.order]


def _envelope(status: str, records: list[dict[str, Any]], errors: list[str]) -> dict:
    return {
        "tool": TOOL_NAME,
        "tool_name": TOOL_NAME,
        "status": status,
        "record_count": len(records),
        "records": records,
        "errors": errors,
    }


def _bounded_context(text: str, start: int, end: int) -> str:
    left = max(0, start - CONTEXT_CHARS // 2)
    right = min(len(text), end + CONTEXT_CHARS // 2)
    return text[left:right].strip()


def _context_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:CONTEXT_CHARS] if text else None


def _clean_token(value: str) -> str:
    return value.strip().strip(TRAILING_TOKEN_CHARS)


def _clean_url(value: str) -> str:
    return _clean_token(value)[:URL_CHARS]


def _path_join(path: str, part: str | int) -> str:
    if isinstance(part, int):
        return f"{path}[{part}]" if path else f"[{part}]"
    return f"{path}.{part}" if path else str(part)


def _source(
    source_tool: str | None,
    source_field: str | None,
    source_index: int | None,
    source_path: str,
    text: str,
    start: int,
    end: int,
    base_offset: int = 0,
    context_override: str | None = None,
) -> dict[str, Any]:
    return {
        "source_tool": source_tool or "provided_input",
        "source_field": source_field or "text",
        "source_index": source_index,
        "source_path": source_path or "$",
        "context": context_override or _bounded_context(text, start, end),
        "offset": base_offset + start,
    }


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _valid_port(value: Any) -> int | None:
    port = _coerce_int(value)
    if port is None or not 1 <= port <= 65535:
        return None
    return port


def _is_port_field(field: str | None) -> bool:
    if not field:
        return False
    lowered = field.lower()
    return lowered in PORT_FIELD_NAMES or lowered.endswith("_port")


def _classify_ipv4(value: str) -> str | None:
    parts = value.split(".")
    if len(parts) != 4 or any(not part.isdigit() for part in parts):
        return None
    octets = tuple(int(part) for part in parts)
    if any(octet > 255 for octet in octets):
        return None
    first, second, third, fourth = octets
    if octets == (0, 0, 0, 0):
        return "unspecified"
    if octets == (255, 255, 255, 255):
        return "broadcast"
    if first == 127:
        return "loopback"
    if first == 10 or (first == 172 and 16 <= second <= 31) or (
        first == 192 and second == 168
    ):
        return "private"
    if first == 169 and second == 254:
        return "link_local"
    if 224 <= first <= 239:
        return "multicast"
    if (
        (first, second, third) == (192, 0, 2)
        or (first, second, third) == (198, 51, 100)
        or (first, second, third) == (203, 0, 113)
    ):
        return "reserved"
    return "public"


def _classify_ipv6(value: str) -> str | None:
    token = value.strip("[]")
    if ":" not in token:
        return None
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return None
    if ip.version != 6:
        return None
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return "public"


def _allowed_ip_classification(
    classification: str,
    include_private: bool,
    include_loopback: bool,
) -> bool:
    if classification == "private" and not include_private:
        return False
    if classification == "loopback" and not include_loopback:
        return False
    return True


def _valid_domain(value: str) -> str | None:
    token = _clean_token(value).lower()
    if not token or "\\" in token or "/" in token or ".." in token:
        return None
    labels = token.split(".")
    if len(labels) < 2:
        return None
    tld = labels[-1]
    if tld in FILE_EXTENSION_TLDS:
        return None
    if not re.fullmatch(r"[a-z]{2,24}", tld):
        return None
    if re.fullmatch(r"v?\d+(?:\.\d+)+(?:[a-z]+)?", token):
        return None
    for label in labels:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            return None
    return token


def _parse_host(value: str) -> tuple[str, str, str | None, int | None, int, int] | None:
    host_start = 0
    host_end = len(value)
    authority = value
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        host_start = len(userinfo) + 1
        host_end = host_start + len(authority)

    port: int | None = None
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host = authority[1:close]
        host_end = host_start + close + 1
        remainder = authority[close + 1:]
        if remainder:
            if not remainder.startswith(":"):
                return None
            port = _valid_port(remainder[1:])
            if port is None:
                return None
        classification = _classify_ipv6(host)
        if classification is None:
            return None
        return host.lower(), "ipv6", classification, port, host_start + 1, host_end - 1

    if ":" in authority:
        host_part, port_part = authority.rsplit(":", 1)
        parsed_port = _valid_port(port_part)
        if parsed_port is not None:
            authority = host_part
            port = parsed_port
            host_end = host_start + len(authority)

    ipv4_class = _classify_ipv4(authority)
    if ipv4_class is not None:
        return authority, "ipv4", ipv4_class, port, host_start, host_end

    domain = _valid_domain(authority)
    if domain is not None:
        return domain, "domain", "unknown", port, host_start, host_end
    return None


def _parse_url(value: str) -> tuple[str, str, str, int, int] | None:
    match = re.match(r"(?P<scheme>https?)://(?P<authority>[^/?#\s]+)(?P<rest>.*)", value, re.IGNORECASE)
    if not match:
        return None
    authority = match.group("authority")
    parsed_host = _parse_host(authority)
    if parsed_host is None:
        return None
    host, _kind, _classification, _port, host_start, host_end = parsed_host
    scheme = match.group("scheme").lower()
    rest = match.group("rest")
    normalized_authority = authority[:host_start] + host + authority[host_end:]
    normalized = f"{scheme}://{normalized_authority}{rest}"
    absolute_host_start = match.start("authority") + host_start
    absolute_host_end = match.start("authority") + host_end
    return normalized, host, authority, absolute_host_start, absolute_host_end


def _inside_any(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(span_start <= start and end <= span_end for span_start, span_end in spans)


def _emit_host(
    acc: _Accumulator,
    host: str,
    original_host: str,
    source: dict[str, Any],
    include_private: bool,
    include_loopback: bool,
) -> None:
    ipv4_class = _classify_ipv4(host)
    if ipv4_class is not None:
        if _allowed_ip_classification(ipv4_class, include_private, include_loopback):
            acc.add("ipv4", host, original_host, ipv4_class, None, source)
        return

    ipv6_class = _classify_ipv6(host)
    if ipv6_class is not None:
        normalized = host.strip("[]").lower()
        if _allowed_ip_classification(ipv6_class, include_private, include_loopback):
            acc.add("ipv6", normalized, original_host, ipv6_class, None, source)
        return

    domain = _valid_domain(host)
    if domain is not None:
        acc.add("domain", domain, original_host, "unknown", None, source)


def _emit_port(
    acc: _Accumulator,
    port: int,
    source: dict[str, Any],
    original_value: str | None = None,
) -> None:
    acc.add("port", str(port), original_value or str(port), "unknown", port, source)


def _extract_from_text(
    text: str,
    acc: _Accumulator,
    source_tool: str | None,
    source_field: str | None,
    source_index: int | None,
    source_path: str,
    base_offset: int,
    context_override: str | None,
    max_text_chars: int,
    include_private: bool,
    include_loopback: bool,
) -> None:
    if max_text_chars <= 0:
        return
    value = text[:max_text_chars]
    host_spans: list[tuple[int, int]] = []
    port_offsets: set[int] = set()

    for match in URL_RE.finditer(value):
        original = _clean_url(match.group(0))
        parsed_url = _parse_url(original)
        if parsed_url is None:
            continue
        normalized, host, authority, host_start, host_end = parsed_url
        url_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            match.start(),
            match.start() + len(original),
            base_offset,
            context_override,
        )
        acc.add("url", normalized, original, "unknown", None, url_source)

        absolute_host_start = match.start() + host_start
        absolute_host_end = match.start() + host_end
        host_spans.append((absolute_host_start, absolute_host_end))
        host_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            absolute_host_start,
            absolute_host_end,
            base_offset,
            context_override,
        )
        _emit_host(
            acc,
            host,
            authority[host_start:host_end],
            host_source,
            include_private,
            include_loopback,
        )

    for match in HOST_PORT_RE.finditer(value):
        host_original = _clean_token(match.group(1))
        port = _valid_port(match.group(2))
        if port is None:
            continue
        host_text = host_original.strip("[]")
        parsed = _parse_host(host_original)
        if parsed is None:
            continue
        normalized_host, host_kind, classification, _inner_port, _hs, _he = parsed
        if not _allowed_ip_classification(classification, include_private, include_loopback):
            continue
        host_port_value = (
            f"[{normalized_host}]:{port}" if host_kind == "ipv6" else f"{normalized_host}:{port}"
        )
        hp_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            match.start(),
            match.end(),
            base_offset,
            context_override,
        )
        acc.add(
            "host_port",
            host_port_value,
            match.group(0),
            classification,
            port,
            hp_source,
        )
        host_start = match.start(1) + (1 if host_original.startswith("[") else 0)
        host_end = host_start + len(host_text)
        port_start = match.start(2)
        host_spans.append((host_start, host_end))
        port_offsets.add(port_start)

        host_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            host_start,
            host_end,
            base_offset,
            context_override,
        )
        _emit_host(
            acc,
            normalized_host,
            host_text,
            host_source,
            include_private,
            include_loopback,
        )
        port_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            port_start,
            match.end(2),
            base_offset,
            context_override,
        )
        _emit_port(acc, port, port_source)

    for match in IPV4_RE.finditer(value):
        if _inside_any(match.start(), match.end(), host_spans):
            continue
        token = match.group(0)
        classification = _classify_ipv4(token)
        if classification is None:
            continue
        if not _allowed_ip_classification(classification, include_private, include_loopback):
            continue
        ip_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            match.start(),
            match.end(),
            base_offset,
            context_override,
        )
        acc.add("ipv4", token, token, classification, None, ip_source)

    for match in IPV6_TOKEN_RE.finditer(value):
        token = _clean_token(match.group(0))
        if ":" not in token or _inside_any(match.start(), match.end(), host_spans):
            continue
        classification = _classify_ipv6(token)
        if classification is None:
            continue
        if not _allowed_ip_classification(classification, include_private, include_loopback):
            continue
        normalized = token.strip("[]").lower()
        ip_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            match.start(),
            match.end(),
            base_offset,
            context_override,
        )
        acc.add("ipv6", normalized, token, classification, None, ip_source)

    for match in DOMAIN_RE.finditer(value):
        if _inside_any(match.start(), match.end(), host_spans):
            continue
        domain = _valid_domain(match.group(0))
        if domain is None:
            continue
        domain_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            match.start(),
            match.end(),
            base_offset,
            context_override,
        )
        acc.add("domain", domain, match.group(0), "unknown", None, domain_source)

    for match in PORT_LABEL_RE.finditer(value):
        port = _valid_port(match.group(1))
        if port is None:
            continue
        port_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            match.start(1),
            match.end(1),
            base_offset,
            context_override,
        )
        _emit_port(acc, port, port_source)

    for match in COLON_PORT_RE.finditer(value):
        if match.start(1) in port_offsets:
            continue
        port = _valid_port(match.group(1))
        if port is None:
            continue
        port_source = _source(
            source_tool,
            source_field,
            source_index,
            source_path,
            value,
            match.start(1),
            match.end(1),
            base_offset,
            context_override,
        )
        _emit_port(acc, port, port_source)


def _maybe_add_field_port(
    value: Any,
    acc: _Accumulator,
    source_tool: str | None,
    source_field: str | None,
    source_index: int | None,
    source_path: str,
) -> None:
    if not _is_port_field(source_field):
        return
    port = _valid_port(value)
    if port is None:
        return
    source = {
        "source_tool": source_tool or "provided_input",
        "source_field": source_field or "text",
        "source_index": source_index,
        "source_path": source_path or "$",
        "context": str(value),
        "offset": None,
    }
    _emit_port(acc, port, source, str(value))


def _tool_from_key(
    current_tool: str | None,
    path: str,
    key: str,
    child: Any,
) -> str | None:
    if not isinstance(child, (dict, list)) or key in GENERIC_CONTAINER_KEYS:
        return current_tool
    if not path or path.endswith("tool_outputs"):
        return key
    return current_tool


def _walk(
    value: Any,
    acc: _Accumulator,
    source_tool: str | None,
    source_field: str | None,
    source_index: int | None,
    source_path: str,
    max_text_chars: int,
    include_private: bool,
    include_loopback: bool,
) -> None:
    if isinstance(value, dict):
        local_tool = source_tool
        explicit_tool = value.get("tool_name") or value.get("tool")
        if isinstance(explicit_tool, str) and explicit_tool.strip():
            local_tool = explicit_tool.strip()

        candidate_value = value.get("value")
        candidate_offset = _coerce_int(value.get("offset")) or 0
        candidate_context = _context_text(value.get("context"))
        skip_keys: set[str] = set()
        if isinstance(candidate_value, str) and (
            "offset" in value or "context" in value
        ):
            candidate_path = _path_join(source_path, "value")
            _maybe_add_field_port(
                candidate_value,
                acc,
                local_tool,
                "value",
                source_index,
                candidate_path,
            )
            _extract_from_text(
                candidate_value,
                acc,
                local_tool,
                "value",
                source_index,
                candidate_path,
                candidate_offset,
                candidate_context,
                max_text_chars,
                include_private,
                include_loopback,
            )
            skip_keys.update({"value", "context"})

        for key, child in value.items():
            key_text = str(key)
            if key_text in skip_keys:
                continue
            child_path = _path_join(source_path, key_text)
            child_tool = _tool_from_key(local_tool, source_path, key_text, child)
            _walk(
                child,
                acc,
                child_tool,
                key_text,
                source_index,
                child_path,
                max_text_chars,
                include_private,
                include_loopback,
            )
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            child_index = index if source_index is None else source_index
            _walk(
                child,
                acc,
                source_tool,
                source_field,
                child_index,
                _path_join(source_path, index),
                max_text_chars,
                include_private,
                include_loopback,
            )
        return

    _maybe_add_field_port(
        value,
        acc,
        source_tool,
        source_field,
        source_index,
        source_path,
    )
    if isinstance(value, str):
        _extract_from_text(
            value,
            acc,
            source_tool,
            source_field,
            source_index,
            source_path,
            0,
            None,
            max_text_chars,
            include_private,
            include_loopback,
        )


def extract_network_iocs(
    tool_outputs: dict | list | str | None = None,
    max_records: int = int(os.environ.get("SIFT_NETWORK_IOC_MAX", "25000")),
    max_text_chars_per_record: int = 20000,
    include_private: bool = True,
    include_loopback: bool = True,
) -> dict:
    """Extract evidence-backed network IOC candidates from supplied outputs.

    The extractor is intentionally read-only and only traverses the supplied
    in-memory object. It returns candidate evidence, not maliciousness labels.
    """
    if tool_outputs is None:
        return _envelope("not_found", [], [])
    if not isinstance(tool_outputs, (dict, list, str)):
        return _envelope(
            "parse_error",
            [],
            [f"unsupported input type: {type(tool_outputs).__name__}"],
        )

    acc = _Accumulator(max_records)
    _walk(
        tool_outputs,
        acc,
        None,
        None,
        None,
        "",
        max(0, int(max_text_chars_per_record)),
        include_private,
        include_loopback,
    )
    records = acc.records()
    if acc.capped:
        status = "capped"
    elif records:
        status = "ok"
    else:
        status = "not_found"
    return _envelope(status, records, [])
