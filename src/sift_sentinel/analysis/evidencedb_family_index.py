from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

# SIFT_EVIDENCEDB_FAMILY_INDEX_V1F
#
# Universal EvidenceDB family index:
# - Handles EvidenceDB layouts that store facts in typed_facts, facts, by_tool,
#   by_family, records, or nested sidecar structures.
# - De-duplicates facts by stable fact id where present.
# - Counts fact families by source tool so gates can validate tool -> typed DB wiring.
# - Does not assume one specific dataset, case, or EvidenceDB schema revision.

_FACT_KEYS = ("fact_type", "family", "type")
_TOOL_KEYS = (
    "source_tool",
    "producer_tool",
    "tool",
    "tool_name",
    "source",
    "producer",
)
_ID_KEYS = ("fact_id", "id", "uid", "uuid", "record_id")


def _load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        return {}


def _iter_dicts(obj: Any) -> Iterable[dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _iter_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_dicts(value)


def _clean_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _family_from_record(rec: dict[str, Any]) -> str:
    for key in _FACT_KEYS:
        value = _clean_string(rec.get(key))
        if value.endswith("_fact"):
            return value
    return ""


def _tools_from_record(rec: dict[str, Any]) -> list[str]:
    tools: list[str] = []
    for key in _TOOL_KEYS:
        value = rec.get(key)
        if isinstance(value, str) and value.strip():
            tools.append(value.strip())
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    tools.append(item.strip())

    # Common nested forms.
    for key in ("metadata", "provenance", "source_metadata"):
        nested = rec.get(key)
        if isinstance(nested, dict):
            tools.extend(_tools_from_record(nested))

    out: list[str] = []
    seen: set[str] = set()
    for tool in tools:
        if tool and tool not in seen:
            seen.add(tool)
            out.append(tool)
    return out


def _record_id(rec: dict[str, Any]) -> str:
    for key in _ID_KEYS:
        value = _clean_string(rec.get(key))
        if value:
            return value
    return ""


def _stable_fallback_id(rec: dict[str, Any], family: str, tool: str) -> str:
    # Keep fallback bounded so the index stays cheap on large EvidenceDB files.
    try:
        blob = json.dumps(rec, sort_keys=True, default=str, ensure_ascii=False)[:1000]
    except Exception:
        blob = repr(rec)[:1000]
    return f"fallback:{family}:{tool}:{blob}"


def index_evidencedb_families(evidence_db_path: str | Path) -> dict[str, Any]:
    db = _load_json(evidence_db_path)

    by_tool: dict[str, Counter[str]] = defaultdict(Counter)
    by_family: Counter[str] = Counter()
    examples: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, str, str]] = set()

    for rec in _iter_dicts(db):
        family = _family_from_record(rec)
        if not family:
            continue

        tools = _tools_from_record(rec)
        if not tools:
            continue

        rid = _record_id(rec)
        for tool in tools:
            if not tool:
                continue
            key = (tool, family, rid or _stable_fallback_id(rec, family, tool))
            if key in seen:
                continue
            seen.add(key)
            by_tool[tool][family] += 1
            by_family[family] += 1
            examples.setdefault(f"{tool}:{family}", rec)

    return {
        "by_tool": {tool: dict(counter) for tool, counter in sorted(by_tool.items())},
        "by_family": dict(sorted(by_family.items())),
        "examples": examples,
        "total_indexed": sum(by_family.values()),
    }


def families_for_tool(evidence_db_path: str | Path, tool: str) -> dict[str, int]:
    return dict(index_evidencedb_families(evidence_db_path).get("by_tool", {}).get(tool, {}))


if __name__ == "__main__":
    import sys
    idx = index_evidencedb_families(sys.argv[1] if len(sys.argv) > 1 else "evidence_db.json")
    print(json.dumps(idx, indent=2, sort_keys=True, default=str))
