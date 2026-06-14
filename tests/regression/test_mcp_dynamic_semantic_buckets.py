"""Slot 31I-alpha: semantic-bucket schema/behavior (synthetic registry).

Dataset-agnostic by construction: only mock tool names are used; no
run-specific assumptions and no predetermined outputs.
"""

from sift_sentinel.tool_semantics import (
    SEMANTIC_BUCKETS,
    DEFAULT_SEMANTIC_BUCKET,
    get_tool_semantics,
    iter_tool_semantics,
    normalize_semantic_buckets,
)

_SYNTH_REGISTRY = {
    "vol_pstree": (object(), "memory"),
    "vol_netscan": (object(), "memory"),
    "vol_malfind": (object(), "memory"),
    "get_amcache": (object(), "disk"),
    "zzz_unknown_tool": (None, "mystery"),
}

_SYNTH_CAPS = {
    "vol_pstree": {"produces": ["process_tree"], "runtime_class": "fast",
                   "applicable_when": ["windows_evidence"],
                   "not_applicable_when": ["linux_evidence"]},
    "get_amcache": {"produces": ["execution_history_amcache"],
                    "runtime_class": "fast",
                    "applicable_when": ["windows_evidence",
                                        "disk_evidence"],
                    "not_applicable_when": ["linux_evidence"]},
}

_REQUIRED_KEYS = {
    "tool_name", "platforms", "evidence_domains", "buckets",
    "detects", "cost", "notes",
}


def test_default_bucket_in_vocabulary():
    assert DEFAULT_SEMANTIC_BUCKET in SEMANTIC_BUCKETS


def test_schema_shape_and_types():
    for name, entry in _SYNTH_REGISTRY.items():
        sem = get_tool_semantics(name, entry, _SYNTH_CAPS.get(name))
        assert set(sem) == _REQUIRED_KEYS
        for key in ("platforms", "evidence_domains", "buckets",
                    "detects"):
            assert isinstance(sem[key], tuple)
        assert sem["cost"] in {"low", "medium", "high"}
        assert isinstance(sem["notes"], str)


def test_buckets_are_non_empty_iterable_not_str_or_dict():
    for name, entry in _SYNTH_REGISTRY.items():
        b = get_tool_semantics(name, entry, _SYNTH_CAPS.get(name))[
            "buckets"]
        assert not isinstance(b, (str, dict))
        assert len(b) >= 1
        assert all(x in SEMANTIC_BUCKETS for x in b)


def test_unknown_tool_resolves_to_uncategorized():
    sem = get_tool_semantics("zzz_unknown_tool",
                             _SYNTH_REGISTRY["zzz_unknown_tool"])
    assert sem["buckets"] == (DEFAULT_SEMANTIC_BUCKET,)


def test_normalize_handles_str_dict_none_and_unknowns():
    assert normalize_semantic_buckets("memory_process") == (
        "memory_process",)
    assert normalize_semantic_buckets(None) == (
        DEFAULT_SEMANTIC_BUCKET,)
    assert normalize_semantic_buckets({}) == (DEFAULT_SEMANTIC_BUCKET,)
    assert normalize_semantic_buckets(["not_a_bucket"]) == (
        DEFAULT_SEMANTIC_BUCKET,)
    assert normalize_semantic_buckets(
        ["memory_process", "memory_process", "memory_network"]
    ) == ("memory_process", "memory_network")


def test_iter_tool_semantics_covers_every_entry():
    out = iter_tool_semantics(_SYNTH_REGISTRY, _SYNTH_CAPS)
    assert set(out) == set(_SYNTH_REGISTRY)
    for sem in out.values():
        assert set(sem) == _REQUIRED_KEYS


def test_iter_accepts_callable_capabilities():
    out = iter_tool_semantics(
        _SYNTH_REGISTRY, lambda n: _SYNTH_CAPS.get(n),
    )
    assert out["vol_pstree"]["cost"] == "low"
