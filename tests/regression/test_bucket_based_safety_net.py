"""Slot 31I-gamma: safety-net padding is bucket-driven, not a list.

A synthetic registry (bucket inferred from tool name) proves thin
selections are padded from REGISTERED tools by semantic bucket
priority, that no exact hardcoded production tool-name list is
required, and that an unregistered name can never be selected.
"""

import pytest

import sift_sentinel.coordinator as c

# Names chosen so the dataset-agnostic semantic resolver routes each to
# a known bucket purely from its name (no run-specific assumptions).
_SYNTH_REGISTRY = {
    # memory_process
    "vol_pstree": (None, "vol_generic"),
    "vol_psscan": (None, "vol_generic"),
    "vol_cmdline": (None, "vol_generic"),
    "vol_sessions": (None, "vol_generic"),
    "vol_envars": (None, "vol_generic"),
    # memory_injection
    "vol_malfind": (None, "vol_generic"),
    "vol_hollowprocesses": (None, "vol_generic"),
    "vol_vadinfo": (None, "vol_generic"),
    # memory_network
    "vol_netscan": (None, "vol_generic"),
    "vol_netstat": (None, "vol_generic"),
    # memory_modules
    "vol_modscan": (None, "vol_generic"),
    "vol_dlllist": (None, "vol_generic"),
    "vol_ldrmodules": (None, "vol_generic"),
    # memory_kernel
    "vol_ssdt": (None, "vol_generic"),
    "vol_callbacks": (None, "vol_generic"),
    # evtx / execution / timeline / triage (disk side)
    "parse_event_logs": (None, "disk"),
    "get_amcache": (None, "disk"),
    "parse_prefetch": (None, "disk"),
    "extract_mft_timeline": (None, "disk"),
    "run_yara": (None, "sift_native"),
    "parse_wmi_subscription": (None, "disk"),
    "decode_base64_strings": (None, "sift_native"),
}


@pytest.fixture
def synth(monkeypatch):
    monkeypatch.setattr(c, "_TOOL_REGISTRY", dict(_SYNTH_REGISTRY))
    monkeypatch.setattr(
        c, "get_capability",
        lambda n: {} if n in _SYNTH_REGISTRY else None,
    )
    monkeypatch.setattr(c, "DISK_TOOLS", {
        "get_amcache", "parse_event_logs", "extract_mft_timeline",
        "parse_prefetch", "parse_wmi_subscription",
    })
    return None


def test_thin_selection_padded_from_registry_only(synth):
    out = c.safety_net_tools([])
    assert out, "expected padding from a thin selection"
    for tool in out:
        assert tool in _SYNTH_REGISTRY, (
            f"{tool} padded but not in the synthetic registry"
        )


def test_padding_mechanism_never_yields_unregistered(synth):
    # The bucket-driven fill and the balance pad must only ever emit
    # tools present in the live registry -- a phantom name can never be
    # introduced by the safety net itself.
    cands = c._bucket_driven_fill_candidates(set())
    assert cands, "expected bucket-driven candidates"
    for name in cands:
        assert name in _SYNTH_REGISTRY
    assert "vol_does_not_exist_phantom" not in cands

    mem_pad = c._first_registered_in_buckets(
        c._MEMORY_BALANCE_BUCKETS, set(),
    )
    disk_pad = c._first_registered_in_buckets(
        c._DISK_BALANCE_BUCKETS, set(),
    )
    assert mem_pad in _SYNTH_REGISTRY
    assert disk_pad in _SYNTH_REGISTRY

    # An unregistered tool given in the INPUT is never *added* by the
    # net: it appears only because the caller supplied it, and the net
    # introduces no phantom of its own.
    out = c.safety_net_tools(["vol_does_not_exist_phantom"])
    padded = [t for t in out if t != "vol_does_not_exist_phantom"]
    for t in padded:
        assert t in _SYNTH_REGISTRY


def test_padding_follows_bucket_priority(synth):
    out = c.safety_net_tools([])
    mem_proc = {"vol_pstree", "vol_psscan", "vol_cmdline",
                "vol_sessions", "vol_envars"}
    timeline = {"extract_mft_timeline"}
    first_mem = min(
        (i for i, t in enumerate(out) if t in mem_proc), default=None,
    )
    first_tl = min(
        (i for i, t in enumerate(out) if t in timeline), default=None,
    )
    assert first_mem is not None
    if first_tl is not None:
        assert first_mem < first_tl, (
            "memory_process must precede disk_timeline by bucket "
            f"priority: {out}"
        )


def test_memory_and_disk_balance_preserved(synth):
    out = c.safety_net_tools(["run_yara"])  # neither vol_ nor disk
    assert any(t.startswith("vol_") for t in out), out
    assert any(t in c.DISK_TOOLS for t in out), out


def test_no_exact_hardcoded_tool_name_list_required():
    # The bucket-driven mechanism must exist and the exact-name list
    # must be gone -- selection cannot depend on any literal tool list.
    assert not hasattr(c, "_SAFETY_NET_FILL")
    assert isinstance(c._SAFETY_NET_BUCKET_PRIORITY, tuple)
    assert "memory_process" == c._SAFETY_NET_BUCKET_PRIORITY[0]
