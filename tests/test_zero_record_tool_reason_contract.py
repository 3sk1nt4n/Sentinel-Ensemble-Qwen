import inspect
from pathlib import Path


def _count(result):
    if not isinstance(result, dict):
        return 0
    rc = result.get("record_count")
    if isinstance(rc, int):
        return rc
    out = result.get("output")
    return len(out) if isinstance(out, list) else 0


def _has_reason(result):
    assert isinstance(result, dict)
    assert _count(result) == 0
    assert result.get("status") in {"not_applicable", "no_records", "ok_no_records", "error"}
    assert result.get("reason") or result.get("zero_record_reason") or result.get("error")


def _call_with_mount(fn, mount):
    sig = inspect.signature(fn)
    for key in ("disk_mount", "mount_path", "disk_path", "root_path", "path", "image_path"):
        if key in sig.parameters:
            return fn(**{key: str(mount)})

    # Exported wrappers may accept **kwargs even if functools.wraps shows the
    # original signature. Try the public disk_mount alias first; fall back to
    # positional if the implementation truly rejects it.
    try:
        return fn(disk_mount=str(mount))
    except TypeError:
        return fn(str(mount))


def test_get_amcache_zero_records_have_explicit_reason(tmp_path):
    from sift_sentinel.tools.disk import get_amcache

    result = _call_with_mount(get_amcache, tmp_path)
    _has_reason(result)


def test_extract_mft_timeline_zero_records_have_explicit_reason(tmp_path):
    from sift_sentinel.tools import disk as disk_mod

    fn = getattr(disk_mod, "extract_mft_timeline", None)
    assert callable(fn), "extract_mft_timeline must be callable"
    result = _call_with_mount(fn, tmp_path)
    _has_reason(result)


def test_parse_prefetch_zero_records_have_explicit_reason(tmp_path):
    from sift_sentinel.tools import disk_extended as de

    fn = getattr(de, "parse_prefetch", None)
    assert callable(fn), "parse_prefetch must be callable"
    result = _call_with_mount(fn, tmp_path)
    _has_reason(result)


def test_run_srumecmd_zero_records_have_explicit_reason(tmp_path):
    from sift_sentinel.tools.generic import run_srumecmd

    missing = tmp_path / "SRUDB.dat"
    result = run_srumecmd(srum_path=str(missing))
    _has_reason(result)
