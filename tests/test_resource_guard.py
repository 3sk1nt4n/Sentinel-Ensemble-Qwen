"""Disk-scratch resource guardrail: size a FOLDER's true contents (so a big
extraction is refused up front instead of half-filling the disk), and prune STALE
scratch from finished runs while keeping recent/active ones. Universal, no case data."""
import os
import shutil
import tempfile
import time

from sift_sentinel.onboard import resource_guard as rg


def test_dir_size_sees_folder_contents_not_the_dir_entry():
    d = tempfile.mkdtemp(prefix="rg-")
    try:
        with open(os.path.join(d, "big"), "wb") as fh:
            fh.write(b"x" * 200000)
        os.makedirs(os.path.join(d, "sub"))
        with open(os.path.join(d, "sub", "more"), "wb") as fh:
            fh.write(b"y" * 50000)
        assert rg.dir_size(d) >= 250000          # walks contents recursively
        assert os.path.getsize(d) < 250000       # the dir entry alone is tiny (the bug)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_dir_size_of_a_file_is_its_size():
    fd, p = tempfile.mkstemp(prefix="rg-")
    os.close(fd)
    try:
        with open(p, "wb") as fh:
            fh.write(b"z" * 1234)
        assert rg.dir_size(p) == 1234
    finally:
        os.unlink(p)


def test_prune_removes_stale_keeps_recent_and_active():
    old = tempfile.mkdtemp(prefix="sift-onboard-ex-")
    recent = tempfile.mkdtemp(prefix="sift-onboard-ex-")
    active = tempfile.mkdtemp(prefix="sift-onboard-ex-")
    try:
        os.utime(old, (time.time() - 4000, time.time() - 4000))      # stale
        os.utime(active, (time.time() - 4000, time.time() - 4000))   # stale BUT active
        r = rg.prune_stale_scratch(keep_active={active})
        assert not os.path.exists(old)           # stale -> removed
        assert os.path.exists(recent)            # too recent -> kept (may be active)
        assert os.path.exists(active)            # in keep_active -> kept even if stale
        assert r["removed"] >= 1
    finally:
        for d in (old, recent, active):
            shutil.rmtree(d, ignore_errors=True)


def test_ensure_space_refuses_impossible_need():
    res = rg.ensure_space_for(10 ** 15)          # ~1 PB -> cannot fit
    assert res["ok"] is False and res["need_bytes"] > 0


def test_ensure_space_ok_for_trivial_need():
    res = rg.ensure_space_for(1)
    assert res["ok"] is True
