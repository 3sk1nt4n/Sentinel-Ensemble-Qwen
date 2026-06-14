"""When a host has MORE THAN ONE memory candidate, the disk must pair with the
STRONGEST one, and a strictly-weaker same-host duplicate is suppressed.

Live bug (a torture-folder of many cases): one host had two memory entries
-- an archive ``<host>-memory.zip`` (classified MEMORY only by name-shape, vol3
could not parse it) AND ``<host>-memory.raw`` (vol3-confirmed) -- plus one disk.
``_pair_by_host`` paired BY INDEX within the host, so the disk grabbed the .zip
(first discovered) and the real vol3 image was orphaned as a separate
memory-only case. One host became two cases, the wrong image paired.

Fix (SIFT_PAIR_BEST_MEMORY, default ON): rank a host's memories by analysis
strength -- vol3-confirmed (non-empty info) over name-shape-only, a real image
over an archive extension -- pair disks with the strongest first, and DROP a
strictly-weaker same-host memory (an unanalyzable archive of an image we already
have). Two EQUALLY strong memories are both kept (could be distinct captures).
Universal: ranks by classification strength + archive-extension SHAPE, never a
filename/host literal.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.onboard.engine import _pair_by_host, _host_token  # noqa: E402

VOL3 = {"NtMajorVersion": "10"}          # non-empty info == vol3-confirmed
NAMESHAPE = {}                            # empty == name-shape rescue only


def _paired(pairings):
    return [(m[0] if m else None, d) for m, d in pairings]


def test_disk_pairs_with_vol3_memory_not_archive():
    mems = [("/e/alpha-memory.zip", NAMESHAPE), ("/e/alpha-memory.raw", VOL3)]
    disks = ["/e/alpha-cdrive.e01"]
    out = _paired(_pair_by_host(mems, disks))
    # the disk pairs with the vol3 raw; the weaker name-shape .zip is dropped
    assert ("/e/alpha-memory.raw", "/e/alpha-cdrive.e01") in out
    assert len(out) == 1
    assert all(m != "/e/alpha-memory.zip" for m, _ in out)


def test_weaker_duplicate_dropped_even_without_disk():
    mems = [("/e/host-memory.zip", NAMESHAPE), ("/e/host-memory.raw", VOL3)]
    out = _paired(_pair_by_host(mems, []))
    assert out == [("/e/host-memory.raw", None)]


def test_two_equally_strong_memories_both_kept():
    # both vol3-confirmed, SAME host token -> could be distinct captures; never
    # silently drop one (.raw and .img both normalize to host 'node7')
    assert _host_token("/e/node7-mem.raw") == _host_token("/e/node7-mem.img")
    mems = [("/e/node7-mem.raw", VOL3), ("/e/node7-mem.img", VOL3)]
    disks = ["/e/node7-cdrive.e01"]
    out = _paired(_pair_by_host(mems, disks))
    paired_mems = {m for m, _ in out}
    assert paired_mems == {"/e/node7-mem.raw", "/e/node7-mem.img"}
    assert sum(1 for _, d in out if d) == 1          # exactly one gets the disk


def test_single_memory_single_disk_unchanged():
    out = _paired(_pair_by_host([("/e/h-memory.img", VOL3)], ["/e/h-cdrive.e01"]))
    assert out == [("/e/h-memory.img", "/e/h-cdrive.e01")]


def test_archive_beats_nothing_when_only_candidate():
    # a lone archive-memory is still surfaced (not dropped) when it is the only one
    out = _paired(_pair_by_host([("/e/h-memory.zip", NAMESHAPE)], ["/e/h-cdrive.e01"]))
    assert out == [("/e/h-memory.zip", "/e/h-cdrive.e01")]


def test_kill_switch_restores_index_pairing(monkeypatch):
    monkeypatch.setenv("SIFT_PAIR_BEST_MEMORY", "0")
    mems = [("/e/alpha-memory.zip", NAMESHAPE), ("/e/alpha-memory.raw", VOL3)]
    out = _paired(_pair_by_host(mems, ["/e/alpha-cdrive.e01"]))
    # legacy: index pairing -> the first-listed .zip takes the disk, .raw orphaned
    assert ("/e/alpha-memory.zip", "/e/alpha-cdrive.e01") in out
    assert ("/e/alpha-memory.raw", None) in out
