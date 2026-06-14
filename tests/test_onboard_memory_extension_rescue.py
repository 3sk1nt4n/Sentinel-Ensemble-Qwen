"""Memory rescue must recognize the canonical memory EXTENSIONS, not only a
'memory'/'mem'/'ram' word in the name.

Bug: when the vol3 probe times out on a cold multi-GB image, the deterministic
name-shape rescue is the only classifier. It keyed solely on role WORDS in the
stripped name, so an extension-only memory capture with no role word --
``host01.vmem``, ``crashdump.dmp``, ``capture.mem`` (``.mem`` was even stripped
as a stem ext, leaving "capture") -- failed the rescue and the case ran
disk-only. The onboarding spec lists ``.raw .img .mem .vmem .dmp`` as memory.

Fix: a file whose basename ends with an UNAMBIGUOUS memory extension
(.vmem/.dmp/.mem/.lime -- formats no disk image uses) is rescued as MEMORY.
``.raw``/``.img``/``.dd`` are SHARED with disk images and are deliberately NOT
classified by extension alone (they stay probe- + role-word- gated). Universal,
zero case data. Kill-switch SIFT_MEMORY_NAME_SHAPE_RESCUE=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.onboard.engine import _memory_role_name_shape  # noqa: E402


def test_unambiguous_memory_extensions_are_rescued():
    for n in ("host01.vmem", "crashdump.dmp", "capture.mem", "linux-acq.lime",
              "WIN-DC.VMEM"):
        assert _memory_role_name_shape(n) is True, n


def test_role_word_names_still_rescued():
    for n in ("node7-memory.raw", "host-mem.img", "physmem.bin",
              "controller-memory-raw.001"):
        assert _memory_role_name_shape(n) is True, n


def test_disk_and_documents_are_not_memory():
    for n in ("host-cdrive.E01", "report.pdf", "image.dd", "volume.img",
              "WIN-SRV.raw"):
        # .dd/.img/.raw with no memory role word -> not memory by extension
        assert _memory_role_name_shape(n) is False, n


def test_kill_switch_disables_all_rescue(monkeypatch):
    monkeypatch.setenv("SIFT_MEMORY_NAME_SHAPE_RESCUE", "0")
    for n in ("host01.vmem", "node7-memory.raw", "capture.mem"):
        assert _memory_role_name_shape(n) is False, n
