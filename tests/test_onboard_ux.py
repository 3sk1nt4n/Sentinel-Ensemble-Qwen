"""Onboarding UX: doc-never-unzipped, dynamic card (no clipping), the menu
handler, honest FIND staging, FIND_WIRED env/flag, and archive de-dup."""
from __future__ import annotations

import os
import zipfile

import pytest

import step0_onboard
from sift_sentinel.onboard import archive, presenter
from sift_sentinel.onboard.engine import CaseManifest, Probes, onboard


# ── RULE 1: a document is ONE leaf, never unzipped ─────────────────────────
def test_extract_all_keeps_pptx_as_single_leaf(tmp_path):
    p = tmp_path / "deck.pptx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<a/>")
        z.writestr("ppt/presentation.xml", "<b/>")
        z.writestr("ppt/slides/slide1.xml", "<c/>")
    leaves = archive.extract_all(str(p))
    assert leaves == [str(p)]                       # exactly one leaf: the doc
    assert not any(".xml" in os.path.basename(x) for x in leaves)


# ── card: dynamic width, no clipping ───────────────────────────────────────
def _manifest(**kw):
    base = dict(
        case_id="rd01-case", os="Windows 7 / Server 2008 R2 (NT 6.1)",
        os_source="memory", memory_path="/e/base-rd01-memory.img",
        memory_health="HEALTHY", memory_health_facts={},
        disk_path="/e/base-rd-01-cdrive.E01", disk_mounted=True,
        mount_method="raw@0", mount_path="/mnt/rd01",
        reference_docs=["note"],
        os_profile={"disk": "Windows XP",
                    "memory": "Windows 7 / Server 2008 R2 (NT 6.1)",
                    "agree": False, "source": "memory",
                    "os": "Windows 7 / Server 2008 R2 (NT 6.1)"},
        documents=[])
    base.update(kw)
    return CaseManifest(**base)


def test_card_renders_rd01_without_clipping():
    card = presenter.case_card(_manifest(), number=1, color=False)
    assert "HEALTHY" in card
    assert "mounted (raw@0)" in card
    assert "base-rd01-memory.img" in card           # full basename, not clipped
    assert "base-rd-01-cdrive.E01" in card
    assert "vol3 windows.info" in card              # Basis line renders fully
    # No truncation artifacts from the old fixed-width slicer.
    assert "[HE" not in card and "'Ve" not in card
    # Box is aligned: every line the same display width.
    lines = card.splitlines()
    assert len({len(ln) for ln in lines}) == 1


def test_card_long_basename_truncates_with_ellipsis():
    huge = "/e/" + ("z" * 300) + ".img"
    card = presenter.case_card(_manifest(memory_path=huge), color=False)
    assert "…" in card                              # ellipsis, not a hard mid-slice
    lines = card.splitlines()
    assert len({len(ln) for ln in lines}) == 1      # still aligned


# ── menu handler ───────────────────────────────────────────────────────────
def _feed(seq):
    it = iter(seq)
    return lambda _prompt: next(it)


@pytest.mark.parametrize("word,expected", [
    ("find", "find"), ("FIND", "find"), ("f", "find"),
    ("a", "a"), ("ANOTHER", "a"), ("another", "a"),
    ("q", "q"), ("QUIT", "q"), ("exit", "q"),
    ("h", "h"), ("HELP", "h"), ("?", "h"),
])
def test_menu_accepts_words(word, expected):
    assert step0_onboard._read_action(_feed([word])) == expected


def test_menu_reasks_on_junk(capsys):
    act = step0_onboard._read_action(_feed(["???", "zzz", "find"]))
    assert act == "find"
    assert "didn't catch that" in capsys.readouterr().out  # re-asked, not quit


def test_menu_eof_quits():
    assert step0_onboard._read_action(lambda _p: None) == "q"


# ── BUG 2: no fake pipeline result when unwired ────────────────────────────
def test_do_find_unwired_only_stages(capsys):
    called = []
    rc = step0_onboard._do_find(_manifest(), wired=False,
                                runner=lambda *a, **k: called.append(1))
    out = capsys.readouterr().out
    assert rc is None
    assert "python3 run_pipeline.py" in out
    assert "cancelled — nothing launched" in out    # EOF confirm -> cancel, no exec
    assert "exited with code" not in out
    assert "report.md" not in out
    assert called == []                             # never executed


def test_do_find_wired_reports_real_exit_code(capsys):
    class _Proc:
        returncode = 7
    rc = step0_onboard._do_find(_manifest(), wired=True,
                                runner=lambda *a, **k: _Proc())
    out = capsys.readouterr().out
    assert rc == 7
    assert "exited with code 7" in out
    assert "report.md" not in out                   # no fabricated output path


# ── BUG 4: FIND_WIRED from env / override / default ────────────────────────
def test_find_wired_env(monkeypatch):
    monkeypatch.setenv("SIFT_FIND_WIRED", "1")
    monkeypatch.setattr(step0_onboard, "_WIRE_OVERRIDE", False)
    assert step0_onboard._find_wired() is True


def test_find_wired_override(monkeypatch):
    monkeypatch.delenv("SIFT_FIND_WIRED", raising=False)
    monkeypatch.setattr(step0_onboard, "_WIRE_OVERRIDE", True)
    assert step0_onboard._find_wired() is True


def test_find_wired_default_false(monkeypatch):
    monkeypatch.delenv("SIFT_FIND_WIRED", raising=False)
    monkeypatch.setattr(step0_onboard, "_WIRE_OVERRIDE", False)
    monkeypatch.setattr(step0_onboard, "FIND_WIRED", False)
    assert step0_onboard._find_wired() is False


# ── de-dup: loose image + its compressed twin -> ONE case, no re-extract ───
class DedupProbes(Probes):
    def __init__(self):
        self.extracted = []

    def discover(self, p):
        return ["/c/Acme-Memory.raw", "/c/Acme-Memory.zip",
                "/c/acme-cdrive.e01"]

    def archive_kind(self, p):
        return "ZIP" if p.endswith(".zip") else None

    def extract(self, p):
        self.extracted.append(p)
        return ["/c/from-zip-mem.raw"]

    def has_filesystem(self, p):
        return p.endswith(".e01")

    def fs_facts(self, p):
        return {"fstype": "NTFS", "volume": "", "version": ""}

    def memory_info(self, p):
        return ({"NtMajorVersion": "10", "NtMinorVersion": "0"}
                if p.endswith(".raw") else None)

    def mount(self, disk, method, mp):
        return (True, "") if method == "raw@0" else (False, "x")

    def health(self, mem):
        return True, [], {}

    def cleanup(self):
        pass


def test_dedup_skips_redundant_archive(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    probes = DedupProbes()
    cases = onboard("/c", on_event=lambda e: None, ai=None, probes=probes)
    assert probes.extracted == []                   # the .zip twin was NOT extracted
    assert len(cases) == 1                           # no duplicate memory case
    assert cases[0].memory_path.endswith("Acme-Memory.raw")
    assert cases[0].disk_path.endswith("acme-cdrive.e01")


# ── multi-add: onboard a list of files as one case ─────────────────────────
class ListProbes(Probes):
    """Each entry discovers to itself (a file). Role by suffix (no real tools)."""
    def discover(self, p):
        return [p]

    def archive_kind(self, p):
        return None

    def has_filesystem(self, p):
        return p.endswith((".e01", ".dd"))

    def fs_facts(self, p):
        return {"fstype": "NTFS", "volume": "", "version": ""}

    def memory_info(self, p):
        return ({"NtMajorVersion": "10", "NtMinorVersion": "0"}
                if p.endswith(".raw") else None)

    def mount(self, disk, method, mp):
        return (True, "") if method == "raw@0" else (False, "x")

    def health(self, mem):
        return True, [], {}

    def cleanup(self):
        pass


def test_onboard_list_pairs_two_files(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    cases = onboard(["/x/mem.raw", "/x/disk.e01"], on_event=lambda e: None,
                    ai=None, probes=ListProbes())
    assert len(cases) == 1
    assert cases[0].memory_path == "/x/mem.raw"
    assert cases[0].disk_path == "/x/disk.e01"


def test_multi_add_collects_echoes_and_dedupes(tmp_path, capsys):
    mem = tmp_path / "mem.raw"
    mem.write_bytes(b"")
    disk = tmp_path / "disk.e01"
    disk.write_bytes(b"")
    feed = iter([str(disk), str(mem), ""])   # add disk; re-add mem (dup); blank=done
    out = step0_onboard._multi_add(str(mem), ListProbes(),
                                   input_fn=lambda _p: next(feed))
    assert out == [str(mem), str(disk)]      # duplicate mem ignored
    text = capsys.readouterr().out
    assert "already added" in text
    assert "MEMORY" in text and "DISK" in text


def test_folder_mode_still_walks(monkeypatch):
    class FolderProbes(ListProbes):
        def discover(self, p):
            return ["/f/m.raw", "/f/d.e01"]     # a directory walk
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    cases = onboard("/f", on_event=lambda e: None, ai=None, probes=FolderProbes())
    assert len(cases) == 1
    assert cases[0].memory_path and cases[0].disk_path


# ── launch trigger: every "Find Evil" form launches ───────────────────────
def _one(word):
    return iter([word]).__next__


@pytest.mark.parametrize("word", [
    "Find Evil", "find evil", "FINDEVIL", "findevil", "find-evil", "find_evil",
    "Find-Evil!", "find evil!", "FE", "fe", "f", "find",
])
def test_launch_trigger_forms(word):
    assert step0_onboard._read_action(lambda _p: word) == "find"


@pytest.mark.parametrize("word,expected", [
    ("a", "a"), ("ANOTHER", "a"), ("add", "a"),
    ("q", "q"), ("QUIT", "q"), ("exit", "q"),
    ("h", "h"), ("HELP", "h"), ("?", "h"),
])
def test_route_forms(word, expected):
    assert step0_onboard._read_action(lambda _p: word) == expected


def test_banana_reasks_not_quit(capsys):
    feed = iter(["banana", "q"])
    assert step0_onboard._read_action(lambda _p: next(feed)) == "q"
    assert "didn't catch" in capsys.readouterr().out


# ── disk OS: fresh per case from the SOFTWARE hive, no XP leak ─────────────
class DiskProbes(Probes):
    """Disk-only. fs_facts returns the misleading NTFS 'Windows XP' label that
    must be IGNORED; disk OS comes from disk_os() (the registry hive)."""
    def __init__(self, disk_os_val):
        self._dos = disk_os_val

    def discover(self, p):
        return ["/c/disk.e01"]

    def archive_kind(self, p):
        return None

    def has_filesystem(self, p):
        return True

    def fs_facts(self, p):
        return {"fstype": "NTFS", "volume": "", "version": "Windows XP"}

    def memory_info(self, p):
        return None

    def disk_os(self, mount_path):
        return self._dos

    def mount(self, disk, method, mp):
        return (True, "") if method == "raw@0" else (False, "x")

    def health(self, mem):
        return True, [], {}

    def cleanup(self):
        pass


def test_disk_os_fresh_per_case_no_xp_leak(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    c1 = onboard("/c1", on_event=lambda e: None, ai=None,
                 probes=DiskProbes("Windows 7 / Server 2008 R2 (NT 6.1)"))[0]
    c2 = onboard("/c2", on_event=lambda e: None, ai=None,
                 probes=DiskProbes("Windows 11 (NT 10.0)"))[0]
    assert c1.os_profile["disk"] == "Windows 7 / Server 2008 R2 (NT 6.1)"
    assert c2.os_profile["disk"] == "Windows 11 (NT 10.0)"
    assert c1.os_profile["disk"] != c2.os_profile["disk"]      # no cross-case leak
    # The misleading fsstat "Windows XP" must NEVER be the disk OS.
    assert "Windows XP" not in (c1.os_profile["disk"] or "")
    assert "Windows XP" not in (c2.os_profile["disk"] or "")


def test_disk_os_undetermined_when_hive_unreadable(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class NoHive(DiskProbes):
        def disk_os(self, mount_path):
            return None                      # hive unreadable
    c = onboard("/c", on_event=lambda e: None, ai=None, probes=NoHive("x"))[0]
    assert c.os_profile["disk"] is None      # never a hardcoded "Windows XP"
    card = presenter.case_card(c, color=False)
    assert "Windows XP" not in card
    assert "undetermined" in card.lower()


def test_disk_os_agree_yes_when_disk_matches_memory(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class MatchProbes(Probes):
        def discover(self, p):
            return ["/c/mem.raw", "/c/disk.e01"]

        def archive_kind(self, p):
            return None

        def has_filesystem(self, p):
            return p.endswith(".e01")

        def fs_facts(self, p):
            return {"fstype": "NTFS", "version": "Windows XP"}

        def memory_info(self, p):
            return ({"NtMajorVersion": "10", "NtMinorVersion": "0"}
                    if p.endswith(".raw") else None)

        def disk_os(self, mount_path):
            return "Windows 10 Pro (NT 10.0)"

        def mount(self, disk, method, mp):
            return (True, "") if method == "raw@0" else (False, "x")

        def health(self, mem):
            return True, [], {}

        def cleanup(self):
            pass

    c = onboard("/c", on_event=lambda e: None, ai=None, probes=MatchProbes())[0]
    assert c.os_profile["agree"] is True     # disk NT10 ~ memory NT10
    assert "NT 10.0" in c.os_profile["disk"]
    assert "NT 10.0" in c.os_profile["memory"]
