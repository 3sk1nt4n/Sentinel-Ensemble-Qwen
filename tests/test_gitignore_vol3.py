"""Commit 9a: Vol3 pollution patterns in .gitignore."""
import pathlib
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_gitignore_has_vol3_patterns():
    """All 5 Vol3 pollution patterns must be present in .gitignore."""
    path = REPO_ROOT / ".gitignore"
    content = path.read_text()
    required = [
        "file.0x*.img",
        "file.0x*.dat",
        "file.0x*.vacb",
        "tmp_*.vol3",
        "live_vol3_*.txt",
    ]
    missing = [p for p in required if p not in content]
    assert not missing, f"Missing patterns: {missing}"


def test_vol3_img_pattern_is_effective():
    """git check-ignore must confirm file.0x*.img matches."""
    result = subprocess.run(
        ["git", "check-ignore", "file.0xDEADBEEF.ImageSectionObject.test.dll.img"],
        cwd=str(REPO_ROOT),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"file.0x*.img pattern not effective. "
        f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_vol3_vol3_extension_pattern_is_effective():
    """git check-ignore must confirm tmp_*.vol3 matches."""
    result = subprocess.run(
        ["git", "check-ignore", "tmp_abc123xyz.vol3"],
        cwd=str(REPO_ROOT),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"tmp_*.vol3 pattern not effective. "
        f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
