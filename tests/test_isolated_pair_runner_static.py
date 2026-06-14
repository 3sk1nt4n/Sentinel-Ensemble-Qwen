from pathlib import Path


def test_isolated_pair_runner_exists_and_never_uses_global_mount_as_run_mount():
    p = Path("scripts/run_live_pair_isolated_mount.sh")
    assert p.exists()
    text = p.read_text(errors="replace")

    assert "MEMORY_IMAGE" in text
    assert "DISK_IMAGE" in text
    assert "CASE_LABEL" in text

    assert "--disk-mount \"$NTFS_DIR\"" in text
    assert 'NTFS_DIR="${MOUNT_ROOT}/ntfs"' in text
    assert 'EWF_DIR="${MOUNT_ROOT}/ewf"' in text

    assert '--disk-mount /mnt/windows_mount' not in text
    assert 'NTFS_DIR="/mnt/windows_mount"' not in text
    assert 'EWF_DIR="/mnt/ewf"' not in text


def test_isolated_pair_runner_records_mount_identity_and_cleans_up():
    text = Path("scripts/run_live_pair_isolated_mount.sh").read_text(errors="replace")
    assert "mount_identity.txt" in text
    assert "findmnt \"$NTFS_DIR\"" in text
    assert "trap cleanup EXIT" in text
    assert "sudo umount \"$NTFS_DIR\"" in text
    assert "sudo umount \"$EWF_DIR\"" in text

def test_isolated_runner_tries_all_offsets_and_raw_fallback():
    from pathlib import Path as _Path
    text = _Path("scripts/run_live_pair_isolated_mount.sh").read_text()
    assert "mapfile -t OFFSET_CANDIDATES" in text
    assert "for cand in" in text
    assert "ntfs_mount_reject" in text
    assert "raw_ntfs_volume" in text
    assert "Windows_directory_missing" in text
    assert "mount_mode=" in text
