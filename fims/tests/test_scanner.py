"""
Automated unit tests for core.scanner module.
Covers:
- Scenario 9: Handling an empty directory
- Scenario 13: Handling nested directories and relative paths
- Scenario 14: Handling symbolic links safely (preventing out-of-root traversal)
- Exclusions filtering (git, temp files, app internal dir)
- Non-existent directory validation
"""

import os
from pathlib import Path
import pytest

from core.scanner import DirectoryScanner


def test_empty_directory_handling(tmp_path: Path):
    """Scenario 9: Handling an empty directory."""
    empty_dir = tmp_path / "empty_target"
    empty_dir.mkdir()

    scanner = DirectoryScanner(root_dir=empty_dir)
    inventory = scanner.scan()

    assert inventory.is_complete is True
    assert len(inventory.scanned_files) == 0
    assert len(inventory.errors) == 0
    assert inventory.total_discovered == 0
    assert inventory.total_hashed == 0


def test_nested_directories_and_relative_paths(tmp_path: Path):
    """Scenario 13: Handling nested directories and relative paths."""
    # Create directory tree
    sub1 = tmp_path / "src" / "modules"
    sub2 = tmp_path / "docs" / "api"
    sub1.mkdir(parents=True)
    sub2.mkdir(parents=True)

    # Populate files
    (sub1 / "auth.py").write_text("print('auth')", encoding="utf-8")
    (sub1 / "crypto.py").write_text("print('crypto')", encoding="utf-8")
    (sub2 / "readme.md").write_text("# API Docs", encoding="utf-8")
    (tmp_path / "root_file.txt").write_text("root", encoding="utf-8")

    scanner = DirectoryScanner(root_dir=tmp_path)
    inventory = scanner.scan()

    assert inventory.is_complete is True
    assert len(inventory.scanned_files) == 4

    # Verify keys are relative forward-slash paths
    keys = list(inventory.scanned_files.keys())
    assert "root_file.txt" in keys
    assert "src/modules/auth.py" in keys
    assert "src/modules/crypto.py" in keys
    assert "docs/api/readme.md" in keys

    # Verify sha256 digests exist
    for rel_path, rec in inventory.scanned_files.items():
        assert len(rec.sha256) == 64
        assert rec.size_bytes > 0


def test_exclusions_filtering(tmp_path: Path):
    """Test that configured exclusions (e.g. .git, *.tmp) are bypassed."""
    (tmp_path / "valid.txt").write_text("valid", encoding="utf-8")

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("git config", encoding="utf-8")

    (tmp_path / "cache.tmp").write_text("temporary", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "swap.swp").write_text("vim swap", encoding="utf-8")

    exclusions = [".git", "*.tmp", "*.swp"]
    scanner = DirectoryScanner(root_dir=tmp_path, exclusions=exclusions)
    inventory = scanner.scan()

    assert "valid.txt" in inventory.scanned_files
    assert ".git/config" not in inventory.scanned_files
    assert "cache.tmp" not in inventory.scanned_files
    assert "sub/swap.swp" not in inventory.scanned_files
    assert len(inventory.scanned_files) == 1


def test_symbolic_link_handling_safeguards(tmp_path: Path):
    """Scenario 14: Handling symbolic links safely."""
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    # Create secret file outside root
    secret_file = outside_dir / "etc_passwd.txt"
    secret_file.write_text("root:x:0:0:root", encoding="utf-8")

    symlink_target = monitored_dir / "external_link.txt"

    try:
        symlink_target.symlink_to(secret_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted or supported on this system")

    # With follow_symlinks=False, the symlink should not be traversed
    scanner = DirectoryScanner(root_dir=monitored_dir, follow_symlinks=False)
    inventory = scanner.scan()

    assert "external_link.txt" not in inventory.scanned_files
    # Symlink blocked error should be recorded
    blocked = [e for e in inventory.errors if e.error_type == "SYMLINK_BLOCKED"]
    assert len(blocked) >= 1


def test_invalid_root_directory(tmp_path: Path):
    """Test scanning a non-existent directory."""
    non_existent = tmp_path / "does_not_exist"
    scanner = DirectoryScanner(root_dir=non_existent)
    inventory = scanner.scan()

    assert inventory.is_complete is False
    assert len(inventory.errors) == 1
    assert inventory.errors[0].error_type == "ROOT_ACCESS_ERROR"
