"""
Automated unit tests for core.hasher module.
Covers:
- Scenario 1: Hashing a known file against standard SHA-256 vector
- Scenario 2: Identical content produces identical hash
- Scenario 3: Modified content produces different hash
- Scenario 10: Handling unreadable files and simulated I/O errors
- Missing file handling
- Mutation/uncertainty detection during hashing
"""

import hashlib
from pathlib import Path
from unittest.mock import patch
import pytest

from core.hasher import calculate_sha256, HashResult


def test_hashing_known_file(tmp_path: Path):
    """Scenario 1: Hashing a known file and matching with standard hashlib."""
    test_file = tmp_path / "known.txt"
    content = b"The quick brown fox jumps over the lazy dog"
    test_file.write_bytes(content)

    expected_sha256 = hashlib.sha256(content).hexdigest()

    result: HashResult = calculate_sha256(test_file)

    assert result.success is True
    assert result.digest == expected_sha256
    assert result.file_size == len(content)
    assert result.error_message is None
    assert result.uncertain is False


def test_identical_content_produces_same_hash(tmp_path: Path):
    """Scenario 2: Confirming that identical content produces the exact same hash."""
    file_a = tmp_path / "file_a.txt"
    file_b = tmp_path / "file_b.txt"

    content = b"Cryptographic integrity test vector 12345"
    file_a.write_bytes(content)
    file_b.write_bytes(content)

    res_a = calculate_sha256(file_a)
    res_b = calculate_sha256(file_b)

    assert res_a.success is True
    assert res_b.success is True
    assert res_a.digest == res_b.digest


def test_modified_content_produces_different_hash(tmp_path: Path):
    """Scenario 3: Confirming that modified content produces a different hash."""
    file_target = tmp_path / "mutable.txt"
    file_target.write_bytes(b"Original trusted system configuration")

    res_original = calculate_sha256(file_target)

    # Modify single character
    file_target.write_bytes(b"Original trusted system Configuration")  # Capital 'C'
    res_modified = calculate_sha256(file_target)

    assert res_original.success is True
    assert res_modified.success is True
    assert res_original.digest != res_modified.digest


def test_missing_file_handling(tmp_path: Path):
    """Test behavior when file does not exist."""
    missing_file = tmp_path / "nonexistent.txt"
    result = calculate_sha256(missing_file)

    assert result.success is False
    assert result.digest is None
    assert "not found" in result.error_message.lower()


def test_unreadable_file_or_io_error(tmp_path: Path):
    """Scenario 10: Handling an unreadable file or simulated I/O error."""
    test_file = tmp_path / "locked.txt"
    test_file.write_bytes(b"Critical sensitive data")

    # Simulate PermissionError on open
    with patch("builtins.open", side_effect=PermissionError("Permission denied")):
        result = calculate_sha256(test_file)
        assert result.success is False
        assert result.digest is None
        assert "access denied" in result.error_message.lower() or "permission" in result.error_message.lower()

    # Simulate OSError during read
    with patch("builtins.open", side_effect=OSError("Device I/O error")):
        result = calculate_sha256(test_file)
        assert result.success is False
        assert result.digest is None
        assert "i/o error" in result.error_message.lower()


def test_file_mutating_during_hash(tmp_path: Path):
    """Test detection when file changes size/timestamp during hash streaming."""
    test_file = tmp_path / "live_log.txt"
    test_file.write_bytes(b"initial data chunk")

    # Simulate stat returning different values before and after
    orig_stat = test_file.stat()

    class FakeStat:
        def __init__(self, mtime_ns, size):
            self.st_size = size
            self.st_mtime_ns = mtime_ns
            self.st_mtime = orig_stat.st_mtime

    stats = [
        FakeStat(1000, 100),   # attempt 0 before
        FakeStat(2000, 120),   # attempt 0 after (changed!)
        FakeStat(3000, 120),   # attempt 1 before (retry)
        FakeStat(4000, 150),   # attempt 1 after (changed again!)
    ]

    with patch.object(Path, "stat", side_effect=stats):
        result = calculate_sha256(test_file, max_retries=1)
        assert result.uncertain is True
        assert result.success is False
        assert "changed during hash" in result.error_message.lower()
