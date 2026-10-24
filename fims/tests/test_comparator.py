"""
Automated unit tests for core.comparator module.
Covers:
- Scenario 5: Detecting an unchanged file
- Scenario 6: Detecting a modified file
- Scenario 7: Detecting an added file
- Scenario 8: Detecting a deleted file
- Scenario 12: Preventing a failed or incomplete scan from generating false deletion results
- Mixed scenario testing
"""

from pathlib import Path
import pytest

from core.baseline import BaselineRecord, FileBaselineEntry, CURRENT_BASELINE_VERSION
from core.comparator import (
    IntegrityComparator,
    ComparisonResult,
    STATUS_UNCHANGED,
    STATUS_MODIFIED,
    STATUS_ADDED,
    STATUS_DELETED,
    STATUS_SCAN_ERROR,
)
from core.scanner import ScanInventory, ScannedFileRecord, ScanErrorRecord

DUMMY_HASH_1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DUMMY_HASH_2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DUMMY_HASH_3 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"


def test_detect_unchanged_file():
    """Scenario 5: Detecting an unchanged file (same path, same hash)."""
    baseline = BaselineRecord(
        version=CURRENT_BASELINE_VERSION,
        created_at="2026-10-24T10:00:00Z",
        root_directory="/monitored",
        total_files=1,
        files={
            "app.py": FileBaselineEntry(
                sha256=DUMMY_HASH_1,
                size_bytes=100,
                mtime_utc="2026-10-24T10:00:00Z",
            )
        },
    )

    inventory = ScanInventory(
        root_dir="/monitored",
        scanned_files={
            "app.py": ScannedFileRecord(
                rel_path="app.py",
                abs_path="/monitored/app.py",
                sha256=DUMMY_HASH_1,
                size_bytes=100,
                mtime_utc="2026-10-24T10:00:00Z",
            )
        },
        is_complete=True,
    )

    result: ComparisonResult = IntegrityComparator.compare(baseline, inventory)

    assert result.unchanged_count == 1
    assert result.modified_count == 0
    assert result.added_count == 0
    assert result.deleted_count == 0
    assert result.error_count == 0
    assert result.has_anomalies is False

    rec = result.records[0]
    assert rec.rel_path == "app.py"
    assert rec.status == STATUS_UNCHANGED
    assert rec.baseline_sha256 == rec.current_sha256 == DUMMY_HASH_1


def test_detect_modified_file():
    """Scenario 6: Detecting a modified file (same path, different hash)."""
    baseline = BaselineRecord(
        version=CURRENT_BASELINE_VERSION,
        created_at="2026-10-24T10:00:00Z",
        root_directory="/monitored",
        total_files=1,
        files={
            "config.ini": FileBaselineEntry(
                sha256=DUMMY_HASH_1,
                size_bytes=100,
                mtime_utc="2026-10-24T10:00:00Z",
            )
        },
    )

    inventory = ScanInventory(
        root_dir="/monitored",
        scanned_files={
            "config.ini": ScannedFileRecord(
                rel_path="config.ini",
                abs_path="/monitored/config.ini",
                sha256=DUMMY_HASH_2,  # altered digest
                size_bytes=105,
                mtime_utc="2026-10-24T10:10:00Z",
            )
        },
        is_complete=True,
    )

    result: ComparisonResult = IntegrityComparator.compare(baseline, inventory)

    assert result.unchanged_count == 0
    assert result.modified_count == 1
    assert result.added_count == 0
    assert result.deleted_count == 0
    assert result.has_anomalies is True

    rec = result.records[0]
    assert rec.rel_path == "config.ini"
    assert rec.status == STATUS_MODIFIED
    assert rec.baseline_sha256 == DUMMY_HASH_1
    assert rec.current_sha256 == DUMMY_HASH_2


def test_detect_added_file():
    """Scenario 7: Detecting an added file (in current scan, not in baseline)."""
    baseline = BaselineRecord(
        version=CURRENT_BASELINE_VERSION,
        created_at="2026-10-24T10:00:00Z",
        root_directory="/monitored",
        total_files=0,
        files={},
    )

    inventory = ScanInventory(
        root_dir="/monitored",
        scanned_files={
            "malware.exe": ScannedFileRecord(
                rel_path="malware.exe",
                abs_path="/monitored/malware.exe",
                sha256=DUMMY_HASH_3,
                size_bytes=2048,
                mtime_utc="2026-10-24T10:20:00Z",
            )
        },
        is_complete=True,
    )

    result = IntegrityComparator.compare(baseline, inventory)

    assert result.added_count == 1
    assert result.modified_count == 0
    assert result.deleted_count == 0
    assert result.has_anomalies is True

    rec = result.records[0]
    assert rec.rel_path == "malware.exe"
    assert rec.status == STATUS_ADDED
    assert rec.baseline_sha256 is None
    assert rec.current_sha256 == DUMMY_HASH_3


def test_detect_deleted_file():
    """Scenario 8: Detecting a deleted file (in baseline, missing from current scan)."""
    baseline = BaselineRecord(
        version=CURRENT_BASELINE_VERSION,
        created_at="2026-10-24T10:00:00Z",
        root_directory="/monitored",
        total_files=1,
        files={
            "legacy_key.pem": FileBaselineEntry(
                sha256=DUMMY_HASH_1,
                size_bytes=512,
                mtime_utc="2026-10-24T10:00:00Z",
            )
        },
    )

    # Clean scan with zero files
    inventory = ScanInventory(
        root_dir="/monitored",
        scanned_files={},
        is_complete=True,
    )

    result = IntegrityComparator.compare(baseline, inventory)

    assert result.deleted_count == 1
    assert result.has_anomalies is True

    rec = result.records[0]
    assert rec.rel_path == "legacy_key.pem"
    assert rec.status == STATUS_DELETED
    assert rec.baseline_sha256 == DUMMY_HASH_1
    assert rec.current_sha256 is None


def test_prevent_false_deletions_on_incomplete_scan():
    """Scenario 12: Preventing a failed or incomplete scan from generating false deletion results."""
    baseline = BaselineRecord(
        version=CURRENT_BASELINE_VERSION,
        created_at="2026-10-24T10:00:00Z",
        root_directory="/monitored",
        total_files=2,
        files={
            "public/index.html": FileBaselineEntry(
                sha256=DUMMY_HASH_1,
                size_bytes=100,
                mtime_utc="2026-10-24T10:00:00Z",
            ),
            "secure/secret.key": FileBaselineEntry(
                sha256=DUMMY_HASH_2,
                size_bytes=200,
                mtime_utc="2026-10-24T10:00:00Z",
            ),
        },
    )

    # Incomplete scan where directory walk failed due to permission denial on root or subtree
    inventory = ScanInventory(
        root_dir="/monitored",
        scanned_files={
            "public/index.html": ScannedFileRecord(
                rel_path="public/index.html",
                abs_path="/monitored/public/index.html",
                sha256=DUMMY_HASH_1,
                size_bytes=100,
                mtime_utc="2026-10-24T10:00:00Z",
            )
        },
        errors=[
            ScanErrorRecord(
                rel_path=".",
                error_type="WALK_PERMISSION_DENIED",
                message="Permission denied opening directory",
                is_directory=True,
            )
        ],
        is_complete=False,  # Incomplete!
    )

    result = IntegrityComparator.compare(baseline, inventory)

    # CRITICAL: "secure/secret.key" must NOT be reported as DELETED
    assert result.deleted_count == 0, "Missing files in an incomplete scan must not be flagged as DELETED!"
    assert result.unchanged_count == 1
    assert result.error_count >= 1

    # Check that secure/secret.key was flagged as SCAN_ERROR
    secure_rec = next((r for r in result.records if r.rel_path == "secure/secret.key"), None)
    assert secure_rec is not None
    assert secure_rec.status == STATUS_SCAN_ERROR
    assert "incomplete scan" in secure_rec.error_details.lower()
