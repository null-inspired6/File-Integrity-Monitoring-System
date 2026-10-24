"""
Integrity comparator for the File Integrity Monitoring System (FIMS).
Compares current directory scan inventories against trusted baselines,
detecting modifications, additions, deletions, and scan errors while strictly
guarding against false deletion reports caused by permission or I/O failures.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional
import uuid

from .baseline import BaselineRecord
from .scanner import ScanErrorRecord, ScanInventory

logger = logging.getLogger("fims.comparator")

STATUS_UNCHANGED = "UNCHANGED"
STATUS_MODIFIED = "MODIFIED"
STATUS_ADDED = "ADDED"
STATUS_DELETED = "DELETED"
STATUS_SCAN_ERROR = "SCAN_ERROR"


@dataclass
class FileComparisonRecord:
    """Detailed comparison state for an individual file."""
    rel_path: str
    status: str  # UNCHANGED | MODIFIED | ADDED | DELETED | SCAN_ERROR
    baseline_sha256: Optional[str] = None
    current_sha256: Optional[str] = None
    baseline_size: Optional[int] = None
    current_size: Optional[int] = None
    error_details: Optional[str] = None
    mtime_utc: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ComparisonResult:
    """Aggregate result of comparing a directory scan with a trusted baseline."""
    scan_id: str
    timestamp_utc: str
    root_directory: str
    baseline_version: str
    is_complete: bool
    total_baseline_files: int = 0
    total_current_files: int = 0
    unchanged_count: int = 0
    modified_count: int = 0
    added_count: int = 0
    deleted_count: int = 0
    error_count: int = 0
    records: List[FileComparisonRecord] = field(default_factory=list)

    @property
    def has_anomalies(self) -> bool:
        """True if any changes (modifications, additions, deletions, or errors) were detected."""
        return (
            self.modified_count > 0
            or self.added_count > 0
            or self.deleted_count > 0
            or self.error_count > 0
        )

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "timestamp_utc": self.timestamp_utc,
            "root_directory": self.root_directory,
            "baseline_version": self.baseline_version,
            "is_complete": self.is_complete,
            "summary": {
                "total_baseline_files": self.total_baseline_files,
                "total_current_files": self.total_current_files,
                "unchanged_count": self.unchanged_count,
                "modified_count": self.modified_count,
                "added_count": self.added_count,
                "deleted_count": self.deleted_count,
                "error_count": self.error_count,
                "has_anomalies": self.has_anomalies,
            },
            "records": [r.to_dict() for r in self.records],
        }


class IntegrityComparator:
    """
    Executes comparison between trusted baseline and current scan inventory.
    Implements security safeguards to prevent false deletions when scans encounter errors.
    """

    @staticmethod
    def compare(
        baseline: BaselineRecord,
        inventory: ScanInventory,
        scan_id: Optional[str] = None,
    ) -> ComparisonResult:
        """
        Compare current file inventory against trusted baseline.

        Safeguard logic:
        1. If a file failed during scanning (e.g. PermissionError, Locked file),
           it is classified as SCAN_ERROR, never DELETED or UNCHANGED.
        2. If the entire scan is incomplete due to directory traversal failure,
           missing baseline files in unvisited subtrees are classified as SCAN_ERROR
           with explanatory note, preventing false positive deletions.
        """
        sid = scan_id or str(uuid.uuid4())[:8]
        now_utc = datetime.now(timezone.utc).isoformat()

        result = ComparisonResult(
            scan_id=sid,
            timestamp_utc=now_utc,
            root_directory=baseline.root_directory,
            baseline_version=baseline.version,
            is_complete=inventory.is_complete,
            total_baseline_files=len(baseline.files),
            total_current_files=len(inventory.scanned_files),
        )

        # Build index of scanner errors by path
        errors_by_path: Dict[str, ScanErrorRecord] = {
            err.rel_path: err for err in inventory.errors
        }
        walk_errors = [err for err in inventory.errors if err.is_directory or err.rel_path == "."]

        baseline_paths = set(baseline.files.keys())
        scanned_paths = set(inventory.scanned_files.keys())
        all_paths = sorted(baseline_paths | scanned_paths | set(errors_by_path.keys()))

        records: List[FileComparisonRecord] = []

        for rel_path in all_paths:
            # Case 1: File had a direct scan or hash error
            if rel_path in errors_by_path and rel_path != ".":
                err = errors_by_path[rel_path]
                base_entry = baseline.files.get(rel_path)
                rec = FileComparisonRecord(
                    rel_path=rel_path,
                    status=STATUS_SCAN_ERROR,
                    baseline_sha256=base_entry.sha256 if base_entry else None,
                    current_sha256=None,
                    baseline_size=base_entry.size_bytes if base_entry else None,
                    current_size=None,
                    error_details=f"[{err.error_type}] {err.message}",
                )
                records.append(rec)
                result.error_count += 1
                continue

            in_baseline = rel_path in baseline_paths
            in_scanned = rel_path in scanned_paths

            # Case 2: Present in both baseline and current scan
            if in_baseline and in_scanned:
                b_entry = baseline.files[rel_path]
                s_entry = inventory.scanned_files[rel_path]

                if b_entry.sha256.lower() == s_entry.sha256.lower():
                    status = STATUS_UNCHANGED
                    result.unchanged_count += 1
                else:
                    status = STATUS_MODIFIED
                    result.modified_count += 1

                records.append(
                    FileComparisonRecord(
                        rel_path=rel_path,
                        status=status,
                        baseline_sha256=b_entry.sha256,
                        current_sha256=s_entry.sha256,
                        baseline_size=b_entry.size_bytes,
                        current_size=s_entry.size_bytes,
                        mtime_utc=s_entry.mtime_utc,
                    )
                )

            # Case 3: Present in current scan, but not in baseline -> ADDED
            elif in_scanned and not in_baseline:
                s_entry = inventory.scanned_files[rel_path]
                result.added_count += 1
                records.append(
                    FileComparisonRecord(
                        rel_path=rel_path,
                        status=STATUS_ADDED,
                        baseline_sha256=None,
                        current_sha256=s_entry.sha256,
                        baseline_size=None,
                        current_size=s_entry.size_bytes,
                        mtime_utc=s_entry.mtime_utc,
                    )
                )

            # Case 4: Present in baseline, but missing from current scan
            elif in_baseline and not in_scanned:
                b_entry = baseline.files[rel_path]

                # Safeguard: if scan was aborted/incomplete due to directory permission failure,
                # do not report missing files as DELETED!
                if not inventory.is_complete and walk_errors:
                    walk_msg = "; ".join(e.message for e in walk_errors)
                    result.error_count += 1
                    records.append(
                        FileComparisonRecord(
                            rel_path=rel_path,
                            status=STATUS_SCAN_ERROR,
                            baseline_sha256=b_entry.sha256,
                            current_sha256=None,
                            baseline_size=b_entry.size_bytes,
                            current_size=None,
                            error_details=(
                                f"Incomplete scan: cannot confirm deletion due to directory walk error ({walk_msg})"
                            ),
                        )
                    )
                else:
                    result.deleted_count += 1
                    records.append(
                        FileComparisonRecord(
                            rel_path=rel_path,
                            status=STATUS_DELETED,
                            baseline_sha256=b_entry.sha256,
                            current_sha256=None,
                            baseline_size=b_entry.size_bytes,
                            current_size=None,
                        )
                    )

        # Include root directory walk errors if present
        for err in walk_errors:
            if err.rel_path == ".":
                records.append(
                    FileComparisonRecord(
                        rel_path="[ROOT DIRECTORY]",
                        status=STATUS_SCAN_ERROR,
                        error_details=f"[{err.error_type}] {err.message}",
                    )
                )
                result.error_count += 1

        result.records = records
        return result
