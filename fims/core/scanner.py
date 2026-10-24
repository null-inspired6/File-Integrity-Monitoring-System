"""
Directory scanning engine for the File Integrity Monitoring System (FIMS).
Discovers files recursively, filters exclusions, prevents symlink escapes,
handles I/O/permission errors gracefully, and computes SHA-256 digests.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import fnmatch
import logging
import os
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from .hasher import HashResult, calculate_sha256

logger = logging.getLogger("fims.scanner")


@dataclass
class ScanErrorRecord:
    """Represents an error encountered while inspecting a file or directory."""
    rel_path: str
    error_type: str  # e.g., "PERMISSION_DENIED", "IO_ERROR", "HASH_FAILED", "SYMLINK_BLOCKED"
    message: str
    is_directory: bool = False


@dataclass
class ScannedFileRecord:
    """Represents a file successfully inspected and hashed during a scan."""
    rel_path: str
    abs_path: str
    sha256: str
    size_bytes: int
    mtime_utc: str


@dataclass
class ScanInventory:
    """Aggregated results of a complete or partial directory scan."""
    root_dir: str
    scanned_files: Dict[str, ScannedFileRecord] = field(default_factory=dict)
    errors: List[ScanErrorRecord] = field(default_factory=list)
    is_complete: bool = True
    timestamp_utc: str = ""
    total_discovered: int = 0
    total_hashed: int = 0

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


class DirectoryScanner:
    """
    Scans a directory hierarchy while applying security policies:
    - Exclusion of sensitive or volatile patterns (git, logs, db, temp)
    - Prevention of symlink traversal outside the monitored root
    - Graceful capture of permission errors without dropping inventory
    """

    def __init__(
        self,
        root_dir: Path,
        exclusions: Optional[List[str]] = None,
        chunk_size: int = 65536,
        follow_symlinks: bool = False,
        app_dir: Optional[Path] = None,
    ):
        self.root_dir = Path(root_dir).resolve()
        self.exclusions = list(exclusions or [])
        self.chunk_size = chunk_size
        self.follow_symlinks = follow_symlinks
        self.app_dir = Path(app_dir).resolve() if app_dir else None

    def validate_root(self) -> Tuple[bool, Optional[str]]:
        """Validate that the root directory exists, is a directory, and is readable."""
        if not self.root_dir.exists():
            return False, f"Directory does not exist: {self.root_dir}"
        if not self.root_dir.is_dir():
            return False, f"Path is not a directory: {self.root_dir}"

        try:
            # Test read permission
            next(os.scandir(self.root_dir), None)
        except PermissionError:
            return False, f"Permission denied accessing directory: {self.root_dir}"
        except OSError as e:
            return False, f"Error accessing directory: {e}"

        return True, None

    def is_excluded(self, item_path: Path, rel_path_str: str) -> bool:
        """
        Check if a file or directory matches configured exclusion rules or points
        inside the application's internal data directories.
        """
        # Exclude app internal directories if monitored root contains them
        if self.app_dir:
            try:
                resolved_item = item_path.resolve()
                if resolved_item == self.app_dir or self.app_dir in resolved_item.parents:
                    return True
            except OSError:
                pass

        # Check path components and filenames against exclusions
        path_parts = Path(rel_path_str).parts
        item_name = item_path.name

        for pattern in self.exclusions:
            clean_pat = pattern.strip()
            if not clean_pat:
                continue

            # Check if any folder segment matches
            for part in path_parts:
                if fnmatch.fnmatch(part.lower(), clean_pat.lower()):
                    return True

            # Check full relative path or filename
            if fnmatch.fnmatch(item_name.lower(), clean_pat.lower()):
                return True
            if fnmatch.fnmatch(rel_path_str.lower(), clean_pat.lower()):
                return True

        return False

    def is_safe_symlink(self, path: Path) -> bool:
        """
        Verify if a symbolic link is safe to traverse.
        If follow_symlinks is False, symlinks are never followed.
        If follow_symlinks is True, target must reside within self.root_dir.
        """
        if not path.is_symlink():
            return True

        if not self.follow_symlinks:
            return False

        try:
            target = path.resolve()
            # Must be inside root_dir
            return self.root_dir in target.parents or target == self.root_dir
        except (OSError, RuntimeError):
            return False

    def scan(
        self,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> ScanInventory:
        """
        Perform a comprehensive file scan of the target root directory.

        Args:
            progress_callback: Optional callback receiving (files_scanned_count, current_filename)

        Returns:
            ScanInventory containing discovered files, digests, errors, and completeness status.
        """
        scan_time = datetime.now(timezone.utc).isoformat()
        inventory = ScanInventory(
            root_dir=str(self.root_dir),
            timestamp_utc=scan_time,
            is_complete=True,
        )

        valid, error_msg = self.validate_root()
        if not valid:
            inventory.is_complete = False
            inventory.errors.append(
                ScanErrorRecord(
                    rel_path=".",
                    error_type="ROOT_ACCESS_ERROR",
                    message=error_msg or "Cannot access root directory",
                    is_directory=True,
                )
            )
            return inventory

        discovered_files: List[Tuple[Path, str]] = []

        # Step 1: Discover eligible files safely using os.walk
        try:
            for root, dirs, files in os.walk(self.root_dir, followlinks=False):
                current_dir = Path(root)

                # Relative path from root
                try:
                    rel_dir = current_dir.relative_to(self.root_dir)
                    rel_dir_str = rel_dir.as_posix()
                except ValueError:
                    continue

                # Filter directories in-place to avoid descending into excluded branches
                eligible_dirs = []
                for d in dirs:
                    d_path = current_dir / d
                    d_rel = (rel_dir / d).as_posix() if rel_dir_str != "." else d

                    if d_path.is_symlink():
                        if not self.is_safe_symlink(d_path):
                            logger.info("Skipping symlink directory: %s", d_rel)
                            continue

                    if self.is_excluded(d_path, d_rel):
                        continue

                    eligible_dirs.append(d)

                dirs[:] = eligible_dirs

                # Inspect files in current folder
                for f in files:
                    file_path = current_dir / f
                    rel_file = (rel_dir / f).as_posix() if rel_dir_str != "." else f

                    if file_path.is_symlink():
                        if not self.is_safe_symlink(file_path):
                            inventory.errors.append(
                                ScanErrorRecord(
                                    rel_path=rel_file,
                                    error_type="SYMLINK_BLOCKED",
                                    message="Symlink traversal outside root blocked by security policy",
                                )
                            )
                            continue

                    if self.is_excluded(file_path, rel_file):
                        continue

                    discovered_files.append((file_path, rel_file))

        except PermissionError as pe:
            logger.error("Permission denied during directory walk: %s", pe)
            inventory.is_complete = False
            inventory.errors.append(
                ScanErrorRecord(
                    rel_path=".",
                    error_type="WALK_PERMISSION_DENIED",
                    message=f"Permission denied traversing directory structure: {pe}",
                    is_directory=True,
                )
            )
        except OSError as oe:
            logger.error("OS error during directory walk: %s", oe)
            inventory.is_complete = False
            inventory.errors.append(
                ScanErrorRecord(
                    rel_path=".",
                    error_type="WALK_OS_ERROR",
                    message=f"I/O error during directory search: {oe}",
                    is_directory=True,
                )
            )

        inventory.total_discovered = len(discovered_files)

        # Step 2: Hash files and construct inventory
        for idx, (f_path, rel_str) in enumerate(discovered_files, start=1):
            if progress_callback:
                progress_callback(idx, rel_str)

            hash_result: HashResult = calculate_sha256(f_path, chunk_size=self.chunk_size)

            if hash_result.success and hash_result.digest:
                inventory.scanned_files[rel_str] = ScannedFileRecord(
                    rel_path=rel_str,
                    abs_path=str(f_path),
                    sha256=hash_result.digest,
                    size_bytes=hash_result.file_size,
                    mtime_utc=hash_result.mtime_utc or "",
                )
                inventory.total_hashed += 1
            else:
                inventory.is_complete = False
                error_type = "HASH_UNCERTAIN" if hash_result.uncertain else "SCAN_ERROR"
                inventory.errors.append(
                    ScanErrorRecord(
                        rel_path=rel_str,
                        error_type=error_type,
                        message=hash_result.error_message or "Failed to calculate SHA-256 digest",
                    )
                )

        return inventory
