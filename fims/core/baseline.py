"""
Baseline management module for the File Integrity Monitoring System (FIMS).
Handles creation, validation, atomic saving, backup, loading, and tamper warnings.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("fims.baseline")

CURRENT_BASELINE_VERSION = "1.0"
TAMPER_WARNING = (
    "SECURITY WARNING: This baseline is stored locally in the filesystem. "
    "An adversary with administrative or write access to this host could alter "
    "or replace the baseline file to hide unauthorized modifications. "
    "In high-assurance production environments, baselines should be cryptographically "
    "signed and stored on write-once media (WORM) or a remote hardened security server."
)


class BaselineValidationError(Exception):
    """Raised when a baseline JSON file is corrupt, invalid, or schema-incompatible."""
    pass


@dataclass
class FileBaselineEntry:
    """Represents a single file's verified state in the baseline."""
    sha256: str
    size_bytes: int
    mtime_utc: str


@dataclass
class BaselineRecord:
    """Represents a complete baseline snapshot."""
    version: str
    created_at: str
    root_directory: str
    total_files: int
    files: Dict[str, FileBaselineEntry]
    tamper_warning: str = TAMPER_WARNING

    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline record to serializable dictionary."""
        return {
            "version": self.version,
            "created_at": self.created_at,
            "root_directory": self.root_directory,
            "total_files": self.total_files,
            "tamper_warning": self.tamper_warning,
            "files": {
                rel_path: asdict(entry)
                for rel_path, entry in self.files.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineRecord":
        """Instantiate a BaselineRecord from validated dictionary data."""
        files_dict = {}
        for path_key, entry_data in data.get("files", {}).items():
            files_dict[path_key] = FileBaselineEntry(
                sha256=entry_data["sha256"],
                size_bytes=int(entry_data["size_bytes"]),
                mtime_utc=entry_data.get("mtime_utc", ""),
            )
        return cls(
            version=str(data.get("version", "")),
            created_at=str(data.get("created_at", "")),
            root_directory=str(data.get("root_directory", "")),
            total_files=int(data.get("total_files", len(files_dict))),
            files=files_dict,
            tamper_warning=data.get("tamper_warning", TAMPER_WARNING),
        )


class BaselineManager:
    """Manages baseline persistence, validation, backup, and atomic transactions."""

    def __init__(self, default_dir: Optional[Path] = None):
        if default_dir:
            self.default_dir = Path(default_dir).resolve()
        else:
            self.default_dir = Path(__file__).resolve().parent.parent / "baselines"
        self.default_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def validate_schema(data: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate baseline dictionary against expected schema and version.

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        if not isinstance(data, dict):
            return False, "Baseline root must be a JSON object"

        if "version" not in data or data["version"] != CURRENT_BASELINE_VERSION:
            return False, (
                f"Unsupported or missing baseline version: "
                f"expected '{CURRENT_BASELINE_VERSION}', got '{data.get('version')}'"
            )

        required_keys = ["created_at", "root_directory", "files"]
        for key in required_keys:
            if key not in data:
                return False, f"Missing required top-level key: '{key}'"

        if not isinstance(data["files"], dict):
            return False, "'files' field must be a dictionary of relative paths"

        for rel_path, file_info in data["files"].items():
            if not isinstance(rel_path, str) or not rel_path.strip():
                return False, f"Invalid file path key: {rel_path}"
            if not isinstance(file_info, dict):
                return False, f"File entry for '{rel_path}' must be an object"
            if "sha256" not in file_info or len(file_info["sha256"]) != 64:
                return False, f"File entry '{rel_path}' missing valid 64-char SHA-256 digest"
            if "size_bytes" not in file_info or not isinstance(file_info["size_bytes"], int):
                return False, f"File entry '{rel_path}' missing valid integer 'size_bytes'"

        return True, None

    def load_baseline(self, baseline_path: Path) -> BaselineRecord:
        """
        Load and validate a baseline file.

        Raises:
            FileNotFoundError: If baseline file does not exist.
            BaselineValidationError: If JSON is invalid or fails schema validation.
        """
        path = Path(baseline_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Baseline file not found at: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as jde:
            logger.error("JSON decode error in baseline %s: %s", path, jde)
            raise BaselineValidationError(f"Baseline file contains invalid JSON: {jde}") from jde
        except Exception as exc:
            logger.error("Error reading baseline %s: %s", path, exc)
            raise BaselineValidationError(f"Failed to read baseline file: {exc}") from exc

        is_valid, error_msg = self.validate_schema(data)
        if not is_valid:
            logger.error("Baseline validation failed: %s", error_msg)
            raise BaselineValidationError(f"Corrupted or invalid baseline: {error_msg}")

        return BaselineRecord.from_dict(data)

    def backup_baseline(self, baseline_path: Path) -> Optional[Path]:
        """
        Create a timestamped backup of the existing baseline before modification.
        Preserves original file timestamp and permissions.

        Returns:
            Path to backup file if existing baseline was backed up, or None if file didn't exist.
        """
        path = Path(baseline_path).resolve()
        if not path.is_file():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{path.stem}.backup_{timestamp}{path.suffix}"
        backup_path = path.parent / backup_filename

        try:
            shutil.copy2(path, backup_path)
            logger.info("Created baseline backup at: %s", backup_path)
            return backup_path
        except Exception as exc:
            logger.error("Failed to create baseline backup for %s: %s", path, exc)
            raise IOError(f"Could not backup existing baseline: {exc}") from exc

    def save_baseline_atomic(
        self,
        record: BaselineRecord,
        target_path: Path,
        create_backup: bool = True,
    ) -> Path:
        """
        Save baseline record to file atomically using a temporary file and rename.
        Ensures atomic replacement, avoiding incomplete or corrupted files on crash or power loss.
        Preserves previous baseline if any error occurs.

        Args:
            record: BaselineRecord to serialize.
            target_path: Destination path for the baseline.
            create_backup: Whether to create a backup of an existing target first.

        Returns:
            Resolved Path to saved baseline file.
        """
        target = Path(target_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)

        # Create backup if file already exists
        if target.is_file() and create_backup:
            self.backup_baseline(target)

        payload = record.to_dict()
        valid, msg = self.validate_schema(payload)
        if not valid:
            raise BaselineValidationError(f"Cannot save invalid baseline: {msg}")

        # Atomic write pattern: write to temp file in same directory, then atomic rename
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            delete=False,
            prefix=".baseline_tmp_",
            suffix=".json",
        )
        temp_path = Path(temp_file.name)

        try:
            json.dump(payload, temp_file, indent=2, ensure_ascii=False)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_file.close()

            # Atomic rename / replace
            os.replace(temp_path, target)
            logger.info("Successfully saved baseline atomically to: %s", target)
            return target
        except Exception as exc:
            # Clean up temp file on failure
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            logger.error("Atomic baseline write failed for %s: %s", target, exc)
            raise IOError(f"Failed to atomically write baseline: {exc}") from exc

    @staticmethod
    def generate_baseline_filename(root_dir: Path) -> str:
        """Generate a safe, unique baseline filename based on directory name and hash."""
        resolved = Path(root_dir).resolve()
        dir_name = resolved.name or "root"
        # Sanitize dir_name for file system
        clean_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in dir_name)
        path_hash = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:8]
        return f"baseline_{clean_name}_{path_hash}.json"
