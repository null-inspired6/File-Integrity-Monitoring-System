"""
Cryptographic SHA-256 hashing engine for the File Integrity Monitoring System (FIMS).
Provides chunk-based, memory-safe hashing, concurrency/mutation detection, and safe I/O handling.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("fims.hasher")

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB chunks to protect memory


@dataclass
class HashResult:
    """Represents the outcome of a file SHA-256 calculation."""
    success: bool
    digest: Optional[str] = None
    file_size: int = 0
    mtime_utc: Optional[str] = None
    error_message: Optional[str] = None
    uncertain: bool = False


def calculate_sha256(
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_retries: int = 1,
) -> HashResult:
    """
    Calculate the SHA-256 digest of a target file using chunked streaming.

    Safeguards:
    1. Memory Safety: Reads the file in fixed chunks (e.g. 64 KB), preventing Out-Of-Memory (OOM)
       crashes on large ISOs or log files.
    2. Change Detection: Inspects file size and modification timestamps before and after reading.
       If modified concurrently during read, it retries up to `max_retries`. If still mutating,
       it flags the result as uncertain.
    3. Safe Exception Handling: Explicitly handles FileNotFoundError, PermissionError, and OSError
       without exposing file contents or crashing the scanner.

    Args:
        file_path: Path to the target file.
        chunk_size: Number of bytes to read per iteration (default: 65,536 bytes).
        max_retries: Number of retries if file changes during read.

    Returns:
        HashResult object containing success status, 64-char hex digest, size, mtime, and errors.
    """
    path_obj = Path(file_path)

    for attempt in range(max_retries + 1):
        try:
            # Pre-check file stats
            stat_before = path_obj.stat()
            file_size_before = stat_before.st_size
            mtime_before = stat_before.st_mtime_ns

            hasher = hashlib.sha256()
            bytes_read = 0

            with open(path_obj, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    bytes_read += len(chunk)

            # Post-check file stats to verify integrity during read
            stat_after = path_obj.stat()
            file_size_after = stat_after.st_size
            mtime_after = stat_after.st_mtime_ns

            # Detect if file mutated while reading
            if file_size_before != file_size_after or mtime_before != mtime_after:
                if attempt < max_retries:
                    logger.warning(
                        "File %s changed during hash calculation; retrying (attempt %d of %d)",
                        path_obj.name, attempt + 1, max_retries
                    )
                    continue

                # Exceeded retries, mark as uncertain
                iso_mtime = datetime.fromtimestamp(
                    stat_after.st_mtime, tz=timezone.utc
                ).isoformat()
                return HashResult(
                    success=False,
                    digest=hasher.hexdigest(),
                    file_size=file_size_after,
                    mtime_utc=iso_mtime,
                    error_message="File changed during hash calculation; result uncertain",
                    uncertain=True,
                )

            # Success
            iso_mtime = datetime.fromtimestamp(
                stat_after.st_mtime, tz=timezone.utc
            ).isoformat()
            return HashResult(
                success=True,
                digest=hasher.hexdigest(),
                file_size=file_size_after,
                mtime_utc=iso_mtime,
                error_message=None,
                uncertain=False,
            )

        except FileNotFoundError:
            logger.error("Hash failed: file not found %s", path_obj.name)
            return HashResult(
                success=False,
                error_message="File not found or was removed during scan",
            )
        except PermissionError as pe:
            logger.error("Hash failed: permission denied for %s", path_obj.name)
            return HashResult(
                success=False,
                error_message=f"Access denied: {str(pe)}",
            )
        except OSError as oe:
            logger.error("Hash failed: OS/IO error for %s: %s", path_obj.name, str(oe))
            return HashResult(
                success=False,
                error_message=f"I/O error: {str(oe)}",
            )
        except Exception as exc:
            logger.critical("Unexpected error hashing %s: %s", path_obj.name, str(exc))
            return HashResult(
                success=False,
                error_message=f"Unexpected error: {str(exc)}",
            )

    return HashResult(
        success=False,
        error_message="Exceeded max hash retries",
    )
