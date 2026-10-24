"""
Core module for File Integrity Monitoring System (FIMS).
Contains cryptographic hashing, baseline management, directory scanning,
integrity comparison, and reporting engines.
"""

from .hasher import HashResult, calculate_sha256
from .baseline import (
    BaselineManager,
    BaselineValidationError,
    BaselineRecord,
)
from .scanner import DirectoryScanner, ScanErrorRecord, ScanInventory
from .comparator import IntegrityComparator, ComparisonResult, FileComparisonRecord
from .reporter import ReportGenerator

__all__ = [
    "HashResult",
    "calculate_sha256",
    "BaselineManager",
    "BaselineValidationError",
    "BaselineRecord",
    "DirectoryScanner",
    "ScanErrorRecord",
    "ScanInventory",
    "IntegrityComparator",
    "ComparisonResult",
    "FileComparisonRecord",
    "ReportGenerator",
]
