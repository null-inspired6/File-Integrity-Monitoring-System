"""
Report generation engine for the File Integrity Monitoring System (FIMS).
Generates audit-ready JSON and CSV reports detailing scan summaries,
completeness status, and individual file integrity states.
"""

import csv
from datetime import datetime, timezone
import io
import json
import logging
from pathlib import Path
from typing import Optional, Union

from .comparator import ComparisonResult

logger = logging.getLogger("fims.reporter")


class ReportGenerator:
    """Produces structured JSON and CSV reports from ComparisonResult objects."""

    @staticmethod
    def to_json(result: ComparisonResult, indent: int = 2) -> str:
        """Serialize ComparisonResult into formatted JSON string."""
        return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)

    @staticmethod
    def to_csv(result: ComparisonResult) -> str:
        """
        Serialize ComparisonResult into RFC 4180 compliant CSV string.
        Includes a metadata header block followed by the tabular file records.
        """
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")

        # Report Header metadata
        writer.writerow(["# FIMS Integrity Scan Audit Report"])
        writer.writerow(["# Scan ID", result.scan_id])
        writer.writerow(["# Scan Timestamp UTC", result.timestamp_utc])
        writer.writerow(["# Monitored Root Directory", result.root_directory])
        writer.writerow(["# Baseline Version", result.baseline_version])
        writer.writerow(["# Scan Complete", "YES" if result.is_complete else "NO (PARTIAL SCAN)"])
        writer.writerow(["# Total Baseline Files", result.total_baseline_files])
        writer.writerow(["# Total Current Files", result.total_current_files])
        writer.writerow(["# Unchanged Files", result.unchanged_count])
        writer.writerow(["# Modified Files", result.modified_count])
        writer.writerow(["# Added Files", result.added_count])
        writer.writerow(["# Deleted Files", result.deleted_count])
        writer.writerow(["# Scan Errors", result.error_count])
        writer.writerow([])  # blank line separator

        # Table Column Headers
        writer.writerow([
            "Relative Path",
            "Detection Status",
            "Baseline SHA-256",
            "Current SHA-256",
            "Baseline Size (Bytes)",
            "Current Size (Bytes)",
            "Timestamp UTC",
            "Error Details",
        ])

        for rec in result.records:
            writer.writerow([
                rec.rel_path,
                rec.status,
                rec.baseline_sha256 or "N/A",
                rec.current_sha256 or "N/A",
                rec.baseline_size if rec.baseline_size is not None else "N/A",
                rec.current_size if rec.current_size is not None else "N/A",
                rec.mtime_utc or result.timestamp_utc,
                rec.error_details or "",
            ])

        return output.getvalue()

    @classmethod
    def save_report(
        cls,
        result: ComparisonResult,
        output_dir: Path,
        format_type: str = "json",
    ) -> Path:
        """
        Save the report to disk in the specified directory.

        Args:
            result: The scan comparison result.
            output_dir: Directory where the report will be saved.
            format_type: "json" or "csv"

        Returns:
            Path to the saved report file.
        """
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"fims_report_{result.scan_id}_{timestamp}.{format_type.lower()}"
        file_path = out_dir / filename

        content = cls.to_json(result) if format_type.lower() == "json" else cls.to_csv(result)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("Saved %s report to: %s", format_type.upper(), file_path)
        return file_path
