"""
Persistent SQLite database layer for the File Integrity Monitoring System (FIMS).
Maintains historical records of scans, change events, and security audit logs.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("fims.database")


class DatabaseManager:
    """Manages SQLite connection, schema migrations, and queries for scans & events."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path:
            self.db_path = Path(db_path).resolve()
        else:
            self.db_path = Path(__file__).resolve().parent / "fims.db"

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection with row factories and foreign keys."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        """Create database tables and indexes if they do not already exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scans table: summary of each scan run
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL UNIQUE,
                    timestamp_utc TEXT NOT NULL,
                    root_directory TEXT NOT NULL,
                    baseline_version TEXT NOT NULL,
                    total_discovered INTEGER NOT NULL,
                    total_scanned INTEGER NOT NULL,
                    unchanged_count INTEGER NOT NULL,
                    modified_count INTEGER NOT NULL,
                    added_count INTEGER NOT NULL,
                    deleted_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    is_complete INTEGER NOT NULL,
                    scan_details_json TEXT NOT NULL
                );
            """)

            # Events table: granular audit log of security events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    file_path TEXT,
                    details TEXT NOT NULL
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp_utc DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")
            conn.commit()

    def log_event(
        self,
        event_type: str,
        details: str,
        file_path: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
    ) -> int:
        """
        Record a security or operational event in the event history.

        Args:
            event_type: Category (e.g., 'BASELINE_CREATED', 'FILE_MODIFIED', 'SCAN_STARTED')
            details: Human-readable context or diagnostic details
            file_path: Relative path affected (if applicable)
            timestamp_utc: ISO UTC timestamp (defaults to current time)

        Returns:
            Inserted event row ID.
        """
        ts = timestamp_utc or datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO events (timestamp_utc, event_type, file_path, details)
                VALUES (?, ?, ?, ?);
                """,
                (ts, event_type, file_path, details),
            )
            conn.commit()
            return cursor.lastrowid

    def save_scan(
        self,
        scan_id: str,
        timestamp_utc: str,
        root_directory: str,
        baseline_version: str,
        total_discovered: int,
        total_scanned: int,
        unchanged_count: int,
        modified_count: int,
        added_count: int,
        deleted_count: int,
        error_count: int,
        is_complete: bool,
        scan_details_json: str,
    ) -> int:
        """Save a completed scan summary and its detailed JSON payload."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (
                    scan_id, timestamp_utc, root_directory, baseline_version,
                    total_discovered, total_scanned, unchanged_count, modified_count,
                    added_count, deleted_count, error_count, is_complete, scan_details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    scan_id,
                    timestamp_utc,
                    root_directory,
                    baseline_version,
                    total_discovered,
                    total_scanned,
                    unchanged_count,
                    modified_count,
                    added_count,
                    deleted_count,
                    error_count,
                    1 if is_complete else 0,
                    scan_details_json,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent scans ordered by timestamp descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, scan_id, timestamp_utc, root_directory, baseline_version,
                       total_discovered, total_scanned, unchanged_count, modified_count,
                       added_count, deleted_count, error_count, is_complete
                FROM scans
                ORDER BY id DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full details of a specific scan by its scan_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM scans WHERE scan_id = ? LIMIT 1;",
                (scan_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent security and audit events."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp_utc, event_type, file_path, details
                FROM events
                ORDER BY id DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
