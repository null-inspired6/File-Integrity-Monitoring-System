"""
Dashboard UI for File Integrity Monitoring System (FIMS).
Built with Streamlit, providing a dark cybersecurity-themed interface,
real-time integrity scanning, interactive file inventory inspection,
event logs, baseline lifecycle workflows, and audit report exports.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st

from core.baseline import (
    BaselineManager,
    BaselineRecord,
    BaselineValidationError,
    FileBaselineEntry,
    CURRENT_BASELINE_VERSION,
    TAMPER_WARNING,
)
from core.comparator import (
    ComparisonResult,
    FileComparisonRecord,
    IntegrityComparator,
    STATUS_ADDED,
    STATUS_DELETED,
    STATUS_MODIFIED,
    STATUS_SCAN_ERROR,
    STATUS_UNCHANGED,
)
from core.reporter import ReportGenerator
from core.scanner import DirectoryScanner, ScanInventory
from storage.database import DatabaseManager

logger = logging.getLogger("fims.ui")


CUSTOM_CSS = """
<style>
/* Cybersecurity Clean Light Theme Overrides */
[data-testid="stAppViewContainer"] {
    background-color: #f8fafc;
    color: #0f172a;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
}
[data-testid="stHeader"] {
    background-color: rgba(248, 250, 252, 0.9);
}
[data-testid="stSidebar"] {
    background-color: #ffffff;
    border-right: 1px solid #e2e8f0;
}

/* Header & Card Styling */
.fims-header {
    background: linear-gradient(135deg, #ffffff 0%, #f1f5f9 100%);
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 8px rgba(15, 23, 42, 0.05);
}
.fims-title {
    font-size: 1.8rem;
    font-weight: 700;
    color: #0284c7;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.fims-subtitle {
    font-size: 0.95rem;
    color: #475569;
    margin-top: 0.25rem;
}

/* Metric Cards */
.metric-box {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
}
.metric-box.danger { border-top: 3px solid #dc2626; }
.metric-box.warning { border-top: 3px solid #d97706; }
.metric-box.success { border-top: 3px solid #16a34a; }
.metric-box.info { border-top: 3px solid #0284c7; }
.metric-box.purple { border-top: 3px solid #7c3aed; }

.metric-title {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #64748b;
    margin-bottom: 0.25rem;
    font-weight: 600;
}
.metric-value {
    font-size: 1.6rem;
    font-weight: 700;
    color: #0f172a;
}

/* Status Badges */
.badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
}
.badge-unchanged { background-color: #dcfce7; color: #15803d; border: 1px solid #86efac; }
.badge-modified { background-color: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }
.badge-added { background-color: #e0f2fe; color: #0369a1; border: 1px solid #7dd3fc; }
.badge-deleted { background-color: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
.badge-error { background-color: #f3e8ff; color: #6b21a8; border: 1px solid #d8b4fe; }

/* Security Warning Alert */
.sec-warning-alert {
    background-color: #fffbeb;
    border: 1px solid #fde68a;
    border-left: 4px solid #f59e0b;
    border-radius: 4px;
    padding: 0.85rem 1rem;
    margin: 1rem 0;
    color: #92400e;
    font-size: 0.88rem;
}

/* Monospace file hashes */
.hash-font {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.8rem;
    word-break: break-all;
}
</style>
"""


def init_session_state(app_dir: Path) -> None:
    """Initialize persistent Streamlit session state."""
    if "app_dir" not in st.session_state:
        st.session_state.app_dir = app_dir

    if "db_manager" not in st.session_state:
        st.session_state.db_manager = DatabaseManager(app_dir / "storage" / "fims.db")

    if "baseline_manager" not in st.session_state:
        st.session_state.baseline_manager = BaselineManager(app_dir / "baselines")

    # Load default settings
    config_file = app_dir / "config" / "settings.json"
    if "config" not in st.session_state:
        if config_file.exists():
            with open(config_file, "r", encoding="utf-8") as f:
                st.session_state.config = json.load(f)
        else:
            st.session_state.config = {
                "chunk_size_bytes": 65536,
                "follow_symlinks": False,
                "default_exclusions": [".git", "__pycache__", "venv", ".venv", "fims.db", "*.tmp"],
            }

    if "monitored_dir" not in st.session_state:
        # Default to a safe demo subfolder
        demo_dir = app_dir / "demo_monitored_folder"
        demo_dir.mkdir(exist_ok=True)
        st.session_state.monitored_dir = str(demo_dir.resolve())

    if "active_baseline" not in st.session_state:
        st.session_state.active_baseline = None
        st.session_state.active_baseline_path = None

    if "last_comparison" not in st.session_state:
        st.session_state.last_comparison = None

    if "exclusions" not in st.session_state:
        st.session_state.exclusions = list(st.session_state.config.get("default_exclusions", []))


def render_header():
    """Render top branding banner."""
    st.markdown(
        """
        <div class="fims-header">
            <h1 class="fims-title">🛡️ FIMS // File Integrity Monitoring System</h1>
            <div class="fims-subtitle">
                Cryptographic SHA-256 Baseline Verification &amp; Change Detection Engine
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_overview():
    """Section 1: Overview Dashboard with system status and metrics cards."""
    st.subheader("1. System Overview & Status")

    comp: Optional[ComparisonResult] = st.session_state.last_comparison
    baseline: Optional[BaselineRecord] = st.session_state.active_baseline

    status_col1, status_col2 = st.columns([2, 1])
    with status_col1:
        if baseline is None:
            st.warning("⚠️ **No Active Baseline**: Create or load a trusted baseline to begin monitoring.")
        elif comp is None:
            st.info(f"ℹ️ **Baseline Loaded**: Monitoring '{baseline.root_directory}'. Ready for integrity scan.")
        elif comp.has_anomalies:
            st.error(f"🚨 **Integrity Anomalies Detected**: Scan `{comp.scan_id}` identified filesystem changes.")
        else:
            st.success(f"✅ **System Integrity Verified**: All files match the trusted baseline.")

    with status_col2:
        last_scan_ts = comp.timestamp_utc if comp else "None recorded"
        st.caption(f"**Last Scan UTC:** {last_scan_ts}")
        st.caption(f"**Baseline Version:** {baseline.version if baseline else 'N/A'}")

    st.markdown("---")

    # Metrics row
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        st.markdown(
            f"""
            <div class="metric-box info">
                <div class="metric-title">Baseline Files</div>
                <div class="metric-value">{len(baseline.files) if baseline else 0}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="metric-box success">
                <div class="metric-title">Unchanged</div>
                <div class="metric-value">{comp.unchanged_count if comp else 0}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="metric-box danger">
                <div class="metric-title">Modified</div>
                <div class="metric-value">{comp.modified_count if comp else 0}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="metric-box info">
                <div class="metric-title">Added</div>
                <div class="metric-value">{comp.added_count if comp else 0}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c5:
        st.markdown(
            f"""
            <div class="metric-box warning">
                <div class="metric-title">Deleted</div>
                <div class="metric-value">{comp.deleted_count if comp else 0}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c6:
        st.markdown(
            f"""
            <div class="metric-box purple">
                <div class="metric-title">Scan Errors</div>
                <div class="metric-value">{comp.error_count if comp else 0}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def section_directory_selection():
    """Section 2: Directory selection and validation."""
    st.subheader("2. Monitored Directory Configuration")

    dir_input = st.text_input(
        "Enter Target Directory Absolute Path:",
        value=st.session_state.monitored_dir,
        help="Specify the folder you wish to inspect and monitor.",
    )

    path_obj = Path(dir_input).expanduser()

    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("Validate & Set Target Directory", type="primary"):
            if not path_obj.exists():
                st.error(f"Directory does not exist: `{path_obj}`")
            elif not path_obj.is_dir():
                st.error(f"Target path is a file, not a directory: `{path_obj}`")
            else:
                try:
                    # Test read permission
                    list(path_obj.iterdir())
                    st.session_state.monitored_dir = str(path_obj.resolve())
                    st.success(f"Successfully selected monitored root: `{path_obj.resolve()}`")
                except PermissionError as pe:
                    st.error(f"Permission denied: {pe}")
                except Exception as ex:
                    st.error(f"Error accessing directory: {ex}")

    with c2:
        st.markdown(f"**Canonical Root:** `{st.session_state.monitored_dir}`")
        if Path(st.session_state.monitored_dir).exists():
            st.markdown("🟢 Status: Directory accessible and readable.")
        else:
            st.markdown("🔴 Status: Directory path invalid or inaccessible.")

    # Exclusions configuration preview
    with st.expander("Configured Exclusion Filters (Excluded from Scans & Baselines)"):
        st.caption("Matches directory and file names. Application databases and logs are always excluded.")
        exclusions_text = st.text_area(
            "Exclusions (one per line):",
            value="\n".join(st.session_state.exclusions),
            height=120,
        )
        if st.button("Save Exclusion Rules"):
            new_excl = [line.strip() for line in exclusions_text.splitlines() if line.strip()]
            st.session_state.exclusions = new_excl
            st.success("Exclusions updated successfully!")


def section_baseline_management():
    """Section 3: Baseline Management with confirmation, validation, and tamper warning."""
    st.subheader("3. Baseline Management")

    st.markdown(
        f"""
        <div class="sec-warning-alert">
            <strong>⚠️ Cryptographic Tampering Notice:</strong> {TAMPER_WARNING}
        </div>
        """,
        unsafe_allow_html=True,
    )

    root_dir = Path(st.session_state.monitored_dir).resolve()
    base_mgr: BaselineManager = st.session_state.baseline_manager
    db_mgr: DatabaseManager = st.session_state.db_manager

    tab_create, tab_load = st.tabs(["Create New Baseline", "Load / Inspect Baseline"])

    with tab_create:
        st.markdown("Generate an initial trusted baseline by computing SHA-256 hashes of all eligible files.")

        confirm_create = st.checkbox(
            "I confirm that all files in this directory are currently trusted and free from unauthorized tampering.",
            value=False,
        )

        if st.button("Generate Trusted Baseline", disabled=not confirm_create, type="primary"):
            with st.spinner("Scanning directory and computing SHA-256 hashes..."):
                scanner = DirectoryScanner(
                    root_dir=root_dir,
                    exclusions=st.session_state.exclusions,
                    chunk_size=st.session_state.config.get("chunk_size_bytes", 65536),
                    follow_symlinks=st.session_state.config.get("follow_symlinks", False),
                    app_dir=st.session_state.app_dir,
                )
                inventory: ScanInventory = scanner.scan()

                if not inventory.is_complete and len(inventory.scanned_files) == 0:
                    st.error("Failed to build baseline: could not access directory or no files found.")
                else:
                    files_dict = {
                        rel_path: FileBaselineEntry(
                            sha256=rec.sha256,
                            size_bytes=rec.size_bytes,
                            mtime_utc=rec.mtime_utc,
                        )
                        for rel_path, rec in inventory.scanned_files.items()
                    }

                    record = BaselineRecord(
                        version=CURRENT_BASELINE_VERSION,
                        created_at=datetime.now(timezone.utc).isoformat(),
                        root_directory=str(root_dir),
                        total_files=len(files_dict),
                        files=files_dict,
                    )

                    baseline_filename = BaselineManager.generate_baseline_filename(root_dir)
                    target_file = base_mgr.default_dir / baseline_filename

                    try:
                        saved_path = base_mgr.save_baseline_atomic(record, target_file)
                        st.session_state.active_baseline = record
                        st.session_state.active_baseline_path = saved_path

                        # Log event
                        db_mgr.log_event(
                            event_type="BASELINE_CREATED",
                            file_path=str(saved_path.name),
                            details=f"Created baseline with {len(files_dict)} files for {root_dir}",
                        )

                        st.success(f"✅ Baseline generated and atomically saved to `{saved_path.name}`!")
                    except Exception as e:
                        st.error(f"Error saving baseline: {e}")

    with tab_load:
        st.markdown("Select an existing baseline file from `baselines/` directory.")
        existing_baselines = list(base_mgr.default_dir.glob("*.json"))

        if not existing_baselines:
            st.info("No baseline files found in the baselines storage directory.")
        else:
            base_options = {p.name: p for p in existing_baselines}
            selected_name = st.selectbox("Select Baseline File:", list(base_options.keys()))

            if st.button("Load Selected Baseline"):
                try:
                    loaded_rec = base_mgr.load_baseline(base_options[selected_name])
                    st.session_state.active_baseline = loaded_rec
                    st.session_state.active_baseline_path = base_options[selected_name]
                    st.success(f"Loaded baseline `{selected_name}` ({loaded_rec.total_files} files)")
                except BaselineValidationError as bve:
                    st.error(f"Corrupted or invalid baseline: {bve}")
                    db_mgr.log_event(
                        event_type="BASELINE_CORRUPTED",
                        file_path=selected_name,
                        details=str(bve),
                    )
                except Exception as ex:
                    st.error(f"Error loading baseline: {ex}")

        if st.session_state.active_baseline:
            active_b: BaselineRecord = st.session_state.active_baseline
            st.markdown("#### Currently Active Baseline Metadata")
            st.json({
                "Baseline File": str(st.session_state.active_baseline_path),
                "Version": active_b.version,
                "Created UTC": active_b.created_at,
                "Root Directory": active_b.root_directory,
                "Total Files": active_b.total_files,
            })


def section_file_integrity_scanning():
    """Section 4: Run file integrity scan with live progress feedback."""
    st.subheader("4. File Integrity Scanning")

    baseline: Optional[BaselineRecord] = st.session_state.active_baseline
    db_mgr: DatabaseManager = st.session_state.db_manager

    if baseline is None:
        st.warning("Please create or load a baseline first (Section 3).")
        return

    root_dir = Path(st.session_state.monitored_dir).resolve()
    st.markdown(f"Ready to scan: `{root_dir}` against baseline `{baseline.created_at}`")

    if st.button("🚀 Start File Integrity Scan", type="primary"):
        # Log scan started
        db_mgr.log_event(
            event_type="SCAN_STARTED",
            details=f"Scan initiated for directory {root_dir}",
        )

        progress_bar = st.progress(0, text="Initializing scan engine...")
        status_text = st.empty()

        scanner = DirectoryScanner(
            root_dir=root_dir,
            exclusions=st.session_state.exclusions,
            chunk_size=st.session_state.config.get("chunk_size_bytes", 65536),
            follow_symlinks=st.session_state.config.get("follow_symlinks", False),
            app_dir=st.session_state.app_dir,
        )

        def on_progress(count: int, filename: str):
            status_text.text(f"Inspecting [{count}]: {filename}")

        inventory: ScanInventory = scanner.scan(progress_callback=on_progress)
        progress_bar.progress(100, text="Hashing complete. Comparing against baseline...")

        comp_result: ComparisonResult = IntegrityComparator.compare(baseline, inventory)
        st.session_state.last_comparison = comp_result

        # Save to SQLite database
        db_mgr.save_scan(
            scan_id=comp_result.scan_id,
            timestamp_utc=comp_result.timestamp_utc,
            root_directory=comp_result.root_directory,
            baseline_version=comp_result.baseline_version,
            total_discovered=inventory.total_discovered,
            total_scanned=inventory.total_hashed,
            unchanged_count=comp_result.unchanged_count,
            modified_count=comp_result.modified_count,
            added_count=comp_result.added_count,
            deleted_count=comp_result.deleted_count,
            error_count=comp_result.error_count,
            is_complete=comp_result.is_complete,
            scan_details_json=json.dumps(comp_result.to_dict()),
        )

        # Log individual change events
        for r in comp_result.records:
            if r.status == STATUS_MODIFIED:
                db_mgr.log_event("FILE_MODIFIED", f"Hash changed: {r.baseline_sha256[:8]}.. -> {r.current_sha256[:8]}..", r.rel_path)
            elif r.status == STATUS_ADDED:
                db_mgr.log_event("FILE_ADDED", f"New file discovered with SHA-256 {r.current_sha256[:8]}..", r.rel_path)
            elif r.status == STATUS_DELETED:
                db_mgr.log_event("FILE_DELETED", "File missing compared to baseline", r.rel_path)
            elif r.status == STATUS_SCAN_ERROR:
                db_mgr.log_event("SCAN_ERROR", r.error_details or "Scan error", r.rel_path)

        db_mgr.log_event(
            event_type="SCAN_COMPLETED",
            details=f"Scan {comp_result.scan_id} finished: {comp_result.unchanged_count} unchanged, {comp_result.modified_count} mod, {comp_result.added_count} add, {comp_result.deleted_count} del, {comp_result.error_count} err",
        )

        progress_bar.empty()
        status_text.empty()
        st.success(f"Scan `{comp_result.scan_id}` completed successfully!")


def section_detected_changes():
    """Section 5: Detected changes table with search, filters, and hash comparison."""
    st.subheader("5. Detected Changes & File Inventory")

    comp: Optional[ComparisonResult] = st.session_state.last_comparison
    if comp is None:
        st.info("No scan results to display yet. Run a scan in Section 4.")
        return

    # Filter and Search row
    f1, f2 = st.columns([1, 2])
    with f1:
        status_filter = st.selectbox(
            "Filter by Detection Status:",
            ["ALL", STATUS_MODIFIED, STATUS_ADDED, STATUS_DELETED, STATUS_SCAN_ERROR, STATUS_UNCHANGED],
        )
    with f2:
        search_query = st.text_input("Search filename / relative path:", placeholder="e.g. index.html or .py")

    # Filter records
    records = comp.records
    if status_filter != "ALL":
        records = [r for r in records if r.status == status_filter]
    if search_query.strip():
        q = search_query.strip().lower()
        records = [r for r in records if q in r.rel_path.lower()]

    st.markdown(f"**Showing {len(records)} of {len(comp.records)} records**")

    # Prepare DataFrame
    table_data = []
    for r in records:
        table_data.append({
            "Status": r.status,
            "Relative Path": r.rel_path,
            "Baseline SHA-256": (r.baseline_sha256[:16] + "...") if r.baseline_sha256 else "N/A",
            "Current SHA-256": (r.current_sha256[:16] + "...") if r.current_sha256 else "N/A",
            "Baseline Size": f"{r.baseline_size} B" if r.baseline_size is not None else "N/A",
            "Current Size": f"{r.current_size} B" if r.current_size is not None else "N/A",
            "Error / Details": r.error_details or "",
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True)

    # Detailed Side-by-Side Inspector for Modified Files
    modified_files = [r for r in comp.records if r.status == STATUS_MODIFIED]
    if modified_files:
        with st.expander(f"🔍 Inspect Cryptographic Hashes for Modified Files ({len(modified_files)})"):
            mod_choice = st.selectbox(
                "Select a modified file to inspect full SHA-256 digests:",
                [m.rel_path for m in modified_files],
            )
            selected_mod = next(m for m in modified_files if m.rel_path == mod_choice)

            col_base, col_curr = st.columns(2)
            with col_base:
                st.markdown("**Trusted Baseline Digest (SHA-256)**")
                st.code(selected_mod.baseline_sha256 or "N/A", language="text")
                st.caption(f"Baseline File Size: {selected_mod.baseline_size} bytes")

            with col_curr:
                st.markdown("**Current File Digest (SHA-256)**")
                st.code(selected_mod.current_sha256 or "N/A", language="text")
                st.caption(f"Current File Size: {selected_mod.current_size} bytes")


def section_baseline_update_workflow():
    """Section H: Explicit baseline update workflow after reviewing detected changes."""
    st.subheader("Baseline Update Workflow (Approve Changes)")

    comp: Optional[ComparisonResult] = st.session_state.last_comparison
    base_mgr: BaselineManager = st.session_state.baseline_manager
    db_mgr: DatabaseManager = st.session_state.db_manager

    if comp is None or not comp.has_anomalies:
        st.caption("Baseline update is only applicable when detected changes need to be approved into a new trusted baseline.")
        return

    st.markdown(
        """
        > **Workflow Notice:** If the detected modifications and additions are legitimate
        > (e.g. following an authorized software update or patch), you can establish a new
        > trusted baseline. The previous baseline will be safely backed up.
        """
    )

    with st.expander("Review & Approve Changes into New Baseline"):
        st.write(f"- Modified files to accept: **{comp.modified_count}**")
        st.write(f"- Added files to incorporate: **{comp.added_count}**")
        st.write(f"- Deleted files to remove: **{comp.deleted_count}**")

        confirm_update = st.checkbox(
            "I have inspected the detected changes, verified they are authorized, and wish to replace the trusted baseline.",
            value=False,
        )

        if st.button("Approve & Save New Baseline", disabled=not confirm_update, type="primary"):
            root_dir = Path(st.session_state.monitored_dir).resolve()
            # Rescan to ensure clean new state
            scanner = DirectoryScanner(
                root_dir=root_dir,
                exclusions=st.session_state.exclusions,
                chunk_size=st.session_state.config.get("chunk_size_bytes", 65536),
                follow_symlinks=st.session_state.config.get("follow_symlinks", False),
                app_dir=st.session_state.app_dir,
            )
            inv = scanner.scan()

            new_files_dict = {
                rel_path: FileBaselineEntry(
                    sha256=rec.sha256,
                    size_bytes=rec.size_bytes,
                    mtime_utc=rec.mtime_utc,
                )
                for rel_path, rec in inv.scanned_files.items()
            }

            new_record = BaselineRecord(
                version=CURRENT_BASELINE_VERSION,
                created_at=datetime.now(timezone.utc).isoformat(),
                root_directory=str(root_dir),
                total_files=len(new_files_dict),
                files=new_files_dict,
            )

            target_path = st.session_state.active_baseline_path or (
                base_mgr.default_dir / BaselineManager.generate_baseline_filename(root_dir)
            )

            try:
                base_mgr.save_baseline_atomic(new_record, target_path, create_backup=True)
                st.session_state.active_baseline = new_record
                st.session_state.active_baseline_path = target_path

                db_mgr.log_event(
                    event_type="BASELINE_UPDATED",
                    file_path=str(target_path.name),
                    details=f"Updated baseline after user approval. New file count: {len(new_files_dict)}",
                )

                st.success("✅ Baseline successfully updated! Previous baseline preserved in backup.")
            except Exception as ex:
                st.error(f"Failed to update baseline: {ex}")


def section_scan_history_and_reports():
    """Section 6 & 7: Persistent scan history, event log, and report export."""
    st.subheader("6. Scan History, Event Log & Reports")

    db_mgr: DatabaseManager = st.session_state.db_manager
    comp: Optional[ComparisonResult] = st.session_state.last_comparison

    # Report Download Section
    if comp:
        st.markdown("#### 📥 Download Current Scan Audit Report")
        r_col1, r_col2 = st.columns(2)
        with r_col1:
            csv_data = ReportGenerator.to_csv(comp)
            st.download_button(
                label="📄 Download Report (CSV format)",
                data=csv_data,
                file_name=f"fims_report_{comp.scan_id}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with r_col2:
            json_data = ReportGenerator.to_json(comp)
            st.download_button(
                label="📦 Download Report (JSON format)",
                data=json_data,
                file_name=f"fims_report_{comp.scan_id}.json",
                mime="application/json",
                use_container_width=True,
            )

    st.markdown("---")

    hist_tab, events_tab = st.tabs(["Scan History", "Granular Security Event Stream"])

    with hist_tab:
        scans = db_mgr.get_recent_scans(limit=25)
        if not scans:
            st.caption("No historical scans stored in database yet.")
        else:
            scan_df = pd.DataFrame(scans)
            st.dataframe(scan_df, use_container_width=True)

    with events_tab:
        events = db_mgr.get_recent_events(limit=50)
        if not events:
            st.caption("No audit events recorded yet.")
        else:
            events_df = pd.DataFrame(events)
            st.dataframe(events_df, use_container_width=True)


def section_application_settings():
    """Section 7: Application Settings."""
    st.subheader("7. Application Settings")

    c1, c2 = st.columns(2)
    with c1:
        chunk_kb = st.number_input(
            "Hash Streaming Chunk Size (KB):",
            min_value=4,
            max_value=1024,
            value=int(st.session_state.config.get("chunk_size_bytes", 65536) / 1024),
            step=16,
            help="Memory buffer size read per hashing chunk. Protects memory when checking large files.",
        )
        st.session_state.config["chunk_size_bytes"] = chunk_kb * 1024

    with c2:
        follow_sym = st.checkbox(
            "Follow Symbolic Links (Strictly restricted to monitored root)",
            value=st.session_state.config.get("follow_symlinks", False),
            help="When disabled, symlinks are never followed, preventing path traversal attacks.",
        )
        st.session_state.config["follow_symlinks"] = follow_sym

    st.markdown("#### Storage Paths")
    st.code(
        f"""
Monitored Root   : {st.session_state.monitored_dir}
Database Path    : {st.session_state.app_dir / "storage" / "fims.db"}
Baselines Folder : {st.session_state.app_dir / "baselines"}
Reports Folder   : {st.session_state.app_dir / "reports"}
Logs Folder      : {st.session_state.app_dir / "logs"}
        """,
        language="text",
    )


def section_help_and_project_info():
    """Section 8: Academic project report information, viva prep, and concepts."""
    st.subheader("8. Help & Academic Cybersecurity Documentation")

    st.markdown(
        """
        ### 🎓 Academic Project Report Reference & Concepts

        #### 1. Project Abstract
        > The **File Integrity Monitoring System (FIMS)** is a host-based cybersecurity tool designed
        > to detect unauthorized alterations to critical files and system directories using the **SHA-256**
        > cryptographic hash function. By establishing an initial trusted baseline of file state and periodically
        > calculating streaming digests, FIMS provides deterministic, auditable detection of file modifications,
        > additions, and deletions. Designed with defense-in-depth principles, FIMS incorporates path-traversal safeguards,
        > atomic baseline transactions, persistent SQLite audit trails, and false-deletion mitigation on partial scan failures.

        #### 2. Key Cybersecurity Concepts Implemented
        - **Cryptographic Hash Functions (SHA-256):** Provides one-way pre-image resistance and strong collision resistance. Any single-bit change in file contents causes a dramatic, unpredictable avalanche effect in the 256-bit digest.
        - **Trusted Baseline Architecture:** The security of FIMS relies on the integrity of the baseline snapshot. Baselines are created only with explicit operator authorization.
        - **Anomaly vs. Cyberattack:** Not all detected changes represent security breaches. Routine software updates, package installations, and application logs alter files legitimately. FIMS reports anomalies without speculative alarmism, providing security analysts with objective ground truth.
        - **Atomic Persistence:** Using temporary staging files and atomic filesystem renames (`os.replace`) prevents baseline corruption in the event of power cuts or unexpected process termination.
        - **Defense Against Traversal & Symlink Attacks:** Relative path normalization and strict rejection of out-of-root symlinks prevent adversaries from tricking FIMS into hashing sensitive system files outside the target directory.

        #### 3. Limitations of Host-Based Integrity Monitoring
        - **Local Baseline Tampering:** If an attacker gains root/administrator privilege on the host, they can tamper with locally stored baselines. In production enterprise environments, baselines must be cryptographically signed or sent to an immutable remote SIEM.
        - **Time-Of-Check to Time-Of-Use (TOCTOU):** Files modifying dynamically during hash calculation are flagged as uncertain to avoid deceptive baselines.
        - **Kernel-Level Evasion:** Rootkits operating in kernel ring 0 can intercept file read syscalls and present clean content to user-space monitors.

        #### 4. Live College Viva / Demonstration Steps
        1. Select a test folder in **Section 2**.
        2. Create an initial trusted baseline in **Section 3**.
        3. Run a scan in **Section 4** & verify all files report `UNCHANGED`.
        4. Edit a test file, add a new file, and delete an existing file outside FIMS.
        5. Re-run scan in **Section 4**; demonstrate `MODIFIED`, `ADDED`, and `DELETED` states in **Section 5**.
        6. Inspect the side-by-side SHA-256 hash avalanche effect.
        7. Download the audit CSV/JSON report and view the event log in **Section 6**.
        8. Demonstrate approving the new baseline in the **Baseline Update Workflow**.
        """
    )


def render_dashboard(app_dir: Path):
    """Main dashboard entry point."""
    st.set_page_config(
        page_title="FIMS - File Integrity Monitoring System",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    init_session_state(app_dir)
    render_header()

    # Sidebar Navigation
    st.sidebar.title("🛡️ FIMS Navigation")
    menu = st.sidebar.radio(
        "Select Module:",
        [
            "Overview",
            "Directory Selection",
            "Baseline Management",
            "Integrity Scanning",
            "Detected Changes",
            "Scan History & Reports",
            "Application Settings",
            "Help & Documentation",
        ],
    )

    st.sidebar.markdown("---")
    st.sidebar.caption("File Integrity Monitoring System v1.0")
    st.sidebar.caption("Academic Cybersecurity Project")

    if menu == "Overview":
        section_overview()
    elif menu == "Directory Selection":
        section_directory_selection()
    elif menu == "Baseline Management":
        section_baseline_management()
    elif menu == "Integrity Scanning":
        section_file_integrity_scanning()
    elif menu == "Detected Changes":
        section_detected_changes()
        st.markdown("---")
        section_baseline_update_workflow()
    elif menu == "Scan History & Reports":
        section_scan_history_and_reports()
    elif menu == "Application Settings":
        section_application_settings()
    elif menu == "Help & Documentation":
        section_help_and_project_info()
