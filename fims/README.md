# 🛡️ File Integrity Monitoring System (FIMS)

A lightweight, robust, browser-accessible **File Integrity Monitoring System (FIMS)** built in Python with a Streamlit interface. FIMS provides deterministic change detection for critical directories and files using the **SHA-256** cryptographic hash algorithm, persistent SQLite audit trails, and atomic baseline management.

Designed for college cybersecurity projects, lab demonstrations, security audits, and security engineering education.

---

## 1. Project Abstract & Academic Summary

> **Abstract:**  
> In modern computer systems and critical infrastructure, unauthorized file alterations—whether introduced by rootkits, ransomware, insider threats, or misconfigured administrative scripts—represent severe security risks. The **File Integrity Monitoring System (FIMS)** provides a host-based solution that establishes an initial trusted cryptographic baseline of target directories and periodically computes streaming **SHA-256** digests to identify file alterations. FIMS classifies detected changes into **Unchanged**, **Modified**, **Added**, **Deleted**, and **Scan Error** categories without assuming every change is malicious. Featuring path traversal protection, symlink traversal controls, atomic JSON transactions, persistent SQLite logging, and CSV/JSON audit report exports, FIMS offers a practical demonstration of host-based intrusion detection principles.

### Key Details for Academic Reports
- **Domain:** Cybersecurity, Host-Based Intrusion Detection Systems (HIDS), Cryptographic Verification
- **Primary Algorithm:** Secure Hash Algorithm 256-bit (SHA-256)
- **Programming Language:** Python 3.11+
- **User Interface:** Streamlit (Dark Cybersecurity Dashboard)
- **Database Engine:** SQLite (Embedded ACID Relational Persistence)
- **Testing Framework:** Pytest (15 automated unit and integration test suites)

---

## 2. Problem Statement & Objectives

### Problem Statement
Operating systems and application directories constantly undergo modifications. Detecting unauthorized modifications requires verifying file contents at scale without consuming excessive memory or risking race conditions. Traditional file metadata (such as timestamps and file sizes) can easily be manipulated or forged by attackers using techniques like *timestomping*. Cryptographic file hashing is the industry standard for integrity verification, but practical implementations must address memory bounds, concurrent modifications, symbolic link escapes, and accidental false alarms during partial scan failures.

### Objectives
1. **Cryptographic Integrity:** Calculate streaming SHA-256 hashes in fixed chunks (64 KB) to support arbitrary file sizes without memory exhaustion.
2. **Deterministic Baseline Management:** Create, validate, atomically save, and back up trusted baselines in JSON format.
3. **Robust Change Classification:** Accurately classify files as Unchanged, Modified, Added, or Deleted.
4. **False Deletion Safeguard:** Guard against reporting missing files as "Deleted" when directory traversal fails due to permission errors.
5. **Persistent Audit History:** Record all scans and granular security events (modifications, additions, deletions, errors) in an embedded SQLite database.
6. **Reporting:** Generate exportable audit reports in CSV and JSON formats.
7. **Educational Value:** Provide clear explanations, visual indicators, and a live demonstration workflow for college evaluations.

---

## 3. System Architecture & Component Diagram

```
+-------------------------------------------------------------+
|                      Streamlit UI                           |
|  (Overview, Directory Selection, Baselines, Scans, Reports) |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                     Core FIMS Engine                        |
|                                                             |
|  +-----------------+  +-----------------+  +--------------+ |
|  |  Directory      |  |  SHA-256        |  |  Integrity   | |
|  |  Scanner        |->|  Hasher         |->|  Comparator  | |
|  +-----------------+  +-----------------+  +--------------+ |
|          |                                         |        |
|          v                                         v        |
|  +-----------------+                       +--------------+ |
|  |  Baseline       |                       |  Report      | |
|  |  Manager        |                       |  Generator   | |
|  +-----------------+                       +--------------+ |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                   Storage & Persistence                     |
|    - SQLite Database (storage/fims.db)                      |
|    - Atomic Baselines (baselines/*.json)                    |
|    - Audit Reports (reports/*.csv, reports/*.json)          |
|    - Application Logs (logs/fims.log)                       |
+-------------------------------------------------------------+
```

### Module Descriptions
- **`app.py`**: Entrypoint script configuring logging and launching the Streamlit server.
- **`core/hasher.py`**: Chunk-based SHA-256 calculation with concurrent modification detection.
- **`core/scanner.py`**: Recursive file discovery, exclusion filtering, path normalization, and symlink protection.
- **`core/baseline.py`**: Creation, atomic saving, schema validation, and timestamped backups of trusted baselines.
- **`core/comparator.py`**: State comparison engine classifying files with false-positive deletion safeguards.
- **`core/reporter.py`**: Generates RFC 4180 CSV and structured JSON audit reports.
- **`storage/database.py`**: SQLite database layer managing scans, events, and audit logs.
- **`ui/dashboard.py`**: Full-featured dark-themed Streamlit UI.
- **`tests/`**: Pytest test suite implementing 15 verification scenarios.

---

## 4. Cybersecurity Concepts Implemented

1. **Cryptographic Hash Functions (SHA-256):**  
   Produces a fixed 256-bit (64-character hexadecimal) digest. It is mathematically infeasible to find two different files with the same hash (collision resistance) or reverse a hash to reveal the original contents (pre-image resistance).
2. **The Avalanche Effect:**  
   Changing even a single byte or punctuation mark in a file causes more than 50% of the bits in the SHA-256 hash to change completely.
3. **Defense Against False Positives (Anomaly vs. Attack):**  
   File modifications are not automatically malicious. Legitimate patches, log rotations, and system updates alter files regularly. FIMS presents objective integrity metrics so security analysts can make informed determinations.
4. **Atomic Transactions:**  
   Baselines are written to temporary files and atomically renamed using operating system primitives (`os.replace`). This prevents baseline file corruption if power is interrupted or the process terminates abruptly.
5. **Path Traversal & Symlink Safety:**  
   Monitored paths are normalized to POSIX relative strings. Traversal of symlinks pointing outside the monitored root is strictly blocked to prevent unauthorized data collection.

---

## 5. Scope & Security Limitations

- **Local Baseline Tampering:**  
  FIMS stores baselines in the local filesystem. An attacker with administrative/root privileges on the host could alter both monitored files and the baseline. In enterprise environments, baselines must be cryptographically signed or shipped to a write-once (WORM) storage or remote SIEM.
- **Time-Of-Check to Time-Of-Use (TOCTOU):**  
  If a file changes while FIMS is actively reading it, FIMS detects the size/mtime change and marks the result as `uncertain` rather than claiming the file is clean.
- **Kernel-Level Rootkits:**  
  A rootkit operating in OS kernel ring 0 can intercept file read system calls and return clean bytes to user-space applications like FIMS. FIMS is designed as an application-level / host-based integrity monitor.

---

## 6. Installation & Setup

### Prerequisites
- Python 3.11 or later
- pip package manager
- Supported OS: Windows 10/11, macOS, Linux (Ubuntu, Debian, Fedora, Arch)

### 1. Clone or Navigate to Project Directory
```bash
cd fims
```

### 2. Create and Activate Virtual Environment
**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**On Linux / macOS (Bash):**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 7. How to Run the Application

Start the Streamlit dashboard:
```bash
streamlit run app.py
```
*(Alternatively, you can run `python app.py` directly; it will launch the Streamlit engine automatically).*

Open your browser to:
```
http://localhost:8501
```

---

## 8. Live Demonstration Guide (College Project / Viva)

Follow these steps to demonstrate all system capabilities during an evaluation:

### Step 1: Select or Create a Monitored Folder
1. In the sidebar, select **Directory Selection**.
2. Keep the default `demo_monitored_folder` or enter the path to any test folder.
3. Click **Validate & Set Target Directory**.

### Step 2: Create Test Files
Create 3 test files in your test directory:
- `file1.txt` -> containing text `Alpha Version 1.0`
- `file2.txt` -> containing text `Database Configuration`
- `subfolder/file3.txt` -> containing text `Nested Module Code`

### Step 3: Create the Trusted Baseline
1. In the sidebar, select **Baseline Management**.
2. Check the confirmation box acknowledging file authenticity.
3. Click **Generate Trusted Baseline**.
4. Notice the baseline is atomically created in `baselines/` and logged in the event history.

### Step 4: Perform Baseline Verification Scan
1. In the sidebar, select **Integrity Scanning**.
2. Click **🚀 Start File Integrity Scan**.
3. Go to **Overview** or **Detected Changes**: Notice all 3 files report status `UNCHANGED`.

### Step 5: Simulate Attacks / Changes Outside FIMS
In your file explorer or terminal:
1. **Modify:** Open `file1.txt` and change text to `Alpha Version 2.0 (Tampered)`.
2. **Add:** Create a new file `backdoor.sh` with text `rm -rf /`.
3. **Delete:** Delete `file2.txt`.

### Step 6: Scan and Observe Detected Changes
1. Go back to **Integrity Scanning** and click **🚀 Start File Integrity Scan**.
2. Go to **Detected Changes**:
   - `file1.txt` is highlighted as **MODIFIED**. Expand the hash inspector to see the SHA-256 avalanche effect.
   - `backdoor.sh` is highlighted as **ADDED**.
   - `file2.txt` is highlighted as **DELETED**.
   - `subfolder/file3.txt` remains **UNCHANGED**.

### Step 7: Export Audit Reports
1. Go to **Scan History & Reports**.
2. Click **📄 Download Report (CSV format)** and **📦 Download Report (JSON format)**.
3. Review the downloaded reports.

### Step 8: Baseline Update Workflow
1. Go to **Detected Changes** -> scroll down to **Baseline Update Workflow**.
2. Review the summary of changes.
3. Check the confirmation box and click **Approve & Save New Baseline**.
4. Re-run scan: All files now report `UNCHANGED` against the newly approved baseline.

---

## 9. Automated Testing with Pytest

Run the comprehensive test suite verifying all 15 required scenarios:

```bash
pytest -v
```

### Covered Test Scenarios:
1. **Hashing a known file** (`test_hashing_known_file`): Verifies against standard SHA-256 test vectors.
2. **Identical content produces identical hash** (`test_identical_content_produces_same_hash`).
3. **Modified content produces different hash** (`test_modified_content_produces_different_hash`).
4. **Creating and loading a valid baseline** (`test_create_and_load_valid_baseline`).
5. **Detecting an unchanged file** (`test_detect_unchanged_file`).
6. **Detecting a modified file** (`test_detect_modified_file`).
7. **Detecting an added file** (`test_detect_added_file`).
8. **Detecting a deleted file** (`test_detect_deleted_file`).
9. **Handling an empty directory** (`test_empty_directory_handling`).
10. **Handling unreadable files and simulated I/O errors** (`test_unreadable_file_or_io_error`).
11. **Handling invalid or corrupted baselines** (`test_corrupted_json_baseline`, `test_invalid_schema_or_version_baseline`).
12. **Preventing false deletions on incomplete scans** (`test_prevent_false_deletions_on_incomplete_scan`).
13. **Handling nested directories and relative paths** (`test_nested_directories_and_relative_paths`).
14. **Handling symbolic links safely** (`test_symbolic_link_handling_safeguards`).
15. **Preserving previous baseline if update fails** (`test_preserve_previous_baseline_if_update_fails`).

---

## 10. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `PermissionError` when scanning | Operating system file lock or elevated folder | Ensure your user account has read permissions for the target folder. Avoid scanning Windows `System32` or Linux `/root` without privileges. |
| Streamlit browser doesn't open | Firewall or headless environment | Open browser manually and navigate to `http://localhost:8501`. |
| Baseline shows `Invalid JSON` | Baseline file was edited manually or truncated | Use the backup created in `baselines/` or generate a new baseline. |
| Files changing during hash | Dynamic log files or database WAL files being written to | Exclude volatile files using the Exclusions filter (e.g. `*.log`, `*.tmp`). |

---

## 11. Future Enhancements
- Integration with remote syslog / SIEM (Splunk, Elastic SIEM).
- HMAC-SHA256 signing of baseline files with a hardware security module (HSM) or secret key.
- Real-time filesystem event monitoring via OS notification APIs (`ReadDirectoryChangesW` on Windows, `inotify` on Linux).
- Automated email / Slack webhook alerts on detected anomalies.
