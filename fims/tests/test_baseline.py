"""
Automated unit tests for core.baseline module.
Covers:
- Scenario 4: Creating and loading a valid baseline
- Scenario 11: Handling an invalid or corrupted baseline
- Scenario 15: Preserving previous baseline if an update fails
- Tamper warning verification
- Atomic write behavior
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import patch
import pytest

from core.baseline import (
    BaselineManager,
    BaselineRecord,
    BaselineValidationError,
    FileBaselineEntry,
    CURRENT_BASELINE_VERSION,
    TAMPER_WARNING,
)


def create_sample_baseline_record(root_dir: str = "/var/test") -> BaselineRecord:
    """Helper to produce a valid in-memory BaselineRecord."""
    return BaselineRecord(
        version=CURRENT_BASELINE_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
        root_directory=root_dir,
        total_files=2,
        files={
            "app.py": FileBaselineEntry(
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                size_bytes=1024,
                mtime_utc="2026-10-24T10:00:00Z",
            ),
            "config/settings.json": FileBaselineEntry(
                sha256="dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
                size_bytes=512,
                mtime_utc="2026-10-24T10:05:00Z",
            ),
        },
        tamper_warning=TAMPER_WARNING,
    )


def test_create_and_load_valid_baseline(tmp_path: Path):
    """Scenario 4: Creating and loading a valid baseline."""
    manager = BaselineManager(default_dir=tmp_path / "baselines")
    record = create_sample_baseline_record(str(tmp_path))

    target_file = tmp_path / "baselines" / "test_baseline.json"
    saved_path = manager.save_baseline_atomic(record, target_file)

    assert saved_path.exists()

    # Load and verify
    loaded = manager.load_baseline(saved_path)
    assert loaded.version == CURRENT_BASELINE_VERSION
    assert loaded.root_directory == str(tmp_path)
    assert loaded.total_files == 2
    assert "app.py" in loaded.files
    assert loaded.files["app.py"].size_bytes == 1024
    assert loaded.tamper_warning == TAMPER_WARNING


def test_corrupted_json_baseline(tmp_path: Path):
    """Scenario 11 (Part A): Handling corrupted JSON syntax in baseline."""
    manager = BaselineManager(default_dir=tmp_path)
    corrupted_file = tmp_path / "corrupt.json"
    corrupted_file.write_text("{ this is not valid json! }", encoding="utf-8")

    with pytest.raises(BaselineValidationError) as exc_info:
        manager.load_baseline(corrupted_file)

    assert "invalid json" in str(exc_info.value).lower()


def test_invalid_schema_or_version_baseline(tmp_path: Path):
    """Scenario 11 (Part B): Handling invalid baseline version or missing keys."""
    manager = BaselineManager(default_dir=tmp_path)

    # Wrong version
    invalid_version_file = tmp_path / "wrong_ver.json"
    data = {
        "version": "99.0",  # unsupported
        "created_at": "2026-01-01T00:00:00Z",
        "root_directory": "/test",
        "files": {},
    }
    invalid_version_file.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(BaselineValidationError) as exc_info:
        manager.load_baseline(invalid_version_file)
    assert "version" in str(exc_info.value).lower()

    # Missing required keys
    missing_keys_file = tmp_path / "missing_keys.json"
    missing_keys_file.write_text(json.dumps({"version": CURRENT_BASELINE_VERSION}), encoding="utf-8")

    with pytest.raises(BaselineValidationError) as exc_info:
        manager.load_baseline(missing_keys_file)
    assert "missing" in str(exc_info.value).lower()

    # Invalid SHA-256 (not 64 chars)
    invalid_hash_file = tmp_path / "bad_hash.json"
    bad_data = {
        "version": CURRENT_BASELINE_VERSION,
        "created_at": "2026-01-01T00:00:00Z",
        "root_directory": "/test",
        "files": {
            "file.txt": {
                "sha256": "tooshort",
                "size_bytes": 100,
            }
        },
    }
    invalid_hash_file.write_text(json.dumps(bad_data), encoding="utf-8")

    with pytest.raises(BaselineValidationError) as exc_info:
        manager.load_baseline(invalid_hash_file)
    assert "sha-256" in str(exc_info.value).lower()


def test_preserve_previous_baseline_if_update_fails(tmp_path: Path):
    """Scenario 15: Preserving previous baseline if an update fails."""
    manager = BaselineManager(default_dir=tmp_path)
    baseline_path = tmp_path / "baseline_prod.json"

    # Step 1: Save initial trusted baseline
    original_record = create_sample_baseline_record(str(tmp_path))
    manager.save_baseline_atomic(original_record, baseline_path)

    orig_content = baseline_path.read_text(encoding="utf-8")
    assert "app.py" in orig_content

    # Step 2: Attempt to save an invalid or failing update
    with patch("os.replace", side_effect=OSError("Disk write simulated crash")):
        with pytest.raises(IOError):
            manager.save_baseline_atomic(original_record, baseline_path)

    # Step 3: Verify original file remains intact and uncorrupted
    assert baseline_path.exists()
    assert baseline_path.read_text(encoding="utf-8") == orig_content

    # Step 4: Verify backup was created
    backups = list(tmp_path.glob("baseline_prod.backup_*"))
    assert len(backups) >= 1
    assert backups[0].read_text(encoding="utf-8") == orig_content
