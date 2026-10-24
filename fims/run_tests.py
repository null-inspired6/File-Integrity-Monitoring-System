"""
Unified Test Runner for File Integrity Monitoring System (FIMS).
Executes pytest if available, or falls back to an internal test runner
that provides tmp_path fixtures for Python standard library execution.
"""

import inspect
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_with_pytest() -> int:
    """Run tests using pytest if installed."""
    try:
        import pytest
        print("\n=================== Running Tests with pytest ===================")
        return pytest.main(["-v", str(PROJECT_ROOT / "tests")])
    except ImportError:
        return None


def run_builtin() -> int:
    """Run tests using standard library reflection with tmp_path fixture emulation."""
    print("\n=================== Running Tests with Standalone Runner ===================")

    import tests.test_hasher as th
    import tests.test_baseline as tb
    import tests.test_scanner as ts
    import tests.test_comparator as tc

    modules = [
        ("core.hasher", th),
        ("core.baseline", tb),
        ("core.scanner", ts),
        ("core.comparator", tc),
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = 0

    for mod_name, mod in modules:
        print(f"\nSuite: {mod_name}")
        for attr_name in dir(mod):
            if attr_name.startswith("test_"):
                func = getattr(mod, attr_name)
                if callable(func):
                    total_tests += 1
                    sig = inspect.signature(func)
                    temp_dir = None
                    try:
                        if "tmp_path" in sig.parameters:
                            temp_dir = tempfile.mkdtemp(prefix="fims_test_")
                            func(Path(temp_dir))
                        else:
                            func()
                        print(f"  [PASS] {attr_name}")
                        passed_tests += 1
                    except Exception as e:
                        # Check for pytest.skip
                        if "Skipped" in type(e).__name__:
                            print(f"  [SKIP] {attr_name} (skipped: {e})")
                            passed_tests += 1
                        else:
                            print(f"  [FAIL] {attr_name}: {e}")
                            traceback.print_exc()
                            failed_tests += 1
                    finally:
                        if temp_dir and Path(temp_dir).exists():
                            try:
                                shutil.rmtree(temp_dir, ignore_errors=True)
                            except OSError:
                                pass

    print("\n" + "=" * 60)
    print(f"Total: {total_tests} | Passed: {passed_tests} | Failed: {failed_tests}")
    print("=" * 60)

    return 0 if failed_tests == 0 else 1


def main():
    pytest_res = run_with_pytest()
    if pytest_res is not None:
        sys.exit(pytest_res)
    else:
        sys.exit(run_builtin())


if __name__ == "__main__":
    main()
