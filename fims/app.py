"""
File Integrity Monitoring System (FIMS) - Main Application Entrypoint.

Usage:
    streamlit run app.py
    (or: python app.py)
"""

import logging
from pathlib import Path
import sys

# Ensure project root is in sys.path
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

# Setup Application Logging
LOG_DIR = APP_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "fims.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("fims.main")


def main():
    """Launch Streamlit dashboard."""
    try:
        import streamlit as st
        from ui.dashboard import render_dashboard
    except ImportError as e:
        logger.error("Missing dependency: %s. Run 'pip install -r requirements.txt'", e)
        print(f"\n[ERROR] Missing required library: {e}")
        print("Please install dependencies: pip install -r requirements.txt\n")
        sys.exit(1)

    # Check if run directly via `python app.py` instead of `streamlit run app.py`
    # When run under streamlit, streamlit's runtime is active
    import streamlit.runtime as st_runtime

    if not st_runtime.exists():
        # User executed `python app.py` directly; launch streamlit CLI automatically!
        from streamlit.web import cli as stcli
        sys.argv = ["streamlit", "run", str(Path(__file__).resolve())]
        sys.exit(stcli.main())
    else:
        render_dashboard(APP_DIR)


if __name__ == "__main__":
    main()
