"""Dev server entry point: `python main.py`."""

import os

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402  pylint: disable=wrong-import-position
from preflight import run_preflight  # noqa: E402  pylint: disable=wrong-import-position

app = create_app()

if __name__ == "__main__":
    # Off by default: the pylint/mypy/bandit/pytest gate adds several seconds
    # to every startup and needs requirements-dev.txt installed. It still
    # runs unconditionally in CI (.github/workflows/ci.yml) and via the
    # pre-commit hook (.pre-commit-config.yaml) -- this is just not also
    # gating the dev server on every run. Opt in for a local sanity check.
    if os.environ.get("APTWATCH_RUN_PREFLIGHT", "").strip().lower() in ("1", "true", "yes"):
        run_preflight()

    # Never default to debug=True: the Werkzeug debugger it enables allows
    # arbitrary code execution from any browser that can reach this process.
    # Opt in explicitly, and only for local development.
    _debug = os.environ.get("APTWATCH_DEBUG", "").strip().lower() in ("1", "true", "yes")
    app.run(debug=_debug)
