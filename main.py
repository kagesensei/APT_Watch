"""Dev server entry point: `python main.py`."""

import os

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402  pylint: disable=wrong-import-position
from preflight import run_preflight  # noqa: E402  pylint: disable=wrong-import-position

app = create_app()

if __name__ == "__main__":
    run_preflight()

    # Never default to debug=True: the Werkzeug debugger it enables allows
    # arbitrary code execution from any browser that can reach this process.
    # Opt in explicitly, and only for local development.
    _debug = os.environ.get("APTWATCH_DEBUG", "").strip().lower() in ("1", "true", "yes")
    app.run(debug=_debug)
