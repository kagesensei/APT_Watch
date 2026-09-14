"""Quality gate: pylint, mypy, bandit, and the pytest suite must all pass.

Power of 10 rule 10 asks for static analysis with zero warnings. This
script is the one place that runs all four checks together; it's invoked
from three places, each with a different opt-in policy it doesn't control:
- The pre-commit hook (.pre-commit-config.yaml) runs it on every commit
  (bypass that the normal pre-commit way, `git commit --no-verify`, if you
  need to commit deliberately-red work in progress).
- CI (.github/workflows/ci.yml) runs the same four checks unconditionally
  on every push, as separate steps rather than via this script, so a
  failure names the specific tool in the GitHub UI.
- `python main.py` runs it only if APTWATCH_RUN_PREFLIGHT=1 is set (off by
  default -- see main.py), for an optional local sanity check before
  starting the dev server.

This module itself has no skip flag: gating whether it runs at all is each
caller's job, not this script's.
"""

import pathlib

# Every command run through this module is a hardcoded literal list below
# (CHECKS), never built from user or request data -- a fixed, closed set of
# dev-tool invocations, not an injection surface.
import subprocess  # nosec B404
import sys

from contracts import precondition

ROOT = pathlib.Path(__file__).resolve().parent
TIMEOUT_SECONDS = 300

# Every command here is a hardcoded literal list -- never built from user or
# request data -- so subprocess.run() below is a fixed, closed set of
# dev-tool invocations, not an injection surface.
CHECKS: list[tuple[str, list[str]]] = [
    (
        "pylint",
        [
            sys.executable, "-m", "pylint",
            "app", "ingest", "resolve", "contracts.py", "main.py", "preflight.py",
        ],
    ),
    ("mypy", [sys.executable, "-m", "mypy", "."]),
    (
        "bandit",
        [
            sys.executable, "-m", "bandit", "-c", "pyproject.toml", "-r",
            "app", "ingest", "resolve", "contracts.py", "main.py", "preflight.py",
        ],
    ),
    ("pytest", [sys.executable, "-m", "pytest", "-q"]),
]


def run_check(name: str, command: list[str]) -> bool:
    """Run one quality-gate command, streaming its output; return whether it passed."""
    precondition(bool(name), "name must not be empty")
    precondition(bool(command), "command must not be empty")
    print(f"--- preflight: {name} ---", flush=True)
    try:
        # command always comes from this module's own CHECKS list (see its
        # comment above) -- fixed argv, no shell.
        result = subprocess.run(  # nosec B603
            command, cwd=ROOT, timeout=TIMEOUT_SECONDS, check=False
        )
    except FileNotFoundError:
        print(
            f"preflight: {name} is not installed -- "
            "run `pip install -r requirements-dev.txt`.",
            file=sys.stderr,
        )
        return False
    except subprocess.TimeoutExpired:
        print(f"preflight: {name} did not finish within {TIMEOUT_SECONDS}s.", file=sys.stderr)
        return False
    return result.returncode == 0


def run_preflight() -> None:
    """Run every quality-gate check; exit(1) if any fails."""
    print("Running pre-flight quality gate (pylint, mypy, bandit, pytest)...", flush=True)
    failed = [name for name, command in CHECKS if not run_check(name, command)]

    if failed:
        print(
            f"\nPre-flight FAILED: {', '.join(failed)}. Fix the issue(s) above and try again.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Pre-flight checks passed -- app is SOLID.\n", flush=True)


if __name__ == "__main__":
    run_preflight()
