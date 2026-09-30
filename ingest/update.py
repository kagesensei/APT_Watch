"""Refresh catalogued local sources and retain per-source run/freshness status.

Run `python ingest/update.py --profile all` once to build all current datasets.
Schedule `daily` and `weekly` profiles externally after the first full ingest.
"""

import argparse
import datetime
import json
import subprocess  # nosec B404
import sys
import uuid
from typing import Any

import common
import duckdb

from contracts import precondition

CATALOG_PATH = common.ROOT / "data" / "seed" / "source_catalog.json"
PROFILES = {
    "daily": ("daily",),
    "weekly": ("weekly",),
    "all": ("daily", "weekly"),
}
RUN_DDL = (
    "CREATE TABLE IF NOT EXISTS source_run (run_id VARCHAR, source_id VARCHAR, "
    "started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, status VARCHAR, "
    "exit_code INTEGER, error VARCHAR)"
)
STATUS_DDL = (
    "CREATE TABLE IF NOT EXISTS source_status (source_id VARCHAR PRIMARY KEY, "
    "last_attempt_at TIMESTAMPTZ, last_success_at TIMESTAMPTZ, "
    "last_status VARCHAR, last_error VARCHAR)"
)


def _utc_now() -> datetime.datetime:
    """Return an aware UTC timestamp for source freshness records."""
    return datetime.datetime.now(datetime.timezone.utc)


def _catalog() -> list[dict[str, Any]]:
    """Read the versioned source catalogue."""
    content: object = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(content, dict):
        raise ValueError("catalogue must be a JSON object")
    sources = content.get("sources")
    if not isinstance(sources, list):
        raise ValueError("catalogue sources must be a JSON array")
    valid_sources: list[dict[str, Any]] = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("each catalogue source must be an object")
        if not isinstance(source.get("id"), str):
            raise ValueError("each source must have a string ID")
        valid_sources.append(source)
    return valid_sources


def _select_sources(profile: str, requested: list[str] | None) -> list[dict[str, Any]]:
    """Select runnable sources from a profile or explicit source IDs."""
    sources = [source for source in _catalog() if source.get("ingest_command")]
    if requested:
        selected = [source for source in sources if source["id"] in requested]
        precondition(
            len(selected) == len(set(requested)), "unknown or non-runnable source ID"
        )
        return selected
    cadences = PROFILES[profile]
    return [source for source in sources if source.get("recommended_profile") in cadences]


def _record(
    run_id: str, source_ids: list[str], started: datetime.datetime,
    finished: datetime.datetime, status: str, exit_code: int | None, error: str | None,
) -> None:
    """Persist source run history and latest attempt without losing last success."""
    with duckdb.connect(str(common.DB_PATH)) as db:
        db.execute(RUN_DDL)
        db.execute(STATUS_DDL)
        for source_id in source_ids:
            db.execute(
                "INSERT INTO source_run VALUES (?, ?, ?, ?, ?, ?, ?)",
                [run_id, source_id, started, finished, status, exit_code, error],
            )
            successful = finished if status == "success" else None
            db.execute(
                "INSERT INTO source_status VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (source_id) DO UPDATE SET "
                "last_attempt_at = excluded.last_attempt_at, "
                "last_success_at = COALESCE(excluded.last_success_at, "
                "source_status.last_success_at), "
                "last_status = excluded.last_status, last_error = excluded.last_error",
                [source_id, finished, successful, status, error],
            )


def _execute(command: str) -> tuple[int | None, str | None]:
    """Run one fixed catalogued ingest command; return its result or timeout."""
    precondition(bool(command), "command must not be empty")
    try:
        result = subprocess.run(  # nosec B603 - argv comes only from the reviewed source catalog
            [sys.executable, str(common.ROOT / command)],
            cwd=common.ROOT, timeout=1800, check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "ingest command timed out after 1800 seconds"
    return result.returncode, None


def _run_group(sources: list[dict[str, Any]]) -> bool:
    """Run one command and associate its result with all sources it refreshes."""
    command = sources[0]["ingest_command"]
    source_ids = [source["id"] for source in sources]
    run_id = str(uuid.uuid4())
    started = _utc_now()
    code, error = _execute(command)
    finished = _utc_now()
    status = "success" if code == 0 else "failed"
    if error is None and code != 0:
        error = f"command exited with status {code}"
    _record(run_id, source_ids, started, finished, status, code, error)
    print(f"SOURCE [{status}] {', '.join(source_ids)} ({command})", flush=True)
    return status == "success"


def _groups(sources: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group shared ingest commands so bundled IOC feeds run once."""
    commands: dict[str, dict[str, Any]] = {}
    for source in sources:
        commands.setdefault(source["ingest_command"], source)
    catalog = _catalog()
    return [
        [source for source in catalog if source.get("ingest_command") == command]
        for command in commands
    ]


def _add_crosswalk(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Include actor crosswalk refresh whenever either parent was updated."""
    parent_commands = {source["ingest_command"] for source in sources}
    if not parent_commands.intersection({"ingest/attack.py", "ingest/misp_galaxy.py"}):
        return sources
    crosswalk = [source for source in _catalog() if source["id"] == "attack_misp_crosswalk"]
    return sources + crosswalk


def _arguments() -> argparse.Namespace:
    """Parse refresh profile or explicit source selections."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="daily")
    parser.add_argument("--source", nargs="+", help="catalogued source IDs to refresh")
    return parser.parse_args()


def main() -> None:
    """Refresh selected sources, continue after individual failures, and report status."""
    args = _arguments()
    sources = _add_crosswalk(_select_sources(args.profile, args.source))
    if not sources:
        raise ValueError("No runnable sources selected")
    failed: list[str] = []
    for group in _groups(sources):
        if not _run_group(group):
            failed.extend(source["id"] for source in group)
    if failed:
        print(f"Refresh finished with failures: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)
    print(f"Refresh completed for {len(sources)} source records.", flush=True)


if __name__ == "__main__":
    main()
