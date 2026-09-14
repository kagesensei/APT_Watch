"""Shared helpers for the ingest/*.py scripts: fetch-with-status-check, a
table row COUNT, and the common "print failures, exit 1" tail every script
in this directory ends with.
"""

import pathlib
import sys

import duckdb
import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Each ingest/*.py script is run directly (`python ingest/attack.py`), which
# puts only this directory on sys.path -- not the project root where
# contracts.py lives. Fixing that here, once, means every script in this
# directory can do a plain `import common` (relying on Python's own
# script-directory default) and transitively get a working `contracts`
# import, without repeating this sys.path fix in each script.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from contracts import not_none, precondition  # noqa: E402  pylint: disable=wrong-import-position

RAW_DIR = ROOT / "data" / "raw"
DB_PATH = ROOT / "data" / "cti.duckdb"

DEFAULT_TIMEOUT_SECONDS = 60


def fetch(url: str, filename: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> pathlib.Path:
    """Download `url` to data/raw/`filename`, raising if the request failed.

    The original scripts wrote the response body to disk unconditionally
    (rule 7: an unchecked return value) -- a failed request (a 404, a rate
    limit, a maintenance page) would silently corrupt the ingested dataset
    with an HTML error page's bytes instead of the expected JSON/CSV.
    raise_for_status() turns that into an immediate, loud failure instead.
    """
    precondition(bool(url), "url must not be empty")
    precondition(bool(filename), "filename must not be empty")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    dest = RAW_DIR / filename
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    dest.write_bytes(response.content)
    return dest


def table_count(con: duckdb.DuckDBPyConnection, table: str) -> int:
    """COUNT(*) for one table -- `table` is always a literal from this
    package's own call sites, never external input.
    """
    precondition(bool(table), "table must not be empty")
    row = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # nosec B608
    return int(not_none(row, f"COUNT query returned no row for table {table!r}")[0])


def print_table_counts(con: duckdb.DuckDBPyConnection, tables: list[str]) -> None:
    """Print COUNT(*) for each just-ingested table, as a quick sanity read."""
    for table in tables:
        print(table, table_count(con, table))


def fail_if_any(failures: list[str]) -> None:
    """Print and exit(1) if any data-quality check named in `failures` failed."""
    if failures:
        print(f"DATA QUALITY CHECK FAILED: {', '.join(failures)}", file=sys.stderr)
        sys.exit(1)
