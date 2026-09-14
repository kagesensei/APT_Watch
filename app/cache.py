"""Request-scoped, writable cache for on-demand NVD lookups.

Kept separate from data/cti.duckdb (which the app opens read-only) because
this table is written to at request time on every fresh NVD lookup.
"""

import pathlib

import duckdb
from flask import Flask, g

CACHE_PATH = pathlib.Path(__file__).resolve().parents[1] / "data" / "nvd_cache.duckdb"


def get_cache_db() -> duckdb.DuckDBPyConnection:
    """Return this request's cache connection, creating the table on first use."""
    if "cache_db" not in g:
        g.cache_db = duckdb.connect(str(CACHE_PATH))
        g.cache_db.execute(
            "CREATE TABLE IF NOT EXISTS cve_cache("
            "cve_id VARCHAR PRIMARY KEY, description VARCHAR, cvss_score DOUBLE, "
            "cvss_severity VARCHAR, cwe_ids VARCHAR, fetched_at TIMESTAMP)"
        )
    connection: duckdb.DuckDBPyConnection = g.cache_db
    return connection


def close_cache_db(_exception: BaseException | None = None) -> None:
    """Teardown hook: close this request's cache connection, if one was opened."""
    db = g.pop("cache_db", None)
    if db is not None:
        db.close()


def init_app(app: Flask) -> None:
    """Register the cache connection teardown hook on the Flask app."""
    app.teardown_appcontext(close_cache_db)
