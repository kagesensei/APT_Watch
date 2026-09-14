"""Request-scoped, read-only connection to the ingested threat-intel DB."""

import pathlib

import duckdb
from flask import Flask, g

from contracts import postcondition

DB_PATH = pathlib.Path(__file__).resolve().parents[1] / "data" / "cti.duckdb"


def get_db() -> duckdb.DuckDBPyConnection:
    """Return this request's connection, opening one on first use.

    Flask's `g` is itself the smallest-scope container for this state (rule
    6): the connection lives no longer than the request that needed it.
    """
    if "db" not in g:
        if not DB_PATH.exists():
            raise FileNotFoundError(
                f"{DB_PATH} not found. Run `python ingest/attack.py` first."
            )
        g.db = duckdb.connect(str(DB_PATH), read_only=True)
    connection: duckdb.DuckDBPyConnection = g.db
    postcondition(connection is not None, "db connection must be set after lazy init")
    return connection


def close_db(_exception: BaseException | None = None) -> None:
    """Teardown hook: close this request's connection, if one was opened."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app: Flask) -> None:
    """Register the connection teardown hook on the Flask app."""
    app.teardown_appcontext(close_db)
