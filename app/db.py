import pathlib

import duckdb
from flask import current_app, g

DB_PATH = pathlib.Path(__file__).resolve().parents[1] / "data" / "cti.duckdb"


def get_db():
    if "db" not in g:
        if not DB_PATH.exists():
            raise FileNotFoundError(
                f"{DB_PATH} not found. Run `python ingest/attack.py` first."
            )
        g.db = duckdb.connect(str(DB_PATH), read_only=True)
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app):
    app.teardown_appcontext(close_db)
