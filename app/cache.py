import pathlib

import duckdb
from flask import g

# Kept separate from data/cti.duckdb (which the app opens read-only) because
# this table is written to at request time on every fresh NVD lookup.
CACHE_PATH = pathlib.Path(__file__).resolve().parents[1] / "data" / "nvd_cache.duckdb"


def get_cache_db():
    if "cache_db" not in g:
        g.cache_db = duckdb.connect(str(CACHE_PATH))
        g.cache_db.execute(
            "CREATE TABLE IF NOT EXISTS cve_cache("
            "cve_id VARCHAR PRIMARY KEY, description VARCHAR, cvss_score DOUBLE, "
            "cvss_severity VARCHAR, cwe_ids VARCHAR, fetched_at TIMESTAMP)"
        )
    return g.cache_db


def close_cache_db(exception=None):
    db = g.pop("cache_db", None)
    if db is not None:
        db.close()


def init_app(app):
    app.teardown_appcontext(close_cache_db)
