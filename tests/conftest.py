import pathlib

import duckdb
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "cti.duckdb"


@pytest.fixture(scope="session")
def db():
    """Read-only connection to the real, committed cti.duckdb snapshot.

    These are integration tests against real ingested data rather than a
    synthetic fixture DB, so assertions key off values queried from the
    database itself (see tests/test_intel.py) rather than hard-coded
    knowledge of dataset contents that could drift on re-ingest.
    """
    if not DB_PATH.exists():
        pytest.skip("data/cti.duckdb not found - run the ingest scripts first")
    con = duckdb.connect(str(DB_PATH), read_only=True)
    yield con
    con.close()


@pytest.fixture()
def cache_db(tmp_path):
    """A throwaway, writable NVD-cache DB, matching app/cache.py's schema."""
    con = duckdb.connect(str(tmp_path / "nvd_cache_test.duckdb"))
    con.execute(
        "CREATE TABLE cve_cache("
        "cve_id VARCHAR PRIMARY KEY, description VARCHAR, cvss_score DOUBLE, "
        "cvss_severity VARCHAR, cwe_ids VARCHAR, fetched_at TIMESTAMP)"
    )
    yield con
    con.close()


@pytest.fixture()
def app(monkeypatch, tmp_path):
    """A real Flask app instance (create_app()), backed by the real read-only
    cti.duckdb and a temp NVD cache/chats dir so tests never write into the
    project's real data/ directory.
    """
    if not DB_PATH.exists():
        pytest.skip("data/cti.duckdb not found - run the ingest scripts first")

    monkeypatch.setenv("APTWATCH_SECRET_KEY", "test-secret-key")
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)

    from app import cache as cache_module
    from app import chats_store

    monkeypatch.setattr(cache_module, "CACHE_PATH", tmp_path / "nvd_cache_test.duckdb")
    monkeypatch.setattr(chats_store, "CHATS_DIR", tmp_path / "chats")

    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True)
    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()
