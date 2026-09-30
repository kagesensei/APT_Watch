"""Show the last attempted and successful refresh for each source."""

import duckdb

import common


def main() -> None:
    """Print per-source freshness without modifying the threat database."""
    if not common.DB_PATH.exists():
        print("Threat database not found. Run the initial refresh first.")
        return
    with duckdb.connect(str(common.DB_PATH), read_only=True) as db:
        exists = db.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_name = 'source_status'"
        ).fetchone()
        if not exists or not exists[0]:
            print("No refresh history yet. Run `python ingest/update.py --profile all`.")
            return
        rows = db.execute(
            "SELECT source_id, last_status, last_attempt_at, last_success_at, last_error "
            "FROM source_status ORDER BY source_id"
        ).fetchall()
    print("source_id | status | last attempt (UTC) | last success (UTC) | error")
    for row in rows:
        print(" | ".join(str(value or "") for value in row))


if __name__ == "__main__":
    main()
