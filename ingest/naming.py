"""Load curated vendor threat-actor naming-convention data into
data/cti.duckdb.

Unlike the other ingest/*.py scripts, this one has no network source: the
mapping from a vendor's naming-scheme word (e.g. "Panda", "Bear") to what it
denotes, and the handful of documented alias etymology notes (e.g. why
"Comment Crew"), is hand-curated reference knowledge, not something any
feed publishes. It's kept in data/seed/*.json (version-controlled, reviewed
like code) rather than hardcoded here, so it can be extended without
touching this script.
"""

import json
import pathlib
from typing import TypedDict

import common
import duckdb

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEED_DIR = ROOT / "data" / "seed"


class NamingConventionEntry(TypedDict):
    """One vendor naming-scheme word and what it denotes."""

    vendor: str
    term: str
    category: str
    meaning: str


class AliasNoteEntry(TypedDict):
    """One actor alias's documented etymology."""

    attack_id: str
    alias: str
    note: str


def load_json_seed(filename: str) -> list[dict[str, object]]:
    """Read one data/seed/*.json file."""
    path = SEED_DIR / filename
    data: list[dict[str, object]] = json.loads(path.read_text(encoding="utf-8"))
    return data


def naming_convention_rows(entries: list[NamingConventionEntry]) -> list[tuple[str, str, str, str]]:
    """One row per naming-convention entry, matching the table's column order."""
    return [(e["vendor"], e["term"], e["category"], e["meaning"]) for e in entries]


def alias_note_rows(entries: list[AliasNoteEntry]) -> list[tuple[str, str, str]]:
    """One row per alias-note entry, matching the table's column order."""
    return [(e["attack_id"], e["alias"], e["note"]) for e in entries]


def write_tables(
    con: duckdb.DuckDBPyConnection,
    naming_rows: list[tuple[str, str, str, str]],
    note_rows: list[tuple[str, str, str]],
) -> None:
    """Create (or replace) and populate the naming_convention and
    actor_alias_note tables.
    """
    con.execute(
        "CREATE OR REPLACE TABLE naming_convention("
        "vendor VARCHAR, term VARCHAR, category VARCHAR, meaning VARCHAR)"
    )
    con.executemany("INSERT INTO naming_convention VALUES (?,?,?,?)", naming_rows)

    con.execute(
        "CREATE OR REPLACE TABLE actor_alias_note("
        "attack_id VARCHAR, alias VARCHAR, note VARCHAR)"
    )
    con.executemany("INSERT INTO actor_alias_note VALUES (?,?,?)", note_rows)


def check_load_count(con: duckdb.DuckDBPyConnection, table: str, expected: int) -> str | None:
    """Every seed row must have loaded -- a mismatch means an insert bug, not
    a data-quality question about an external source. Returns a failure
    name, or None.
    """
    actual = common.table_count(con, table)
    status = "PASS" if actual == expected else "FAIL"
    print(f"DQ [{status}] {table}: {actual} loaded vs {expected} rows in seed file")
    return None if status == "PASS" else table


def main() -> None:
    """Load the curated naming-convention and alias-note seed data."""
    naming_entries = load_json_seed("naming_conventions.json")
    note_entries = load_json_seed("actor_alias_notes.json")

    naming_rows = naming_convention_rows(naming_entries)  # type: ignore[arg-type]
    note_rows = alias_note_rows(note_entries)  # type: ignore[arg-type]

    con = duckdb.connect(str(common.DB_PATH))
    write_tables(con, naming_rows, note_rows)
    common.print_table_counts(con, ["naming_convention", "actor_alias_note"])

    failures = [
        failure
        for failure in (
            check_load_count(con, "naming_convention", len(naming_rows)),
            check_load_count(con, "actor_alias_note", len(note_rows)),
        )
        if failure
    ]
    common.fail_if_any(failures)


if __name__ == "__main__":
    main()
