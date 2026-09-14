"""Ingest MITRE CAPEC (attack patterns) and its CWE/ATT&CK crosswalk into
data/cti.duckdb.
"""

import pathlib
import re
from typing import Any, TypeAlias

import common
import duckdb
from stix2 import Filter, MemoryStore

from contracts import not_none

URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

INACTIVE_STATUSES = {"Deprecated", "Obsolete"}
TAG_RE = re.compile(r"<[^>]+>")

# stix2's AttackPattern has no published stub; treated as structurally
# duck-typed (id, name, description, external_references, x_capec_status).
AttackPattern: TypeAlias = Any


def clean_description(text: str | None) -> str | None:
    """Strip HTML tags and collapse whitespace in a CAPEC description."""
    if not text:
        return None
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", text)).strip()


def external_ids(pattern: AttackPattern, source_name: str) -> list[str]:
    """External reference IDs of one source (e.g. "capec", "cwe", "ATTACK")."""
    return [
        ref["external_id"]
        for ref in getattr(pattern, "external_references", [])
        if ref.get("source_name") == source_name and ref.get("external_id")
    ]


def is_active(pattern: AttackPattern) -> bool:
    """Whether a CAPEC attack pattern is neither Deprecated nor Obsolete."""
    return getattr(pattern, "x_capec_status", None) not in INACTIVE_STATUSES


def active_patterns(store: MemoryStore) -> list[AttackPattern]:
    """Every non-deprecated, non-obsolete CAPEC attack pattern in the store."""
    patterns = store.query([Filter("type", "=", "attack-pattern")])
    return [pattern for pattern in patterns if is_active(pattern)]


CapecRow = tuple[str, str, str | None]
CrosswalkRow = tuple[str, str]


def load_capec_data(
    patterns: list[AttackPattern],
) -> tuple[list[CapecRow], list[CrosswalkRow], list[CrosswalkRow]]:
    """Extract (capec rows, capec-cwe rows, capec-technique rows) from the
    active attack patterns -- one row per pattern that has its own CAPEC id.
    """
    capec_rows: list[CapecRow] = []
    cwe_rows: list[CrosswalkRow] = []
    technique_rows: list[CrosswalkRow] = []
    for pattern in patterns:
        capec_ids = external_ids(pattern, "capec")
        if not capec_ids:
            continue
        capec_id = capec_ids[0]
        description = clean_description(getattr(pattern, "description", None))
        capec_rows.append((capec_id, pattern.name, description))
        for cwe_id in external_ids(pattern, "cwe"):
            cwe_rows.append((capec_id, cwe_id))
        for technique_id in external_ids(pattern, "ATTACK"):
            technique_rows.append((capec_id, technique_id))
    return capec_rows, cwe_rows, technique_rows


def write_tables(
    con: duckdb.DuckDBPyConnection,
    capec_rows: list[CapecRow],
    cwe_rows: list[CrosswalkRow],
    technique_rows: list[CrosswalkRow],
) -> None:
    """Create (or replace) and populate the capec, capec_cwe, and
    capec_technique tables.
    """
    con.execute(
        "CREATE OR REPLACE TABLE capec(capec_id VARCHAR, name VARCHAR, description VARCHAR)"
    )
    con.executemany("INSERT INTO capec VALUES (?,?,?)", capec_rows)

    con.execute("CREATE OR REPLACE TABLE capec_cwe(capec_id VARCHAR, cwe_id VARCHAR)")
    con.executemany("INSERT INTO capec_cwe VALUES (?,?)", cwe_rows)

    con.execute("CREATE OR REPLACE TABLE capec_technique(capec_id VARCHAR, technique_id VARCHAR)")
    con.executemany("INSERT INTO capec_technique VALUES (?,?)", technique_rows)


def check_capec_count(con: duckdb.DuckDBPyConnection, store: MemoryStore) -> str | None:
    """Recount active attack-patterns independently of the extraction loop
    above, so a bug in load_capec_data's filtering would still be caught.
    """
    published_active = len(active_patterns(store))
    distinct_row = con.execute("SELECT COUNT(DISTINCT capec_id) FROM capec").fetchone()
    actual_capec = not_none(distinct_row, "COUNT query must always return a row")[0]
    status = "PASS" if actual_capec == published_active else "FAIL"
    print(
        f"DQ [{status}] capec: {actual_capec} distinct vs {published_active} "
        f"active attack-patterns in source"
    )
    return None if status == "PASS" else "capec"


def main() -> None:
    """Fetch, ingest, and data-quality-check the MITRE CAPEC dataset."""
    raw_path: pathlib.Path = common.fetch(URL, "capec.json")
    store = MemoryStore()
    store.load_from_file(str(raw_path))

    capec_rows, cwe_rows, technique_rows = load_capec_data(active_patterns(store))

    con = duckdb.connect(str(common.DB_PATH))
    write_tables(con, capec_rows, cwe_rows, technique_rows)
    common.print_table_counts(con, ["capec", "capec_cwe", "capec_technique"])

    failure = check_capec_count(con, store)
    common.fail_if_any([failure] if failure else [])


if __name__ == "__main__":
    main()
