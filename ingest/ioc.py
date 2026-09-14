"""Ingest public IOC feeds (URLhaus, MalwareBazaar, Feodo Tracker) and cross-
walk their malware family names against known ATT&CK software, into
data/cti.duckdb.
"""

import csv
import json
import pathlib
from typing import TypedDict

import common
import duckdb

from contracts import precondition

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

CsvRow = list[str]


class FeodoEntry(TypedDict, total=False):
    """The subset of one Feodo Tracker JSON entry this script uses."""

    ip_address: str
    port: int
    malware: str
    first_seen: str
    last_online: str
    status: str


def parse_csv_rows(path: pathlib.Path) -> tuple[list[str], list[CsvRow]]:
    """abuse.ch CSVs are '#'-commented; the last comment line is the header."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    data_lines = [line for line in lines if line and not line.startswith("#")]
    header_line = next(line for line in reversed(lines) if line.startswith("# ") and "," in line)
    header = [h.strip().strip('"') for h in header_line.lstrip("#").strip().split(",")]
    reader = csv.reader(data_lines, skipinitialspace=True)
    return header, list(reader)


def column_index(header: list[str]) -> dict[str, int]:
    """Map each CSV column name to its position, for name-based row access."""
    return {name: i for i, name in enumerate(header)}


def build_url_rows(rows: list[CsvRow], idx: dict[str, int]) -> list[tuple[str, ...]]:
    """One row per URLhaus CSV entry, matching the ioc_url table's columns."""
    return [
        (
            r[idx["id"]], r[idx["url"]], r[idx["dateadded"]], r[idx["threat"]],
            r[idx["tags"]], r[idx["url_status"]], r[idx["urlhaus_link"]],
        )
        for r in rows
    ]


def build_hash_rows(rows: list[CsvRow], idx: dict[str, int]) -> list[tuple[str, ...]]:
    """One row per MalwareBazaar CSV entry, matching the ioc_hash table's columns."""
    return [
        (
            r[idx["sha256_hash"]], r[idx["md5_hash"]], r[idx["sha1_hash"]],
            r[idx["file_name"]], r[idx["signature"]], r[idx["first_seen_utc"]],
        )
        for r in rows
    ]


def build_c2_rows(entries: list[FeodoEntry]) -> list[tuple[object, ...]]:
    """One row per Feodo Tracker JSON entry, matching the ioc_c2 table's columns."""
    return [
        (
            e["ip_address"], e.get("port"), e.get("malware"),
            e.get("first_seen"), e.get("last_online"), e.get("status"),
        )
        for e in entries
    ]


def check_load_count(
    con: duckdb.DuckDBPyConnection, table: str, expected: int, source_label: str
) -> str | None:
    """Compare a table's loaded row count against the source feed's own row
    count. Returns a failure name (the table), or None.
    """
    actual = common.table_count(con, table)
    status = "PASS" if actual == expected else "FAIL"
    print(f"{table} {actual}")
    print(f"DQ [{status}] {table}: {actual} loaded vs {expected} {source_label}")
    return None if status == "PASS" else table


def ingest_urlhaus(con: duckdb.DuckDBPyConnection) -> str | None:
    """Fetch and load URLhaus (malicious URLs). Returns a failure name, or None."""
    raw_path = common.fetch(URLHAUS_URL, "urlhaus.csv")
    header, rows = parse_csv_rows(raw_path)
    con.execute(
        "CREATE OR REPLACE TABLE ioc_url(id VARCHAR, url VARCHAR, date_added VARCHAR, "
        "threat VARCHAR, tags VARCHAR, status VARCHAR, urlhaus_link VARCHAR)"
    )
    con.executemany(
        "INSERT INTO ioc_url VALUES (?,?,?,?,?,?,?)", build_url_rows(rows, column_index(header))
    )
    return check_load_count(con, "ioc_url", len(rows), "rows in source CSV")


def ingest_malwarebazaar(con: duckdb.DuckDBPyConnection) -> str | None:
    """Fetch and load MalwareBazaar (file hashes). Returns a failure name, or None."""
    raw_path = common.fetch(MALWAREBAZAAR_URL, "malwarebazaar.csv")
    header, rows = parse_csv_rows(raw_path)
    con.execute(
        "CREATE OR REPLACE TABLE ioc_hash(sha256 VARCHAR, md5 VARCHAR, sha1 VARCHAR, "
        "file_name VARCHAR, signature VARCHAR, first_seen VARCHAR)"
    )
    con.executemany(
        "INSERT INTO ioc_hash VALUES (?,?,?,?,?,?)", build_hash_rows(rows, column_index(header))
    )
    return check_load_count(con, "ioc_hash", len(rows), "rows in source CSV")


def ingest_feodo(con: duckdb.DuckDBPyConnection) -> str | None:
    """Fetch and load Feodo Tracker (botnet C2 IPs). Returns a failure name, or None."""
    raw_path = common.fetch(FEODO_URL, "feodotracker.json")
    entries: list[FeodoEntry] = json.loads(raw_path.read_text(encoding="utf-8"))
    con.execute(
        "CREATE OR REPLACE TABLE ioc_c2(ip_address VARCHAR, port INTEGER, malware VARCHAR, "
        "first_seen VARCHAR, last_online VARCHAR, status VARCHAR)"
    )
    con.executemany("INSERT INTO ioc_c2 VALUES (?,?,?,?,?,?)", build_c2_rows(entries))
    return check_load_count(con, "ioc_c2", len(entries), "entries in source JSON")


# (table holding a malware-family-name column, that column's name). Both are
# always one of these two literal pairs, never external input -- see
# build_crosswalk_rows's f-string SQL below.
CROSSWALK_SOURCES = (("ioc_hash", "signature"), ("ioc_c2", "malware"))


def build_crosswalk_rows(con: duckdb.DuckDBPyConnection) -> list[tuple[str, str, str, str]]:
    """Malware family name -> known ATT&CK software, matched exactly
    (case-insensitive) against each IOC table's own name column.
    """
    crosswalk_rows: list[tuple[str, str, str, str]] = []
    for source_table, name_col in CROSSWALK_SOURCES:
        precondition(bool(source_table) and bool(name_col), "must not be empty")
        matches = con.execute(
            f"SELECT DISTINCT i.{name_col}, s.software_id, s.software_name "  # nosec B608
            f"FROM {source_table} i "
            "JOIN (SELECT DISTINCT software_id, software_name FROM actor_software) s "
            f"ON lower(i.{name_col}) = lower(s.software_name) "
            f"WHERE i.{name_col} IS NOT NULL AND i.{name_col} != ''"
        ).fetchall()
        crosswalk_rows.extend(
            (source_table, malware_name, software_id, software_name)
            for malware_name, software_id, software_name in matches
        )
    return crosswalk_rows


def write_crosswalk(con: duckdb.DuckDBPyConnection) -> None:
    """Create (or replace) and populate the ioc_software crosswalk table."""
    con.execute(
        "CREATE OR REPLACE TABLE ioc_software(source_table VARCHAR, malware_name VARCHAR, "
        "software_id VARCHAR, software_name VARCHAR)"
    )
    crosswalk_rows = build_crosswalk_rows(con)
    con.executemany("INSERT INTO ioc_software VALUES (?,?,?,?)", crosswalk_rows)
    print(f"ioc_software {len(crosswalk_rows)}")


def main() -> None:
    """Fetch, ingest, and data-quality-check every IOC feed, then build the
    malware-name-to-ATT&CK-software crosswalk.
    """
    con = duckdb.connect(str(common.DB_PATH))

    failures = [
        failure
        for failure in (ingest_urlhaus(con), ingest_malwarebazaar(con), ingest_feodo(con))
        if failure
    ]
    write_crosswalk(con)

    common.fail_if_any(failures)


if __name__ == "__main__":
    main()
