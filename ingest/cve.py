"""Ingest CISA's Known Exploited Vulnerabilities (KEV) catalog into
data/cti.duckdb.
"""

import json
import pathlib
from typing import TypedDict

import common
import duckdb

from contracts import not_none

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevEntry(TypedDict, total=False):
    """The subset of one CISA KEV JSON entry this script uses."""

    cveID: str
    vendorProject: str
    product: str
    vulnerabilityName: str
    dateAdded: str
    dueDate: str
    shortDescription: str
    requiredAction: str
    knownRansomwareCampaignUse: str
    cwes: list[str]


class KevCatalog(TypedDict):
    """The top-level shape of the CISA KEV JSON file."""

    catalogVersion: str
    count: int
    vulnerabilities: list[KevEntry]


def load_catalog(path: pathlib.Path) -> KevCatalog:
    """Parse the downloaded KEV JSON file."""
    data: KevCatalog = json.loads(path.read_text(encoding="utf-8"))
    return data


def kev_rows(vulnerabilities: list[KevEntry]) -> list[tuple[object, ...]]:
    """One row per KEV entry, matching the `kev` table's column order."""
    return [
        (
            v["cveID"],
            v.get("vendorProject"),
            v.get("product"),
            v.get("vulnerabilityName"),
            v.get("dateAdded"),
            v.get("dueDate"),
            v.get("shortDescription"),
            v.get("requiredAction"),
            v.get("knownRansomwareCampaignUse"),
        )
        for v in vulnerabilities
    ]


def cwe_rows(vulnerabilities: list[KevEntry]) -> list[tuple[str, str]]:
    """One (cve_id, cwe_id) row per weakness listed on each KEV entry."""
    return [
        (v["cveID"], cwe_id)
        for v in vulnerabilities
        for cwe_id in v.get("cwes") or []
    ]


def write_tables(con: duckdb.DuckDBPyConnection, catalog: KevCatalog) -> None:
    """Create (or replace) and populate the kev and kev_cwe tables."""
    con.execute(
        "CREATE OR REPLACE TABLE kev("
        "cve_id VARCHAR, vendor_project VARCHAR, product VARCHAR, vulnerability_name VARCHAR, "
        "date_added VARCHAR, due_date VARCHAR, short_description VARCHAR, "
        "required_action VARCHAR, known_ransomware VARCHAR)"
    )
    con.executemany(
        "INSERT INTO kev VALUES (?,?,?,?,?,?,?,?,?)", kev_rows(catalog["vulnerabilities"])
    )

    con.execute("CREATE OR REPLACE TABLE kev_cwe(cve_id VARCHAR, cwe_id VARCHAR)")
    con.executemany("INSERT INTO kev_cwe VALUES (?,?)", cwe_rows(catalog["vulnerabilities"]))


def check_kev_count(con: duckdb.DuckDBPyConnection, catalog: KevCatalog) -> str | None:
    """Compare the loaded distinct CVE count against the catalog's own
    published count. Returns a failure name, or None.
    """
    published_count = catalog["count"]
    distinct_row = con.execute("SELECT COUNT(DISTINCT cve_id) FROM kev").fetchone()
    actual_count = not_none(distinct_row, "COUNT query must always return a row")[0]
    status = "PASS" if actual_count == published_count else "FAIL"
    print(
        f"DQ [{status}] kev: {actual_count} distinct vs {published_count} published "
        f"by CISA catalog {catalog['catalogVersion']}"
    )
    return None if status == "PASS" else "kev"


def main() -> None:
    """Fetch, ingest, and data-quality-check the CISA KEV catalog."""
    raw_path = common.fetch(URL, "known_exploited_vulnerabilities.json")
    catalog = load_catalog(raw_path)

    con = duckdb.connect(str(common.DB_PATH))
    write_tables(con, catalog)
    common.print_table_counts(con, ["kev", "kev_cwe"])

    failure = check_kev_count(con, catalog)
    common.fail_if_any([failure] if failure else [])


if __name__ == "__main__":
    main()
