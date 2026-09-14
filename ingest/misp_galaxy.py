"""Ingest MISP Galaxy's threat-actor cluster -- a community-maintained list
of actor names, aliases, country, and references -- into data/cti.duckdb.

The cluster JSON's shape was inspected directly (see data/raw/ after a run,
or the MISP/misp-galaxy repo) before this parser was written: each entry in
its top-level "values" list has "uuid", "value" (canonical name), an
optional "description", and an optional "meta" dict whose "country",
"synonyms", and "refs" sub-fields are each present on only some entries (of
1052 entries checked, "meta.country" was present on 482, "meta.synonyms" on
408, "meta.refs" on 1035) -- the parser below tolerates every field being
absent rather than assuming a fixed shape.
"""

import datetime
import json
import pathlib
from typing import TypedDict

import common
import duckdb

from contracts import not_none, precondition

URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"

MispActorRow = tuple[str, str, str | None, str | None, str, str, str]
ActorAliasRow = tuple[str, str, str, str, str]


class ClusterMeta(TypedDict, total=False):
    """The subset of one cluster value's optional "meta" dict this script uses."""

    country: str
    synonyms: list[str]
    refs: list[str]


class ClusterValue(TypedDict):
    """One MISP galaxy cluster entry -- one threat actor."""

    uuid: str
    value: str
    description: str
    meta: ClusterMeta


class ClusterFile(TypedDict):
    """The top-level shape of clusters/threat-actor.json."""

    values: list[ClusterValue]


def dated_filename(today: datetime.date) -> str:
    """A dated filename for the downloaded cluster file, e.g.
    misp_threat-actor_2026-09-14.json.
    """
    return f"misp_threat-actor_{today.isoformat()}.json"


def load_cluster(path: pathlib.Path) -> ClusterFile:
    """Parse the downloaded MISP galaxy cluster file."""
    data: ClusterFile = json.loads(path.read_text(encoding="utf-8"))
    precondition("values" in data, "cluster file must have a top-level 'values' list")
    return data


def misp_actor_rows(
    values: list[ClusterValue], source_url: str, retrieved: str
) -> list[MispActorRow]:
    """One row per cluster value, matching the misp_actor table's column order."""
    rows: list[MispActorRow] = []
    for cluster_value in values:
        meta = cluster_value.get("meta", {})
        refs = ";".join(meta.get("refs", []))
        rows.append((
            cluster_value["uuid"],
            cluster_value["value"],
            cluster_value.get("description"),
            meta.get("country"),
            refs,
            source_url,
            retrieved,
        ))
    return rows


def actor_alias_rows(
    values: list[ClusterValue], source_url: str, retrieved: str
) -> list[ActorAliasRow]:
    """One canonical-name row plus one row per synonym, per cluster value,
    matching the actor_alias table's column order.
    """
    rows: list[ActorAliasRow] = []
    for cluster_value in values:
        misp_uuid = cluster_value["uuid"]
        rows.append((misp_uuid, cluster_value["value"], "canonical", source_url, retrieved))
        for synonym in cluster_value.get("meta", {}).get("synonyms", []):
            rows.append((misp_uuid, synonym, "synonym", source_url, retrieved))
    return rows


def write_tables(
    con: duckdb.DuckDBPyConnection,
    actor_rows: list[MispActorRow],
    alias_rows: list[ActorAliasRow],
) -> None:
    """Create (or replace) and populate the misp_actor and actor_alias tables."""
    con.execute(
        "CREATE OR REPLACE TABLE misp_actor("
        "misp_uuid VARCHAR, canonical_name VARCHAR, description VARCHAR, "
        "country VARCHAR, refs VARCHAR, source_url VARCHAR, retrieved DATE)"
    )
    con.executemany("INSERT INTO misp_actor VALUES (?,?,?,?,?,?,?)", actor_rows)

    con.execute(
        "CREATE OR REPLACE TABLE actor_alias("
        "misp_uuid VARCHAR, alias VARCHAR, alias_type VARCHAR, "
        "source_url VARCHAR, retrieved DATE)"
    )
    con.executemany("INSERT INTO actor_alias VALUES (?,?,?,?,?)", alias_rows)


def check_actor_count(con: duckdb.DuckDBPyConnection, expected: int) -> str | None:
    """misp_actor's row count must equal the cluster file's own value count.
    Returns a failure name, or None.
    """
    actual = common.table_count(con, "misp_actor")
    status = "PASS" if actual == expected else "FAIL"
    print(f"DQ [{status}] misp_actor: {actual} loaded vs {expected} values in cluster file")
    return None if status == "PASS" else "misp_actor row count"


def check_uuid_uniqueness(con: duckdb.DuckDBPyConnection) -> str | None:
    """Every misp_uuid in misp_actor must be unique. Returns a failure name, or None."""
    total = common.table_count(con, "misp_actor")
    distinct_row = con.execute("SELECT COUNT(DISTINCT misp_uuid) FROM misp_actor").fetchone()
    distinct = not_none(distinct_row, "COUNT query must always return a row")[0]
    status = "PASS" if distinct == total else "FAIL"
    print(f"DQ [{status}] misp_actor.misp_uuid uniqueness: {distinct} distinct vs {total} total")
    return None if status == "PASS" else "misp_actor.misp_uuid uniqueness"


def main() -> None:
    """Fetch, ingest, and data-quality-check the MISP galaxy threat-actor cluster."""
    today = datetime.datetime.now(datetime.timezone.utc).date()
    raw_path = common.fetch(URL, dated_filename(today))
    cluster = load_cluster(raw_path)
    values = cluster["values"]

    retrieved = today.isoformat()
    actor_rows = misp_actor_rows(values, URL, retrieved)
    alias_rows = actor_alias_rows(values, URL, retrieved)

    con = duckdb.connect(str(common.DB_PATH))
    write_tables(con, actor_rows, alias_rows)
    common.print_table_counts(con, ["misp_actor", "actor_alias"])

    failures = [
        failure
        for failure in (check_actor_count(con, len(values)), check_uuid_uniqueness(con))
        if failure
    ]
    common.fail_if_any(failures)


if __name__ == "__main__":
    main()
