"""Ingest MITRE ATT&CK Enterprise: actors, techniques, software, mitigations,
and the relationships between them, into data/cti.duckdb.
"""

import common
import duckdb
from mitreattack.stix20 import MitreAttackData

from contracts import precondition

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Every loop below iterates atk.get_groups()/get_techniques(), MITRE's own
# in-memory STIX object lists for one release -- fixed-size for the
# lifetime of this script, not attacker-controlled or unbounded.


def load_actors(atk: MitreAttackData) -> list[tuple[str, str, str, str]]:
    """One row per ATT&CK group: (stix_id, attack_id, name, aliases)."""
    return [
        (g.id, atk.get_attack_id(g.id), g.name, ";".join(getattr(g, "aliases", []) or []))
        for g in atk.get_groups(remove_revoked_deprecated=True)
    ]


def load_actor_techniques(atk: MitreAttackData) -> list[tuple[str, str, str]]:
    """One row per (actor, technique) usage relationship."""
    rows = []
    for group in atk.get_groups(remove_revoked_deprecated=True):
        for rel in atk.get_techniques_used_by_group(group.id):
            technique = rel["object"]
            rows.append((group.id, atk.get_attack_id(technique.id), technique.name))
    return rows


def load_actor_software(atk: MitreAttackData) -> list[tuple[str, str, str, str]]:
    """One row per (actor, software) usage relationship."""
    rows = []
    for group in atk.get_groups(remove_revoked_deprecated=True):
        for rel in atk.get_software_used_by_group(group.id):
            software = rel["object"]
            rows.append((group.id, software.id, software.name, software.type))
    return rows


def load_technique_mitigations(atk: MitreAttackData) -> list[tuple[str, str, str]]:
    """One row per (technique, mitigation) relationship."""
    rows = []
    for technique in atk.get_techniques(remove_revoked_deprecated=True):
        for rel in atk.get_mitigations_mitigating_technique(technique.id):
            mitigation = rel["object"]
            rows.append(
                (atk.get_attack_id(technique.id), atk.get_attack_id(mitigation.id), mitigation.name)
            )
    return rows


def write_tables(con: duckdb.DuckDBPyConnection, atk: MitreAttackData) -> None:
    """Create (or replace) and populate every ATT&CK table."""
    con.execute(
        "CREATE OR REPLACE TABLE actor(stix_id VARCHAR, attack_id VARCHAR, "
        "name VARCHAR, aliases VARCHAR)"
    )
    con.executemany("INSERT INTO actor VALUES (?,?,?,?)", load_actors(atk))

    con.execute(
        "CREATE OR REPLACE TABLE actor_technique(actor_stix_id VARCHAR, "
        "technique_id VARCHAR, technique_name VARCHAR)"
    )
    con.executemany("INSERT INTO actor_technique VALUES (?,?,?)", load_actor_techniques(atk))

    con.execute(
        "CREATE OR REPLACE TABLE actor_software(actor_stix_id VARCHAR, software_id VARCHAR, "
        "software_name VARCHAR, software_type VARCHAR)"
    )
    con.executemany("INSERT INTO actor_software VALUES (?,?,?,?)", load_actor_software(atk))

    con.execute(
        "CREATE OR REPLACE TABLE technique_mitigation(technique_id VARCHAR, "
        "mitigation_id VARCHAR, mitigation_name VARCHAR)"
    )
    con.executemany(
        "INSERT INTO technique_mitigation VALUES (?,?,?)", load_technique_mitigations(atk)
    )


def published_totals(atk: MitreAttackData) -> dict[str, int]:
    """MITRE's own canonical per-release entity counts (same numbers
    reflected on attack.mitre.org's Groups/Software/Techniques/Mitigations
    pages), filtered the same way (remove_revoked_deprecated=True) as
    write_tables() above.
    """
    return {
        "actor": len(atk.get_groups(remove_revoked_deprecated=True)),
        "technique": len(atk.get_techniques(remove_revoked_deprecated=True)),
        "software": len(atk.get_software(remove_revoked_deprecated=True)),
        "mitigation": len(atk.get_mitigations(remove_revoked_deprecated=True)),
    }


def check_actor_count(con: duckdb.DuckDBPyConnection, published: dict[str, int]) -> str | None:
    """The actor table holds every group regardless of usage, so it must
    match the published total exactly. Returns a failure name, or None.
    """
    actual = common.table_count(con, "actor")
    status = "PASS" if actual == published["actor"] else "FAIL"
    print(f"DQ [{status}] actor: {actual} distinct vs {published['actor']} published")
    return None if status == "PASS" else "actor"


# (entity key in `published`, relationship table, its id column)
SUBSET_CHECKS = [
    ("technique", "actor_technique", "technique_id"),
    ("software", "actor_software", "software_id"),
    ("technique", "technique_mitigation", "technique_id"),
    ("mitigation", "technique_mitigation", "mitigation_id"),
]


def check_subset_coverage(
    con: duckdb.DuckDBPyConnection, published: dict[str, int]
) -> list[str]:
    """The relationship tables only cover entities with >=1 relationship, so
    they're subsets: a distinct count exceeding the published total would
    mean duplicates, stray revoked/deprecated rows, or an id-matching bug.
    """
    failures = []
    for entity, table, column in SUBSET_CHECKS:
        # table/column are always one of the four literal tuples above, never
        # external input.
        distinct_row = con.execute(
            f"SELECT COUNT(DISTINCT {column}) FROM {table}"  # nosec B608
        ).fetchone()
        distinct = distinct_row[0] if distinct_row else 0
        total = published[entity]
        ok = distinct <= total
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures.append(f"{table}.{column}")
        pct = (distinct / total * 100) if total else 0.0
        print(
            f"DQ [{status}] {table}.{column}: {distinct} distinct <= {total} "
            f"published {entity}s ({pct:.0f}% coverage)"
        )
    return failures


def main() -> None:
    """Fetch, ingest, and data-quality-check the ATT&CK Enterprise dataset."""
    raw_path = common.fetch(URL, "enterprise-attack.json")
    atk = MitreAttackData(str(raw_path))
    con = duckdb.connect(str(common.DB_PATH))

    write_tables(con, atk)
    common.print_table_counts(
        con, ["actor", "actor_technique", "actor_software", "technique_mitigation"]
    )

    published = published_totals(atk)
    precondition(all(v >= 0 for v in published.values()), "published totals must be non-negative")

    failures = []
    actor_failure = check_actor_count(con, published)
    if actor_failure:
        failures.append(actor_failure)
    failures.extend(check_subset_coverage(con, published))

    common.fail_if_any(failures)


if __name__ == "__main__":
    main()
