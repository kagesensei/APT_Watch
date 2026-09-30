"""Small DB query helpers shared across app/routes.py, app/preview.py,
app/dashboard.py, and app/intel.py.
"""

import json
import pathlib
from typing import NamedTuple, Sequence, TypedDict

import duckdb
import alias_matching

from contracts import not_none, precondition


def count(
    db: duckdb.DuckDBPyConnection, sql: str, params: Sequence[object] | None = None
) -> int:
    """Run a COUNT(...) query and return its scalar result.

    A COUNT query always returns exactly one row by SQL's own semantics, so
    a None result would mean something is badly wrong with the connection
    or the query -- not_none() turns that into an immediate, clear failure
    instead of a confusing "NoneType is not subscriptable" deeper in a
    template.
    """
    row = db.execute(sql, params or []).fetchone()
    return int(not_none(row, f"COUNT query returned no row: {sql!r}")[0])


class OverviewCounts(TypedDict):
    """Total distinct entity counts shown on both the Library index and the dashboard."""

    actors: int
    techniques: int
    software: int
    mitigations: int
    cves: int


def overview_counts(db: duckdb.DuckDBPyConnection) -> OverviewCounts:
    """Total distinct entity counts across the ingested ATT&CK/KEV dataset."""
    return {
        "actors": count(db, "SELECT COUNT(*) FROM actor"),
        "techniques": count(db, "SELECT COUNT(DISTINCT technique_id) FROM actor_technique"),
        "software": count(db, "SELECT COUNT(DISTINCT software_id) FROM actor_software"),
        "mitigations": count(db, "SELECT COUNT(DISTINCT mitigation_id) FROM technique_mitigation"),
        "cves": count(db, "SELECT COUNT(DISTINCT cve_id) FROM kev"),
    }


def in_placeholders(count_of_values: int) -> str:
    """A `?,?,...` placeholder list for a SQL `IN (...)` clause of this many
    values. Only the *number* of values is dynamic here; every value itself
    is still bound through the driver's own parameter list, never
    interpolated into the SQL text -- callers still need a `# nosec B608`
    at their own f-string, since bandit's syntactic scan can't see that far,
    but the actual safety guarantee (no value ever touches the SQL text)
    lives here.
    """
    precondition(count_of_values > 0, "count_of_values must be positive")
    return ",".join("?" * count_of_values)


def technique_name(db: duckdb.DuckDBPyConnection, technique_id: str) -> str | None:
    """The documented name for an ATT&CK technique ID, or None if unknown."""
    row = db.execute(
        "SELECT DISTINCT technique_name FROM actor_technique WHERE technique_id = ?",
        [technique_id],
    ).fetchone()
    return row[0] if row else None


def mitigation_name(db: duckdb.DuckDBPyConnection, mitigation_id: str) -> str | None:
    """The documented name for an ATT&CK mitigation ID, or None if unknown."""
    row = db.execute(
        "SELECT DISTINCT mitigation_name FROM technique_mitigation WHERE mitigation_id = ?",
        [mitigation_id],
    ).fetchone()
    return row[0] if row else None


class ListQuery(NamedTuple):
    """The fixed, literal parts of one app/routes.py list page's query --
    never request data (see searchable_list's docstring).
    """

    table: str
    count_expr: str
    select_columns: str
    search_columns: Sequence[str]
    order_by: str


def searchable_list(
    db: duckdb.DuckDBPyConnection, spec: ListQuery, q: str, size: int, offset: int
) -> tuple[int, list[tuple[object, ...]]]:
    """A paginated `SELECT ... FROM table [WHERE col ILIKE ? OR ...] ORDER BY
    ... LIMIT ? OFFSET ?`, with an optional multi-column search filter.

    Every field of `spec` is always a literal string from this module's own
    call sites in app/routes.py -- never request data. Only `q`'s value
    flows into the query, and always as a `?`-bound parameter, never
    interpolated into the SQL text. Bandit's B608 can't verify that a WHERE
    clause built from an f-string is safe from a purely syntactic scan,
    hence the explicit, narrow suppression below -- the one place in this
    app where a query's shape (not its data) is assembled at runtime, from a
    fixed, closed set of call sites.
    """
    precondition(
        bool(spec.table) and bool(spec.select_columns) and bool(spec.order_by),
        "table, select_columns, and order_by must not be empty",
    )
    if q and spec.search_columns:
        where = "WHERE " + " OR ".join(f"{col} ILIKE ?" for col in spec.search_columns)
        params: list[object] = [f"%{q}%"] * len(spec.search_columns)
    else:
        where = ""
        params = []

    total = count(db, f"SELECT {spec.count_expr} FROM {spec.table} {where}", params)  # nosec B608
    rows = db.execute(
        f"SELECT {spec.select_columns} FROM {spec.table} {where} "  # nosec B608
        f"ORDER BY {spec.order_by} LIMIT ? OFFSET ?",
        [*params, size, offset],
    ).fetchall()
    return total, rows


class SigmaRuleMatch(TypedDict):
    """One Sigma rule covering one technique an actor is documented to use."""

    rule_id: str
    title: str
    level: str
    technique_id: str
    source_url: str
    retrieved: str


class SigmaCoverage(TypedDict):
    """Sigma detection coverage for one ATT&CK actor's documented techniques."""

    attack_id: str
    covered_techniques: list[str]
    uncovered_techniques: list[str]
    covered_technique_count: int
    uncovered_technique_count: int
    rules: list[SigmaRuleMatch]
    untagged_rule_count: int


def sigma_coverage_for_actor(db: duckdb.DuckDBPyConnection, attack_id: str) -> SigmaCoverage:
    """Sigma rules covering any technique this ATT&CK actor is documented to
    use (via sigma_rule_technique, see ingest/sigma.py), plus which of the
    actor's techniques have no covering rule at all.
    """
    precondition(bool(attack_id), "attack_id must not be empty")
    technique_rows = db.execute(
        "SELECT DISTINCT atq.technique_id FROM actor_technique atq "
        "JOIN actor a ON a.stix_id = atq.actor_stix_id WHERE a.attack_id = ?",
        [attack_id],
    ).fetchall()
    actor_techniques = sorted({row[0] for row in technique_rows})

    if not actor_techniques:
        return {
            "attack_id": attack_id,
            "covered_techniques": [],
            "uncovered_techniques": [],
            "covered_technique_count": 0,
            "uncovered_technique_count": 0,
            "rules": [],
            "untagged_rule_count": _sigma_untagged_rule_count(db),
        }

    # placeholders is only ever "?,?,..." (in_placeholders); actor_techniques'
    # actual values are bound via the parameter list below, not this string.
    placeholders = in_placeholders(len(actor_techniques))
    rule_rows = db.execute(
        "SELECT srt.technique_id, sr.rule_id, sr.title, sr.level, sr.source_url, sr.retrieved "
        "FROM sigma_rule_technique srt "
        "JOIN sigma_rule sr ON sr.rule_id = srt.rule_id "
        f"WHERE srt.technique_id IN ({placeholders})",  # nosec B608
        actor_techniques,
    ).fetchall()

    covered = sorted({row[0] for row in rule_rows})
    uncovered = sorted(set(actor_techniques) - set(covered))
    rules: list[SigmaRuleMatch] = [
        {
            "rule_id": rule_id, "title": title, "level": level,
            "technique_id": technique_id, "source_url": source_url,
            "retrieved": str(retrieved),
        }
        for technique_id, rule_id, title, level, source_url, retrieved in rule_rows
    ]

    return {
        "attack_id": attack_id,
        "covered_techniques": covered,
        "uncovered_techniques": uncovered,
        "covered_technique_count": len(covered),
        "uncovered_technique_count": len(uncovered),
        "rules": rules,
        "untagged_rule_count": _sigma_untagged_rule_count(db),
    }


def _sigma_untagged_rule_count(db: duckdb.DuckDBPyConnection) -> int:
    """Count ingested Sigma rules with no ATT&CK technique tag."""
    return count(
        db,
        "SELECT COUNT(*) FROM sigma_rule sr WHERE NOT EXISTS "
        "(SELECT 1 FROM sigma_rule_technique srt WHERE srt.rule_id = sr.rule_id)",
    )


class SigmaTechniqueCoverage(TypedDict):
    """Rules tagged by their authors for a technique and dataset scope."""

    technique_id: str
    rules: list[SigmaRuleMatch]
    untagged_rule_count: int


def sigma_coverage_for_technique(
    db: duckdb.DuckDBPyConnection, technique_id: str
) -> SigmaTechniqueCoverage:
    """Return rules whose author-supplied tags name a technique."""
    precondition(bool(technique_id), "technique_id must not be empty")
    rows = db.execute(
        "SELECT sr.rule_id, sr.title, sr.level, sr.source_url, sr.retrieved "
        "FROM sigma_rule_technique srt JOIN sigma_rule sr ON sr.rule_id = srt.rule_id "
        "WHERE srt.technique_id = ? ORDER BY sr.title, sr.rule_id",
        [technique_id],
    ).fetchall()
    rules: list[SigmaRuleMatch] = [
        {
            "rule_id": rule_id, "title": title, "level": level,
            "technique_id": technique_id, "source_url": source_url,
            "retrieved": str(retrieved),
        }
        for rule_id, title, level, source_url, retrieved in rows
    ]
    return {
        "technique_id": technique_id,
        "rules": rules,
        "untagged_rule_count": _sigma_untagged_rule_count(db),
    }


class ActorIdentityEvidence(TypedDict):
    """One source-name correspondence, review decision, or unresolved gap."""

    status: str
    attack_id: str
    attack_name: str
    misp_uuid: str | None
    misp_name: str | None
    match_score: float | None
    attack_alias: str | None
    misp_alias: str | None
    shared_aliases: list[str]
    other_attack_names: list[str]
    source_url: str | None
    retrieved: str | None
    reason: str | None
    reviewed: str | None
    review_sources: list[str]


class ManualReviewDetails(TypedDict):
    """Review provenance from the local structured manual decision file."""

    reason: str | None
    reviewed: str | None
    sources: list[str]


def _exact_identity_evidence(
    stix_id: str, attack_id: str, attack_name: str,
    attack_actors: list[alias_matching.AttackActor],
    misp_rows: list[alias_matching.MispAliasRow],
    misp_names: dict[str, str],
    match_sets: alias_matching.ExactMatchSets,
) -> list[ActorIdentityEvidence]:
    actor_map = {actor["stix_id"]: actor for actor in attack_actors}
    alias_map: dict[str, set[str]] = {}
    for alias in actor_map[stix_id]["aliases"]:
        alias_map.setdefault(alias_matching.normalize(alias), set()).add(alias)

    evidence: list[ActorIdentityEvidence] = []
    exact_uuids = match_sets["attack_to_misp"].get(stix_id, set())
    for misp_uuid in sorted(exact_uuids):
        other_ids = sorted(match_sets["misp_to_attack"].get(misp_uuid, set()))
        collisions = len(exact_uuids) > 1 or len(other_ids) > 1
        shared_aliases = sorted({
            f"ATT&CK {attack_alias!r} ↔ MISP {misp_alias!r}"
            for misp_id, misp_alias, _url, _retrieved in misp_rows
            if misp_id == misp_uuid
            for attack_alias in alias_map.get(alias_matching.normalize(misp_alias), set())
        })
        source = next((row for row in misp_rows if row[0] == misp_uuid), None)
        evidence.append({
            "status": "collision" if collisions else "exact",
            "attack_id": attack_id,
            "attack_name": attack_name,
            "misp_uuid": misp_uuid,
            "misp_name": misp_names.get(misp_uuid),
            "match_score": 100.0,
            "attack_alias": "; ".join(shared_aliases) or None,
            "misp_alias": "; ".join(shared_aliases) or None,
            "shared_aliases": shared_aliases,
            "other_attack_names": [actor_map[other]["name"] for other in other_ids
                                   if other != stix_id and other in actor_map],
            "source_url": source[2] if source else None,
            "retrieved": str(source[3]) if source else None,
            "reason": None,
            "reviewed": None,
            "review_sources": [],
        })

    return evidence


def _alias_set(name: str, aliases_field: str | None) -> list[str]:
    """Normalize the semicolon-delimited ATT&CK alias field for matching."""
    aliases = (part.strip() for part in (aliases_field or "").split(";"))
    return sorted({name, *(alias for alias in aliases if alias)})


def _reviewed_identity_evidence(
    db: duckdb.DuckDBPyConnection, stix_id: str, attack_id: str, attack_name: str,
    reviews: dict[tuple[str, str], ManualReviewDetails],
) -> list[ActorIdentityEvidence]:
    rows = db.execute(
        "SELECT misp_uuid, misp_name, match_score, source_url, retrieved "
        "FROM actor_xwalk WHERE attack_stix_id = ? AND match_method = 'manual'",
        [stix_id],
    ).fetchall()
    result: list[ActorIdentityEvidence] = []
    for misp_uuid, misp_name, score, source_url, retrieved in rows:
        review = reviews.get((attack_id, misp_uuid))
        result.append({
            "status": "manual", "attack_id": attack_id, "attack_name": attack_name,
            "misp_uuid": misp_uuid, "misp_name": misp_name,
            "match_score": score, "attack_alias": None, "misp_alias": None,
            "shared_aliases": [], "other_attack_names": [],
            "source_url": source_url, "retrieved": str(retrieved),
            "reason": review["reason"] if review else None,
            "reviewed": review["reviewed"] if review else None,
            "review_sources": review["sources"] if review else [],
        })
    return result


def _rejected_identity_evidence(
    db: duckdb.DuckDBPyConnection, stix_id: str, attack_id: str, attack_name: str,
    reviews: dict[tuple[str, str], ManualReviewDetails],
) -> list[ActorIdentityEvidence]:
    rows = db.execute(
        "SELECT misp_uuid, misp_name, match_score, reason, reviewed "
        "FROM actor_xwalk_rejected WHERE attack_stix_id = ?", [stix_id],
    ).fetchall()
    result: list[ActorIdentityEvidence] = []
    for misp_uuid, misp_name, score, reason, reviewed in rows:
        review = reviews.get((attack_id, misp_uuid))
        result.append({
            "status": "rejected", "attack_id": attack_id, "attack_name": attack_name,
            "misp_uuid": misp_uuid, "misp_name": misp_name,
            "match_score": score, "attack_alias": None, "misp_alias": None,
            "shared_aliases": [], "other_attack_names": [], "source_url": None,
            "retrieved": None, "reason": reason, "reviewed": str(reviewed),
            "review_sources": review["sources"] if review else [],
        })
    return result


def _candidate_identity_evidence(
    db: duckdb.DuckDBPyConnection, stix_id: str, attack_id: str, attack_name: str
) -> list[ActorIdentityEvidence]:
    rows = db.execute(
        "SELECT misp_uuid, misp_name, match_score, matched_attack_alias, "
        "matched_misp_alias, source_url, retrieved FROM actor_xwalk_candidates "
        "WHERE attack_stix_id = ? ORDER BY match_score DESC, misp_name",
        [stix_id],
    ).fetchall()
    result: list[ActorIdentityEvidence] = []
    for uuid, misp_name, score, attack_alias, misp_alias, source_url, retrieved in rows:
        result.append({
            "status": "candidate", "attack_id": attack_id, "attack_name": attack_name,
            "misp_uuid": uuid, "misp_name": misp_name,
            "match_score": score, "attack_alias": attack_alias, "misp_alias": misp_alias,
            "shared_aliases": [], "other_attack_names": [],
            "source_url": source_url, "retrieved": str(retrieved),
            "reason": None, "reviewed": None, "review_sources": [],
        })
    return result


def _manual_review_details() -> dict[tuple[str, str], ManualReviewDetails]:
    """Load reviewer rationale and publisher links from the structured catalog."""
    path = pathlib.Path(__file__).resolve().parents[1] / "data/seed/actor_xwalk_manual.json"
    if not path.exists():
        return {}
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(records, list):
        return {}
    result: dict[tuple[str, str], ManualReviewDetails] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        attack_id = record.get("attack_id")
        misp_uuid = record.get("misp_uuid")
        sources = record.get("sources", [])
        if isinstance(attack_id, str) and isinstance(misp_uuid, str) and isinstance(sources, list):
            reason = record.get("reason")
            reviewed = record.get("reviewed")
            result[(attack_id, misp_uuid)] = {
                "reason": reason if isinstance(reason, str) else None,
                "reviewed": reviewed if isinstance(reviewed, str) else None,
                "sources": [source for source in sources if isinstance(source, str)],
            }
    return result


def actor_identity_evidence(
    db: duckdb.DuckDBPyConnection, stix_id: str
) -> tuple[bool, list[ActorIdentityEvidence]]:
    """Expose current alias matches and review states without treating names
    as attribution. Collisions are recomputed from source alias tables using
    the existing resolver's exact-match functions, never parsed from its
    generated Markdown report. `available` is false if any required persisted
    resolver table or source table is missing.
    """
    precondition(bool(stix_id), "stix_id must not be empty")
    required_tables = {
        "actor", "actor_alias", "misp_actor", "actor_xwalk",
        "actor_xwalk_candidates", "actor_xwalk_rejected",
    }
    table_rows = db.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_name IN "
        "('actor', 'actor_alias', 'misp_actor', 'actor_xwalk', "
        "'actor_xwalk_candidates', 'actor_xwalk_rejected')"
    ).fetchall()
    if {row[0] for row in table_rows} != required_tables:
        return False, []

    actor_row = db.execute(
        "SELECT attack_id, name FROM actor WHERE stix_id = ?", [stix_id]
    ).fetchone()
    if actor_row is None:
        return True, []
    attack_id, attack_name = actor_row
    attack_rows = db.execute(
        "SELECT stix_id, attack_id, name, aliases FROM actor"
    ).fetchall()
    attack_actors: list[alias_matching.AttackActor] = [
        {
            "stix_id": row[0], "attack_id": row[1], "name": row[2],
            "aliases": _alias_set(row[2], row[3]),
        }
        for row in attack_rows
    ]
    misp_rows = db.execute(
        "SELECT misp_uuid, alias, source_url, CAST(retrieved AS VARCHAR) FROM actor_alias"
    ).fetchall()
    misp_names = dict(db.execute(
        "SELECT misp_uuid, canonical_name FROM misp_actor"
    ).fetchall())
    match_sets = alias_matching.build_exact_match_sets(
        attack_actors, alias_matching.build_normalized_index(misp_rows)
    )
    evidence = _exact_identity_evidence(
        stix_id, attack_id, attack_name, attack_actors, misp_rows, misp_names, match_sets
    )
    reviews = _manual_review_details()

    evidence.extend(
        _reviewed_identity_evidence(db, stix_id, attack_id, attack_name, reviews)
    )
    evidence.extend(
        _rejected_identity_evidence(db, stix_id, attack_id, attack_name, reviews)
    )
    evidence.extend(_candidate_identity_evidence(db, stix_id, attack_id, attack_name))

    if not evidence:
        evidence.append({
            "status": "unmatched", "attack_id": attack_id, "attack_name": attack_name,
            "misp_uuid": None, "misp_name": None, "match_score": None,
            "attack_alias": None, "misp_alias": None, "shared_aliases": [],
            "other_attack_names": [], "source_url": None, "retrieved": None,
            "reason": (
                "No mutual exact match, reviewed mapping, rejected pair, or open "
                "fuzzy candidate is stored."
            ),
            "reviewed": None, "review_sources": [],
        })
    return True, evidence
