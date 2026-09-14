"""Resolve MITRE ATT&CK actor identities against MISP Galaxy's threat-actor
cluster, producing a cross-walk between the two independently-maintained
name lists.

Two passes, in order:
1. Exact match after normalization (case/whitespace/punctuation-insensitive)
   between an ATT&CK actor's name+aliases and a MISP actor's canonical
   name+synonyms. Only a *mutual* one-to-one match (this ATT&CK actor
   matches exactly one MISP UUID, and that MISP UUID matches exactly this
   one ATT&CK actor) is written to actor_xwalk -- anything else (one ATT&CK
   actor matching several MISP UUIDs, or vice versa) is a naming collision
   that needs a human, not an algorithm, so it's reported instead of guessed
   at (see data/reports/alias_resolution.md).
2. RapidFuzz token_set_ratio (score >= FUZZY_THRESHOLD) for every ATT&CK
   actor left with zero exact matches. These are never written to
   actor_xwalk automatically -- only to actor_xwalk_candidates, for manual
   review and (if confirmed) promotion to actor_xwalk with
   match_method='manual'.

source_url/retrieved on both output tables are copied from the actor_alias
row that produced the match: that's the data this cross-walk is actually
built from, and the match is only as current as that data.
"""

import datetime
import pathlib
import re
import sys
from typing import TypedDict

import duckdb
from rapidfuzz import fuzz

ROOT = pathlib.Path(__file__).resolve().parents[1]

# resolve/aliases.py is run directly (`python resolve/aliases.py`), which
# puts only this directory on sys.path -- neither the project root (for
# contracts) nor ingest/ (for its shared DB_PATH/table_count/etc. helpers)
# would otherwise be importable. Both are added once, here.
for _extra_path in (ROOT, ROOT / "ingest"):
    if str(_extra_path) not in sys.path:
        sys.path.insert(0, str(_extra_path))

import common  # noqa: E402  pylint: disable=wrong-import-position

from contracts import precondition  # noqa: E402  pylint: disable=wrong-import-position

REPORT_PATH = ROOT / "data" / "reports" / "alias_resolution.md"

FUZZY_THRESHOLD = 90

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


def normalize(name: str) -> str:
    """Case/whitespace/punctuation-insensitive form of a name: lowercase
    with every non-alphanumeric character removed, so "APT-1", "APT 1",
    and "Apt1" all normalize to "apt1".
    """
    return _NON_ALNUM_RE.sub("", name.lower())


class AttackActor(TypedDict):
    """One ATT&CK actor and its full alias set (name + listed aliases)."""

    stix_id: str
    attack_id: str
    name: str
    aliases: list[str]


def _split_aliases(aliases_field: str | None) -> list[str]:
    return [a.strip() for a in (aliases_field or "").split(";") if a.strip()]


def load_attack_actors(db: duckdb.DuckDBPyConnection) -> list[AttackActor]:
    """Every ATT&CK actor, with its own name included in its alias set."""
    rows = db.execute("SELECT stix_id, attack_id, name, aliases FROM actor").fetchall()
    actors: list[AttackActor] = []
    for stix_id, attack_id, name, aliases_field in rows:
        alias_set = {name, *_split_aliases(aliases_field)}
        actors.append({
            "stix_id": stix_id,
            "attack_id": attack_id,
            "name": name,
            "aliases": sorted(alias_set),
        })
    return actors


MispAliasRow = tuple[str, str, str, str]  # (misp_uuid, alias, source_url, retrieved)


def load_misp_alias_rows(db: duckdb.DuckDBPyConnection) -> list[MispAliasRow]:
    """Every (misp_uuid, alias, source_url, retrieved) row to match against."""
    return db.execute("SELECT misp_uuid, alias, source_url, retrieved FROM actor_alias").fetchall()


def build_normalized_index(
    misp_rows: list[MispAliasRow],
) -> dict[str, set[str]]:
    """normalized alias string -> set of misp_uuids that use it (canonical or synonym)."""
    index: dict[str, set[str]] = {}
    for misp_uuid, alias, _source_url, _retrieved in misp_rows:
        index.setdefault(normalize(alias), set()).add(misp_uuid)
    return index


def exact_matches_for_actor(
    attack_aliases: list[str], normalized_index: dict[str, set[str]]
) -> set[str]:
    """Every misp_uuid sharing any normalized alias with this ATT&CK actor."""
    matched: set[str] = set()
    for alias in attack_aliases:
        matched.update(normalized_index.get(normalize(alias), set()))
    return matched


class ExactMatchSets(TypedDict):
    """The full bipartite exact-match relation, both directions."""

    attack_to_misp: dict[str, set[str]]
    misp_to_attack: dict[str, set[str]]


def build_exact_match_sets(
    attack_actors: list[AttackActor], normalized_index: dict[str, set[str]]
) -> ExactMatchSets:
    """Compute, for every ATT&CK actor, which misp_uuids it exact-matches --
    and the reverse map -- so 1-to-many/many-to-one cases are visible before
    anything is written to actor_xwalk.
    """
    attack_to_misp: dict[str, set[str]] = {}
    misp_to_attack: dict[str, set[str]] = {}
    for actor in attack_actors:
        matched = exact_matches_for_actor(actor["aliases"], normalized_index)
        attack_to_misp[actor["stix_id"]] = matched
        for misp_uuid in matched:
            misp_to_attack.setdefault(misp_uuid, set()).add(actor["stix_id"])
    return {"attack_to_misp": attack_to_misp, "misp_to_attack": misp_to_attack}


class Classified(TypedDict):
    """Every ATT&CK actor, sorted into exactly one of four buckets."""

    clean: list[tuple[AttackActor, str]]
    attack_side_ambiguous: list[AttackActor]
    misp_side_ambiguous: list[tuple[AttackActor, str]]
    unmatched: list[AttackActor]


def classify_exact_matches(
    attack_actors: list[AttackActor], match_sets: ExactMatchSets
) -> Classified:
    """Split ATT&CK actors by exact-match outcome:
    - clean: exactly one misp_uuid, and that misp_uuid matches only this actor.
    - attack_side_ambiguous: this actor matches more than one misp_uuid.
    - misp_side_ambiguous: this actor matches exactly one misp_uuid, but that
      misp_uuid also matches at least one other ATT&CK actor.
    - unmatched: no exact match at all -- goes on to the fuzzy pass.
    """
    clean: list[tuple[AttackActor, str]] = []
    attack_side_ambiguous: list[AttackActor] = []
    misp_side_ambiguous: list[tuple[AttackActor, str]] = []
    unmatched: list[AttackActor] = []
    for actor in attack_actors:
        misp_uuids = match_sets["attack_to_misp"][actor["stix_id"]]
        if not misp_uuids:
            unmatched.append(actor)
        elif len(misp_uuids) > 1:
            attack_side_ambiguous.append(actor)
        else:
            (only_uuid,) = misp_uuids
            if len(match_sets["misp_to_attack"][only_uuid]) == 1:
                clean.append((actor, only_uuid))
            else:
                misp_side_ambiguous.append((actor, only_uuid))
    return {
        "clean": clean,
        "attack_side_ambiguous": attack_side_ambiguous,
        "misp_side_ambiguous": misp_side_ambiguous,
        "unmatched": unmatched,
    }


def load_misp_names(db: duckdb.DuckDBPyConnection) -> dict[str, str]:
    """misp_uuid -> canonical_name, for labeling matches in output/reports."""
    rows = db.execute("SELECT misp_uuid, canonical_name FROM misp_actor").fetchall()
    return dict(rows)


XwalkRow = tuple[str, str, str, str, str, str, float, str, str]


def build_xwalk_rows(
    clean: list[tuple[AttackActor, str]],
    misp_names: dict[str, str],
    misp_source: dict[str, tuple[str, str]],
) -> list[XwalkRow]:
    """One actor_xwalk row per clean (mutual 1-to-1) exact match."""
    rows: list[XwalkRow] = []
    for actor, misp_uuid in clean:
        source_url, retrieved = misp_source[misp_uuid]
        rows.append((
            actor["stix_id"],
            actor["attack_id"],
            actor["name"],
            misp_uuid,
            misp_names.get(misp_uuid, misp_uuid),
            "exact",
            100.0,
            source_url,
            retrieved,
        ))
    return rows


def fuzzy_candidates_for_actor(
    actor: AttackActor, misp_rows: list[MispAliasRow]
) -> dict[str, tuple[str, str, float, str, str]]:
    """Best fuzzy match (attack_alias, misp_alias, score, source_url,
    retrieved) per candidate misp_uuid, keeping only scores >= FUZZY_THRESHOLD.
    """
    best: dict[str, tuple[str, str, float, str, str]] = {}
    for attack_alias in actor["aliases"]:
        attack_lower = attack_alias.lower()
        for misp_uuid, misp_alias, source_url, retrieved in misp_rows:
            score = fuzz.token_set_ratio(attack_lower, misp_alias.lower())
            if score < FUZZY_THRESHOLD:
                continue
            current = best.get(misp_uuid)
            if current is None or score > current[2]:
                best[misp_uuid] = (attack_alias, misp_alias, score, source_url, retrieved)
    return best


CandidateRow = tuple[str, str, str, str, str, str, float, str, str, str, str]


def build_candidate_rows(
    unmatched: list[AttackActor],
    misp_rows: list[MispAliasRow],
    misp_names: dict[str, str],
) -> list[CandidateRow]:
    """One actor_xwalk_candidates row per (unmatched ATT&CK actor, candidate
    misp_uuid) pair scoring >= FUZZY_THRESHOLD, sorted best-score first.
    """
    rows: list[CandidateRow] = []
    for actor in unmatched:
        for misp_uuid, (attack_alias, misp_alias, score, source_url, retrieved) in (
            fuzzy_candidates_for_actor(actor, misp_rows).items()
        ):
            rows.append((
                actor["stix_id"],
                actor["attack_id"],
                actor["name"],
                misp_uuid,
                misp_names.get(misp_uuid, misp_uuid),
                "fuzzy",
                float(score),
                attack_alias,
                misp_alias,
                source_url,
                retrieved,
            ))
    rows.sort(key=lambda r: r[6], reverse=True)
    return rows


def write_tables(
    con: duckdb.DuckDBPyConnection,
    xwalk_rows: list[XwalkRow],
    candidate_rows: list[CandidateRow],
) -> None:
    """Create (or replace) and populate actor_xwalk and actor_xwalk_candidates."""
    con.execute(
        "CREATE OR REPLACE TABLE actor_xwalk("
        "attack_stix_id VARCHAR, attack_id VARCHAR, attack_name VARCHAR, "
        "misp_uuid VARCHAR, misp_name VARCHAR, match_method VARCHAR, "
        "match_score DOUBLE, source_url VARCHAR, retrieved DATE)"
    )
    con.executemany("INSERT INTO actor_xwalk VALUES (?,?,?,?,?,?,?,?,?)", xwalk_rows)

    con.execute(
        "CREATE OR REPLACE TABLE actor_xwalk_candidates("
        "attack_stix_id VARCHAR, attack_id VARCHAR, attack_name VARCHAR, "
        "misp_uuid VARCHAR, misp_name VARCHAR, match_method VARCHAR, match_score DOUBLE, "
        "matched_attack_alias VARCHAR, matched_misp_alias VARCHAR, "
        "source_url VARCHAR, retrieved DATE)"
    )
    con.executemany(
        "INSERT INTO actor_xwalk_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?)", candidate_rows
    )


def check_unique_column(con: duckdb.DuckDBPyConnection, table: str, column: str) -> str | None:
    """No value in `column` may repeat within `table`. Returns a failure name, or None."""
    precondition(bool(table) and bool(column), "table and column must not be empty")
    total = common.table_count(con, table)
    # table/column are always one of the two literal call sites below, never external input.
    distinct_row = con.execute(
        f"SELECT COUNT(DISTINCT {column}) FROM {table}"  # nosec B608
    ).fetchone()
    distinct = distinct_row[0] if distinct_row else 0
    status = "PASS" if distinct == total else "FAIL"
    print(f"QC [{status}] {table}.{column} uniqueness: {distinct} distinct vs {total} total")
    return None if status == "PASS" else f"{table}.{column} uniqueness"


def _attack_label(actor: AttackActor) -> str:
    return f"{actor['attack_id']} {actor['name']} ({actor['stix_id']})"


def _misp_label(misp_uuid: str, misp_names: dict[str, str]) -> str:
    return f"{misp_names.get(misp_uuid, '?')} ({misp_uuid})"


def _render_summary(
    attack_actors: list[AttackActor],
    misp_row_count: int,
    misp_alias_row_count: int,
    classified: Classified,
    fuzzy_attack_count: int,
    misp_ambiguous_count: int,
    unmatched_no_candidates_count: int,
    generated: str,
) -> list[str]:
    return [
        "# Alias resolution report",
        "",
        f"Generated {generated} by `resolve/aliases.py`, matching "
        f"{len(attack_actors)} ATT&CK actors against {misp_row_count} MISP Galaxy "
        f"threat-actor cluster entries ({misp_alias_row_count} alias rows).",
        "",
        "## Summary",
        "",
        f"- Matched exactly, 1-to-1 (written to `actor_xwalk`): **{len(classified['clean'])}**",
        f"- Ambiguous: one ATT&CK group matched >1 MISP UUID: "
        f"**{len(classified['attack_side_ambiguous'])}**",
        f"- Ambiguous: one MISP UUID matched >1 ATT&CK group: **{misp_ambiguous_count}**",
        f"- Unmatched, with a fuzzy candidate >= {FUZZY_THRESHOLD} for review "
        f"(in `actor_xwalk_candidates`): **{fuzzy_attack_count}**",
        f"- Completely unmatched (no exact match, no fuzzy candidate >= {FUZZY_THRESHOLD}): "
        f"**{unmatched_no_candidates_count}**",
    ]


def _render_unmatched_section(unmatched_no_candidates: list[AttackActor]) -> list[str]:
    lines = [
        "",
        f"## Unmatched ATT&CK groups ({len(unmatched_no_candidates)})",
        "",
        "No exact match after normalization, and no fuzzy candidate scored "
        f">= {FUZZY_THRESHOLD} against any MISP entry.",
        "",
        "| ATT&CK ID | Name | STIX ID |",
        "|---|---|---|",
    ]
    for actor in sorted(unmatched_no_candidates, key=lambda a: a["attack_id"]):
        lines.append(f"| {actor['attack_id']} | {actor['name']} | {actor['stix_id']} |")
    return lines


def _render_fuzzy_section(candidate_rows: list[CandidateRow]) -> list[str]:
    lines = [
        "",
        f"## Fuzzy candidates ({len(candidate_rows)}) -- NOT written to `actor_xwalk`; "
        "review and promote manually",
        "",
        "| Score | ATT&CK ID | ATT&CK name | Matched ATT&CK alias | MISP name | "
        "Matched MISP alias | MISP UUID |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in candidate_rows:
        lines.append(
            f"| {row[6]:.0f} | {row[1]} | {row[2]} | {row[7]} | {row[4]} | {row[8]} | {row[3]} |"
        )
    return lines


def _render_attack_side_ambiguous(
    actors: list[AttackActor], match_sets: ExactMatchSets, misp_names: dict[str, str]
) -> list[str]:
    lines = [
        "",
        f"### One ATT&CK group matches more than one MISP UUID ({len(actors)})",
        "",
    ]
    if not actors:
        return lines + ["None."]
    for actor in sorted(actors, key=lambda a: a["attack_id"]):
        misp_uuids = sorted(match_sets["attack_to_misp"][actor["stix_id"]])
        labels = ", ".join(_misp_label(u, misp_names) for u in misp_uuids)
        lines.append(f"- {_attack_label(actor)} matches: {labels}")
    return lines


def _render_misp_side_ambiguous(
    misp_ambiguous_uuids: list[str],
    match_sets: ExactMatchSets,
    attack_by_id: dict[str, AttackActor],
    misp_names: dict[str, str],
) -> list[str]:
    lines = [
        "",
        f"### One MISP UUID matches more than one ATT&CK group ({len(misp_ambiguous_uuids)})",
        "",
    ]
    if not misp_ambiguous_uuids:
        return lines + ["None."]
    for misp_uuid in misp_ambiguous_uuids:
        attacker_ids = sorted(match_sets["misp_to_attack"][misp_uuid])
        labels = ", ".join(_attack_label(attack_by_id[sid]) for sid in attacker_ids)
        lines.append(f"- {_misp_label(misp_uuid, misp_names)} matches: {labels}")
    return lines


def build_report_markdown(
    generated: str,
    attack_actors: list[AttackActor],
    misp_row_count: int,
    misp_alias_row_count: int,
    classified: Classified,
    candidate_rows: list[CandidateRow],
    match_sets: ExactMatchSets,
    misp_names: dict[str, str],
) -> str:
    """Render the human-review report: counts, unmatched groups, fuzzy
    candidates, and every 1-to-many/many-to-one exact-match collision.
    """
    fuzzy_attack_ids = {row[0] for row in candidate_rows}
    unmatched_no_candidates = [
        a for a in classified["unmatched"] if a["stix_id"] not in fuzzy_attack_ids
    ]
    misp_ambiguous_uuids = sorted(
        uuid for uuid, attackers in match_sets["misp_to_attack"].items() if len(attackers) > 1
    )

    lines = _render_summary(
        attack_actors, misp_row_count, misp_alias_row_count, classified,
        len(fuzzy_attack_ids), len(misp_ambiguous_uuids), len(unmatched_no_candidates), generated,
    )
    lines += _render_unmatched_section(unmatched_no_candidates)
    lines += _render_fuzzy_section(candidate_rows)
    lines += ["", "## Ambiguous matches"]
    lines += _render_attack_side_ambiguous(
        classified["attack_side_ambiguous"], match_sets, misp_names
    )
    lines += _render_misp_side_ambiguous(
        misp_ambiguous_uuids, match_sets, {a["stix_id"]: a for a in attack_actors}, misp_names
    )
    lines.append("")
    return "\n".join(lines)


class ResolutionResult(TypedDict):
    """Everything needed to write the output tables and render the report."""

    attack_actors: list[AttackActor]
    misp_names: dict[str, str]
    misp_row_count: int
    misp_alias_row_count: int
    classified: Classified
    match_sets: ExactMatchSets
    xwalk_rows: list[XwalkRow]
    candidate_rows: list[CandidateRow]


def build_misp_source_index(misp_rows: list[MispAliasRow]) -> dict[str, tuple[str, str]]:
    """misp_uuid -> (source_url, retrieved), from its first actor_alias row
    (every row for one misp_uuid carries the same values, from one ingest run).
    """
    index: dict[str, tuple[str, str]] = {}
    for misp_uuid, _alias, source_url, retrieved in misp_rows:
        index.setdefault(misp_uuid, (source_url, retrieved))
    return index


def resolve_actors(con: duckdb.DuckDBPyConnection) -> ResolutionResult:
    """Run both matching passes; return everything main() needs to act on."""
    attack_actors = load_attack_actors(con)
    misp_rows = load_misp_alias_rows(con)
    misp_names = load_misp_names(con)

    normalized_index = build_normalized_index(misp_rows)
    match_sets = build_exact_match_sets(attack_actors, normalized_index)
    classified = classify_exact_matches(attack_actors, match_sets)

    misp_source = build_misp_source_index(misp_rows)
    xwalk_rows = build_xwalk_rows(classified["clean"], misp_names, misp_source)
    candidate_rows = build_candidate_rows(classified["unmatched"], misp_rows, misp_names)

    return {
        "attack_actors": attack_actors,
        "misp_names": misp_names,
        "misp_row_count": common.table_count(con, "misp_actor"),
        "misp_alias_row_count": len(misp_rows),
        "classified": classified,
        "match_sets": match_sets,
        "xwalk_rows": xwalk_rows,
        "candidate_rows": candidate_rows,
    }


def write_report(result: ResolutionResult) -> None:
    """Render and write data/reports/alias_resolution.md."""
    generated_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    report = build_report_markdown(
        generated_str,
        result["attack_actors"],
        result["misp_row_count"],
        result["misp_alias_row_count"],
        result["classified"],
        result["candidate_rows"],
        result["match_sets"],
        result["misp_names"],
    )
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"Report written to {REPORT_PATH}")


def main() -> None:
    """Resolve ATT&CK actors against the MISP galaxy cross-walk and report."""
    con = duckdb.connect(str(common.DB_PATH))
    result = resolve_actors(con)

    write_tables(con, result["xwalk_rows"], result["candidate_rows"])
    common.print_table_counts(con, ["actor_xwalk", "actor_xwalk_candidates"])

    failures = [
        failure
        for failure in (
            check_unique_column(con, "actor_xwalk", "attack_stix_id"),
            check_unique_column(con, "actor_xwalk", "misp_uuid"),
        )
        if failure
    ]

    write_report(result)
    common.fail_if_any(failures)


if __name__ == "__main__":
    main()
