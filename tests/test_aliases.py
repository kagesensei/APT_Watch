import json

import aliases
import duckdb
import pytest

from conftest import FIXTURES_DIR

SOURCE_URL = "https://example.com/misp-fixture"
RETRIEVED = "2026-09-14"


@pytest.fixture()
def resolve_db() -> duckdb.DuckDBPyConnection:
    """An in-memory DB with tiny actor/misp_actor/actor_alias fixture data
    covering: a clean match via canonical name, a clean match via synonym,
    a near-miss spelling (fuzzy candidate), one ATT&CK group matching two
    MISP UUIDs, two ATT&CK groups matching one MISP UUID, and one
    completely unmatched group. Never a live download.
    """
    con = duckdb.connect(":memory:")
    con.execute(
        "CREATE TABLE actor(stix_id VARCHAR, attack_id VARCHAR, name VARCHAR, aliases VARCHAR)"
    )
    attack_actors = json.loads(
        (FIXTURES_DIR / "resolve_attack_actors.json").read_text(encoding="utf-8")
    )
    con.executemany(
        "INSERT INTO actor VALUES (?,?,?,?)",
        [(a["stix_id"], a["attack_id"], a["name"], a["aliases"]) for a in attack_actors],
    )

    con.execute(
        "CREATE TABLE misp_actor(misp_uuid VARCHAR, canonical_name VARCHAR, description VARCHAR, "
        "country VARCHAR, refs VARCHAR, source_url VARCHAR, retrieved DATE)"
    )
    con.execute(
        "CREATE TABLE actor_alias(misp_uuid VARCHAR, alias VARCHAR, alias_type VARCHAR, "
        "source_url VARCHAR, retrieved DATE)"
    )
    misp_entries = json.loads(
        (FIXTURES_DIR / "resolve_misp_actors.json").read_text(encoding="utf-8")
    )
    for entry in misp_entries:
        con.execute(
            "INSERT INTO misp_actor VALUES (?,?,?,?,?,?,?)",
            [entry["misp_uuid"], entry["canonical_name"], None, None, "", SOURCE_URL, RETRIEVED],
        )
        con.execute(
            "INSERT INTO actor_alias VALUES (?,?,?,?,?)",
            [entry["misp_uuid"], entry["canonical_name"], "canonical", SOURCE_URL, RETRIEVED],
        )
        for synonym in entry["synonyms"]:
            con.execute(
                "INSERT INTO actor_alias VALUES (?,?,?,?,?)",
                [entry["misp_uuid"], synonym, "synonym", SOURCE_URL, RETRIEVED],
            )
    return con


class TestNormalize:
    def test_lowercases_strips_whitespace_and_punctuation(self):
        assert aliases.normalize("  APT-1  ") == "apt1"
        assert aliases.normalize("PLA Unit 61398") == "plaunit61398"

    def test_different_forms_normalize_the_same(self):
        assert aliases.normalize("APT-1") == aliases.normalize("APT 1") == aliases.normalize("apt1")


class TestResolveActors:
    def test_clean_exact_match_via_canonical_name(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        clean_ids = {actor["stix_id"] for actor, _uuid in result["classified"]["clean"]}
        assert "intrusion-set--alpha" in clean_ids

    def test_clean_exact_match_via_synonym(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        clean_map = dict(
            (actor["stix_id"], uuid) for actor, uuid in result["classified"]["clean"]
        )
        assert clean_map.get("intrusion-set--beta") == "misp-beta-uuid"

    def test_attack_side_ambiguous_when_one_actor_matches_two_uuids(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        ambiguous_ids = {a["stix_id"] for a in result["classified"]["attack_side_ambiguous"]}
        assert "intrusion-set--gamma" in ambiguous_ids

    def test_misp_side_ambiguous_when_two_actors_share_one_uuid(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        misp_side_ids = {a["stix_id"] for a, _uuid in result["classified"]["misp_side_ambiguous"]}
        assert {"intrusion-set--delta", "intrusion-set--epsilon"} <= misp_side_ids

    def test_fuzzy_candidate_found_for_near_miss_spelling(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        candidate_ids = {row[0] for row in result["candidate_rows"]}
        assert "intrusion-set--betaa" in candidate_ids
        row = next(r for r in result["candidate_rows"] if r[0] == "intrusion-set--betaa")
        assert row[6] >= aliases.FUZZY_THRESHOLD

    def test_completely_unmatched_group_has_no_exact_or_fuzzy_match(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        unmatched_ids = {a["stix_id"] for a in result["classified"]["unmatched"]}
        candidate_ids = {row[0] for row in result["candidate_rows"]}
        assert "intrusion-set--zeta" in unmatched_ids
        assert "intrusion-set--zeta" not in candidate_ids

    def test_xwalk_rows_written_only_for_clean_matches(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        assert len(result["xwalk_rows"]) == len(result["classified"]["clean"])
        xwalk_stix_ids = {row[0] for row in result["xwalk_rows"]}
        assert "intrusion-set--gamma" not in xwalk_stix_ids
        assert "intrusion-set--delta" not in xwalk_stix_ids
        assert "intrusion-set--epsilon" not in xwalk_stix_ids


class TestQualityChecks:
    def test_no_duplicate_attack_stix_id_or_misp_uuid_in_xwalk(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        aliases.write_tables(resolve_db, result["xwalk_rows"], result["candidate_rows"])
        assert aliases.check_unique_column(resolve_db, "actor_xwalk", "attack_stix_id") is None
        assert aliases.check_unique_column(resolve_db, "actor_xwalk", "misp_uuid") is None


class TestReportMarkdown:
    def test_report_contains_expected_sections_and_names(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        report = aliases.build_report_markdown(
            "2026-09-14",
            result["attack_actors"],
            result["misp_row_count"],
            result["misp_alias_row_count"],
            result["classified"],
            result["candidate_rows"],
            result["match_sets"],
            result["misp_names"],
        )
        assert "# Alias resolution report" in report
        assert "## Summary" in report
        assert "Betaa Groupp" in report          # fuzzy candidate
        assert "Totally Unmatched Group" in report  # unmatched
        assert "Test Group Gamma" in report          # attack-side ambiguous
