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
        aliases.write_tables(
            resolve_db, result["xwalk_rows"], result["candidate_rows"], result["rejected_rows"]
        )
        assert aliases.check_unique_column(resolve_db, "actor_xwalk", "attack_stix_id") is None
        assert aliases.check_unique_column(resolve_db, "actor_xwalk", "misp_uuid") is None

    def test_write_tables_handles_all_empty_lists(self, resolve_db):
        aliases.write_tables(resolve_db, [], [], [])
        assert resolve_db.execute("SELECT COUNT(*) FROM actor_xwalk").fetchone()[0] == 0
        assert resolve_db.execute("SELECT COUNT(*) FROM actor_xwalk_candidates").fetchone()[0] == 0
        assert resolve_db.execute("SELECT COUNT(*) FROM actor_xwalk_rejected").fetchone()[0] == 0


class TestReportMarkdown:
    def test_report_contains_expected_sections_and_names(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        report = aliases.build_report_markdown(result, "2026-09-14")
        assert "# Alias resolution report" in report
        assert "## Summary" in report
        assert "Betaa Groupp" in report          # fuzzy candidate
        assert "Totally Unmatched Group" in report  # unmatched
        assert "Test Group Gamma" in report          # attack-side ambiguous


class TestManualReviews:
    ATTACK_ACTORS = [
        {"stix_id": "intrusion-set--x", "attack_id": "G0001", "name": "X", "aliases": ["X"]},
        {"stix_id": "intrusion-set--y", "attack_id": "G0002", "name": "Y", "aliases": ["Y"]},
    ]
    MISP_NAMES = {"uuid-1": "MispX", "uuid-2": "MispY"}
    MISP_SOURCE = {
        "uuid-1": ("https://example.com/x", "2026-01-01"),
        "uuid-2": ("https://example.com/y", "2026-01-02"),
    }
    CANDIDATE_ROWS = [
        (
            "intrusion-set--x", "G0001", "X", "uuid-1", "MispX", "fuzzy", 92.0,
            "X", "MispX Alias", "https://example.com/x", "2026-01-01",
        ),
        (
            "intrusion-set--y", "G0002", "Y", "uuid-2", "MispY", "fuzzy", 91.0,
            "Y", "MispY Alias", "https://example.com/y", "2026-01-02",
        ),
    ]

    def test_load_manual_reviews_returns_empty_list_when_file_missing(self, tmp_path):
        assert aliases.load_manual_reviews(tmp_path / "does_not_exist.json") == []

    def test_load_manual_reviews_parses_existing_file(self, tmp_path):
        path = tmp_path / "manual.json"
        path.write_text(
            json.dumps([{
                "attack_id": "G0001", "misp_uuid": "uuid-1", "decision": "promoted",
                "match_score": 90.0, "reason": "r", "sources": ["https://example.com"],
                "reviewed": "2026-09-14",
            }]),
            encoding="utf-8",
        )
        reviews = aliases.load_manual_reviews(path)
        assert reviews[0]["attack_id"] == "G0001"

    def test_promoted_review_becomes_xwalk_row_and_leaves_candidates(self):
        reviews = [{
            "attack_id": "G0001", "misp_uuid": "uuid-1", "decision": "promoted",
            "match_score": 92.0, "reason": "test reason", "sources": ["https://example.com/x"],
            "reviewed": "2026-09-14",
        }]
        result = aliases.apply_manual_reviews(
            reviews, self.ATTACK_ACTORS, self.MISP_NAMES, self.MISP_SOURCE, self.CANDIDATE_ROWS
        )
        assert len(result["xwalk_rows"]) == 1
        row = result["xwalk_rows"][0]
        assert row[:6] == ("intrusion-set--x", "G0001", "X", "uuid-1", "MispX", "manual")
        assert result["rejected_rows"] == []
        assert result["invalid_references"] == []
        remaining_ids = {row[0] for row in result["remaining_candidates"]}
        assert "intrusion-set--x" not in remaining_ids
        assert "intrusion-set--y" in remaining_ids

    def test_rejected_review_becomes_rejected_row_and_removes_candidate(self):
        reviews = [{
            "attack_id": "G0002", "misp_uuid": "uuid-2", "decision": "rejected",
            "match_score": 91.0, "reason": "test rejection", "sources": ["https://example.com/y"],
            "reviewed": "2026-09-14",
        }]
        result = aliases.apply_manual_reviews(
            reviews, self.ATTACK_ACTORS, self.MISP_NAMES, self.MISP_SOURCE, self.CANDIDATE_ROWS
        )
        assert result["xwalk_rows"] == []
        assert len(result["rejected_rows"]) == 1
        row = result["rejected_rows"][0]
        assert row[:5] == ("intrusion-set--y", "G0002", "Y", "uuid-2", "MispY")
        assert result["invalid_references"] == []
        remaining_ids = {row[0] for row in result["remaining_candidates"]}
        assert remaining_ids == {"intrusion-set--x"}

    def test_unknown_attack_id_misp_uuid_or_decision_are_flagged_invalid(self):
        reviews = [
            {
                "attack_id": "G9999", "misp_uuid": "uuid-1", "decision": "promoted",
                "match_score": 100.0, "reason": "r", "sources": [], "reviewed": "2026-09-14",
            },
            {
                "attack_id": "G0001", "misp_uuid": "uuid-unknown", "decision": "promoted",
                "match_score": 100.0, "reason": "r", "sources": [], "reviewed": "2026-09-14",
            },
            {
                "attack_id": "G0001", "misp_uuid": "uuid-1", "decision": "maybe",
                "match_score": 100.0, "reason": "r", "sources": [], "reviewed": "2026-09-14",
            },
        ]
        result = aliases.apply_manual_reviews(
            reviews, self.ATTACK_ACTORS, self.MISP_NAMES, self.MISP_SOURCE, []
        )
        assert result["xwalk_rows"] == []
        assert result["rejected_rows"] == []
        assert len(result["invalid_references"]) == 3

    def test_resolve_actors_applies_manual_reviews_from_seed_file(
        self, resolve_db, tmp_path, monkeypatch
    ):
        # G9006/zeta has no exact or fuzzy match in the resolve_db fixture;
        # a manual review should still be able to promote it.
        manual_path = tmp_path / "actor_xwalk_manual.json"
        manual_path.write_text(
            json.dumps([{
                "attack_id": "G9006", "misp_uuid": "misp-alpha-uuid", "decision": "promoted",
                "match_score": 90.0, "reason": "test", "sources": ["https://example.com"],
                "reviewed": "2026-09-14",
            }]),
            encoding="utf-8",
        )
        monkeypatch.setattr(aliases, "MANUAL_REVIEW_PATH", manual_path)
        result = aliases.resolve_actors(resolve_db)
        assert any(row[0] == "intrusion-set--zeta" for row in result["xwalk_rows"])
        assert result["invalid_manual_references"] == []

    def test_manually_reviewed_actor_is_excluded_from_unmatched_section(self, resolve_db):
        result = aliases.resolve_actors(resolve_db)
        result = dict(result)
        result["manual_reviews"] = list(result["manual_reviews"]) + [{
            "attack_id": "G9006", "misp_uuid": "misp-alpha-uuid", "decision": "promoted",
            "match_score": 90.0, "reason": "synthetic test promotion",
            "sources": ["https://example.com"], "reviewed": "2026-09-14",
        }]
        report = aliases.build_report_markdown(result, "2026-09-14")
        unmatched_section = report.split("## Open fuzzy candidates")[0]
        assert "Totally Unmatched Group" not in unmatched_section
        manual_section = report.split("## Manually reviewed")[1].split("## Ambiguous matches")[0]
        assert "Totally Unmatched Group" in manual_section
