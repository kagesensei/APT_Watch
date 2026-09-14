import datetime

import duckdb
import misp_galaxy

from conftest import FIXTURES_DIR


def _load_fixture_values() -> list[misp_galaxy.ClusterValue]:
    cluster = misp_galaxy.load_cluster(FIXTURES_DIR / "misp_threat_actor_sample.json")
    return cluster["values"]


class TestDatedFilename:
    def test_includes_the_iso_date(self):
        assert misp_galaxy.dated_filename(datetime.date(2026, 9, 14)) == (
            "misp_threat-actor_2026-09-14.json"
        )


class TestLoadCluster:
    def test_reads_the_values_list(self):
        cluster = misp_galaxy.load_cluster(FIXTURES_DIR / "misp_threat_actor_sample.json")
        assert len(cluster["values"]) == 3
        assert cluster["values"][0]["value"] == "Test Actor Full"


class TestMispActorRows:
    def test_full_entry_has_every_field(self):
        values = _load_fixture_values()
        rows = misp_galaxy.misp_actor_rows(values, "https://example.com/source", "2026-09-14")
        full_row = next(r for r in rows if r[0] == "11111111-1111-1111-1111-111111111111")
        assert full_row == (
            "11111111-1111-1111-1111-111111111111",
            "Test Actor Full",
            "An actor entry with every optional field present.",
            "US",
            "https://example.com/one;https://example.com/two",
            "https://example.com/source",
            "2026-09-14",
        )

    def test_minimal_entry_has_none_for_absent_fields(self):
        values = _load_fixture_values()
        rows = misp_galaxy.misp_actor_rows(values, "https://example.com/source", "2026-09-14")
        minimal_row = next(r for r in rows if r[0] == "22222222-2222-2222-2222-222222222222")
        assert minimal_row == (
            "22222222-2222-2222-2222-222222222222",
            "Test Actor Minimal",
            None,   # description absent
            None,   # meta absent entirely -> country absent
            "",     # refs absent -> empty joined string, not None
            "https://example.com/source",
            "2026-09-14",
        )

    def test_row_count_matches_value_count(self):
        values = _load_fixture_values()
        rows = misp_galaxy.misp_actor_rows(values, "https://example.com/source", "2026-09-14")
        assert len(rows) == len(values) == 3


class TestActorAliasRows:
    def test_full_entry_gets_canonical_plus_each_synonym(self):
        values = _load_fixture_values()
        rows = misp_galaxy.actor_alias_rows(values, "https://example.com/source", "2026-09-14")
        full_uuid = "11111111-1111-1111-1111-111111111111"
        full_rows = [r for r in rows if r[0] == full_uuid]
        assert full_rows == [
            (full_uuid, "Test Actor Full", "canonical", "https://example.com/source", "2026-09-14"),
            (full_uuid, "Test Alias One", "synonym", "https://example.com/source", "2026-09-14"),
            (full_uuid, "Test Alias Two", "synonym", "https://example.com/source", "2026-09-14"),
        ]

    def test_entry_with_no_synonyms_field_gets_only_a_canonical_row(self):
        values = _load_fixture_values()
        rows = misp_galaxy.actor_alias_rows(values, "https://example.com/source", "2026-09-14")
        no_syn_uuid = "33333333-3333-3333-3333-333333333333"
        no_syn_rows = [r for r in rows if r[0] == no_syn_uuid]
        assert no_syn_rows == [
            (no_syn_uuid, "Test Actor No Synonyms", "canonical", "https://example.com/source", "2026-09-14"),
        ]

    def test_minimal_entry_with_no_meta_gets_only_a_canonical_row(self):
        values = _load_fixture_values()
        rows = misp_galaxy.actor_alias_rows(values, "https://example.com/source", "2026-09-14")
        minimal_uuid = "22222222-2222-2222-2222-222222222222"
        minimal_rows = [r for r in rows if r[0] == minimal_uuid]
        assert minimal_rows == [
            (minimal_uuid, "Test Actor Minimal", "canonical", "https://example.com/source", "2026-09-14"),
        ]


class TestQualityChecks:
    def test_check_actor_count_passes_when_counts_match(self):
        con = duckdb.connect(":memory:")
        values = _load_fixture_values()
        actor_rows = misp_galaxy.misp_actor_rows(values, "https://example.com", "2026-09-14")
        alias_rows = misp_galaxy.actor_alias_rows(values, "https://example.com", "2026-09-14")
        misp_galaxy.write_tables(con, actor_rows, alias_rows)

        assert misp_galaxy.check_actor_count(con, len(values)) is None

    def test_check_actor_count_fails_when_counts_differ(self):
        con = duckdb.connect(":memory:")
        values = _load_fixture_values()
        actor_rows = misp_galaxy.misp_actor_rows(values, "https://example.com", "2026-09-14")
        alias_rows = misp_galaxy.actor_alias_rows(values, "https://example.com", "2026-09-14")
        misp_galaxy.write_tables(con, actor_rows, alias_rows)

        assert misp_galaxy.check_actor_count(con, len(values) + 1) == "misp_actor row count"

    def test_check_uuid_uniqueness_passes_on_the_fixture(self):
        con = duckdb.connect(":memory:")
        values = _load_fixture_values()
        actor_rows = misp_galaxy.misp_actor_rows(values, "https://example.com", "2026-09-14")
        alias_rows = misp_galaxy.actor_alias_rows(values, "https://example.com", "2026-09-14")
        misp_galaxy.write_tables(con, actor_rows, alias_rows)

        assert misp_galaxy.check_uuid_uniqueness(con) is None

    def test_check_uuid_uniqueness_fails_on_a_duplicate(self):
        con = duckdb.connect(":memory:")
        values = _load_fixture_values()
        actor_rows = misp_galaxy.misp_actor_rows(values, "https://example.com", "2026-09-14")
        alias_rows = misp_galaxy.actor_alias_rows(values, "https://example.com", "2026-09-14")
        duplicated = actor_rows + [actor_rows[0]]
        misp_galaxy.write_tables(con, duplicated, alias_rows)

        assert misp_galaxy.check_uuid_uniqueness(con) == "misp_actor.misp_uuid uniqueness"
