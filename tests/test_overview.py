"""Overview filters use source attribution, never inferred activity rankings."""

import duckdb

from app import nlp, overview


def test_country_examples_are_filtered_and_snapshot_is_disclosed():
    with duckdb.connect(":memory:") as db:
        db.execute("CREATE TABLE misp_actor(canonical_name VARCHAR, country VARCHAR, "
                   "retrieved DATE, source_url VARCHAR, misp_uuid VARCHAR)")
        db.executemany("INSERT INTO misp_actor VALUES (?, ?, ?, ?, ?)", [
            ("Example CN", "CN", "2026-09-01", "https://example.test/source", "cn"),
            ("Example RU", "RU", "2026-09-01", "https://example.test/source", "ru"),
            ("Unlinked CN", "CN", "2026-09-01", "https://example.test/source", "other"),
        ])
        db.execute("CREATE TABLE actor_xwalk(misp_uuid VARCHAR)")
        db.execute("INSERT INTO actor_xwalk VALUES ('cn'), ('ru')")
        facts = overview.actor_facts("Which Chinese APT groups are most active?", db)
        assert "no dated incident counts" in facts[0]["text"]
        assert "not an activity ranking" in facts[0]["text"]
        assert len(facts) == 2
        assert "Example CN" in facts[1]["text"]
        assert "2026-09-01" in facts[1]["text"]
        assert facts[1]["source"]["url"] == "https://example.test/source"
        answer = overview.render_answer(facts)
        assert "Example CN" in answer
        assert "Example RU" not in answer
        assert "Unlinked CN" not in answer
        assert "2026-09-01" in answer
        assert nlp.actor_country("Russian APT groups") == "RU"
        assert nlp.actor_country("French APT groups") is None


def test_kev_scope_reports_catalog_date_without_claiming_live_freshness():
    with duckdb.connect(":memory:") as db:
        db.execute("CREATE TABLE kev(date_added VARCHAR)")
        db.execute("INSERT INTO kev VALUES ('2026-01-01'), ('2026-02-01')")
        text = overview.kev_scope(db)["text"]
        assert "2026-02-01" in text
        assert "not a live ranking" in text
        assert "does not rank all CVEs by CVSS" in text


def test_narrow_lookup_still_uses_llm():
    assert overview.render_answer([]) is None
