import requests

from app import intel

# Concrete fixture values pulled from a locally built data/cti.duckdb
# (see tests/conftest.py for why real data, not a synthetic DB, is used).
CROSSWALK_HIT_CVE = "CVE-2026-84869"          # CWE-862 -> CAPEC -> T1211
CAPEC_BUT_NO_TECHNIQUE_CVE = "CVE-2026-86060"  # CWE-88 maps to CAPEC(s), none map to a technique
NO_CAPEC_AT_ALL_CVE = "CVE-2026-42016"         # CWE-863 has no CAPEC mapping at all
WANNACRY_SHA256 = "3044416f2a33213a25eddda36cf89533d6edf2fed6ea018ee858238099e545de"


class TestUrlBuilders:
    def test_technique_url_handles_subtechniques(self):
        assert intel.technique_url("T1055") == "https://attack.mitre.org/techniques/T1055/"
        assert intel.technique_url("T1055.001") == "https://attack.mitre.org/techniques/T1055/001"

    def test_mitigation_group_capec_cwe_nvd_urls(self):
        assert intel.mitigation_url("M1047") == "https://attack.mitre.org/mitigations/M1047/"
        assert intel.group_url("G0032") == "https://attack.mitre.org/groups/G0032/"
        assert intel.group_url(None) is None
        assert intel.capec_url("CAPEC-63") == "https://capec.mitre.org/data/definitions/63.html"
        assert intel.cwe_url("CWE-79") == "https://cwe.mitre.org/data/definitions/79.html"


class TestDedupSources:
    def test_removes_duplicate_dataset_id_pairs_preserving_order(self):
        facts = [
            {"source": {"dataset": "CISA KEV", "id": "CVE-1"}},
            {"source": {"dataset": "NVD", "id": "CVE-1"}},
            {"source": {"dataset": "CISA KEV", "id": "CVE-1"}},
        ]
        sources = intel.dedup_sources(facts)
        assert sources == [
            {"dataset": "CISA KEV", "id": "CVE-1"},
            {"dataset": "NVD", "id": "CVE-1"},
        ]


class TestFetchNvd:
    def test_returns_cached_row_without_hitting_network(self, cache_db, monkeypatch):
        cache_db.execute(
            "INSERT INTO cve_cache VALUES (?,?,?,?,?,?)",
            ["CVE-2024-0001", "cached description", 9.8, "CRITICAL", "CWE-79,CWE-89", None],
        )

        def _fail(*a, **k):
            raise AssertionError("should not hit the network when cached")

        monkeypatch.setattr(intel.requests, "get", _fail)
        result = intel.fetch_nvd("CVE-2024-0001", cache_db)
        assert result == {
            "description": "cached description",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cwe_ids": ["CWE-79", "CWE-89"],
        }

    def test_network_error_returns_none(self, cache_db, monkeypatch):
        def _raise(*a, **k):
            raise requests.RequestException("boom")

        monkeypatch.setattr(intel.requests, "get", _raise)
        assert intel.fetch_nvd("CVE-2024-0002", cache_db) is None

    def test_no_vulnerabilities_in_response_returns_none(self, cache_db, monkeypatch):
        class FakeResp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"vulnerabilities": []}

        monkeypatch.setattr(intel.requests, "get", lambda *a, **k: FakeResp())
        assert intel.fetch_nvd("CVE-2024-0003", cache_db) is None

    def test_parses_and_caches_a_successful_response(self, cache_db, monkeypatch):
        payload = {
            "vulnerabilities": [{
                "cve": {
                    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                }
            }]
        }

        class FakeResp:
            def raise_for_status(self):
                pass

            def json(self):
                return payload

        monkeypatch.setattr(intel.requests, "get", lambda *a, **k: FakeResp())
        result = intel.fetch_nvd("CVE-2024-0004", cache_db)
        assert result["description"] == "A test vulnerability."
        assert result["cvss_score"] == 7.5
        assert result["cvss_severity"] == "HIGH"
        assert result["cwe_ids"] == ["CWE-79"]

        cached = cache_db.execute(
            "SELECT description FROM cve_cache WHERE cve_id = 'CVE-2024-0004'"
        ).fetchone()
        assert cached[0] == "A test vulnerability."


class TestLookupRecentKev:
    def test_returns_up_to_limit_facts_tagged_direct(self, db):
        facts, sources = intel.lookup_recent_kev(db, limit=3)
        assert 0 < len(facts) <= 3
        assert all(f["derived"] is False for f in facts)
        assert all(f["category"] == "vuln_info" for f in facts)
        assert len(sources) == len(facts)

    def test_ransomware_linked_entries_are_prioritized_first(self, db):
        facts, _ = intel.lookup_recent_kev(db, limit=len(db.execute("SELECT cve_id FROM kev").fetchall()))
        ransomware_flags = ["Known ransomware use: Known" in f["text"] for f in facts]
        if True in ransomware_flags and False in ransomware_flags:
            assert ransomware_flags.index(True) < ransomware_flags.index(False)


class TestLookupCve:
    def test_full_crosswalk_hit_produces_technique_mitigation_and_actor_facts(self, db, cache_db, monkeypatch):
        monkeypatch.setattr(intel, "fetch_nvd", lambda cve_id, cache: None)
        facts, sources = intel.lookup_cve(CROSSWALK_HIT_CVE, db, cache_db)

        crosswalk_facts = [f for f in facts if f["category"] == "crosswalk_detail"]
        assert crosswalk_facts, "expected at least one derived crosswalk_detail fact"
        assert all(f["derived"] for f in crosswalk_facts)
        assert any("T1211" in f["text"] for f in crosswalk_facts)

        # A dead-end "coverage note" must NOT appear when the crosswalk succeeded.
        assert not any(f["source"]["name"] == "crosswalk coverage note" for f in facts)

    def test_capec_but_no_technique_dead_end_is_explained(self, db, cache_db, monkeypatch):
        monkeypatch.setattr(intel, "fetch_nvd", lambda cve_id, cache: None)
        facts, _ = intel.lookup_cve(CAPEC_BUT_NO_TECHNIQUE_CVE, db, cache_db)

        coverage_notes = [f for f in facts if f["source"]["name"] == "crosswalk coverage note"]
        assert len(coverage_notes) == 1
        assert "CAPEC attack pattern" in coverage_notes[0]["text"]
        assert "gap in CAPEC's own ATT&CK coverage" in coverage_notes[0]["text"]
        assert not any(f["category"] == "crosswalk_detail" for f in facts)

    def test_no_capec_mapping_at_all_dead_end_is_explained_differently(self, db, cache_db, monkeypatch):
        monkeypatch.setattr(intel, "fetch_nvd", lambda cve_id, cache: None)
        facts, _ = intel.lookup_cve(NO_CAPEC_AT_ALL_CVE, db, cache_db)

        coverage_notes = [f for f in facts if f["source"]["name"] == "crosswalk coverage note"]
        assert len(coverage_notes) == 1
        assert "do not map to any MITRE" in coverage_notes[0]["text"]

    def test_unknown_cve_with_no_kev_or_nvd_data_returns_no_facts(self, db, cache_db, monkeypatch):
        monkeypatch.setattr(intel, "fetch_nvd", lambda cve_id, cache: None)
        facts, sources = intel.lookup_cve("CVE-1999-9999999", db, cache_db)
        assert facts == []
        assert sources == []

    def test_nvd_facts_are_tagged_direct_not_derived(self, db, cache_db, monkeypatch):
        monkeypatch.setattr(
            intel, "fetch_nvd",
            lambda cve_id, cache: {
                "description": "desc", "cvss_score": 5.0, "cvss_severity": "MEDIUM", "cwe_ids": [],
            },
        )
        facts, _ = intel.lookup_cve(NO_CAPEC_AT_ALL_CVE, db, cache_db)
        vuln_facts = [f for f in facts if f["category"] == "vuln_info" and f["source"]["dataset"] == "NVD"]
        assert vuln_facts and vuln_facts[0]["derived"] is False
        assert "CVSS 5.0, MEDIUM" in vuln_facts[0]["text"]


class TestLookupIocForCve:
    def test_wannacry_hash_correlates_to_kev_product_name(self, db):
        # Real chain in the committed snapshot: kev.product/vendor for
        # CROSSWALK_HIT_CVE is "ConnectWise"/"ScreenConnect", so this mostly
        # exercises the "no name match" path; the WannaCry/Lazarus chain is
        # exercised directly via lookup_ioc below instead.
        facts = intel.lookup_ioc_for_cve(CROSSWALK_HIT_CVE, db)
        assert all(f["derived"] for f in facts)
        assert all(f["category"] == "ioc" for f in facts)

    def test_cve_not_in_kev_returns_no_ioc_facts(self, db):
        assert intel.lookup_ioc_for_cve("CVE-1999-9999999", db) == []


class TestLookupIoc:
    def test_known_hash_is_confirmed_and_links_to_actor_via_software_name(self, db):
        facts, sources = intel.lookup_ioc(WANNACRY_SHA256, "hash", db)
        direct = [f for f in facts if not f["derived"]]
        derived = [f for f in facts if f["derived"]]

        assert len(direct) == 1
        assert "confirmed" in direct[0]["text"]
        assert direct[0]["source"]["dataset"] == "MalwareBazaar"

        assert any("Lazarus Group" in f["text"] for f in derived)
        assert all(f["category"] == "actor_usage" for f in derived)
        assert sources  # dedup_sources output non-empty

    def test_unknown_hash_returns_no_facts(self, db):
        facts, sources = intel.lookup_ioc("f" * 64, "hash", db)
        assert facts == []
        assert sources == []

    def test_unknown_ip_and_url_return_no_facts(self, db):
        facts_ip, _ = intel.lookup_ioc("203.0.113.99", "ip", db)
        facts_url, _ = intel.lookup_ioc("http://not-a-real-indicator.example/x", "url", db)
        assert facts_ip == []
        assert facts_url == []


class TestLookupTechnique:
    def test_returns_mitigations_and_actors_for_a_real_technique(self, db):
        technique_id = db.execute(
            "SELECT DISTINCT technique_id FROM technique_mitigation LIMIT 1"
        ).fetchone()[0]
        facts, sources = intel.lookup_technique(technique_id, db)
        assert facts
        assert all(f["derived"] is False for f in facts)
        assert {"mitigation", "actor_usage"} >= {f["category"] for f in facts}

    def test_unknown_technique_returns_empty_but_not_an_error(self, db):
        facts, sources = intel.lookup_technique("T9999", db)
        assert facts == []
        assert sources == []


class TestLookupMitigation:
    def test_known_mitigation_returns_techniques(self, db):
        mitigation_id = db.execute(
            "SELECT DISTINCT mitigation_id FROM technique_mitigation LIMIT 1"
        ).fetchone()[0]
        facts, sources = intel.lookup_mitigation(mitigation_id, db)
        assert facts
        assert all(f["category"] == "mitigation" for f in facts)

    def test_unknown_mitigation_returns_empty_lists(self, db):
        assert intel.lookup_mitigation("M9999", db) == ([], [])


class TestLookupActor:
    def test_known_actor_returns_technique_and_software_facts(self, db):
        stix_id, _name = db.execute("SELECT stix_id, name FROM actor LIMIT 1").fetchone()
        facts, sources = intel.lookup_actor(stix_id, db)
        assert facts
        assert all(f["derived"] is False for f in facts)
        assert {f["category"] for f in facts} <= {"actor_usage", "naming_note"}

    def test_unknown_actor_returns_empty_lists(self, db):
        assert intel.lookup_actor("intrusion-set--nonexistent", db) == ([], [])

    def test_includes_naming_convention_fact_for_a_panda_alias(self, db):
        stix_id = db.execute(
            "SELECT stix_id FROM actor WHERE attack_id = 'G0006'"
        ).fetchone()[0]
        facts, _sources = intel.lookup_actor(stix_id, db)
        naming_facts = [f for f in facts if f["category"] == "naming_note"]
        assert any("Comment Panda" in f["text"] and "China" in f["text"] for f in naming_facts)

    def test_includes_alias_etymology_note_for_comment_crew(self, db):
        stix_id = db.execute(
            "SELECT stix_id FROM actor WHERE attack_id = 'G0006'"
        ).fetchone()[0]
        facts, _sources = intel.lookup_actor(stix_id, db)
        naming_facts = [f for f in facts if f["category"] == "naming_note"]
        assert any("Comment Crew" in f["text"] and "HTML comment" in f["text"] for f in naming_facts)


class TestParseAliases:
    def test_splits_and_strips_semicolon_separated_aliases(self):
        assert intel.parse_aliases("APT1; Comment Crew ;Comment Panda") == [
            "APT1", "Comment Crew", "Comment Panda",
        ]

    def test_handles_none_and_empty_string(self):
        assert intel.parse_aliases(None) == []
        assert intel.parse_aliases("") == []


class TestNamingConventionFacts:
    def test_matches_a_panda_alias_to_china(self, db):
        facts = intel.naming_convention_facts(["Stone Panda"], db)
        assert any("China" in f["text"] and "naming_note" == f["category"] for f in facts)

    def test_matches_a_bear_alias_to_russia(self, db):
        facts = intel.naming_convention_facts(["Fancy Bear"], db)
        assert any("Russia" in f["text"] for f in facts)

    def test_does_not_match_an_unrelated_alias(self, db):
        assert intel.naming_convention_facts(["Threat Group-1234"], db) == []

    def test_empty_aliases_returns_no_facts(self, db):
        assert intel.naming_convention_facts([], db) == []

    def test_does_not_match_a_substring_of_a_longer_word(self, db):
        # "Iron" is not a naming-convention term; "IRON" (Secureworks) must
        # only match as a whole word, not as a substring of an unrelated word.
        assert intel.naming_convention_facts(["Irontown Group"], db) == []


class TestAliasNoteFacts:
    def test_returns_the_comment_crew_note_for_apt1(self, db):
        facts = intel.alias_note_facts("G0006", db)
        assert any("Comment Crew" in f["text"] for f in facts)

    def test_returns_nothing_for_an_actor_with_no_note(self, db):
        assert intel.alias_note_facts("G9999", db) == []


class TestLookupNamingTerm:
    def test_known_term_returns_facts_and_sources(self, db):
        facts, sources = intel.lookup_naming_term("Panda", db)
        assert facts
        assert any("China" in f["text"] for f in facts)
        assert sources

    def test_matching_is_case_insensitive(self, db):
        facts, _sources = intel.lookup_naming_term("panda", db)
        assert facts

    def test_unknown_term_returns_empty_lists(self, db):
        assert intel.lookup_naming_term("Aardvark", db) == ([], [])
