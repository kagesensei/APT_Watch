from app import nlp


class TestExtractIds:
    def test_extracts_cve_technique_and_mitigation_ids(self):
        text = "What mitigates T1055.001 and M1047, and is CVE-2024-3400 related?"
        ids = nlp.extract_ids(text)
        assert ids["cves"] == ["CVE-2024-3400"]
        assert ids["techniques"] == ["T1055.001"]
        assert ids["mitigations"] == ["M1047"]

    def test_uppercases_and_dedupes(self):
        ids = nlp.extract_ids("cve-2024-3400 CVE-2024-3400 t1055 T1055")
        assert ids["cves"] == ["CVE-2024-3400"]
        assert ids["techniques"] == ["T1055"]

    def test_no_ids_found_returns_empty_lists(self):
        ids = nlp.extract_ids("What's a concerning CVE-like risk right now?")
        assert ids == {"cves": [], "techniques": [], "mitigations": []}

    def test_bare_t_number_without_leading_zero_pattern_is_not_matched(self):
        # T#### requires exactly 4 digits (+ optional .### sub-technique)
        ids = nlp.extract_ids("T99 T99999")
        assert ids["techniques"] == []


class TestWantsGeneralOverview:
    def test_matches_concern_keywords(self):
        assert nlp.wants_general_overview("What's concerning right now?")
        assert nlp.wants_general_overview("Any critical or active threats?")

    def test_no_match_on_specific_technical_question(self):
        assert not nlp.wants_general_overview("What mitigates T1055?")


class TestWantsPipelineAssessment:
    def test_matches_assessment_phrasing(self):
        assert nlp.wants_pipeline_assessment("Give me a full assessment of APT29")
        assert nlp.wants_pipeline_assessment("Can you profile this campaign?")
        assert nlp.wants_pipeline_assessment("How should we defend against Lazarus Group?")
        assert nlp.wants_pipeline_assessment("What do we know about this actor?")

    def test_no_match_on_narrow_factual_question(self):
        assert not nlp.wants_pipeline_assessment("What mitigates T1055?")
        assert not nlp.wants_pipeline_assessment("What software does APT29 use?")


class TestExtractIocs:
    def test_extracts_url_hash_and_ip(self):
        text = (
            "Saw traffic to http://bad.example.com/payload.exe, hash "
            "44d88612fea8a8f36de82e1278abb02f, and C2 at 192.168.1.1."
        )
        iocs = nlp.extract_iocs(text)
        types = {i["type"] for i in iocs}
        assert types == {"url", "hash", "ip"}

    def test_url_trailing_punctuation_is_stripped(self):
        iocs = nlp.extract_iocs("See http://bad.example.com/x (it's malicious).")
        urls = [i["value"] for i in iocs if i["type"] == "url"]
        assert urls == ["http://bad.example.com/x"]

    def test_sha256_takes_priority_over_shorter_hash_patterns(self):
        sha256 = "a" * 64
        iocs = nlp.extract_iocs(sha256)
        hashes = [i["value"] for i in iocs if i["type"] == "hash"]
        assert hashes == [sha256]

    def test_invalid_ipv4_octet_is_rejected(self):
        # 999 is not a valid octet - must not be reported as an IP
        iocs = nlp.extract_iocs("weird value 999.999.999.999 here")
        assert not any(i["type"] == "ip" for i in iocs)

    def test_valid_ipv4_is_accepted(self):
        iocs = nlp.extract_iocs("beacon to 8.8.8.8 observed")
        ips = [i["value"] for i in iocs if i["type"] == "ip"]
        assert ips == ["8.8.8.8"]

    def test_duplicates_are_removed(self):
        iocs = nlp.extract_iocs("8.8.8.8 and again 8.8.8.8")
        assert len(iocs) == 1

    def test_domains_alone_are_not_extracted(self):
        # By design (see app/nlp.py) - too high a false-positive rate.
        iocs = nlp.extract_iocs("evil.example.com was seen in the logs")
        assert iocs == []


class TestMatchActorsAndSoftware:
    def test_match_actors_exact_name(self, db):
        row = db.execute("SELECT name FROM actor LIMIT 1").fetchone()
        name = row[0]
        matches = nlp.match_actors(f"Tell me about {name} activity", db)
        assert any(m[1] == name and m[2] == 100.0 for m in matches)

    def test_match_actors_no_match_on_unrelated_text(self, db):
        matches = nlp.match_actors("What's the weather like today?", db)
        assert matches == []

    def test_match_software_exact_name(self, db):
        row = db.execute("SELECT software_name FROM actor_software LIMIT 1").fetchone()
        name = row[0]
        matches = nlp.match_software(f"Have we seen {name} deployed?", db)
        assert any(m[1] == name and m[3] == 100.0 for m in matches)

    def test_extract_entities_combines_everything(self, db):
        row = db.execute("SELECT name FROM actor LIMIT 1").fetchone()
        name = row[0]
        text = f"Does {name} use T1055 and is CVE-2024-3400 exploited by them? Seen 8.8.8.8 too."
        entities = nlp.extract_entities(text, db)
        assert entities["cves"] == ["CVE-2024-3400"]
        assert entities["techniques"] == ["T1055"]
        assert any(a[1] == name for a in entities["actors"])
        assert any(i["type"] == "ip" for i in entities["iocs"])

    def test_match_naming_terms_finds_a_whole_word_match(self, db):
        assert "Panda" in nlp.match_naming_terms("What does Panda mean?", db)

    def test_match_naming_terms_is_case_insensitive(self, db):
        assert "Panda" in nlp.match_naming_terms("what does panda mean?", db)

    def test_match_naming_terms_no_match_on_unrelated_text(self, db):
        assert nlp.match_naming_terms("What's the weather like today?", db) == []

    def test_extract_entities_includes_naming_terms(self, db):
        entities = nlp.extract_entities("Why is it called Comment Panda?", db)
        assert "Panda" in entities["naming_terms"]
