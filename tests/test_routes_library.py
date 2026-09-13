class TestLibraryIndex:
    def test_index_renders_with_counts(self, client):
        resp = client.get("/library/")
        assert resp.status_code == 200
        assert b"Actors" in resp.data or b"actor" in resp.data.lower()


class TestActors:
    def test_list_page_ok(self, client):
        assert client.get("/library/actors").status_code == 200

    def test_search_filters_results(self, client, db):
        name = db.execute("SELECT name FROM actor LIMIT 1").fetchone()[0]
        resp = client.get("/library/actors", query_string={"q": name})
        assert resp.status_code == 200
        assert name.encode() in resp.data

    def test_detail_page_for_real_actor(self, client, db):
        stix_id = db.execute("SELECT stix_id FROM actor LIMIT 1").fetchone()[0]
        resp = client.get(f"/library/actors/{stix_id}")
        assert resp.status_code == 200

    def test_detail_page_404_for_unknown_actor(self, client):
        resp = client.get("/library/actors/intrusion-set--does-not-exist")
        assert resp.status_code == 404


class TestTechniques:
    def test_list_page_ok(self, client):
        assert client.get("/library/techniques").status_code == 200

    def test_detail_page_for_real_technique(self, client, db):
        technique_id = db.execute("SELECT technique_id FROM actor_technique LIMIT 1").fetchone()[0]
        resp = client.get(f"/library/techniques/{technique_id}")
        assert resp.status_code == 200

    def test_detail_page_404_for_unknown_technique(self, client):
        assert client.get("/library/techniques/T9999").status_code == 404


class TestSoftware:
    def test_list_page_ok(self, client):
        assert client.get("/library/software").status_code == 200

    def test_detail_page_for_real_software(self, client, db):
        software_id = db.execute("SELECT software_id FROM actor_software LIMIT 1").fetchone()[0]
        resp = client.get(f"/library/software/{software_id}")
        assert resp.status_code == 200

    def test_detail_page_404_for_unknown_software(self, client):
        assert client.get("/library/software/malware--does-not-exist").status_code == 404


class TestMitigations:
    def test_list_page_ok(self, client):
        assert client.get("/library/mitigations").status_code == 200

    def test_detail_page_for_real_mitigation(self, client, db):
        mitigation_id = db.execute(
            "SELECT DISTINCT mitigation_id FROM technique_mitigation LIMIT 1"
        ).fetchone()[0]
        resp = client.get(f"/library/mitigations/{mitigation_id}")
        assert resp.status_code == 200

    def test_detail_page_404_for_unknown_mitigation(self, client):
        assert client.get("/library/mitigations/M9999").status_code == 404


class TestCves:
    def test_list_page_ok(self, client):
        assert client.get("/library/cves").status_code == 200

    def test_detail_page_for_kev_cve_avoids_network(self, client, db, monkeypatch):
        from app import intel
        monkeypatch.setattr(intel, "fetch_nvd", lambda cve_id, cache: None)
        cve_id = db.execute("SELECT cve_id FROM kev LIMIT 1").fetchone()[0]
        resp = client.get(f"/library/cves/{cve_id}")
        assert resp.status_code == 200

    def test_detail_page_404_for_unknown_cve(self, client, monkeypatch):
        from app import intel
        monkeypatch.setattr(intel, "fetch_nvd", lambda cve_id, cache: None)
        assert client.get("/library/cves/CVE-1999-9999999").status_code == 404


class TestPagination:
    def test_invalid_page_param_falls_back_to_page_one(self, client):
        resp = client.get("/library/actors", query_string={"page": "not-a-number"})
        assert resp.status_code == 200


class TestErrorPages:
    def test_unknown_route_is_404(self, client):
        assert client.get("/library/totally-not-a-route").status_code == 404
