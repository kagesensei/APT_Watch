class TestDashboard:
    def test_dashboard_renders_ok(self, client):
        resp = client.get("/dashboard/")
        assert resp.status_code == 200

    def test_dashboard_contains_rendered_svg_charts(self, client):
        resp = client.get("/dashboard/")
        assert b"<svg" in resp.data

    def test_dashboard_coverage_percent_is_consistent_with_db(self, client, db):
        total = db.execute("SELECT COUNT(DISTINCT cve_id) FROM kev").fetchone()[0]
        resolved = db.execute(
            "SELECT COUNT(DISTINCT k.cve_id) FROM kev k "
            "JOIN kev_cwe kc ON kc.cve_id = k.cve_id "
            "JOIN capec_cwe cc ON cc.cwe_id = kc.cwe_id "
            "JOIN capec_technique ct ON ct.capec_id = cc.capec_id"
        ).fetchone()[0]
        expected_pct = round(100 * resolved / total) if total else 0

        resp = client.get("/dashboard/")
        assert f"{expected_pct}%".encode() in resp.data or str(expected_pct).encode() in resp.data
