from app import linkify


def _fact(entity_id, text=""):
    return {"text": text or entity_id, "derived": False, "category": "vuln_info",
            "source": {"dataset": "test", "id": entity_id, "name": entity_id, "url": None}}


class TestResolveLink:
    def test_cve(self, db):
        assert linkify.resolve_link("cve-2024-3400", db) == ("cve", "/library/cves/CVE-2024-3400")

    def test_technique(self, db):
        assert linkify.resolve_link("t1055.001", db) == ("technique", "/library/techniques/T1055.001")

    def test_mitigation(self, db):
        assert linkify.resolve_link("m1047", db) == ("mitigation", "/library/mitigations/M1047")

    def test_known_actor_group_id_resolves(self, db):
        row = db.execute("SELECT attack_id, stix_id FROM actor LIMIT 1").fetchone()
        attack_id, stix_id = row
        assert linkify.resolve_link(attack_id, db) == ("actor", f"/library/actors/{stix_id}")

    def test_unknown_actor_group_id_returns_none(self, db):
        assert linkify.resolve_link("G9999", db) is None

    def test_unrecognized_shape_returns_none(self, db):
        assert linkify.resolve_link("CWE-79", db) is None
        assert linkify.resolve_link("not-an-id", db) is None


class TestLinkify:
    def test_verified_id_becomes_a_link(self, db):
        facts = [_fact("CVE-2024-3400")]
        html_out = linkify.linkify("See CVE-2024-3400 for details.", facts, db)
        assert '<a href="/library/cves/CVE-2024-3400"' in html_out
        assert 'class="entity-link"' in html_out
        assert 'data-type="cve"' in html_out

    def test_unverified_id_stays_plain_text(self, db):
        # CVE-2099-0001 never appears in facts, so it must not be linked even
        # though it matches the CVE shape - this is the same guard the
        # hallucination check relies on (app/llm.py allowed_ids).
        facts = [_fact("CVE-2024-3400")]
        html_out = linkify.linkify("Unrelated CVE-2099-0001 mentioned.", facts, db)
        assert "<a " not in html_out
        assert "CVE-2099-0001" in html_out

    def test_html_in_model_text_is_escaped(self, db):
        facts = [_fact("CVE-2024-3400")]
        html_out = linkify.linkify("<script>alert(1)</script> CVE-2024-3400", facts, db)
        assert "<script>" not in html_out
        assert "&lt;script&gt;" in html_out

    def test_cwe_and_capec_ids_are_never_linked(self, db):
        # CWE/CAPEC are crosswalk plumbing, not first-class Library entities.
        facts = [_fact("CWE-79"), _fact("CAPEC-63")]
        html_out = linkify.linkify("Weakness CWE-79 relates to CAPEC-63.", facts, db)
        assert "<a " not in html_out

    def test_verified_but_unresolvable_actor_id_stays_plain(self, db):
        # G9999 is "verified" (present in facts) but doesn't exist in the DB,
        # so resolve_link returns None and it must not become a dead link.
        facts = [_fact("G9999")]
        html_out = linkify.linkify("Group G9999 was involved.", facts, db)
        assert "<a " not in html_out
        assert "G9999" in html_out
