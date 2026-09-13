from app import llm


def _fact(category, entity_id, dataset="APT_Watch", derived=False, text=None):
    return {
        "text": text or f"fact about {entity_id}",
        "derived": derived,
        "category": category,
        "source": {"dataset": dataset, "id": entity_id, "name": entity_id, "url": None},
    }


class TestAllowedIds:
    def test_collects_source_ids_and_ids_mentioned_in_fact_text(self):
        facts = [_fact("vuln_info", "CVE-2024-3400", text="CVE-2024-3400 relates to T1055.")]
        allowed = llm.allowed_ids(facts)
        assert "CVE-2024-3400" in allowed
        assert "T1055" in allowed

    def test_empty_facts_yields_empty_set(self):
        assert llm.allowed_ids([]) == set()


class TestFabricationGuard:
    def test_reply_using_only_known_ids_is_unmodified(self):
        facts = [_fact("vuln_info", "CVE-2024-3400")]
        reply = "This relates to CVE-2024-3400."
        assert llm._check_for_fabricated_ids(reply, facts) == reply

    def test_reply_with_unverified_id_gets_a_warning_appended(self):
        facts = [_fact("vuln_info", "CVE-2024-3400")]
        reply = "This also involves CVE-9999-9999, which is unrelated."
        result = llm._check_for_fabricated_ids(reply, facts)
        assert result.startswith(reply)
        assert "Verification warning" in result
        assert "CVE-9999-9999" in result

    def test_case_insensitive_id_matching(self):
        facts = [_fact("vuln_info", "cve-2024-3400")]
        reply = "See CVE-2024-3400."
        assert "Verification warning" not in llm._check_for_fabricated_ids(reply, facts)


class TestBuildContext:
    def test_no_facts_returns_explanatory_placeholder(self):
        assert "No matching facts" in llm.build_context([])

    def test_facts_are_numbered_and_tagged_direct_or_derived(self):
        facts = [
            _fact("vuln_info", "CVE-1", derived=False, text="direct fact"),
            _fact("mitigation", "M1047", derived=True, text="derived fact"),
        ]
        context = llm.build_context(facts)
        assert "1. [DIRECT] direct fact" in context
        assert "[DERIVED] derived fact" in context

    def test_category_priority_order_is_respected(self):
        # mitigation must appear before actor_usage regardless of input order.
        facts = [
            _fact("actor_usage", "G1", text="actor fact"),
            _fact("mitigation", "M1", text="mitigation fact"),
        ]
        context = llm.build_context(facts)
        assert context.index("mitigation fact") < context.index("actor fact")

    def test_apt_watch_coverage_note_is_sorted_first_within_vuln_info(self):
        facts = [
            _fact("vuln_info", "CVE-1", dataset="NVD", text="nvd detail"),
            _fact("vuln_info", "CVE-1", dataset="APT_Watch", text="coverage note"),
        ]
        context = llm.build_context(facts)
        assert context.index("coverage note") < context.index("nvd detail")

    def test_per_category_cap_is_enforced(self):
        facts = [_fact("mitigation", f"M{i}", text=f"mitigation {i}") for i in range(20)]
        context = llm.build_context(facts)
        assert context.count("mitigation ") == llm.MAX_PER_TIER

    def test_overall_fact_cap_and_omitted_count_note(self):
        facts = []
        for category in llm.CATEGORY_PRIORITY:
            facts.extend(_fact(category, f"{category}-{i}", text=f"{category} fact {i}") for i in range(10))
        context = llm.build_context(facts)
        lines = context.splitlines()
        assert len(lines) == llm.MAX_FACTS + 1  # +1 for the "omitted" note
        assert "additional lower-priority facts omitted" in lines[-1]

    def test_fact_with_a_category_outside_priority_list_is_silently_dropped(self):
        # tiers.setdefault(category, []) keys the tier by the fact's own
        # category string, but the selection loop only ever reads keys in
        # CATEGORY_PRIORITY - so a fact tagged with a category not in that
        # list (e.g. a typo, or a new category added to intel.py without
        # updating llm.CATEGORY_PRIORITY) never reaches the model at all.
        # This pins down that non-obvious behavior rather than asserting
        # what would be the "nicer" outcome.
        facts = [_fact("some_unexpected_category", "X1", text="mystery fact")]
        context = llm.build_context(facts)
        assert "mystery fact" not in context
