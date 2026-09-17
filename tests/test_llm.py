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

    def test_guard_still_catches_a_fabricated_id_buried_in_a_structured_pipeline_answer(self):
        # A PIPELINE_SYSTEM_PROMPT-shaped answer is much longer and has many
        # headed sections -- the guard must still scan the whole thing, not
        # just an opening line.
        facts = [_fact("actor_usage", "G0016", text="APT29 uses T1071.")]
        pipeline_reply = (
            "Likely Actor(s)\nAPT29 (G0016), per MITRE ATT&CK.\n\n"
            "ATT&CK Techniques\nT1071.\n\n"
            "Unanswered Questions / Gaps\nAlso possibly linked to G9999, unconfirmed."
        )
        result = llm._check_for_fabricated_ids(pipeline_reply, facts)
        assert "Verification warning" in result
        assert "G9999" in result


class TestSystemPromptSelection:
    def test_pipeline_false_selects_the_concise_prompt(self):
        assert llm._system_prompt_for(False) == llm.SYSTEM_PROMPT

    def test_pipeline_true_selects_the_structured_prompt(self):
        assert llm._system_prompt_for(True) == llm.PIPELINE_SYSTEM_PROMPT

    def test_prompts_are_distinct(self):
        assert llm.SYSTEM_PROMPT != llm.PIPELINE_SYSTEM_PROMPT

    def test_pipeline_prompt_requires_the_same_id_fabrication_rule(self):
        # The core anti-hallucination rule must survive into the new prompt
        # verbatim in spirit, even though the wording differs slightly.
        assert "does not appear verbatim in the facts below" in llm.PIPELINE_SYSTEM_PROMPT

    def test_pipeline_prompt_requires_all_documented_sections(self):
        for heading in (
            "Likely Actor", "Observed Behavior", "ATT&CK Techniques", "Supporting Evidence",
            "Confidence", "IOCs", "Detections", "Mitigations", "Unanswered Questions",
        ):
            assert heading in llm.PIPELINE_SYSTEM_PROMPT


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
