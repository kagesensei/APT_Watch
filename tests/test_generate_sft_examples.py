"""Tests for finetune/generate_sft_examples.py.

finetune/ is run directly (like ingest/*.py and resolve/aliases.py), so it
has no __init__.py -- conftest.py adds it to sys.path the same way it does
for ingest/ and resolve/.
"""

import json
import random

import generate_sft_examples as sft
import pytest
from contracts import ContractViolation


class TestRenderFactsBlock:
    def test_empty_facts_says_no_matching_facts(self):
        assert "No matching facts" in sft.render_facts_block([])

    def test_facts_are_numbered_and_tagged(self):
        facts = [
            sft.Fact("direct one", derived=False, category="vuln_info", source_id="a"),
            sft.Fact("derived one", derived=True, category="mitigation", source_id="b"),
        ]
        rendered = sft.render_facts_block(facts)
        assert "1. [DIRECT] direct one" in rendered
        assert "[DERIVED] derived one" in rendered

    def test_facts_are_grouped_by_category_priority_order(self):
        # crosswalk_detail is last in CATEGORY_PRIORITY, vuln_info is second.
        facts = [
            sft.Fact("late", derived=True, category="crosswalk_detail", source_id="x"),
            sft.Fact("early", derived=False, category="vuln_info", source_id="y"),
        ]
        rendered = sft.render_facts_block(facts)
        assert rendered.index("early") < rendered.index("late")


class TestRenderUserMessage:
    def test_contains_facts_and_question(self):
        rendered = sft.render_user_message("What mitigates T1071?", [])
        assert rendered.startswith("FACTS:\n")
        assert "QUESTION: What mitigates T1071?" in rendered


class TestScenarios:
    """Every scenario must produce a well-formed (question, facts, tag) triple."""

    @pytest.mark.parametrize("scenario_fn", sft.SCENARIOS)
    def test_scenario_shape_is_valid(self, scenario_fn):
        rng = random.Random(1)
        question, facts, tag = scenario_fn(rng)
        assert question
        assert isinstance(facts, list)
        assert all(isinstance(f, sft.Fact) for f in facts)
        assert all(f.category in sft.CATEGORY_PRIORITY for f in facts)
        assert tag

    def test_every_scenario_tag_is_unique(self):
        rng = random.Random(1)
        tags = {scenario_fn(rng)[2] for scenario_fn in sft.SCENARIOS}
        assert len(tags) == len(sft.SCENARIOS)


class TestDeterministicAnswer:
    def test_zero_facts_gets_a_fixed_answer(self):
        answer = sft.deterministic_answer([], "zero_facts")
        assert answer == "I don't have that information in the data available for this question."

    def test_single_confirmed_ioc_gets_a_derived_answer(self):
        fact = sft.fact_ioc_confirmed_hash(sft.SYNTHETIC_HASH, "ExampleRAT")
        answer = sft.deterministic_answer([fact], "ioc_confirmed")
        assert answer is not None
        assert sft.SYNTHETIC_HASH in answer
        assert "ExampleRAT" in answer

    def test_scenarios_needing_synthesis_return_none(self):
        assert sft.deterministic_answer([], "full_crosswalk") is None
        assert sft.deterministic_answer([], "technique_lookup") is None


class TestSynthesizeAnswer:
    def test_deterministic_scenario_ignores_missing_teacher_fn(self):
        answer = sft.synthesize_answer("q", [], "zero_facts", teacher_fn=None)
        assert "don't have that information" in answer

    def test_synthesis_scenario_without_teacher_fn_raises(self):
        with pytest.raises(NotImplementedError):
            sft.synthesize_answer("q", [], "full_crosswalk", teacher_fn=None)

    def test_synthesis_scenario_with_teacher_fn_uses_it(self):
        calls = []

        def fake_teacher(system_prompt, rubric, user_content):
            calls.append((system_prompt, rubric, user_content))
            return "a synthesized analyst answer"

        answer = sft.synthesize_answer("q", [], "full_crosswalk", teacher_fn=fake_teacher)
        assert answer == "a synthesized analyst answer"
        assert len(calls) == 1
        assert calls[0][0] == sft.SYSTEM_PROMPT
        assert calls[0][1] == sft.STRICT_RUBRIC


class TestGenerateDataset:
    def test_rejects_non_positive_n(self, tmp_path):
        with pytest.raises(ContractViolation):
            sft.generate_dataset(n=0, seed=1, out_path=tmp_path / "out.jsonl")

    def test_without_teacher_fn_only_writes_deterministic_scenarios(self, tmp_path):
        out_path = tmp_path / "out.jsonl"
        counts = sft.generate_dataset(n=20, seed=42, out_path=out_path, teacher_fn=None)

        written_scenarios = {k for k in counts if not k.startswith("_")}
        assert written_scenarios <= {"zero_facts", "ioc_confirmed"}
        assert counts["_skipped_needs_teacher_model"] > 0

        lines = out_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == sum(v for k, v in counts.items() if not k.startswith("_"))

    def test_with_teacher_fn_writes_every_scenario_type(self, tmp_path):
        def fake_teacher(system_prompt, rubric, user_content):
            del system_prompt, rubric, user_content
            return "a synthesized analyst answer"

        out_path = tmp_path / "out.jsonl"
        counts = sft.generate_dataset(n=60, seed=42, out_path=out_path, teacher_fn=fake_teacher)

        written_scenarios = {k for k in counts if not k.startswith("_")}
        all_tags = {scenario_fn(random.Random(0))[2] for scenario_fn in sft.SCENARIOS}
        assert written_scenarios == all_tags
        assert counts["_skipped_needs_teacher_model"] == 0

    def test_each_written_line_is_a_valid_chat_example(self, tmp_path):
        out_path = tmp_path / "out.jsonl"
        sft.generate_dataset(n=10, seed=1, out_path=out_path, teacher_fn=None)

        for line in out_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            roles = [m["role"] for m in row["messages"]]
            assert roles == ["system", "user", "assistant"]
            assert row["messages"][0]["content"] == sft.SYSTEM_PROMPT
            assert row["meta"]["scenario"]
