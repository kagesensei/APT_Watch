"""Sigma rule-author tag facts for actor lookups and assessments."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from duckdb import DuckDBPyConnection

from . import queries

if TYPE_CHECKING:
    from .intel import Fact, Source


def actor_facts(
    attack_id: str,
    db: DuckDBPyConnection,
    source_factory: Callable[[str, str, str, str | None], Source],
) -> list[Fact]:
    """Build attributed-to-rule-author coverage facts for one actor."""
    coverage = queries.sigma_coverage_for_actor(db, attack_id)
    facts: list[Fact] = [{
        "text": (
            f"In the ingested Sigma index, {coverage['covered_technique_count']} of this "
            f"actor's documented techniques have an author-tagged rule and "
            f"{coverage['uncovered_technique_count']} have no ingested rule tag. "
            f"{coverage['untagged_rule_count']} Sigma rules in the index lack ATT&CK "
            "technique tags. These are rule-author tag claims, not MITRE-confirmed "
            "detection coverage; no ingested rule does not prove no detection exists."
        ),
        "derived": False, "category": "detection",
        "source": source_factory("APT_Watch Sigma index", attack_id, "coverage summary", None),
    }]
    for rule in coverage["rules"]:
        text = (
            f"Sigma rule-author tag claims rule {rule['rule_id']} ({rule['title']}) "
            f"applies to technique {rule['technique_id']} for this actor's documented "
            "techniques. This is not MITRE-confirmed detection coverage or proof the "
            "rule detects activity in a particular environment. "
            f"Source retrieved {rule['retrieved']}."
        )
        facts.append({
            "text": text, "derived": False, "category": "detection",
            "source": source_factory(
                "Sigma rule author tags", rule["rule_id"], rule["title"], rule["source_url"]
            ),
        })
    for technique_id in coverage["uncovered_techniques"]:
        facts.append({
            "text": (
                f"No ingested Sigma rule is tagged by its author for {technique_id}, "
                "among this actor's documented techniques. This does not prove that "
                "no detection exists."
            ),
            "derived": False, "category": "detection", "evidence_kind": "GAP",
            "source": source_factory("APT_Watch Sigma index", technique_id, "coverage gap", None),
        })
    if coverage["untagged_rule_count"]:
        text = (
            f"{coverage['untagged_rule_count']} ingested Sigma rule(s) have no ATT&CK "
            "technique tag and cannot be assigned technique coverage from their tags."
        )
        facts.append({
            "text": text, "derived": False, "category": "detection",
            "source": source_factory(
                "APT_Watch Sigma index", attack_id, "untagged rule count", None
            ),
        })
    return facts
