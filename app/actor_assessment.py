"""Bounded, evidence-only actor assessment retrieval."""

import duckdb

from contracts import not_none, precondition

from . import intel


def lookup(
    stix_id: str, db: duckdb.DuckDBPyConnection, limit: int = 32
) -> tuple[list[intel.Fact], list[intel.Source]]:
    """Return a bounded actor fact set and reserve room for explicit gaps."""
    precondition(limit > 0, "limit must be positive")
    facts, _sources = intel.lookup_actor(stix_id, db)
    if not facts:
        return [], []
    actor = not_none(
        db.execute("SELECT attack_id, name FROM actor WHERE stix_id = ?", [stix_id]).fetchone(),
        "actor must still exist after actor fact lookup",
    )
    attack_id, name = actor
    gaps = [
        (
            "No campaign-linked facts are available in this actor assessment retrieval.",
            "campaigns",
        ),
        (
            "No actor-linked IOC facts are available in this actor assessment retrieval.",
            "IOCs",
        ),
        (
            "No current-activity or recency evidence is available in this assessment retrieval.",
            "current activity",
        ),
        (
            "No victimology or targeting facts are available in this actor assessment retrieval.",
            "victimology",
        ),
    ]
    gap_facts: list[intel.Fact] = [
        {
            "text": f"{name}: {gap}", "derived": False, "category": "assessment_gap",
            "evidence_kind": "GAP",
            "source": intel._source("APT_Watch", attack_id, scope, None),
        }
        for gap, scope in gaps
    ]
    evidence_facts = [fact for fact in facts if fact["category"] != "assessment_gap"]
    bounded = evidence_facts[:max(0, limit - len(gap_facts))] + gap_facts[:limit]
    return bounded, intel.dedup_sources(bounded)
