"""Pure alias normalization and exact bipartite match utilities."""

import re
from typing import TypedDict

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


def normalize(name: str) -> str:
    """Lowercase and remove punctuation/whitespace for lexical matching."""
    return _NON_ALNUM_RE.sub("", name.lower())


class AttackActor(TypedDict):
    """An ATT&CK actor and its name/alias set."""

    stix_id: str
    attack_id: str
    name: str
    aliases: list[str]


MispAliasRow = tuple[str, str, str, str]


class ExactMatchSets(TypedDict):
    """The exact bipartite actor relation in both directions."""

    attack_to_misp: dict[str, set[str]]
    misp_to_attack: dict[str, set[str]]


def build_normalized_index(misp_rows: list[MispAliasRow]) -> dict[str, set[str]]:
    """Map each normalized MISP alias to its actor UUIDs."""
    index: dict[str, set[str]] = {}
    for misp_uuid, alias, _source_url, _retrieved in misp_rows:
        index.setdefault(normalize(alias), set()).add(misp_uuid)
    return index


def exact_matches_for_actor(
    attack_aliases: list[str], normalized_index: dict[str, set[str]]
) -> set[str]:
    """Return every MISP UUID sharing a normalized ATT&CK name or alias."""
    matched: set[str] = set()
    for alias in attack_aliases:
        matched.update(normalized_index.get(normalize(alias), set()))
    return matched


def build_exact_match_sets(
    attack_actors: list[AttackActor], normalized_index: dict[str, set[str]]
) -> ExactMatchSets:
    """Compute exact match sets both ways, retaining all collision edges."""
    attack_to_misp: dict[str, set[str]] = {}
    misp_to_attack: dict[str, set[str]] = {}
    for actor in attack_actors:
        matched = exact_matches_for_actor(actor["aliases"], normalized_index)
        attack_to_misp[actor["stix_id"]] = matched
        for misp_uuid in matched:
            misp_to_attack.setdefault(misp_uuid, set()).add(actor["stix_id"])
    return {"attack_to_misp": attack_to_misp, "misp_to_attack": misp_to_attack}
