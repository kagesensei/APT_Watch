"""Turn verified entity IDs in model answer text into in-app links."""

import html
import re
from re import Match

import duckdb

from contracts import postcondition, precondition

from . import intel, llm

# Only these ID shapes get turned into an in-app link with a right-panel
# preview. CWE/CAPEC IDs are left as plain text — they're crosswalk plumbing,
# not first-class Library entities with their own page.
LINKABLE_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    re.compile(r"\bM\d{4}\b"),
    re.compile(r"\bG\d{4}\b"),
]


def resolve_link(
    entity_id: str, db: duckdb.DuckDBPyConnection
) -> tuple[str, str] | None:
    """Map a verified ID to (entity_type, internal_library_url), or None."""
    precondition(bool(entity_id), "entity_id must not be empty")
    entity_id = entity_id.upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", entity_id):
        return "cve", f"/library/cves/{entity_id}"
    if re.fullmatch(r"T\d{4}(?:\.\d{3})?", entity_id):
        return "technique", f"/library/techniques/{entity_id}"
    if re.fullmatch(r"M\d{4}", entity_id):
        return "mitigation", f"/library/mitigations/{entity_id}"
    if re.fullmatch(r"G\d{4}", entity_id):
        row = db.execute("SELECT stix_id FROM actor WHERE attack_id = ?", [entity_id]).fetchone()
        if row:
            return "actor", f"/library/actors/{row[0]}"
    return None


def linkify(
    text: str, facts: list[intel.Fact], db: duckdb.DuckDBPyConnection
) -> str:
    """Escape the model's raw answer text, then wrap only IDs that are both
    (a) already verified against the retrieved facts (llm.allowed_ids — the
    same check the hallucination guard uses) and (b) resolvable to a real
    Library page, in a clickable <a class="entity-link"> the frontend
    intercepts to populate the view panel instead of navigating.
    """
    allowed = llm.allowed_ids(facts)
    escaped = html.escape(text)

    def replace(match: Match[str]) -> str:
        raw = match.group(0)
        entity_id = raw.upper()
        if entity_id not in allowed:
            return raw
        resolved = resolve_link(entity_id, db)
        if not resolved:
            return raw
        entity_type, url = resolved
        return (
            f'<a href="{url}" class="entity-link" '
            f'data-type="{entity_type}" data-id="{entity_id}">{raw}</a>'
        )

    for pattern in LINKABLE_PATTERNS:
        escaped = pattern.sub(replace, escaped)
    postcondition("<script" not in escaped.lower(), "output must stay HTML-escaped")
    return escaped
