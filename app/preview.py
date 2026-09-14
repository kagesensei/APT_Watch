"""The right-panel preview API: a compact summary for one entity, used when
the chat UI wants to show context for an ID without a full page navigation.
"""

from flask import Blueprint, Response, abort, jsonify

from contracts import precondition

from . import intel, queries
from .cache import get_cache_db
from .db import get_db

bp = Blueprint("preview", __name__, url_prefix="/api/preview")

PREVIEW_FACT_LIMIT = 8


def _response(
    title: str,
    subtitle: str | None,
    facts: list[intel.Fact],
    sources: list[intel.Source],
    full_url: str,
) -> Response:
    return jsonify({
        "title": title,
        "subtitle": subtitle,
        "facts": [
            {"text": f["text"], "derived": f["derived"]} for f in facts[:PREVIEW_FACT_LIMIT]
        ],
        "sources": sources[:PREVIEW_FACT_LIMIT],
        "full_url": full_url,
        "truncated": len(facts) > PREVIEW_FACT_LIMIT,
    })


@bp.route("/cve/<cve_id>")
def preview_cve(cve_id: str) -> Response:
    """Preview panel content for a CVE."""
    precondition(bool(cve_id), "cve_id must not be empty")
    db = get_db()
    cache_db = get_cache_db()
    kev_row = db.execute(
        "SELECT vulnerability_name FROM kev WHERE cve_id = ?", [cve_id]
    ).fetchone()
    facts, sources = intel.lookup_cve(cve_id, db, cache_db)
    if kev_row is None and not facts:
        abort(404)
    subtitle = kev_row[0] if kev_row else None
    return _response(cve_id, subtitle, facts, sources, f"/library/cves/{cve_id}")


@bp.route("/technique/<technique_id>")
def preview_technique(technique_id: str) -> Response:
    """Preview panel content for an ATT&CK technique."""
    precondition(bool(technique_id), "technique_id must not be empty")
    db = get_db()
    subtitle = queries.technique_name(db, technique_id)
    facts, sources = intel.lookup_technique(technique_id, db)
    if subtitle is None and not facts:
        abort(404)
    return _response(
        technique_id, subtitle, facts, sources, f"/library/techniques/{technique_id}"
    )


@bp.route("/mitigation/<mitigation_id>")
def preview_mitigation(mitigation_id: str) -> Response:
    """Preview panel content for an ATT&CK mitigation."""
    precondition(bool(mitigation_id), "mitigation_id must not be empty")
    db = get_db()
    mitigation_title = queries.mitigation_name(db, mitigation_id)
    if mitigation_title is None:
        abort(404)
    facts, sources = intel.lookup_mitigation(mitigation_id, db)
    return _response(
        mitigation_id, mitigation_title, facts, sources, f"/library/mitigations/{mitigation_id}"
    )


@bp.route("/actor/<attack_id>")
def preview_actor(attack_id: str) -> Response:
    """Preview panel content for an ATT&CK group."""
    precondition(bool(attack_id), "attack_id must not be empty")
    db = get_db()
    actor_row = db.execute(
        "SELECT stix_id, name FROM actor WHERE attack_id = ?", [attack_id]
    ).fetchone()
    if actor_row is None:
        abort(404)
    stix_id, name = actor_row
    facts, sources = intel.lookup_actor(stix_id, db)
    return _response(name, attack_id, facts, sources, f"/library/actors/{stix_id}")
