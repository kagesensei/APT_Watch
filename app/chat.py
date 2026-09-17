"""The chat API: turn a free-text question into grounded facts and an
LLM-composed, source-linked answer, plus signed-in users' saved chat history.
"""

import duckdb
from flask import Blueprint, Response, abort, jsonify, render_template, request

from contracts import not_none, precondition

from . import chats_store, intel, linkify, llm, nlp
from .auth import current_user, login_required
from .cache import get_cache_db
from .db import get_db

bp = Blueprint("chat", __name__)


@bp.route("/")
def index() -> str:
    """Render the chat page."""
    return render_template("chat.html")


def _has_any_entity(entities: nlp.Entities) -> bool:
    return bool(
        entities["cves"] or entities["techniques"] or entities["mitigations"]
        or entities["actors"] or entities["software"] or entities["iocs"]
        or entities["naming_terms"]
    )


def _resolve_entities(
    message: str, history: list[object], db: duckdb.DuckDBPyConnection
) -> nlp.Entities:
    """Extract entities from the message, falling back to message+recent
    history when the message alone names nothing — a follow-up like "what
    mitigates this CVE?" names no entity of its own.
    """
    entities = nlp.extract_entities(message, db)
    if _has_any_entity(entities) or not history:
        return entities

    contextual_text = " ".join(str(h) for h in history[-3:]) + " " + message
    contextual_entities = nlp.extract_entities(contextual_text, db)
    return contextual_entities if _has_any_entity(contextual_entities) else entities


def _facts_for_entities(
    entities: nlp.Entities,
    db: duckdb.DuckDBPyConnection,
    cache_db: duckdb.DuckDBPyConnection,
) -> list[intel.Fact]:
    """Look up every entity nlp.py found, in a fixed, entity-kind order."""
    facts: list[intel.Fact] = []
    for cve_id in entities["cves"]:
        found, _sources = intel.lookup_cve(cve_id, db, cache_db)
        facts.extend(found)
    for technique_id in entities["techniques"]:
        found, _sources = intel.lookup_technique(technique_id, db)
        facts.extend(found)
    for mitigation_id in entities["mitigations"]:
        found, _sources = intel.lookup_mitigation(mitigation_id, db)
        facts.extend(found)
    for stix_id, _name, _score in entities["actors"]:
        found, _sources = intel.lookup_actor(stix_id, db)
        facts.extend(found)
    for ioc in entities["iocs"]:
        found, _sources = intel.lookup_ioc(ioc["value"], ioc["type"], db)
        facts.extend(found)
    for term in entities["naming_terms"]:
        found, _sources = intel.lookup_naming_term(term, db)
        facts.extend(found)
    return facts


def _general_overview_facts(
    message: str, db: duckdb.DuckDBPyConnection, cache_db: duckdb.DuckDBPyConnection
) -> list[intel.Fact]:
    """Fallback for an open-ended question naming no specific entity (e.g.
    "what's concerning right now?"): the most notable current KEV entries,
    plus the top one's own crosswalk, instead of always answering "no data".
    """
    if not nlp.wants_general_overview(message):
        return []
    recent, _sources = intel.lookup_recent_kev(db)
    if not recent:
        return recent
    top_cve = recent[0]["source"]["id"]
    crosswalk, _sources = intel.lookup_cve(top_cve, db, cache_db)
    return recent + crosswalk


def _wants_pipeline_assessment(message: str, entities: nlp.Entities) -> bool:
    """Whether to use llm.py's structured PIPELINE_SYSTEM_PROMPT instead of
    the default concise one. Requires BOTH a resolved actor entity AND
    assessment-intent phrasing -- an actor named in an otherwise narrow
    question ("what mitigates T1055 for APT29?") should stay concise.
    """
    return bool(entities["actors"]) and nlp.wants_pipeline_assessment(message)


@bp.route("/ask", methods=["POST"])
def ask() -> tuple[Response, int] | Response:
    """Answer a chat question: extract entities, gather grounding facts,
    ask the LLM, and return a source-linked, HTML-linkified reply.
    """
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    history = data.get("history") or []
    if not message:
        return jsonify({"error": "Message is required."}), 400

    db = get_db()
    cache_db = get_cache_db()
    entities = _resolve_entities(message, history, db)

    facts = _facts_for_entities(entities, db, cache_db)
    if not facts:
        facts = _general_overview_facts(message, db, cache_db)

    pipeline = _wants_pipeline_assessment(message, entities)
    try:
        reply = llm.answer(message, facts, pipeline=pipeline)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "answer": reply,
        "answer_html": linkify.linkify(reply, facts, db),
        "sources": intel.dedup_sources(facts),
        "pipeline": pipeline,
        "entities": {
            "cves": entities["cves"],
            "techniques": entities["techniques"],
            "mitigations": entities["mitigations"],
            "actors": [name for _sid, name, _score in entities["actors"]],
            "iocs": [ioc["value"] for ioc in entities["iocs"]],
            "naming_terms": entities["naming_terms"],
        },
    })


# --- Saved chats (signed-in users only; anonymous chats live in the browser's
# sessionStorage on the frontend and never touch the server) ---


def _current_user_id() -> str:
    """The signed-in user's id. Only called from a @login_required view, so
    current_user() is guaranteed non-None -- not_none() documents that
    guarantee instead of indexing a value typed as possibly None.
    """
    user = not_none(current_user(), "current_user() must be set behind @login_required")
    return str(user["id"])


@bp.route("/api/chats")
@login_required
def list_chats() -> Response:
    """List the signed-in user's saved chats."""
    return jsonify(chats_store.list_chats(_current_user_id()))


@bp.route("/api/chats/<chat_id>", methods=["GET"])
@login_required
def get_chat(chat_id: str) -> Response:
    """Fetch one saved chat's full message log."""
    precondition(bool(chat_id), "chat_id must not be empty")
    chat = chats_store.get_chat(_current_user_id(), chat_id)
    if chat is None:
        abort(404)
    return jsonify({"id": chat_id, **chat})


@bp.route("/api/chats/<chat_id>", methods=["PUT"])
@login_required
def put_chat(chat_id: str) -> tuple[Response, int] | Response:
    """Create or overwrite one saved chat."""
    precondition(bool(chat_id), "chat_id must not be empty")
    data = request.get_json(silent=True) or {}
    messages = data.get("messages")
    title = (data.get("title") or "").strip()
    if messages is None:
        return jsonify({"error": "messages is required."}), 400
    if not title:
        first_user_message = next(
            (m.get("content", "") for m in messages if m.get("role") == "user"), ""
        )
        title = first_user_message[:60] or "New chat"
    chats_store.upsert_chat(_current_user_id(), chat_id, title, messages)
    return jsonify({"id": chat_id, "title": title})


@bp.route("/api/chats/<chat_id>", methods=["DELETE"])
@login_required
def delete_chat(chat_id: str) -> Response:
    """Delete one saved chat."""
    precondition(bool(chat_id), "chat_id must not be empty")
    deleted = chats_store.delete_chat(_current_user_id(), chat_id)
    if not deleted:
        abort(404)
    return jsonify({"deleted": chat_id})
