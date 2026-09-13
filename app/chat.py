from flask import Blueprint, abort, jsonify, render_template, request

from . import chats_store, intel, linkify, llm, nlp
from .auth import current_user, login_required
from .cache import get_cache_db
from .db import get_db

bp = Blueprint("chat", __name__)


@bp.route("/")
def index():
    return render_template("chat.html")


def _has_any_entity(entities):
    return bool(
        entities["cves"] or entities["techniques"] or entities["mitigations"]
        or entities["actors"] or entities["software"] or entities["iocs"]
    )


@bp.route("/ask", methods=["POST"])
def ask():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    history = data.get("history") or []
    if not message:
        return jsonify({"error": "Message is required."}), 400

    db = get_db()
    cache_db = get_cache_db()
    entities = nlp.extract_entities(message, db)

    # A follow-up like "what mitigates this CVE?" names no entity of its own —
    # re-run extraction against recent turns + this message so references back
    # to something already discussed (a CVE ID mentioned two messages ago, say)
    # still resolve, without letting old context override a genuinely new topic.
    if not _has_any_entity(entities) and history:
        contextual_text = " ".join(str(h) for h in history[-3:]) + " " + message
        contextual_entities = nlp.extract_entities(contextual_text, db)
        if _has_any_entity(contextual_entities):
            entities = contextual_entities

    facts = []
    for cve_id in entities["cves"]:
        found, _ = intel.lookup_cve(cve_id, db, cache_db)
        facts.extend(found)
    for technique_id in entities["techniques"]:
        found, _ = intel.lookup_technique(technique_id, db)
        facts.extend(found)
    for mitigation_id in entities["mitigations"]:
        found, _ = intel.lookup_mitigation(mitigation_id, db)
        facts.extend(found)
    for stix_id, name, _score in entities["actors"]:
        found, _ = intel.lookup_actor(stix_id, name, db)
        facts.extend(found)
    for ioc in entities["iocs"]:
        found, _ = intel.lookup_ioc(ioc["value"], ioc["type"], db)
        facts.extend(found)

    # No specific CVE/technique/mitigation/actor/software was named in the
    # question (e.g. "what's concerning right now?") — fall back to the most
    # notable current KEV entries instead of always answering "no data".
    if not facts and nlp.wants_general_overview(message):
        recent, _ = intel.lookup_recent_kev(db)
        facts.extend(recent)
        if recent:
            top_cve = recent[0]["source"]["id"]
            crosswalk, _ = intel.lookup_cve(top_cve, db, cache_db)
            facts.extend(crosswalk)

    try:
        reply = llm.answer(message, facts)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "answer": reply,
        "answer_html": linkify.linkify(reply, facts, db),
        "sources": intel.dedup_sources(facts),
        "entities": {
            "cves": entities["cves"],
            "techniques": entities["techniques"],
            "mitigations": entities["mitigations"],
            "actors": [name for _sid, name, _score in entities["actors"]],
            "iocs": [ioc["value"] for ioc in entities["iocs"]],
        },
    })


# --- Saved chats (signed-in users only; anonymous chats live in the browser's
# sessionStorage on the frontend and never touch the server) ---

@bp.route("/api/chats")
@login_required
def list_chats():
    return jsonify(chats_store.list_chats(current_user()["id"]))


@bp.route("/api/chats/<chat_id>", methods=["GET"])
@login_required
def get_chat(chat_id):
    chat = chats_store.get_chat(current_user()["id"], chat_id)
    if chat is None:
        abort(404)
    return jsonify({"id": chat_id, **chat})


@bp.route("/api/chats/<chat_id>", methods=["PUT"])
@login_required
def put_chat(chat_id):
    data = request.get_json(silent=True) or {}
    messages = data.get("messages")
    title = (data.get("title") or "").strip()
    if messages is None:
        return jsonify({"error": "messages is required."}), 400
    if not title:
        first_user_message = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
        title = first_user_message[:60] or "New chat"
    chats_store.upsert_chat(current_user()["id"], chat_id, title, messages)
    return jsonify({"id": chat_id, "title": title})


@bp.route("/api/chats/<chat_id>", methods=["DELETE"])
@login_required
def delete_chat(chat_id):
    deleted = chats_store.delete_chat(current_user()["id"], chat_id)
    if not deleted:
        abort(404)
    return jsonify({"deleted": chat_id})
