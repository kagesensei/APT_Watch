from flask import Blueprint, jsonify, render_template, request

from . import intel, llm, nlp
from .cache import get_cache_db
from .db import get_db

bp = Blueprint("chat", __name__)


@bp.route("/")
def index():
    return render_template("chat.html")


@bp.route("/ask", methods=["POST"])
def ask():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Message is required."}), 400

    db = get_db()
    cache_db = get_cache_db()
    entities = nlp.extract_entities(message, db)

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
        "sources": intel.dedup_sources(facts),
        "entities": {
            "cves": entities["cves"],
            "techniques": entities["techniques"],
            "mitigations": entities["mitigations"],
            "actors": [name for _sid, name, _score in entities["actors"]],
        },
    })
