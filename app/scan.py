from flask import Blueprint, jsonify, render_template, request

from . import intel, nlp
from .db import get_db

bp = Blueprint("scan", __name__, url_prefix="/scan")

# Bounds how much text we regex over per upload; paired with the app-level
# MAX_CONTENT_LENGTH (set in app/__init__.py) which rejects the upload
# outright before this code even runs if the raw file is too big.
MAX_CHARS = 2_000_000
MAX_REPLACEMENT_RATIO = 0.05


@bp.route("/")
def index():
    return render_template("scan.html")


@bp.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    raw = file.read(MAX_CHARS + 1)
    if len(raw) > MAX_CHARS:
        return jsonify({"error": "File too large to scan (limit ~2MB of text)."}), 400

    # The file is only ever held in memory for this request — never written
    # to disk — and discarded once this function returns.
    text = raw.decode("utf-8", errors="replace")
    if text and text.count("�") / len(text) > MAX_REPLACEMENT_RATIO:
        return jsonify({"error": "This doesn't look like a text file."}), 400

    db = get_db()
    iocs = nlp.extract_iocs(text)
    results = []
    for ioc in iocs:
        facts, sources = intel.lookup_ioc(ioc["value"], ioc["type"], db)
        results.append({
            "indicator": ioc["value"],
            "type": ioc["type"],
            "matched": bool(facts),
            "facts": [{"text": f["text"], "derived": f["derived"]} for f in facts],
            "sources": sources,
        })

    return jsonify({"results": results, "total_indicators_found": len(iocs)})
