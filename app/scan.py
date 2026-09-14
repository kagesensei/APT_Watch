"""The file-upload IOC scanner: extract indicators from an uploaded text
file and look each one up, without ever persisting the file itself.
"""

from flask import Blueprint, Response, jsonify, render_template, request

from contracts import precondition

from . import intel, nlp
from .db import get_db

bp = Blueprint("scan", __name__, url_prefix="/scan")

# Bounds how much text we regex over per upload; paired with the app-level
# MAX_CONTENT_LENGTH (set in app/__init__.py) which rejects the upload
# outright before this code even runs if the raw file is too big.
MAX_CHARS = 2_000_000
MAX_REPLACEMENT_RATIO = 0.05


@bp.route("/")
def index() -> str:
    """Render the scan page."""
    return render_template("scan.html")


@bp.route("/upload", methods=["POST"])
def upload() -> tuple[Response, int] | Response:
    """Extract and look up every IOC found in an uploaded text file.

    The file is only ever held in memory for this request — never written
    to disk — and discarded once this function returns.
    """
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    raw = file.read(MAX_CHARS + 1)
    if len(raw) > MAX_CHARS:
        return jsonify({"error": "File too large to scan (limit ~2MB of text)."}), 400

    text = raw.decode("utf-8", errors="replace")
    if text and text.count("\N{REPLACEMENT CHARACTER}") / len(text) > MAX_REPLACEMENT_RATIO:
        return jsonify({"error": "This doesn't look like a text file."}), 400

    db = get_db()
    iocs = nlp.extract_iocs(text)
    precondition(len(iocs) <= len(text), "cannot find more IOCs than characters scanned")

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
