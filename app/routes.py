from flask import Blueprint, abort, render_template, request

from .db import get_db

bp = Blueprint("main", __name__, url_prefix="/library")

PAGE_SIZE = 50


def paginate(args):
    try:
        page = max(1, int(args.get("page", 1)))
    except ValueError:
        page = 1
    return page, PAGE_SIZE, (page - 1) * PAGE_SIZE


@bp.route("/")
def index():
    db = get_db()
    counts = {
        "actors": db.execute("SELECT COUNT(*) FROM actor").fetchone()[0],
        "techniques": db.execute("SELECT COUNT(DISTINCT technique_id) FROM actor_technique").fetchone()[0],
        "software": db.execute("SELECT COUNT(DISTINCT software_id) FROM actor_software").fetchone()[0],
        "mitigations": db.execute("SELECT COUNT(DISTINCT mitigation_id) FROM technique_mitigation").fetchone()[0],
    }
    return render_template("index.html", counts=counts)


@bp.route("/actors")
def actors():
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    where = "WHERE name ILIKE ? OR aliases ILIKE ?" if q else ""
    params = [f"%{q}%", f"%{q}%"] if q else []

    total = db.execute(f"SELECT COUNT(*) FROM actor {where}", params).fetchone()[0]
    rows = db.execute(
        f"SELECT stix_id, attack_id, name, aliases FROM actor {where} "
        "ORDER BY name LIMIT ? OFFSET ?",
        params + [size, offset],
    ).fetchall()

    return render_template(
        "actors.html", actors=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/actors/<stix_id>")
def actor_detail(stix_id):
    db = get_db()
    actor = db.execute(
        "SELECT stix_id, attack_id, name, aliases FROM actor WHERE stix_id = ?",
        [stix_id],
    ).fetchone()
    if actor is None:
        abort(404)

    techniques = db.execute(
        "SELECT DISTINCT technique_id, technique_name FROM actor_technique "
        "WHERE actor_stix_id = ? ORDER BY technique_id",
        [stix_id],
    ).fetchall()
    software = db.execute(
        "SELECT DISTINCT software_id, software_name, software_type FROM actor_software "
        "WHERE actor_stix_id = ? ORDER BY software_name",
        [stix_id],
    ).fetchall()

    return render_template(
        "actor_detail.html", actor=actor, techniques=techniques, software=software
    )


@bp.route("/techniques")
def techniques():
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    where = "WHERE technique_id ILIKE ? OR technique_name ILIKE ?" if q else ""
    params = [f"%{q}%", f"%{q}%"] if q else []

    total = db.execute(
        f"SELECT COUNT(DISTINCT technique_id) FROM actor_technique {where}", params
    ).fetchone()[0]
    rows = db.execute(
        f"SELECT DISTINCT technique_id, technique_name FROM actor_technique {where} "
        "ORDER BY technique_id LIMIT ? OFFSET ?",
        params + [size, offset],
    ).fetchall()

    return render_template(
        "techniques.html", techniques=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/techniques/<technique_id>")
def technique_detail(technique_id):
    db = get_db()
    name_row = db.execute(
        "SELECT DISTINCT technique_name FROM actor_technique WHERE technique_id = ?",
        [technique_id],
    ).fetchone()
    mitigations = db.execute(
        "SELECT DISTINCT mitigation_id, mitigation_name FROM technique_mitigation "
        "WHERE technique_id = ? ORDER BY mitigation_id",
        [technique_id],
    ).fetchall()

    if name_row is None and not mitigations:
        abort(404)

    actors_using = db.execute(
        "SELECT DISTINCT a.stix_id, a.name FROM actor a "
        "JOIN actor_technique atq ON atq.actor_stix_id = a.stix_id "
        "WHERE atq.technique_id = ? ORDER BY a.name",
        [technique_id],
    ).fetchall()

    technique_name = name_row[0] if name_row else technique_id

    return render_template(
        "technique_detail.html",
        technique_id=technique_id,
        technique_name=technique_name,
        actors=actors_using,
        mitigations=mitigations,
    )


@bp.route("/software")
def software():
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    where = "WHERE software_name ILIKE ?" if q else ""
    params = [f"%{q}%"] if q else []

    total = db.execute(
        f"SELECT COUNT(DISTINCT software_id) FROM actor_software {where}", params
    ).fetchone()[0]
    rows = db.execute(
        f"SELECT DISTINCT software_id, software_name, software_type FROM actor_software {where} "
        "ORDER BY software_name LIMIT ? OFFSET ?",
        params + [size, offset],
    ).fetchall()

    return render_template(
        "software.html", software=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/software/<software_id>")
def software_detail(software_id):
    db = get_db()
    row = db.execute(
        "SELECT DISTINCT software_id, software_name, software_type FROM actor_software "
        "WHERE software_id = ?",
        [software_id],
    ).fetchone()
    if row is None:
        abort(404)

    actors_using = db.execute(
        "SELECT DISTINCT a.stix_id, a.name FROM actor a "
        "JOIN actor_software asw ON asw.actor_stix_id = a.stix_id "
        "WHERE asw.software_id = ? ORDER BY a.name",
        [software_id],
    ).fetchall()

    return render_template("software_detail.html", software=row, actors=actors_using)


@bp.route("/mitigations")
def mitigations():
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    where = "WHERE mitigation_id ILIKE ? OR mitigation_name ILIKE ?" if q else ""
    params = [f"%{q}%", f"%{q}%"] if q else []

    total = db.execute(
        f"SELECT COUNT(DISTINCT mitigation_id) FROM technique_mitigation {where}", params
    ).fetchone()[0]
    rows = db.execute(
        f"SELECT DISTINCT mitigation_id, mitigation_name FROM technique_mitigation {where} "
        "ORDER BY mitigation_id LIMIT ? OFFSET ?",
        params + [size, offset],
    ).fetchall()

    return render_template(
        "mitigations.html", mitigations=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/mitigations/<mitigation_id>")
def mitigation_detail(mitigation_id):
    db = get_db()
    name_row = db.execute(
        "SELECT DISTINCT mitigation_name FROM technique_mitigation WHERE mitigation_id = ?",
        [mitigation_id],
    ).fetchone()
    if name_row is None:
        abort(404)

    techniques_mitigated = db.execute(
        "SELECT DISTINCT tm.technique_id, atq.technique_name FROM technique_mitigation tm "
        "LEFT JOIN actor_technique atq ON atq.technique_id = tm.technique_id "
        "WHERE tm.mitigation_id = ? ORDER BY tm.technique_id",
        [mitigation_id],
    ).fetchall()

    return render_template(
        "mitigation_detail.html",
        mitigation_id=mitigation_id,
        mitigation_name=name_row[0],
        techniques=techniques_mitigated,
    )
