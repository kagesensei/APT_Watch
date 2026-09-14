"""The Library: browsable, paginated, searchable ATT&CK/KEV reference pages."""

from flask import Blueprint, abort, render_template, request
from werkzeug.datastructures import MultiDict
from werkzeug.wrappers import Response

from contracts import precondition

from . import intel, queries
from .cache import get_cache_db
from .db import get_db

bp = Blueprint("main", __name__, url_prefix="/library")

PAGE_SIZE = 50


def paginate(args: MultiDict[str, str]) -> tuple[int, int, int]:
    """Parse a ?page= query param into (page, page_size, row_offset)."""
    try:
        page = max(1, int(args.get("page", 1)))
    except ValueError:
        page = 1
    return page, PAGE_SIZE, (page - 1) * PAGE_SIZE


@bp.route("/")
def index() -> str:
    """Library home: total entity counts, linking to each browsable list."""
    db = get_db()
    counts = queries.overview_counts(db)
    return render_template("index.html", counts=counts)


@bp.route("/actors")
def actors() -> str:
    """Paginated, searchable list of ATT&CK groups."""
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    total, rows = queries.searchable_list(
        db,
        queries.ListQuery(
            "actor", "COUNT(*)", "stix_id, attack_id, name, aliases", ["name", "aliases"], "name"
        ),
        q, size, offset,
    )

    return render_template(
        "actors.html", actors=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/actors/<stix_id>")
def actor_detail(stix_id: str) -> str:
    """One ATT&CK group's documented techniques and software."""
    precondition(bool(stix_id), "stix_id must not be empty")
    db = get_db()
    actor = db.execute(
        "SELECT stix_id, attack_id, name, aliases FROM actor WHERE stix_id = ?",
        [stix_id],
    ).fetchone()
    if actor is None:
        abort(404)

    actor_techniques = db.execute(
        "SELECT DISTINCT technique_id, technique_name FROM actor_technique "
        "WHERE actor_stix_id = ? ORDER BY technique_id",
        [stix_id],
    ).fetchall()
    actor_software = db.execute(
        "SELECT DISTINCT software_id, software_name, software_type FROM actor_software "
        "WHERE actor_stix_id = ? ORDER BY software_name",
        [stix_id],
    ).fetchall()

    attack_id, aliases_field = actor[1], actor[3]
    naming_facts = intel.naming_convention_facts(
        intel.parse_aliases(aliases_field), db
    ) + intel.alias_note_facts(attack_id, db)

    return render_template(
        "actor_detail.html",
        actor=actor,
        techniques=actor_techniques,
        software=actor_software,
        naming_facts=naming_facts,
    )


@bp.route("/techniques")
def techniques() -> str:
    """Paginated, searchable list of ATT&CK techniques."""
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    total, rows = queries.searchable_list(
        db,
        queries.ListQuery(
            "actor_technique", "COUNT(DISTINCT technique_id)",
            "DISTINCT technique_id, technique_name",
            ["technique_id", "technique_name"], "technique_id",
        ),
        q, size, offset,
    )

    return render_template(
        "techniques.html", techniques=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/techniques/<technique_id>")
def technique_detail(technique_id: str) -> str:
    """One ATT&CK technique's mitigations and the actors documented using it."""
    precondition(bool(technique_id), "technique_id must not be empty")
    db = get_db()
    found_name = queries.technique_name(db, technique_id)
    technique_mitigations = db.execute(
        "SELECT DISTINCT mitigation_id, mitigation_name FROM technique_mitigation "
        "WHERE technique_id = ? ORDER BY mitigation_id",
        [technique_id],
    ).fetchall()

    if found_name is None and not technique_mitigations:
        abort(404)

    actors_using = db.execute(
        "SELECT DISTINCT a.stix_id, a.name FROM actor a "
        "JOIN actor_technique atq ON atq.actor_stix_id = a.stix_id "
        "WHERE atq.technique_id = ? ORDER BY a.name",
        [technique_id],
    ).fetchall()

    technique_name = found_name or technique_id

    return render_template(
        "technique_detail.html",
        technique_id=technique_id,
        technique_name=technique_name,
        actors=actors_using,
        mitigations=technique_mitigations,
    )


@bp.route("/software")
def software() -> str:
    """Paginated, searchable list of ATT&CK software."""
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    total, rows = queries.searchable_list(
        db,
        queries.ListQuery(
            "actor_software", "COUNT(DISTINCT software_id)",
            "DISTINCT software_id, software_name, software_type",
            ["software_name"], "software_name",
        ),
        q, size, offset,
    )

    return render_template(
        "software.html", software=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/software/<software_id>")
def software_detail(software_id: str) -> str:
    """One ATT&CK software entry and the actors documented using it."""
    precondition(bool(software_id), "software_id must not be empty")
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
def mitigations() -> str:
    """Paginated, searchable list of ATT&CK mitigations."""
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    total, rows = queries.searchable_list(
        db,
        queries.ListQuery(
            "technique_mitigation", "COUNT(DISTINCT mitigation_id)",
            "DISTINCT mitigation_id, mitigation_name",
            ["mitigation_id", "mitigation_name"], "mitigation_id",
        ),
        q, size, offset,
    )

    return render_template(
        "mitigations.html", mitigations=rows, q=q, page=page, total=total, size=size
    )


@bp.route("/mitigations/<mitigation_id>")
def mitigation_detail(mitigation_id: str) -> str:
    """One ATT&CK mitigation and the techniques it's documented to address."""
    precondition(bool(mitigation_id), "mitigation_id must not be empty")
    db = get_db()
    found_name = queries.mitigation_name(db, mitigation_id)
    if found_name is None:
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
        mitigation_name=found_name,
        techniques=techniques_mitigated,
    )


@bp.route("/cves")
def cves() -> str:
    """Paginated, searchable list of CISA KEV entries."""
    db = get_db()
    q = request.args.get("q", "").strip()
    page, size, offset = paginate(request.args)

    total, rows = queries.searchable_list(
        db,
        queries.ListQuery(
            "kev", "COUNT(*)",
            "cve_id, vulnerability_name, vendor_project, product, date_added, known_ransomware",
            ["cve_id", "vulnerability_name"], "date_added DESC",
        ),
        q, size, offset,
    )

    return render_template("cves.html", cves=rows, q=q, page=page, total=total, size=size)


@bp.route("/cves/<cve_id>")
def cve_detail(cve_id: str) -> str | Response:
    """One CVE's KEV record plus its full crosswalk facts (see app/intel.py)."""
    precondition(bool(cve_id), "cve_id must not be empty")
    db = get_db()
    kev_row = db.execute(
        "SELECT vulnerability_name, vendor_project, product, date_added, due_date, "
        "short_description, required_action, known_ransomware FROM kev WHERE cve_id = ?",
        [cve_id],
    ).fetchone()

    cache_db = get_cache_db()
    facts, sources = intel.lookup_cve(cve_id, db, cache_db)

    # Not every CVE chat links to is in the curated KEV list (NVD covers all
    # CVEs; KEV is only actively-exploited ones) — only 404 if we truly have
    # nothing on this ID from either source.
    if kev_row is None and not facts:
        abort(404)

    return render_template(
        "cve_detail.html",
        cve_id=cve_id,
        kev=kev_row,
        facts=facts,
        sources=sources,
    )
