from flask import Blueprint, render_template

from . import charts
from .db import get_db

bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

# Documented categorical palette slots 1 (blue) and 2 (orange), dark-mode
# steps — validated for this app's dark surface (#121821) with
# scripts/validate_palette.js from the dataviz skill before use here.
# Assigned in fixed order (never cycled); meaning comes from the legend
# label, not the hue.
RANSOMWARE_COLOR = "#3987e5"
OTHER_COLOR = "#d95926"

# The app's existing --accent token — a lone sequential hue for magnitude
# rankings, not a categorical identity choice, so it isn't subject to the
# categorical validator (see dataviz skill scope note).
RANKING_COLOR = "#4fd1c5"

WEEKS_SHOWN = 12
TOP_N = 10


@bp.route("/")
def index():
    db = get_db()

    counts = {
        "actors": db.execute("SELECT COUNT(*) FROM actor").fetchone()[0],
        "techniques": db.execute("SELECT COUNT(DISTINCT technique_id) FROM actor_technique").fetchone()[0],
        "software": db.execute("SELECT COUNT(DISTINCT software_id) FROM actor_software").fetchone()[0],
        "mitigations": db.execute("SELECT COUNT(DISTINCT mitigation_id) FROM technique_mitigation").fetchone()[0],
        "cves": db.execute("SELECT COUNT(DISTINCT cve_id) FROM kev").fetchone()[0],
        "iocs": (
            db.execute("SELECT COUNT(*) FROM ioc_url").fetchone()[0]
            + db.execute("SELECT COUNT(*) FROM ioc_hash").fetchone()[0]
            + db.execute("SELECT COUNT(*) FROM ioc_c2").fetchone()[0]
        ),
    }

    coverage_total = db.execute("SELECT COUNT(DISTINCT cve_id) FROM kev").fetchone()[0]
    coverage_resolved = db.execute(
        "SELECT COUNT(DISTINCT k.cve_id) FROM kev k "
        "JOIN kev_cwe kc ON kc.cve_id = k.cve_id "
        "JOIN capec_cwe cc ON cc.cwe_id = kc.cwe_id "
        "JOIN capec_technique ct ON ct.capec_id = cc.capec_id"
    ).fetchone()[0]
    coverage_pct = round(100 * coverage_resolved / coverage_total) if coverage_total else 0

    top_techniques = db.execute(
        "SELECT technique_name, COUNT(DISTINCT actor_stix_id) AS actor_count "
        "FROM actor_technique GROUP BY technique_name "
        "ORDER BY actor_count DESC LIMIT ?",
        [TOP_N],
    ).fetchall()

    top_actors = db.execute(
        "SELECT a.name, COUNT(DISTINCT atq.technique_id) AS technique_count "
        "FROM actor a JOIN actor_technique atq ON atq.actor_stix_id = a.stix_id "
        "GROUP BY a.name ORDER BY technique_count DESC LIMIT ?",
        [TOP_N],
    ).fetchall()

    top_software = db.execute(
        "SELECT software_name, COUNT(DISTINCT actor_stix_id) AS actor_count "
        "FROM actor_software GROUP BY software_name "
        "ORDER BY actor_count DESC LIMIT ?",
        [TOP_N],
    ).fetchall()

    weekly_rows = db.execute(
        "SELECT date_trunc('week', CAST(date_added AS DATE)) AS week_start, "
        "strftime(date_trunc('week', CAST(date_added AS DATE)), '%b %d') AS week_label, "
        "SUM(CASE WHEN known_ransomware = 'Known' THEN 1 ELSE 0 END) AS ransomware_count, "
        "SUM(CASE WHEN known_ransomware != 'Known' THEN 1 ELSE 0 END) AS other_count "
        "FROM kev GROUP BY week_start ORDER BY week_start DESC LIMIT ?",
        [WEEKS_SHOWN],
    ).fetchall()
    weekly_rows.reverse()

    weeks = [row[1] for row in weekly_rows]
    ransomware_counts = [row[2] for row in weekly_rows]
    other_counts = [row[3] for row in weekly_rows]

    return render_template(
        "dashboard.html",
        counts=counts,
        coverage_total=coverage_total,
        coverage_resolved=coverage_resolved,
        coverage_pct=coverage_pct,
        top_techniques=top_techniques,
        top_actors=top_actors,
        top_software=top_software,
        chart_techniques=charts.horizontal_bar_chart(top_techniques, RANKING_COLOR),
        chart_actors=charts.horizontal_bar_chart(top_actors, RANKING_COLOR),
        chart_software=charts.horizontal_bar_chart(top_software, RANKING_COLOR),
        chart_weekly=charts.stacked_weekly_chart(
            weeks,
            [("Ransomware-linked", ransomware_counts), ("Other", other_counts)],
            [RANSOMWARE_COLOR, OTHER_COLOR],
        ),
    )
