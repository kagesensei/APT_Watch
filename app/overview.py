"""Source-backed overview candidates and explicit limits on current rankings."""

import duckdb

from contracts import precondition

from . import intel, nlp


def render_answer(facts: list[intel.Fact]) -> str | None:
    """Render overview records directly so dates and ranking limits remain exact."""
    scopes = {fact["source"]["name"]: fact["text"] for fact in facts
              if fact["source"]["dataset"] == "APT_Watch"}
    if "Vulnerability shortlist coverage" in scopes:
        scope = scopes["Vulnerability shortlist coverage"]
        dataset, limit = "CISA KEV", 3
        next_step = "Which of these products do you run, and are they internet-facing?"
    elif "Actor activity coverage" in scopes:
        scope = scopes["Actor activity coverage"]
        dataset, limit = "MISP Galaxy", 6
        next_step = "Which named group would you like assessed for techniques and mitigations?"
    else:
        return None
    examples = [fact["text"] for fact in facts if fact["source"]["dataset"] == dataset]
    examples = [text.replace("is confirmed to be actively exploited in the wild",
                             "has documented exploitation in the wild")
                for text in examples[:limit]]
    body = "\n\n".join(f"- {text}" for text in examples)
    if not examples:
        body = "No matching examples are available for this overview in the local database."
    return f"{scope}\n\n{body}\n\n{next_step}"


def _scope_fact(text: str, name: str) -> intel.Fact:
    """Describe the application's actual coverage, not a threat attribution."""
    return {
        "text": text,
        "derived": False,
        "category": "vuln_info",
        "source": {"dataset": "APT_Watch", "id": name, "name": name, "url": None},
    }


def kev_scope(db: duckdb.DuckDBPyConnection) -> intel.Fact:
    """Explain the snapshot and heuristic behind the KEV shortlist."""
    latest = db.execute("SELECT MAX(date_added) FROM kev").fetchone()
    newest = latest[0] if latest else None
    return _scope_fact(
        f"The newest KEV addition in this local database is dated {newest}. This is a "
        "local snapshot, not a live ranking. The shortlist prioritizes known ransomware "
        "use, then catalog addition date; it does not rank all CVEs by CVSS or establish "
        "a single most critical CVE right now. KEV inclusion records known exploitation, "
        "not its present frequency. These are patch-triage candidates; actual priority "
        "depends on which products and versions you run and their exposure.",
        "Vulnerability shortlist coverage",
    )


def actor_facts(message: str, db: duckdb.DuckDBPyConnection) -> list[intel.Fact]:
    """Retrieve country-attributed examples without inventing activity rankings."""
    precondition(bool(message), "message must not be empty")
    country = nlp.actor_country(message)
    facts = [_scope_fact(
        "APT_Watch has no dated incident counts or live activity feed to rank the most "
        "active groups right now. MISP country attribution and ATT&CK technique counts "
        "do not measure current activity. Any groups listed below are alphabetically "
        "selected MISP examples linked to ATT&CK groups by the local name crosswalk, "
        "not an activity ranking. The crosswalk is partial and name-based. "
        "A current ranking needs dated "
        "campaign reporting and a defined time window.",
        "Actor activity coverage",
    )]
    if country is None:
        return facts
    rows = db.execute(
        "SELECT canonical_name, country, retrieved, source_url, misp_uuid "
        "FROM misp_actor m WHERE UPPER(country) = ? "
        "AND EXISTS (SELECT 1 FROM actor_xwalk x WHERE x.misp_uuid = m.misp_uuid) "
        "ORDER BY canonical_name, misp_uuid LIMIT 6", [country],
    ).fetchall()
    for name, attribution, retrieved, source_url, uuid in rows:
        facts.append({
            "text": f"MISP Galaxy lists {name} with country attribution {attribution}; "
                    f"this record was retrieved on {retrieved}. "
                    "This record alone does not establish current activity.",
            "derived": False,
            "category": "actor_usage",
            "source": {"dataset": "MISP Galaxy", "id": uuid, "name": name, "url": source_url},
        })
    return facts
