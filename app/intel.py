"""Fact retrieval: turn a CVE/technique/mitigation/actor/IOC identifier into
a list of grounding facts (with sources) for the chat LLM to answer from.

Every fact is tagged `derived: False` when it states something a dataset
says directly, or `derived: True` when it was reached by chaining across
datasets that don't publish a direct link to each other (e.g. CVE -> CWE ->
CAPEC -> ATT&CK technique). That flag is what `app/llm.py`'s prompt uses to
tell the model which claims need a "this is an inferred/correlated
relationship" caveat.
"""

import re
from datetime import datetime, timezone
from typing import TypedDict

import duckdb
import requests

from contracts import not_none, postcondition, precondition

from . import queries

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# Every DB call in this module either fetches one row or a query result set
# bounded by MITRE's own ATT&CK/CAPEC dataset size (hundreds to low
# thousands of rows, fixed at ingest time) -- none of it is attacker-
# controlled or unbounded, so no contracts.bounded() wrapping is needed here.


class Source(TypedDict):
    """Where a fact came from, for citation and dedup."""

    dataset: str
    id: str
    name: str
    url: str | None


class Fact(TypedDict):
    """One grounding fact handed to the LLM, with its provenance."""

    text: str
    derived: bool
    category: str
    source: Source


class NvdResult(TypedDict):
    """The subset of an NVD CVE record this app uses."""

    description: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cwe_ids: list[str]


def technique_url(technique_id: str) -> str:
    """MITRE ATT&CK technique page URL, handling sub-technique IDs."""
    precondition(bool(technique_id), "technique_id must not be empty")
    if "." in technique_id:
        base, sub = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def mitigation_url(mitigation_id: str) -> str:
    """MITRE ATT&CK mitigation page URL."""
    return f"https://attack.mitre.org/mitigations/{mitigation_id}/"


def group_url(attack_id: str | None) -> str | None:
    """MITRE ATT&CK group page URL, or None if the group has no ATT&CK ID."""
    return f"https://attack.mitre.org/groups/{attack_id}/" if attack_id else None


def capec_url(capec_id: str) -> str:
    """MITRE CAPEC attack pattern page URL."""
    num = capec_id.split("-")[-1]
    return f"https://capec.mitre.org/data/definitions/{num}.html"


def cwe_url(cwe_id: str) -> str:
    """MITRE CWE weakness page URL."""
    num = cwe_id.split("-")[-1]
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def nvd_url(cve_id: str) -> str:
    """NVD detail page URL for a CVE."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _source(dataset: str, entity_id: str, name: str, url: str | None) -> Source:
    """Build a Source dict; a tiny helper that keeps fact literals under the line-length limit."""
    return {"dataset": dataset, "id": entity_id, "name": name, "url": url}


def dedup_sources(facts: list[Fact]) -> list[Source]:
    """Collapse facts down to their unique (dataset, id) sources, in order."""
    seen: set[tuple[str, str]] = set()
    sources: list[Source] = []
    for fact in facts:
        src = fact["source"]
        key = (src["dataset"], src["id"])
        if key not in seen:
            seen.add(key)
            sources.append(src)
    return sources


def fetch_nvd(cve_id: str, cache_db: duckdb.DuckDBPyConnection) -> NvdResult | None:
    """Look up a CVE from NVD, caching the result. Returns None if not found/unreachable."""
    precondition(bool(cve_id), "cve_id must not be empty")
    row = cache_db.execute(
        "SELECT description, cvss_score, cvss_severity, cwe_ids FROM cve_cache WHERE cve_id = ?",
        [cve_id],
    ).fetchone()
    if row:
        description, cvss_score, cvss_severity, cwe_ids = row
        return {
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cwe_ids": cwe_ids.split(",") if cwe_ids else [],
        }

    try:
        resp = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities") or []
    except (requests.RequestException, ValueError):
        return None

    if not vulns:
        return None

    cve = vulns[0]["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None
    )

    cvss_score = cvss_severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0]
            cvss_score = metric["cvssData"].get("baseScore")
            cvss_severity = metric["cvssData"].get("baseSeverity") or metric.get("baseSeverity")
            break

    cwe_ids = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
    )

    cache_db.execute(
        "INSERT OR REPLACE INTO cve_cache VALUES (?,?,?,?,?,?)",
        [
            cve_id, description, cvss_score, cvss_severity,
            ",".join(cwe_ids), datetime.now(timezone.utc),
        ],
    )

    return {
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_ids": cwe_ids,
    }


def lookup_recent_kev(
    db: duckdb.DuckDBPyConnection, limit: int = 8
) -> tuple[list[Fact], list[Source]]:
    """For open-ended questions with no specific CVE named ("what's concerning
    right now?"). Surfaces the most recently added KEV entries, prioritizing
    ones with known ransomware use, so the model has something concrete and
    current to summarize instead of nothing.
    """
    precondition(limit > 0, "limit must be positive")
    rows = db.execute(
        "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, known_ransomware "
        "FROM kev ORDER BY (known_ransomware = 'Known') DESC, date_added DESC LIMIT ?",
        [limit],
    ).fetchall()

    facts: list[Fact] = []
    for cve_id, vendor, product, name, date_added, ransomware in rows:
        facts.append({
            "text": (
                f"{cve_id} ({name}; affects {vendor} {product}) was added to CISA's Known "
                f"Exploited Vulnerabilities catalog on {date_added}, meaning it is confirmed "
                f"to be actively exploited in the wild. Known ransomware use: {ransomware}."
            ),
            "derived": False,
            "category": "vuln_info",
            "source": _source("CISA KEV", cve_id, name, KEV_CATALOG_URL),
        })
    postcondition(len(facts) <= limit, "must not return more than limit facts")
    return facts, dedup_sources(facts)


def _nvd_fact(cve_id: str, nvd: NvdResult | None) -> Fact | None:
    if not nvd:
        return None
    text = f"{cve_id}: {nvd['description']}"
    if nvd["cvss_score"] is not None:
        text += f" (CVSS {nvd['cvss_score']}, {nvd['cvss_severity']})"
    return {
        "text": text,
        "derived": False,
        "category": "vuln_info",
        "source": _source("NVD", cve_id, cve_id, nvd_url(cve_id)),
    }


def _kev_fact_for_cve(cve_id: str, db: duckdb.DuckDBPyConnection) -> Fact | None:
    kev = db.execute(
        "SELECT vulnerability_name, date_added, due_date, required_action, known_ransomware "
        "FROM kev WHERE cve_id = ?",
        [cve_id],
    ).fetchone()
    if not kev:
        return None
    name, date_added, due_date, required_action, ransomware = kev
    return {
        "text": (
            f"{cve_id} ({name}) is in CISA's Known Exploited Vulnerabilities catalog, "
            f"added {date_added}, remediation due {due_date}. Known ransomware use: "
            f"{ransomware}. Required action: {required_action}"
        ),
        "derived": False,
        "category": "vuln_info",
        "source": _source("CISA KEV", cve_id, name, KEV_CATALOG_URL),
    }


def _cwe_ids_for_cve(
    cve_id: str, db: duckdb.DuckDBPyConnection, nvd: NvdResult | None
) -> list[str]:
    if nvd and nvd["cwe_ids"]:
        return list(nvd["cwe_ids"])
    return [
        row[0]
        for row in db.execute("SELECT cwe_id FROM kev_cwe WHERE cve_id = ?", [cve_id]).fetchall()
    ]


def _crosswalk_dead_end_fact(
    cve_id: str, cwe_ids: list[str], db: duckdb.DuckDBPyConnection
) -> Fact:
    # Distinguish *why* the crosswalk came up empty — most CAPEC patterns
    # aren't mapped to any ATT&CK technique at all (only ~29% are), so this
    # is a common, expected dead end, not a bug. Surfacing it as a fact lets
    # the model explain the gap instead of just saying "I don't know" with
    # no context.
    # placeholders is only ever "?,?,..." (queries.in_placeholders); cwe_ids'
    # actual values are bound via the parameter list below, not this string.
    placeholders = queries.in_placeholders(len(cwe_ids))
    count_sql = (
        "SELECT COUNT(DISTINCT capec_id) FROM capec_cwe "
        f"WHERE cwe_id IN ({placeholders})"  # nosec B608
    )
    count_row = db.execute(count_sql, cwe_ids).fetchone()
    capec_count = not_none(count_row, "COUNT query must always return a row")[0]
    cwe_list = ", ".join(cwe_ids)
    if capec_count:
        text = (
            f"{cve_id} involves weakness(es) {cwe_list}, which map to {capec_count} "
            f"MITRE CAPEC attack pattern(s) — but none of those patterns have an "
            f"ATT&CK technique mapping in MITRE's own CAPEC data. No specific TTP can "
            f"be identified for this CVE from the available crosswalk data; this is a "
            f"gap in CAPEC's own ATT&CK coverage (most CAPEC patterns aren't mapped to "
            f"any technique), not a missing lookup."
        )
    else:
        text = (
            f"{cve_id} involves weakness(es) {cwe_list}, which do not map to any MITRE "
            f"CAPEC attack pattern in the available data. No specific TTP can be "
            f"identified for this CVE from the available crosswalk data."
        )
    return {
        "text": text,
        "derived": False,
        "category": "vuln_info",
        "source": _source("APT_Watch", cve_id, "crosswalk coverage note", None),
    }


def _crosswalk_rows(
    cwe_ids: list[str], db: duckdb.DuckDBPyConnection
) -> list[tuple[str, str, str, str]]:
    # placeholders is only ever "?,?,..." (queries.in_placeholders); cwe_ids'
    # actual values are bound via the parameter list below, not this string.
    placeholders = queries.in_placeholders(len(cwe_ids))
    return db.execute(
        "SELECT DISTINCT cc.cwe_id, capec.capec_id, capec.name, ct.technique_id "
        "FROM capec_cwe cc "
        "JOIN capec ON capec.capec_id = cc.capec_id "
        "JOIN capec_technique ct ON ct.capec_id = cc.capec_id "
        f"WHERE cc.cwe_id IN ({placeholders})",  # nosec B608
        cwe_ids,
    ).fetchall()


def _crosswalk_technique_facts(
    cve_id: str, technique_rows: list[tuple[str, str, str, str]], db: duckdb.DuckDBPyConnection
) -> list[Fact]:
    facts: list[Fact] = []
    for cwe_id, capec_id, capec_name, technique_id in technique_rows:
        technique_name = queries.technique_name(db, technique_id) or technique_id
        facts.append({
            "text": (
                f"{cve_id} involves weakness {cwe_id}, which MITRE CAPEC pattern {capec_id} "
                f"({capec_name}) maps to ATT&CK technique {technique_id} ({technique_name}). "
                f"This is an inferred relationship via the CWE/CAPEC crosswalk, not a direct "
                f"MITRE ATT&CK-to-CVE mapping (MITRE does not publish one)."
            ),
            "derived": True,
            "category": "crosswalk_detail",
            "source": _source("MITRE CAPEC", capec_id, capec_name, capec_url(capec_id)),
        })
    return facts


def _technique_followon_facts(
    cve_id: str, technique_ids: list[str], db: duckdb.DuckDBPyConnection
) -> list[Fact]:
    """Mitigations and actors for techniques reached via the CWE/CAPEC
    crosswalk above -- always derived, since the link back to `cve_id` is
    two hops removed from anything MITRE states directly.
    """
    facts: list[Fact] = []
    for technique_id in technique_ids:
        mitigations = db.execute(
            "SELECT DISTINCT mitigation_id, mitigation_name FROM technique_mitigation "
            "WHERE technique_id = ?",
            [technique_id],
        ).fetchall()
        for mitigation_id, mitigation_name in mitigations:
            facts.append({
                "text": (
                    f"Mitigation {mitigation_id} ({mitigation_name}) addresses technique "
                    f"{technique_id}, which is derived from {cve_id} via the CWE/CAPEC crosswalk "
                    f"above, not a direct statement about {cve_id} itself."
                ),
                "derived": True,
                "category": "mitigation",
                "source": _source(
                    "MITRE ATT&CK", mitigation_id, mitigation_name, mitigation_url(mitigation_id)
                ),
            })

        actors = db.execute(
            "SELECT DISTINCT a.attack_id, a.name FROM actor a "
            "JOIN actor_technique atq ON atq.actor_stix_id = a.stix_id "
            "WHERE atq.technique_id = ?",
            [technique_id],
        ).fetchall()
        for attack_id, name in actors:
            facts.append({
                "text": (
                    f"{name} is documented by MITRE ATT&CK as using technique {technique_id}, "
                    f"which is derived from {cve_id} via the CWE/CAPEC crosswalk above — this is "
                    f"NOT a documented statement that {name} exploits {cve_id} specifically."
                ),
                "derived": True,
                "category": "actor_usage",
                "source": _source("MITRE ATT&CK", attack_id, name, group_url(attack_id)),
            })
    return facts


def lookup_cve(
    cve_id: str, db: duckdb.DuckDBPyConnection, cache_db: duckdb.DuckDBPyConnection
) -> tuple[list[Fact], list[Source]]:
    """The full CVE -> KEV -> CWE -> CAPEC -> ATT&CK -> mitigation/actor
    crosswalk for one CVE, plus any IOCs correlated to it by product name.
    """
    precondition(bool(cve_id), "cve_id must not be empty")
    facts: list[Fact] = []

    nvd = fetch_nvd(cve_id, cache_db)
    nvd_fact = _nvd_fact(cve_id, nvd)
    if nvd_fact:
        facts.append(nvd_fact)

    kev_fact = _kev_fact_for_cve(cve_id, db)
    if kev_fact:
        facts.append(kev_fact)

    cwe_ids = _cwe_ids_for_cve(cve_id, db, nvd)
    technique_rows: list[tuple[str, str, str, str]] = []
    if cwe_ids:
        technique_rows = _crosswalk_rows(cwe_ids, db)
        if not technique_rows:
            facts.append(_crosswalk_dead_end_fact(cve_id, cwe_ids, db))

    facts.extend(_crosswalk_technique_facts(cve_id, technique_rows, db))

    technique_ids = sorted({row[3] for row in technique_rows})
    facts.extend(_technique_followon_facts(cve_id, technique_ids, db))

    facts.extend(lookup_ioc_for_cve(cve_id, db))

    return facts, dedup_sources(facts)


def _ioc_hash_facts_for_term(term: str, cve_id: str, db: duckdb.DuckDBPyConnection) -> list[Fact]:
    like = f"%{term}%"
    facts: list[Fact] = []
    for sha256, file_name, signature, first_seen in db.execute(
        "SELECT sha256, file_name, signature, first_seen FROM ioc_hash "
        "WHERE signature ILIKE ? OR file_name ILIKE ? LIMIT 5",
        [like, like],
    ).fetchall():
        facts.append({
            "text": (
                f"Indicator of Compromise (IOC) - file hash: MalwareBazaar has a file hash "
                f"({sha256[:16]}..., file name '{file_name}', family '{signature}') tagged "
                f"with '{term}', the product {cve_id} affects per CISA KEV, first seen "
                f"{first_seen}. This is a name-based correlation, not confirmed evidence "
                f"this file exploited {cve_id}."
            ),
            "derived": True,
            "category": "ioc",
            "source": _source("MalwareBazaar", sha256, file_name, None),
        })
    return facts


def _ioc_url_facts_for_term(term: str, cve_id: str, db: duckdb.DuckDBPyConnection) -> list[Fact]:
    like = f"%{term}%"
    facts: list[Fact] = []
    for entry_id, url, tags, threat in db.execute(
        "SELECT id, url, tags, threat FROM ioc_url WHERE tags ILIKE ? OR url ILIKE ? LIMIT 5",
        [like, like],
    ).fetchall():
        facts.append({
            "text": (
                f"Indicator of Compromise (IOC) - malicious URL: URLhaus has a URL "
                f"({url}, threat '{threat}', tags '{tags}') tagged with '{term}', the "
                f"product {cve_id} affects per CISA KEV. This is a name-based correlation, "
                f"not confirmed evidence this URL relates to {cve_id}."
            ),
            "derived": True,
            "category": "ioc",
            "source": _source(
                "URLhaus", entry_id, url, f"https://urlhaus.abuse.ch/url/{entry_id}/"
            ),
        })
    return facts


def _ioc_c2_facts_for_term(term: str, cve_id: str, db: duckdb.DuckDBPyConnection) -> list[Fact]:
    like = f"%{term}%"
    facts: list[Fact] = []
    for ip_address, malware, first_seen in db.execute(
        "SELECT ip_address, malware, first_seen FROM ioc_c2 WHERE malware ILIKE ? LIMIT 5",
        [like],
    ).fetchall():
        facts.append({
            "text": (
                f"Indicator of Compromise (IOC) - C2 IP address: Feodo Tracker lists "
                f"{ip_address} as a botnet C2 server for '{malware}', tagged with '{term}', "
                f"the product {cve_id} affects per CISA KEV, first seen {first_seen}. This "
                f"is a name-based correlation, not confirmed evidence this C2 relates to "
                f"{cve_id}."
            ),
            "derived": True,
            "category": "ioc",
            "source": _source("Feodo Tracker", ip_address, malware, None),
        })
    return facts


def lookup_ioc_for_cve(cve_id: str, db: duckdb.DuckDBPyConnection) -> list[Fact]:
    """Public IOC feeds don't carry a CVE field (no source publishes CVE->IOC
    mappings) — but CISA KEV directly states the affected vendor/product, so
    search IOC feeds for that product name. This is a short, legible 2-hop
    correlation (CVE -> KEV's own product field -> IOC), always marked
    derived: a name match is not confirmed evidence a given indicator relates
    to exploitation of this specific CVE.
    """
    kev_row = db.execute(
        "SELECT vendor_project, product FROM kev WHERE cve_id = ?", [cve_id]
    ).fetchone()
    if not kev_row:
        return []
    vendor, product = kev_row
    terms = {t for t in (vendor, product) if t}
    if not terms:
        return []

    facts: list[Fact] = []
    for term in terms:
        facts.extend(_ioc_hash_facts_for_term(term, cve_id, db))
        facts.extend(_ioc_url_facts_for_term(term, cve_id, db))
        facts.extend(_ioc_c2_facts_for_term(term, cve_id, db))
    return facts


def _ioc_hash_fact(indicator: str, db: duckdb.DuckDBPyConnection) -> tuple[Fact | None, str | None]:
    row = db.execute(
        "SELECT sha256, md5, sha1, file_name, signature, first_seen FROM ioc_hash "
        "WHERE sha256 = ? OR md5 = ? OR sha1 = ?",
        [indicator, indicator, indicator],
    ).fetchone()
    if not row:
        return None, None
    sha256, _md5, _sha1, file_name, signature, first_seen = row
    fact: Fact = {
        "text": (
            f"Indicator of Compromise (IOC) confirmed: {indicator} matches a known "
            f"malware sample in MalwareBazaar: file name '{file_name}', family "
            f"'{signature}', first seen {first_seen}."
        ),
        "derived": False,
        "category": "ioc",
        "source": _source("MalwareBazaar", sha256, file_name, None),
    }
    return fact, signature


def _ioc_ip_fact(indicator: str, db: duckdb.DuckDBPyConnection) -> tuple[Fact | None, str | None]:
    row = db.execute(
        "SELECT ip_address, malware, first_seen, status FROM ioc_c2 WHERE ip_address = ?",
        [indicator],
    ).fetchone()
    if not row:
        return None, None
    ip_address, malware, first_seen, ioc_status = row
    fact: Fact = {
        "text": (
            f"Indicator of Compromise (IOC) confirmed: {indicator} is listed by Feodo "
            f"Tracker as a botnet C2 server for '{malware}' (status: {ioc_status}, "
            f"first seen {first_seen})."
        ),
        "derived": False,
        "category": "ioc",
        "source": _source("Feodo Tracker", ip_address, malware, None),
    }
    return fact, malware


def _ioc_url_fact(
    indicator: str, db: duckdb.DuckDBPyConnection
) -> tuple[Fact | None, str | None]:
    row = db.execute(
        "SELECT id, url, threat, tags FROM ioc_url WHERE url = ?", [indicator]
    ).fetchone()
    if not row:
        return None, None
    entry_id, url, threat, tags = row
    fact: Fact = {
        "text": (
            f"Indicator of Compromise (IOC) confirmed: {indicator} is listed by URLhaus "
            f"as a malicious URL (threat: {threat}, tags: {tags})."
        ),
        "derived": False,
        "category": "ioc",
        "source": _source(
            "URLhaus", entry_id, url, f"https://urlhaus.abuse.ch/url/{entry_id}/"
        ),
    }
    return fact, None


def _actor_usage_facts_for_malware(malware_name: str, db: duckdb.DuckDBPyConnection) -> list[Fact]:
    """Actors documented as using ATT&CK software whose name matches an IOC
    feed's malware family name -- a name-based correlation, always derived.
    """
    facts: list[Fact] = []
    for software_id, software_name in db.execute(
        "SELECT DISTINCT software_id, software_name FROM ioc_software WHERE malware_name = ?",
        [malware_name],
    ).fetchall():
        actors = db.execute(
            "SELECT DISTINCT a.attack_id, a.name FROM actor a "
            "JOIN actor_software asw ON asw.actor_stix_id = a.stix_id "
            "WHERE asw.software_id = ?",
            [software_id],
        ).fetchall()
        for attack_id, name in actors:
            facts.append({
                "text": (
                    f"'{malware_name}' matches ATT&CK software {software_name}, which "
                    f"{name} is documented to use. This is a name-based correlation between "
                    f"the IOC feed's family name and ATT&CK's software name, not a confirmed "
                    f"link between this specific indicator and {name}."
                ),
                "derived": True,
                "category": "actor_usage",
                "source": _source("MITRE ATT&CK", attack_id, name, group_url(attack_id)),
            })
    return facts


_IOC_LOOKUPS = {
    "hash": _ioc_hash_fact,
    "ip": _ioc_ip_fact,
    "url": _ioc_url_fact,
}


def lookup_ioc(
    indicator: str, indicator_type: str, db: duckdb.DuckDBPyConnection
) -> tuple[list[Fact], list[Source]]:
    """Look up a single hash/IP/URL directly named in a chat question or a
    scanned file. Unlike the CVE correlation above, an exact match here IS a
    fact (this hash/IP/URL is a known indicator) — only the follow-on
    actor/technique context (via ioc_software) is a derived name-based
    correlation.
    """
    precondition(bool(indicator), "indicator must not be empty")
    precondition(
        indicator_type in _IOC_LOOKUPS, f"unknown indicator_type: {indicator_type!r}"
    )

    fact, malware_name = _IOC_LOOKUPS[indicator_type](indicator, db)
    facts: list[Fact] = [fact] if fact else []

    if malware_name:
        facts.extend(_actor_usage_facts_for_malware(malware_name, db))

    return facts, dedup_sources(facts)


def lookup_technique(
    technique_id: str, db: duckdb.DuckDBPyConnection
) -> tuple[list[Fact], list[Source]]:
    """Mitigations and actors directly documented (by MITRE) for one technique."""
    precondition(bool(technique_id), "technique_id must not be empty")
    technique_name = queries.technique_name(db, technique_id) or technique_id

    facts: list[Fact] = []

    mitigations = db.execute(
        "SELECT DISTINCT mitigation_id, mitigation_name FROM technique_mitigation "
        "WHERE technique_id = ?",
        [technique_id],
    ).fetchall()
    for mitigation_id, mitigation_name in mitigations:
        facts.append({
            "text": (
                f"Mitigation {mitigation_id} ({mitigation_name}) addresses technique "
                f"{technique_id} ({technique_name})."
            ),
            "derived": False,
            "category": "mitigation",
            "source": _source(
                "MITRE ATT&CK", mitigation_id, mitigation_name, mitigation_url(mitigation_id)
            ),
        })

    actors = db.execute(
        "SELECT DISTINCT a.attack_id, a.name FROM actor a "
        "JOIN actor_technique atq ON atq.actor_stix_id = a.stix_id "
        "WHERE atq.technique_id = ?",
        [technique_id],
    ).fetchall()
    for attack_id, name in actors:
        facts.append({
            "text": (
                f"{name} is documented by MITRE ATT&CK as using technique {technique_id} "
                f"({technique_name})."
            ),
            "derived": False,
            "category": "actor_usage",
            "source": _source("MITRE ATT&CK", attack_id, name, group_url(attack_id)),
        })

    return facts, dedup_sources(facts)


def lookup_mitigation(
    mitigation_id: str, db: duckdb.DuckDBPyConnection
) -> tuple[list[Fact], list[Source]]:
    """Techniques directly documented (by MITRE) as addressed by one mitigation."""
    precondition(bool(mitigation_id), "mitigation_id must not be empty")
    mitigation_name = queries.mitigation_name(db, mitigation_id)
    if mitigation_name is None:
        return [], []

    techniques = db.execute(
        "SELECT DISTINCT tm.technique_id, atq.technique_name FROM technique_mitigation tm "
        "LEFT JOIN actor_technique atq ON atq.technique_id = tm.technique_id "
        "WHERE tm.mitigation_id = ?",
        [mitigation_id],
    ).fetchall()

    facts: list[Fact] = []
    for technique_id, technique_name in techniques:
        technique_name = technique_name or technique_id
        facts.append({
            "text": (
                f"Mitigation {mitigation_id} ({mitigation_name}) addresses technique "
                f"{technique_id} ({technique_name})."
            ),
            "derived": False,
            "category": "mitigation",
            "source": _source(
                "MITRE ATT&CK", technique_id, technique_name, technique_url(technique_id)
            ),
        })

    return facts, dedup_sources(facts)


def parse_aliases(aliases_field: str | None) -> list[str]:
    """Split an actor's ';'-separated aliases field into a clean list."""
    return [a.strip() for a in (aliases_field or "").split(";") if a.strip()]


def _naming_fact(
    vendor: str,
    term: str,
    category: str,
    meaning: str,
    source_url: str,
    alias: str | None = None,
) -> Fact:
    """One fact explaining a vendor naming-scheme word, optionally in the
    context of a specific alias that uses it. source_url is the vendor's own
    published naming-scheme page, verified against this row -- see
    model/schema.sql's naming_convention table.
    """
    if category == "nation-state":
        meaning_clause = f"suspected {meaning}-nexus (state-sponsored) activity"
    else:
        meaning_clause = f"{meaning}, not a nation-state attribution"
    if alias:
        text = (
            f"The alias '{alias}' follows {vendor}'s adversary-naming convention: the "
            f"word '{term}' denotes {meaning_clause}. The other word in the name is "
            f"{vendor}'s unique label for this specific actor within that category, "
            f"not an additional signal."
        )
    else:
        text = (
            f"{vendor} uses the word '{term}' in its adversary-naming convention "
            f"to denote {meaning_clause}."
        )
    return {
        "text": text,
        "derived": False,
        "category": "naming_note",
        "source": _source(
            f"{vendor} naming convention", term, f"{vendor} adversary naming convention",
            source_url,
        ),
    }


def _matching_alias(term: str, aliases: list[str]) -> str | None:
    pattern = re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
    return next((alias for alias in aliases if pattern.search(alias)), None)


def naming_convention_facts(aliases: list[str], db: duckdb.DuckDBPyConnection) -> list[Fact]:
    """Facts explaining any vendor naming-convention word found among an
    actor's own aliases (e.g. an alias ending in 'Panda' or 'Bear').
    """
    if not aliases:
        return []
    facts = []
    for vendor, term, category, meaning, source_url in db.execute(
        "SELECT vendor, term, category, meaning, source_url FROM naming_convention"
    ).fetchall():
        alias = _matching_alias(term, aliases)
        if alias:
            facts.append(_naming_fact(vendor, term, category, meaning, source_url, alias))
    return facts


def alias_note_facts(attack_id: str, db: duckdb.DuckDBPyConnection) -> list[Fact]:
    """Documented etymology for any of this actor's aliases (e.g. why
    "Comment Crew"), for the handful of aliases that have one.
    """
    precondition(bool(attack_id), "attack_id must not be empty")
    rows = db.execute(
        "SELECT alias, note, source_url FROM actor_alias_note WHERE attack_id = ?", [attack_id]
    ).fetchall()
    return [
        {
            "text": f"Why the name '{alias}': {note}",
            "derived": False,
            "category": "naming_note",
            "source": _source("Vendor reporting", alias, f"Etymology of '{alias}'", source_url),
        }
        for alias, note, source_url in rows
    ]


def lookup_naming_term(
    term: str, db: duckdb.DuckDBPyConnection
) -> tuple[list[Fact], list[Source]]:
    """Every vendor's meaning for a single naming-convention word (e.g.
    'Panda'), independent of any specific actor -- for a question like
    "what does Panda mean" that names no actor of its own.
    """
    precondition(bool(term), "term must not be empty")
    rows = db.execute(
        "SELECT vendor, term, category, meaning, source_url FROM naming_convention "
        "WHERE lower(term) = lower(?)",
        [term],
    ).fetchall()
    facts = [
        _naming_fact(vendor, term_, category, meaning, source_url)
        for vendor, term_, category, meaning, source_url in rows
    ]
    return facts, dedup_sources(facts)


def lookup_actor(stix_id: str, db: duckdb.DuckDBPyConnection) -> tuple[list[Fact], list[Source]]:
    """Techniques, software, and naming-convention notes for one actor."""
    precondition(bool(stix_id), "stix_id must not be empty")
    actor_row = db.execute(
        "SELECT attack_id, name, aliases FROM actor WHERE stix_id = ?", [stix_id]
    ).fetchone()
    if actor_row is None:
        return [], []
    attack_id, name, aliases_field = actor_row
    aliases = parse_aliases(aliases_field)

    facts: list[Fact] = []
    facts.extend(naming_convention_facts(aliases, db))
    facts.extend(alias_note_facts(attack_id, db))

    techniques = db.execute(
        "SELECT DISTINCT technique_id, technique_name FROM actor_technique "
        "WHERE actor_stix_id = ?",
        [stix_id],
    ).fetchall()
    for technique_id, technique_name in techniques:
        facts.append({
            "text": (
                f"{name} is documented by MITRE ATT&CK as using technique {technique_id} "
                f"({technique_name})."
            ),
            "derived": False,
            "category": "actor_usage",
            "source": _source(
                "MITRE ATT&CK", technique_id, technique_name, technique_url(technique_id)
            ),
        })

    software = db.execute(
        "SELECT DISTINCT software_id, software_name, software_type FROM actor_software "
        "WHERE actor_stix_id = ?",
        [stix_id],
    ).fetchall()
    for software_id, software_name, software_type in software:
        facts.append({
            "text": (
                f"{name} is documented by MITRE ATT&CK as using {software_type} "
                f"{software_name}."
            ),
            "derived": False,
            "category": "actor_usage",
            "source": _source("MITRE ATT&CK", software_id, software_name, None),
        })

    return facts, dedup_sources(facts)
