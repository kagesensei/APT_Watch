from datetime import datetime, timezone

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def technique_url(technique_id):
    if "." in technique_id:
        base, sub = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def mitigation_url(mitigation_id):
    return f"https://attack.mitre.org/mitigations/{mitigation_id}/"


def group_url(attack_id):
    return f"https://attack.mitre.org/groups/{attack_id}/" if attack_id else None


def capec_url(capec_id):
    num = capec_id.split("-")[-1]
    return f"https://capec.mitre.org/data/definitions/{num}.html"


def cwe_url(cwe_id):
    num = cwe_id.split("-")[-1]
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def nvd_url(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def dedup_sources(facts):
    seen = set()
    sources = []
    for fact in facts:
        src = fact["source"]
        key = (src["dataset"], src["id"])
        if key not in seen:
            seen.add(key)
            sources.append(src)
    return sources


def fetch_nvd(cve_id, cache_db):
    """Look up a CVE from NVD, caching the result. Returns dict or None if not found/unreachable."""
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
            m = metrics[key][0]
            cvss_score = m["cvssData"].get("baseScore")
            cvss_severity = m["cvssData"].get("baseSeverity") or m.get("baseSeverity")
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
        [cve_id, description, cvss_score, cvss_severity, ",".join(cwe_ids), datetime.now(timezone.utc)],
    )

    return {
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_ids": cwe_ids,
    }


def lookup_recent_kev(db, limit=8):
    """For open-ended questions with no specific CVE named ("what's concerning
    right now?"). Surfaces the most recently added KEV entries, prioritizing
    ones with known ransomware use, so the model has something concrete and
    current to summarize instead of nothing.
    """
    rows = db.execute(
        "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, known_ransomware "
        "FROM kev ORDER BY (known_ransomware = 'Known') DESC, date_added DESC LIMIT ?",
        [limit],
    ).fetchall()

    facts = []
    for cve_id, vendor, product, name, date_added, ransomware in rows:
        facts.append({
            "text": (
                f"{cve_id} ({name}; affects {vendor} {product}) was added to CISA's Known "
                f"Exploited Vulnerabilities catalog on {date_added}, meaning it is confirmed "
                f"to be actively exploited in the wild. Known ransomware use: {ransomware}."
            ),
            "derived": False,
            "category": "vuln_info",
            "source": {"dataset": "CISA KEV", "id": cve_id, "name": name, "url": KEV_CATALOG_URL},
        })
    return facts, dedup_sources(facts)


def lookup_cve(cve_id, db, cache_db):
    facts = []

    nvd = fetch_nvd(cve_id, cache_db)
    if nvd:
        text = f"{cve_id}: {nvd['description']}"
        if nvd["cvss_score"] is not None:
            text += f" (CVSS {nvd['cvss_score']}, {nvd['cvss_severity']})"
        facts.append({
            "text": text,
            "derived": False,
            "category": "vuln_info",
            "source": {"dataset": "NVD", "id": cve_id, "name": cve_id, "url": nvd_url(cve_id)},
        })

    kev = db.execute(
        "SELECT vulnerability_name, date_added, due_date, required_action, known_ransomware "
        "FROM kev WHERE cve_id = ?",
        [cve_id],
    ).fetchone()
    if kev:
        name, date_added, due_date, required_action, ransomware = kev
        facts.append({
            "text": (
                f"{cve_id} ({name}) is in CISA's Known Exploited Vulnerabilities catalog, "
                f"added {date_added}, remediation due {due_date}. Known ransomware use: "
                f"{ransomware}. Required action: {required_action}"
            ),
            "derived": False,
            "category": "vuln_info",
            "source": {"dataset": "CISA KEV", "id": cve_id, "name": name, "url": KEV_CATALOG_URL},
        })

    cwe_ids = list(nvd["cwe_ids"]) if nvd and nvd["cwe_ids"] else []
    if not cwe_ids:
        cwe_ids = [
            row[0]
            for row in db.execute("SELECT cwe_id FROM kev_cwe WHERE cve_id = ?", [cve_id]).fetchall()
        ]

    technique_rows = []
    if cwe_ids:
        placeholders = ",".join("?" * len(cwe_ids))
        technique_rows = db.execute(
            f"SELECT DISTINCT cc.cwe_id, capec.capec_id, capec.name, ct.technique_id "
            f"FROM capec_cwe cc "
            f"JOIN capec ON capec.capec_id = cc.capec_id "
            f"JOIN capec_technique ct ON ct.capec_id = cc.capec_id "
            f"WHERE cc.cwe_id IN ({placeholders})",
            cwe_ids,
        ).fetchall()

    technique_ids = sorted({row[3] for row in technique_rows})
    for cwe_id, capec_id, capec_name, technique_id in technique_rows:
        technique_name_row = db.execute(
            "SELECT DISTINCT technique_name FROM actor_technique WHERE technique_id = ?",
            [technique_id],
        ).fetchone()
        technique_name = technique_name_row[0] if technique_name_row else technique_id
        facts.append({
            "text": (
                f"{cve_id} involves weakness {cwe_id}, which MITRE CAPEC pattern {capec_id} "
                f"({capec_name}) maps to ATT&CK technique {technique_id} ({technique_name}). "
                f"This is an inferred relationship via the CWE/CAPEC crosswalk, not a direct "
                f"MITRE ATT&CK-to-CVE mapping (MITRE does not publish one)."
            ),
            "derived": True,
            "category": "crosswalk_detail",
            "source": {"dataset": "MITRE CAPEC", "id": capec_id, "name": capec_name, "url": capec_url(capec_id)},
        })

    for technique_id in technique_ids:
        mitigations = db.execute(
            "SELECT DISTINCT mitigation_id, mitigation_name FROM technique_mitigation WHERE technique_id = ?",
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
                "source": {
                    "dataset": "MITRE ATT&CK",
                    "id": mitigation_id,
                    "name": mitigation_name,
                    "url": mitigation_url(mitigation_id),
                },
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
                "source": {"dataset": "MITRE ATT&CK", "id": attack_id, "name": name, "url": group_url(attack_id)},
            })

    facts.extend(lookup_ioc_for_cve(cve_id, db))

    return facts, dedup_sources(facts)


def lookup_ioc_for_cve(cve_id, db):
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

    facts = []
    for term in terms:
        like = f"%{term}%"

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
                "source": {"dataset": "MalwareBazaar", "id": sha256, "name": file_name, "url": None},
            })

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
                "source": {
                    "dataset": "URLhaus", "id": entry_id, "name": url,
                    "url": f"https://urlhaus.abuse.ch/url/{entry_id}/",
                },
            })

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
                "source": {"dataset": "Feodo Tracker", "id": ip_address, "name": malware, "url": None},
            })

    return facts


def lookup_ioc(indicator, indicator_type, db):
    """Look up a single hash/IP/URL directly named in a chat question or a
    scanned file. Unlike the CVE correlation above, an exact match here IS a
    fact (this hash/IP/URL is a known indicator) — only the follow-on
    actor/technique context (via ioc_software) is a derived name-based
    correlation.
    """
    facts = []
    malware_name = None

    if indicator_type == "hash":
        row = db.execute(
            "SELECT sha256, md5, sha1, file_name, signature, first_seen FROM ioc_hash "
            "WHERE sha256 = ? OR md5 = ? OR sha1 = ?",
            [indicator, indicator, indicator],
        ).fetchone()
        if row:
            sha256, md5, sha1, file_name, signature, first_seen = row
            malware_name = signature
            facts.append({
                "text": (
                    f"Indicator of Compromise (IOC) confirmed: {indicator} matches a known "
                    f"malware sample in MalwareBazaar: file name '{file_name}', family "
                    f"'{signature}', first seen {first_seen}."
                ),
                "derived": False,
                "category": "ioc",
                "source": {"dataset": "MalwareBazaar", "id": sha256, "name": file_name, "url": None},
            })
    elif indicator_type == "ip":
        row = db.execute(
            "SELECT ip_address, malware, first_seen, status FROM ioc_c2 WHERE ip_address = ?",
            [indicator],
        ).fetchone()
        if row:
            ip_address, malware, first_seen, ioc_status = row
            malware_name = malware
            facts.append({
                "text": (
                    f"Indicator of Compromise (IOC) confirmed: {indicator} is listed by Feodo "
                    f"Tracker as a botnet C2 server for '{malware}' (status: {ioc_status}, "
                    f"first seen {first_seen})."
                ),
                "derived": False,
                "category": "ioc",
                "source": {"dataset": "Feodo Tracker", "id": ip_address, "name": malware, "url": None},
            })
    elif indicator_type == "url":
        row = db.execute(
            "SELECT id, url, threat, tags FROM ioc_url WHERE url = ?", [indicator]
        ).fetchone()
        if row:
            entry_id, url, threat, tags = row
            facts.append({
                "text": (
                    f"Indicator of Compromise (IOC) confirmed: {indicator} is listed by URLhaus "
                    f"as a malicious URL (threat: {threat}, tags: {tags})."
                ),
                "derived": False,
                "category": "ioc",
                "source": {
                    "dataset": "URLhaus", "id": entry_id, "name": url,
                    "url": f"https://urlhaus.abuse.ch/url/{entry_id}/",
                },
            })

    if malware_name:
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
                    "source": {"dataset": "MITRE ATT&CK", "id": attack_id, "name": name, "url": group_url(attack_id)},
                })

    return facts, dedup_sources(facts)


def lookup_technique(technique_id, db):
    name_row = db.execute(
        "SELECT DISTINCT technique_name FROM actor_technique WHERE technique_id = ?",
        [technique_id],
    ).fetchone()
    technique_name = name_row[0] if name_row else technique_id

    facts = []

    mitigations = db.execute(
        "SELECT DISTINCT mitigation_id, mitigation_name FROM technique_mitigation WHERE technique_id = ?",
        [technique_id],
    ).fetchall()
    for mitigation_id, mitigation_name in mitigations:
        facts.append({
            "text": f"Mitigation {mitigation_id} ({mitigation_name}) addresses technique {technique_id} ({technique_name}).",
            "derived": False,
            "category": "mitigation",
            "source": {
                "dataset": "MITRE ATT&CK",
                "id": mitigation_id,
                "name": mitigation_name,
                "url": mitigation_url(mitigation_id),
            },
        })

    actors = db.execute(
        "SELECT DISTINCT a.attack_id, a.name FROM actor a "
        "JOIN actor_technique atq ON atq.actor_stix_id = a.stix_id "
        "WHERE atq.technique_id = ?",
        [technique_id],
    ).fetchall()
    for attack_id, name in actors:
        facts.append({
            "text": f"{name} is documented by MITRE ATT&CK as using technique {technique_id} ({technique_name}).",
            "derived": False,
            "category": "actor_usage",
            "source": {"dataset": "MITRE ATT&CK", "id": attack_id, "name": name, "url": group_url(attack_id)},
        })

    return facts, dedup_sources(facts)


def lookup_mitigation(mitigation_id, db):
    name_row = db.execute(
        "SELECT DISTINCT mitigation_name FROM technique_mitigation WHERE mitigation_id = ?",
        [mitigation_id],
    ).fetchone()
    if name_row is None:
        return [], []
    mitigation_name = name_row[0]

    techniques = db.execute(
        "SELECT DISTINCT tm.technique_id, atq.technique_name FROM technique_mitigation tm "
        "LEFT JOIN actor_technique atq ON atq.technique_id = tm.technique_id "
        "WHERE tm.mitigation_id = ?",
        [mitigation_id],
    ).fetchall()

    facts = []
    for technique_id, technique_name in techniques:
        technique_name = technique_name or technique_id
        facts.append({
            "text": f"Mitigation {mitigation_id} ({mitigation_name}) addresses technique {technique_id} ({technique_name}).",
            "derived": False,
            "category": "mitigation",
            "source": {
                "dataset": "MITRE ATT&CK",
                "id": technique_id,
                "name": technique_name,
                "url": technique_url(technique_id),
            },
        })

    return facts, dedup_sources(facts)


def lookup_actor(stix_id, name, db):
    facts = []

    actor_row = db.execute(
        "SELECT attack_id, name, aliases FROM actor WHERE stix_id = ?", [stix_id]
    ).fetchone()
    if actor_row is None:
        return [], []
    attack_id, name, aliases = actor_row

    techniques = db.execute(
        "SELECT DISTINCT technique_id, technique_name FROM actor_technique WHERE actor_stix_id = ?",
        [stix_id],
    ).fetchall()
    for technique_id, technique_name in techniques:
        facts.append({
            "text": f"{name} is documented by MITRE ATT&CK as using technique {technique_id} ({technique_name}).",
            "derived": False,
            "category": "actor_usage",
            "source": {"dataset": "MITRE ATT&CK", "id": technique_id, "name": technique_name, "url": technique_url(technique_id)},
        })

    software = db.execute(
        "SELECT DISTINCT software_id, software_name, software_type FROM actor_software WHERE actor_stix_id = ?",
        [stix_id],
    ).fetchall()
    for software_id, software_name, software_type in software:
        facts.append({
            "text": f"{name} is documented by MITRE ATT&CK as using {software_type} {software_name}.",
            "derived": False,
            "category": "actor_usage",
            "source": {"dataset": "MITRE ATT&CK", "id": software_id, "name": software_name, "url": None},
        })

    return facts, dedup_sources(facts)
