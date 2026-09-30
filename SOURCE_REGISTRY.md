# Source registry audit

This is the human-readable audit of `data/seed/source_catalog.json`. The
machine-readable catalogue is a starting inventory, **not yet a complete
source registry** under `PROJECT_VISION.md`. Current terms, availability,
schemas, quotas and redistribution rights must be verified from publisher
primary documentation before enabling new sources. Unknown-term candidates
stay disabled. Do not infer “open” from free access.

## Required per-source registry fields

The implementation must record: name/publisher; purpose and intelligence
level; canonical URL and retrieval method; authentication and cost; terms URL
and redistribution restrictions; rate limits and update frequency; expected
schema/version; last success/attempt; content hash or upstream version; parser
version; accepted/rejected row counts; data-quality result; enabled status;
and a classification. Classifications must separately identify open-source
software, openly licensed data, publicly accessible data, free keyed API, free
limited use, redistribution-restricted, and unknown terms (disabled).

The current ingestors do not maintain most of those fields. Historical freshness
timestamps, hashes, parser versions and row rejection metrics are therefore
unknown unless specifically noted below.

## Existing collection and derived datasets

| Registry ID | Source / publisher | Current retrieval and purpose | Known from code | Open questions / target state |
|---|---|---|---|---|
| `mitre_attack_enterprise` | MITRE ATT&CK | STIX Enterprise JSON snapshot; actors, software, techniques and mitigations | `ingest/attack.py` checks actor count and relationship subsets | Terms/reuse, version/hash, retrieval history and parser version; retain after review |
| `capec_attack_crosswalk` | MITRE CAPEC | STIX snapshot; CAPEC↔CWE↔ATT&CK relationships | `ingest/capec.py` checks active CAPEC count; CVE relationship is derived | Terms/reuse, snapshot and parser metadata; retain after review |
| `cisa_kev` | CISA KEV | JSON snapshot; known-exploited CVEs, dates, actions, ransomware field | `catalogVersion` and published count checked during ingest | Terms, timestamps/hash and history; retain after reuse review |
| `misp_galaxy` | MISP Project | GitHub raw JSON; actor names, synonyms, refs, optional country | Source URL and retrieval date stored; count and UUID uniqueness checked | Data/repository license, upstream revision, schema and retention |
| `sigma_rules` | SigmaHQ | GitHub tarball; rule metadata and rule-author ATT&CK tags | Rule URL/retrieval date; malformed/unsupported counts; archive read without extraction | Rule-level/repository licenses, revision/hash and parser version; tags are not MITRE verification |
| `abusech_urlhaus` | abuse.ch / Spamhaus | Recent CSV; malicious URLs | Exact endpoint in `ingest/ioc.py`; row count checked | Current endpoint, terms, quota, expiration/revocation, redistribution |
| `abusech_malwarebazaar` | abuse.ch / Spamhaus | Recent CSV; file hashes and metadata; no sample download in code | Exact endpoint in `ingest/ioc.py`; row count checked | Current endpoint/terms and redistribution; keep samples disabled by default |
| `abusech_feodo_tracker` | abuse.ch / Spamhaus | JSON blocklist; botnet C2 observations | Exact endpoint in `ingest/ioc.py`; row count checked | Current endpoint/terms, freshness and expiry/revocation behavior |
| `nvd_cve_api` | NIST NVD | On-demand REST lookup cached in separate DuckDB | CVSS/CWE/description retrieved for a queried CVE | No batch sync, rate-limit handling, cache expiry, API-key setting or run history; terms and schema version need review |
| `attack_misp_crosswalk` | APT_Watch derived | Offline name normalization, conservative matching, manual decisions | Exact/fuzzy candidates, human promote/reject, ambiguity report | Not exposed in actor retrieval/UI; current 1:1 table cannot express overlap/subset or temporal edges |
| `curated_naming_notes` | APT_Watch curated | Local JSON seed for vendor naming terms and alias notes | Source URLs/retrieved dates stored with seed records | Ongoing citation verification; always distinguish curated data |

`ingest/feeds.py` and `ingest/malpedia.py` are empty files, not working
integrations.

## Candidate inventory

Every source in this table is disabled/not wired unless already listed above.
License, use class, cost, terms URL, redistribution scope, schema/version,
registration, rate limit and cadence are **unknown until verified**. Purpose
describes the requirement to evaluate, not an endorsement or a legal finding.

| Candidate | Intelligence need / potential distinct value | Required primary-source verification |
|---|---|---|
| MITRE CWE | Weakness taxonomy for CVE/CAPEC reasoning | Official distribution, version, terms and schema |
| CVEProject `cvelistV5` | CVE record history distinct from NVD enrichment | Official repository, update/version model, reuse/license |
| FIRST EPSS | Exploitation probability/percentile, distinct from CVSS severity and KEV | Official API/dataset, quota, cadence, license and schema |
| CISA Vulnrichment / CVE ADP | SSVC and CISA enrichment claims | Repository terms, provenance, schema and update model |
| CISA alerts/advisories | Government campaign, actor, CVE, TTP and mitigation reporting | Documented API/RSS, text/excerpt terms, publication/update metadata |
| CERT/CC | Coordinated vulnerability and incident reporting | Primary feeds/API, terms, schema, limits and unique value |
| US-CERT/CISA RSS | Official alerts; avoid duplicates of CISA advisory sources | Current documented feeds, terms and overlap |
| CERT-EU | European public-sector advisory reporting | Public API/RSS, audience scope and reuse terms |
| UK NCSC | Government threat reports and advisories | RSS/API, license applicability, attribution and excerpt terms |
| ASD/ACSC Australia | Government advisories and reporting | Current feed/API, terms and schema |
| Canadian Cyber Centre | Government alerts and advisories | Feed/API, terms and update semantics |
| New Zealand NCSC | Government cyber threat reporting | RSS/API, terms and schema |
| Vendor RSS/Atom research | Dated actor/campaign evidence | Publisher rights for metadata/excerpts; independence and canonical links |
| APTnotes | Index/discovery of public APT reports | Index/link rights, link health and each linked publisher's terms |
| YARA repositories | Detection coverage complementary to Sigma | Repository/rule licenses, schema, quality and attribution |
| CIRCL Vulnerability-Lookup / CVE Search | Alternative vulnerability enrichment | API terms, provenance, quota, schema and non-duplicative value |
| ThreatFox | IOC and malware-family relationships | Current access, API/feed terms, quota and expiration semantics |
| CIRCL / Botvrij MISP feeds | Community events and IOCs | Per-event TLP, redistribution terms, feed schema and data quality |
| ThreatCluster public feeds | Incident/CVE/exploit/ransomware-claim context | Endpoint-specific terms, limits, attribution and source independence; claims are not confirmed breaches |
| VirusTotal public API | Optional user-keyed IOC lookup, not bulk collection | Current API terms, noncommercial limits, quota, user consent and secret handling |
| Mandiant public research | Vendor actor/campaign/vulnerability reporting | Publication terms, excerpt limits; licensed APIs are separate |
| ThreatQ/TAXII | Optional organization-authorized exchange | Customer authorization/license, credentials, TLP and redistribution constraints |

## Collection rules

- No paid source is required for core operation. Optional keyed services degrade
  gracefully when credentials are absent.
- Prefer documented APIs and RSS/Atom; do not scrape sites whose terms do not
  allow it. For reporting, retain permitted headlines, metadata, short excerpts,
  hashes and canonical links rather than full articles.
- Explain which requirement each selected source uniquely satisfies; avoid
  duplicate volume without independent evidence. Track circular reporting.
- Before enablement, fill all required fields, verify current primary docs,
  record a sample data-quality result and define retention/deletion behavior.

Machine-readable seed: [`data/seed/source_catalog.json`](data/seed/source_catalog.json).
It is incomplete until it carries the full field set and verified source
classifications described above.
