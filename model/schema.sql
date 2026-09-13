-- APT_Watch schema reference.
--
-- This file documents the tables built by the ingest scripts in ingest/; it
-- is not executed directly (each ingest script creates its own tables via
-- `CREATE OR REPLACE TABLE`). Keep this in sync when a table's shape changes.
--
-- data/cti.duckdb — built by ingest/attack.py, ingest/capec.py, ingest/cve.py.
-- data/nvd_cache.duckdb — separate file, written at request time by the chat
-- feature (app/cache.py) to cache on-demand NVD lookups; kept out of the
-- read-only main database on purpose.

-- === MITRE ATT&CK (ingest/attack.py) ===

CREATE TABLE actor(
    stix_id VARCHAR,     -- STIX intrusion-set id
    attack_id VARCHAR,   -- ATT&CK group id, e.g. G0016
    name VARCHAR,
    aliases VARCHAR       -- ';'-separated
);

CREATE TABLE actor_technique(
    actor_stix_id VARCHAR,  -- actor.stix_id
    technique_id VARCHAR,   -- ATT&CK technique id, e.g. T1055 or T1055.011
    technique_name VARCHAR
);

CREATE TABLE actor_software(
    actor_stix_id VARCHAR,  -- actor.stix_id
    software_id VARCHAR,    -- STIX malware/tool id
    software_name VARCHAR,
    software_type VARCHAR   -- 'malware' | 'tool'
);

CREATE TABLE technique_mitigation(
    technique_id VARCHAR,     -- ATT&CK technique id
    mitigation_id VARCHAR,    -- ATT&CK mitigation id, e.g. M1040
    mitigation_name VARCHAR
);

-- === MITRE CAPEC (ingest/capec.py) ===
-- Source of the CVE -> ATT&CK crosswalk: CAPEC attack patterns carry both
-- CWE weaknesses and ATT&CK technique mappings in their taxonomy.

CREATE TABLE capec(
    capec_id VARCHAR,    -- e.g. CAPEC-665
    name VARCHAR,
    description VARCHAR  -- HTML tags stripped
);

CREATE TABLE capec_cwe(
    capec_id VARCHAR,
    cwe_id VARCHAR        -- e.g. CWE-862
);

CREATE TABLE capec_technique(
    capec_id VARCHAR,
    technique_id VARCHAR  -- ATT&CK technique id
);

-- === CISA KEV (ingest/cve.py) ===

CREATE TABLE kev(
    cve_id VARCHAR,
    vendor_project VARCHAR,
    product VARCHAR,
    vulnerability_name VARCHAR,
    date_added VARCHAR,
    due_date VARCHAR,
    short_description VARCHAR,
    required_action VARCHAR,
    known_ransomware VARCHAR
);

CREATE TABLE kev_cwe(
    cve_id VARCHAR,
    cwe_id VARCHAR
);

-- === NVD cache (app/cache.py, separate file: data/nvd_cache.duckdb) ===
-- Populated lazily as users ask about specific CVEs in chat; not part of the
-- ingest pipeline and not rebuilt from ingest/*.py.

CREATE TABLE cve_cache(
    cve_id VARCHAR PRIMARY KEY,
    description VARCHAR,
    cvss_score DOUBLE,
    cvss_severity VARCHAR,
    cwe_ids VARCHAR,       -- comma-separated
    fetched_at TIMESTAMP
);

-- The CVE -> ATT&CK technique crosswalk used by the chat feature (app/intel.py)
-- joins across all of the above:
--
--   kev / cve_cache  --(cwe_id)-->  capec_cwe  --(capec_id)-->  capec_technique
--     --(technique_id)-->  technique_mitigation / actor_technique
--
-- This path is a computed correlation, not a fact any single source states
-- directly — MITRE does not publish a CVE-to-ATT&CK mapping. The app labels
-- every fact reached this way as "derived" and never presents it as a direct
-- MITRE/NVD/CISA statement.
