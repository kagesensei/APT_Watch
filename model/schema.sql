-- APT_Watch schema reference.
--
-- This file documents the tables built by the ingest scripts in ingest/; it
-- is not executed directly (each ingest script creates its own tables via
-- `CREATE OR REPLACE TABLE`). Keep this in sync when a table's shape changes.
--
-- data/cti.duckdb — built by ingest/attack.py, ingest/capec.py, ingest/cve.py,
-- ingest/ioc.py.
-- data/nvd_cache.duckdb — separate file, written at request time by the chat
-- feature (app/cache.py) to cache on-demand NVD lookups; kept out of the
-- read-only main database on purpose.
-- data/chats/<user_id>.json — per-user saved chats (app/chats_store.py), not
-- a DuckDB table at all; documented here for completeness.

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

-- === IOC feeds (ingest/ioc.py) ===
-- No signup required. There is no CVE field in any of these — the CVE
-- correlation in app/intel.py.lookup_ioc_for_cve works by matching KEV's own
-- vendor_project/product fields against these tables' name/tag/signature
-- fields, always marked "derived" (a name match, not confirmed evidence).

CREATE TABLE ioc_url(          -- abuse.ch URLhaus (malicious URLs)
    id VARCHAR,
    url VARCHAR,
    date_added VARCHAR,
    threat VARCHAR,
    tags VARCHAR,             -- comma-separated, mixes format/arch tags with malware family
    status VARCHAR,
    urlhaus_link VARCHAR
);

CREATE TABLE ioc_hash(         -- abuse.ch MalwareBazaar (file hashes)
    sha256 VARCHAR,
    md5 VARCHAR,
    sha1 VARCHAR,
    file_name VARCHAR,
    signature VARCHAR,        -- malware family name, e.g. 'Emotet' ('n/a' if unclassified)
    first_seen VARCHAR
);

CREATE TABLE ioc_c2(           -- abuse.ch Feodo Tracker (active botnet C2 IPs)
    ip_address VARCHAR,
    port INTEGER,
    malware VARCHAR,          -- malware family name
    first_seen VARCHAR,
    last_online VARCHAR,
    status VARCHAR
);

CREATE TABLE ioc_software(     -- crosswalk built at ingest time
    source_table VARCHAR,     -- 'ioc_hash' | 'ioc_c2'
    malware_name VARCHAR,     -- exact, case-insensitive match to actor_software.software_name
    software_id VARCHAR,
    software_name VARCHAR
);

-- === Naming conventions (ingest/naming.py) ===
-- Hand-curated reference data (data/seed/*.json), not from any live feed:
-- what a vendor's naming-scheme word denotes, and documented etymology for
-- specific aliases. Every row was verified against a fetched source in the
-- session that added it (never filled from assumed knowledge) -- source_url
-- and retrieved record exactly what was checked and when, so a row can be
-- re-verified or retired if the source changes. See app/intel.py's
-- naming_convention_facts()/alias_note_facts() for how these become
-- chat/Library facts.

CREATE TABLE naming_convention(
    vendor VARCHAR,      -- e.g. 'CrowdStrike', 'Microsoft', 'Secureworks'
    term VARCHAR,        -- the naming-scheme word, e.g. 'Panda', 'Bear', 'Typhoon'
    category VARCHAR,    -- 'nation-state' | 'motivation'
    meaning VARCHAR,      -- e.g. 'China', 'financially motivated (eCrime)'
    source_url VARCHAR,   -- the vendor's own published naming-scheme page
    retrieved DATE         -- when source_url was fetched and checked against this row
);

CREATE TABLE actor_alias_note(
    attack_id VARCHAR,  -- actor.attack_id, e.g. G0006
    alias VARCHAR,        -- the specific alias this note explains, e.g. 'Comment Crew'
    note VARCHAR,          -- documented etymology, matching what source_url actually says
    source_url VARCHAR,     -- a primary or reputable secondary source for the note
    retrieved DATE            -- when source_url was fetched and checked against this row
);

-- === MISP Galaxy threat-actor cluster (ingest/misp_galaxy.py) ===
-- A community-maintained actor list, independent of MITRE ATT&CK's own
-- group list -- used (see resolve/aliases.py) to cross-reference ATT&CK
-- group names/aliases against a second, differently-curated source rather
-- than trusting ATT&CK's own alias list alone.

CREATE TABLE misp_actor(
    misp_uuid VARCHAR,      -- the cluster value's own "uuid" field
    canonical_name VARCHAR,  -- the cluster value's "value" field
    description VARCHAR,      -- absent on some entries -> NULL
    country VARCHAR,           -- meta.country (ISO-ish 2-letter code); absent on most entries -> NULL
    refs VARCHAR,                -- meta.refs, ';'-joined; absent -> ''
    source_url VARCHAR,           -- the fetched clusters/threat-actor.json URL
    retrieved DATE                 -- when it was fetched
);

CREATE TABLE actor_alias(
    misp_uuid VARCHAR,   -- misp_actor.misp_uuid
    alias VARCHAR,         -- the canonical name itself (alias_type='canonical') or one synonym
    alias_type VARCHAR,     -- 'canonical' | 'synonym'
    source_url VARCHAR,      -- the fetched clusters/threat-actor.json URL
    retrieved DATE             -- when it was fetched
);

-- === Actor identity cross-walk (resolve/aliases.py) ===
-- Matches ATT&CK's own actor/alias list against MISP Galaxy's, so an actor
-- can eventually be looked up regardless of which source's name was used.
-- Not run automatically by any ingest script -- run resolve/aliases.py by
-- hand after both actor and misp_actor/actor_alias are populated.

CREATE TABLE actor_xwalk(
    attack_stix_id VARCHAR,  -- actor.stix_id; UNIQUE by construction (checked at build time)
    attack_id VARCHAR,         -- actor.attack_id, e.g. G0006
    attack_name VARCHAR,
    misp_uuid VARCHAR,           -- misp_actor.misp_uuid; UNIQUE by construction (checked at build time)
    misp_name VARCHAR,
    match_method VARCHAR,          -- 'exact' (mutual 1-to-1 after normalization) |
                                     -- 'manual' (a fuzzy candidate promoted by a human --
                                     -- see data/seed/actor_xwalk_manual.json)
    match_score DOUBLE,               -- 100.0 for 'exact'; the original fuzzy score for 'manual'
    source_url VARCHAR,                 -- copied from the actor_alias row that produced the match
    retrieved DATE                        -- likewise
);

-- Every ATT&CK actor with zero exact matches, fuzzy-matched (RapidFuzz
-- token_set_ratio >= 90) against MISP's alias list, MINUS any pair already
-- decided in data/seed/actor_xwalk_manual.json (promoted or rejected --
-- either way it's no longer "open"). See data/reports/alias_resolution.md.
CREATE TABLE actor_xwalk_candidates(
    attack_stix_id VARCHAR,
    attack_id VARCHAR,
    attack_name VARCHAR,
    misp_uuid VARCHAR,
    misp_name VARCHAR,
    match_method VARCHAR,      -- always 'fuzzy' here
    match_score DOUBLE,          -- RapidFuzz token_set_ratio, 90-100
    matched_attack_alias VARCHAR,  -- which of the ATT&CK actor's aliases scored highest
    matched_misp_alias VARCHAR,      -- which MISP alias it matched against
    source_url VARCHAR,
    retrieved DATE
);

-- A fuzzy candidate a human reviewed and decided was NOT the same actor --
-- kept so the same candidate doesn't need re-litigating on every re-run,
-- and so the rejection's reasoning stays attached to the pair it applies
-- to. Populated from data/seed/actor_xwalk_manual.json's "rejected" entries.
CREATE TABLE actor_xwalk_rejected(
    attack_stix_id VARCHAR,
    attack_id VARCHAR,
    attack_name VARCHAR,
    misp_uuid VARCHAR,
    misp_name VARCHAR,
    match_score DOUBLE,  -- the original fuzzy score that was rejected
    reason VARCHAR,         -- why, and what was checked to reach that conclusion
    reviewed DATE
);

-- === Sigma detection rules (ingest/sigma.py) ===
-- SigmaHQ/sigma's rule set, so a technique or actor can be answered with
-- "here's what detects it" (see app/queries.py's sigma_coverage_for_actor)
-- as well as "here's what mitigates it". 'deprecated' and 'unsupported'
-- rule directories are excluded -- see ingest/sigma.py's module docstring.

CREATE TABLE sigma_rule(
    rule_id VARCHAR,             -- the rule's own "id" field (a UUID)
    title VARCHAR,
    status VARCHAR,                -- e.g. 'stable' | 'test' | 'experimental'
    level VARCHAR,                   -- e.g. 'informational' | 'low' | 'medium' | 'high' | 'critical'
    logsource_category VARCHAR,        -- logsource.category; absent on ~22% of rules -> NULL
    logsource_product VARCHAR,           -- logsource.product; absent on ~4% of rules -> NULL
    description VARCHAR,
    file_path VARCHAR,                     -- path within the SigmaHQ/sigma repo
    source_url VARCHAR,                      -- this rule's own GitHub blob URL
    retrieved DATE                             -- when the repo snapshot was fetched
);

CREATE TABLE sigma_rule_technique(  -- from tags matching attack.tNNNN(.NNN), uppercased
    rule_id VARCHAR,
    technique_id VARCHAR  -- matches actor_technique.technique_id
);

CREATE TABLE sigma_rule_actor(  -- from tags matching attack.gNNNN, uppercased
    rule_id VARCHAR,
    attack_id VARCHAR  -- matches actor.attack_id
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
-- MITRE/NVD/CISA statement. Every fact intel.py produces also carries an
-- explicit "category" (vuln_info/mitigation/ioc/actor_usage/crosswalk_detail)
-- used purely to budget how many facts of each kind reach the LLM's context
-- window (app/llm.py) without one numerous category crowding out another.
