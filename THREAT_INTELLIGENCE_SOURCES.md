# Threat-intelligence source catalogue and update plan

This project is intended for academic and personal non-commercial research.
That describes the project's purpose; it is **not** a license to use or
redistribute any source's data. The source-specific terms below must be checked
before a connector is enabled, and provider restrictions always apply.
The machine-readable catalogue is [data/seed/source_catalog.json](data/seed/source_catalog.json).

## First ingestion wave

Prioritize sources that answer the target questions and add reliable dates and
provenance:

1. **Update and measure what is already ingested.** CISA KEV; ATT&CK; MISP
   Galaxy; CAPEC; Sigma; and the existing abuse.ch/Spamhaus feeds. The
   catalogued updater now runs these on daily or weekly profiles. Verify their
   endpoints and current access requirements before scheduling, especially
   older abuse.ch download URLs. Record the source version, record dates, last
   successful refresh, failures, and data-quality counts.
2. **Improve vulnerability coverage.** Incrementally ingest NVD CVE records
   and change history; add FIRST EPSS and CISA Vulnrichment/ADP fields alongside
   KEV. Preserve each publisher's own exploitation evidence and score rather
   than merging them into a synthetic score.
3. **Add government reporting.** Parse official CISA advisories and alerts,
   followed by UK NCSC threat-report RSS, Australia's ASD/ACSC advisories,
   Canada's Cyber Centre alerts/advisories, and New Zealand NCSC threat reports.
   Keep report publication/update dates and link to the original advisory.
4. **Add incident context.** Evaluate ThreatCluster's public incident, CVE,
   exploit, and ransomware feeds. Attribute claims to the feed and link its
   source reporting. A ransomware leak-site post is a group's claim, not proof
   that a breach occurred. Its public feeds advertise hourly refresh, but the
   free API has a limited lookback/quota; verify its terms and attribution for
   each endpoint before storing or sharing responses.
5. **Add community events selectively.** Evaluate CIRCL and Botvrij MISP feeds
   after reviewing event TLP, redistribution terms, duplication, and data
   quality. Keep IOC expiration/revocation and observation dates so old
   infrastructure does not look active.

The [ThreatCluster feed directory](https://threatcluster.io/free-threat-intelligence-feeds)
is a useful discovery list, not an endorsement or license review. Its own page
states that terms vary by publisher. The selected sources above add information
types missing from simple IP/hash lists: official exploitation evidence,
qualitative actor reporting, source-specific actor identities, and incident
context.

## Optional and entitlement-dependent sources

- **VirusTotal:** use only as a user-keyed, on-demand lookup for academic or
  personal research after the user accepts the applicable terms. VirusTotal's
  documentation describes the public API as non-commercial/academic, capped at
  four requests per minute, and separates the private API for commercial or
  government use. Never put personal API keys in source control, shared
  notebooks, or shared agent configuration. Do not treat this API as a bulk
  intelligence feed. VirusTotal and Mandiant are distinct Google security
  products; one does not provide entitlement to the other's data.
- **Mandiant Threat Intelligence:** ingest public research and advisories first.
  Treat enriched platform data and APIs as subscription/contract dependent.
  Preserve Mandiant's actor names and citations instead of overwriting them
  with ATT&CK or MISP names.
- **ThreatQ:** treat this as an optional connector to a customer's authorized
  ThreatQ Data Exchange or TAXII endpoint, not as a free public source.
  ThreatQ's Data Exchange supports sharing via OpenDXL or TAXII/STIX; access
  requires the organization's configured service and credentials.

See the primary [VirusTotal API terms](https://docs.virustotal.com/docs/api-overview),
[ThreatQ Data Exchange documentation](https://helpcenter.threatq.com/TQX/About_ThreatQ_Data_Exchange.htm),
and [MITRE ATT&CK STIX/TAXII documentation](https://attack.mitre.org/resources/working-with-attack/).

## Data and relationship model

Start with source-specific observations and stable source object IDs. Every
observation needs its publisher, object ID, original actor/product name,
publication and modification dates when supplied, observation period when
known, retrieval time, source URL, source version/hash, and the publisher's
handling/license metadata. Store evidence and attribution as first-class
records.

Represent cross-source actor mappings as dated, evidence-linked relationships
between source-specific entities. Relationship kinds should distinguish
`same_as`, `overlaps_with`, `subset_of`, `related_to`, and `disputed`; include
confidence, method, reviewer, and review state. Never merge entities merely
because their names resemble each other. This is already more graph-shaped
than the present mutual one-to-one ATT&CK/MISP crosswalk.

Keep DuckDB as the first analytical store and model relationships in explicit
entity/relationship/evidence tables. ATT&CK itself is available in STIX, which
is designed for machine-readable CTI exchange. Evaluate a separate graph
database only after measured queries show that multi-hop investigation or
relationship editing is cumbersome in DuckDB. Add vector search for report
passages and semantic discovery after provenance-preserving document storage;
use exact identifiers and structured graph/SQL queries for CVEs, actor IDs,
TTPs, dates, and mitigations. A vector score is retrieval relevance, not proof
that two actors are the same.

## Freshness and cadence

The updater currently implements daily refreshes for KEV, MISP Galaxy, and the
bundled abuse.ch feeds, plus weekly refreshes for ATT&CK, CAPEC, and Sigma.
These are starting cadences, not publisher guarantees; the catalogue describes
future cadence proposals for sources without runnable connectors. In
particular, government advisories and EPSS are not yet automatically ingested.
Honor each service's rate limits and cache headers. Use ETags or Last-Modified
where available, and NVD's modified-date checkpoints for incremental CVE
synchronization. Keep the last successful run when a later fetch fails; a
failed or stale source must never appear freshly updated.

The schema now includes source-specific entity, observation, and claim tables
as a graph-ready evidence model. Existing connectors do not yet populate those
tables, and no dedicated graph database or vector index has been deployed.

Government advisories are valuable but incomplete for an individual
enterprise's exposure and may report exploitation after it has begun. Combine
them with vendor advisories, vulnerability records, exploit evidence, and the
enterprise's own product inventory. Preserve the distinction between
“published exploit exists,” “exploitation reported,” “CISA KEV-listed,” and
“this environment is affected.”

## References

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD CVE API and incremental synchronization guidance](https://nvd.nist.gov/developers/vulnerabilities)
- [FIRST EPSS](https://www.first.org/epss/)
- [CISA Vulnrichment repository](https://github.com/cisagov/vulnrichment)
- [UK NCSC RSS feeds](https://www.ncsc.gov.uk/information/rss-feeds)
- [ASD/ACSC RSS feeds](https://www.cyber.gov.au/about-us/about-asdacsc/who-we-are/ACSC-social-media-community)
- [Canadian Cyber Centre alerts and advisories](https://www.cyber.gc.ca/en/alerts-advisories)
- [MISP community feeds](https://www.misp-project.org/communities/)
- [abuse.ch / Spamhaus API documentation](https://abusech-docs.spamhaus.com/api-reference)
