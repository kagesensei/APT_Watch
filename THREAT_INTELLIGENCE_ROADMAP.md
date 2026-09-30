# Core threat-intelligence to-do

Status: product direction and planned work; not an implemented capability claim.

APT_Watch's central purpose is a powerful data-science threat-intelligence
tool that brings together different APT watchdogs and reporting organizations.
Analysts should be able to compare their definitions of actors, understand
full or partial overlap, connect observed behavior to defenses, and ask what
a reported vulnerability or campaign means for their own enterprise.

## Planned capabilities

See the [source catalogue and update plan](THREAT_INTELLIGENCE_SOURCES.md) for
the initial connector order, source-access distinctions, and proposed polling
cadences. Source terms must be reviewed individually; academic/personal intent
does not grant rights to third-party data.

- [ ] Keep intelligence up to date through scheduled refreshes and on-demand
  updates suited to each source. Track publication dates, observation periods,
  retrieval dates, source revisions, and failed refreshes; expose freshness
  and gaps to analysts. Continuous live activity feeds are not a requirement
  by themselves; current, traceable intelligence is the requirement.
- [ ] Bring together reporting from multiple APT watchdogs and vendors,
  including Mandiant, alongside the existing datasets. Preserve each source's
  own actor names, definitions, attribution, and supporting references.
- [ ] Model relationships between source-defined actors: equivalent identities,
  partial overlaps, subsets/supersets, related campaigns, and disputed or
  unresolved associations. Support many-to-many and time-dependent mappings;
  do not collapse every similar name into a single actor. Record evidence,
  confidence, and analyst review for each relationship.
- [ ] Map actors and campaigns to their observed TTPs, tools, infrastructure,
  and exploited vulnerabilities, then map those TTPs to mitigations and
  detections. Make cross-source agreement, disagreement, and coverage gaps
  visible and explorable.
- [ ] Answer vulnerability-led investigations: Is this CVE being exploited?
  Who is reported to be exploiting it, how, and in which campaigns? Include
  reported zero-day exploitation, even before a CVE is assigned, while
  preserving the report's date, evidence, and uncertainty. Distinguish direct
  reporting from inferred correlations and unknown attribution.
- [ ] Translate that evidence into enterprise-specific defensive priorities:
  affected products and versions, exposure, relevant assets, patches,
  mitigations, compensating controls when no patch exists, detection coverage,
  and concrete investigation steps. Collect the environment context needed
  to explain what applies and why it should be prioritized.
- [ ] Support this workflow through both natural-language questions and
  data-science exploration: cross-source comparisons, relationship graphs,
  timelines, notebooks, reproducible analyses, and evidence-backed reports.
  Build on the planned [analyst workspace](notebooks/README.md).

## Target analyst workflow

Given an actor name, CVE, or report of zero-day exploitation, an analyst can
trace related actor definitions across sources, inspect the evidence for
full or partial overlap, understand reported exploitation and TTPs, and
identify protections relevant to their enterprise. Answers show their sources,
dates, confidence, and unresolved gaps instead of treating an inferred link
as a confirmed attribution.

Apply the [security requirements](SECURITY_ROADMAP.md) throughout this work.
