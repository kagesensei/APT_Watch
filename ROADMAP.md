# Roadmap

Ordered by prerequisite and analyst value. Each phase is a separately
reviewable increment. The required preflight baseline is clean. Phase 1 has been approved and is
being implemented as a focused slice.

## Phase 0 — Baseline and source governance

- Resolve quality-gate errors in current `ingest/update.py`; establish a green
  baseline on the actual app and DB-independent test fixtures.
- Complete source registry fields and primary-source review. Unknown terms,
  reuse rights or schemas keep a source disabled. Record current active feeds
  distinctly from candidates.
- Fix stale/current language, model identity/configuration visibility, prompt
  duplication and setup docs. Update the conflicting model clause to reflect
  the user's abliterated-model decision.
- Define evidence/claim schema migration strategy without changing DuckDB as
  the default store.

## Phase 1 — Expose intelligence already collected (recommended first slice)

- Surface ATT&CK↔MISP exact, reviewed, ambiguous, rejected and unresolved
  relationships on actor lookup and UI; preserve many-to-many constraints and
  never auto-promote fuzzy candidates.
- Surface Sigma rule links and technique coverage gaps on actor/technique
  lookup. Label rule-authored ATT&CK tags as rule-author claims and avoid
  implying endpoint validation.
- Add a bounded actor-assessment retrieval path whose prompt sections are
  backed by the specific retrieved facts or explicitly marked unknown.
- Consolidate production and fine-tuning prompt/rubric strings to one shared
  source; add deterministic tests and a local-model comparison suite plan.

## Phase 2 — Evidence model and observability

- Migrate source, snapshot/run, report, claim, evidence and temporal observation
  records with exact record links, direct/derived/assessed status, support and
  contradiction, confidence, derivation, independence, review and retraction.
- Populate the model from existing ATT&CK, MISP, CAPEC, KEV and Sigma ingestors.
- Add source versions/hashes, parser versions, row accepted/rejected counts,
  data quality, attempts/success, source freshness display and partial-failure
  behavior. Add bounded parsing and SSRF-resistant retrieval.

## Phase 3 — Vulnerability and public-report collection

- After primary-source terms/schema verification, implement prioritized
  machine-readable sources: CVEProject, incremental NVD, FIRST EPSS,
  Vulnrichment, then selected CISA/CERT and Western government advisories.
- Store permitted metadata/excerpts and canonical report links. Add campaigns,
  claims, exploitation evidence, source independence and retract/change history.
- Add compatible YARA/community sources and ThreatFox/CIRCL only when they add
  unique evidence and their reuse rules fit. Optional keyed sources degrade
  cleanly. Do not add a paid-feed dependency.

## Phase 4 — Analyst workflows and products

- Actor dossiers, campaign timelines and vulnerability prioritization.
- Technique-to-Sigma/YARA coverage, required telemetry and clearly labeled
  detection gaps.
- Hypothesis-driven hunt creation, evidence capture, findings, confidence,
  action, outcome and lessons. Add change intelligence and metrics.
- Provide executive, analyst and engineer/hunter presentations over the same
  underlying evidence. Add diagrams only where they improve reasoning.

## Phase 5 — Extensible workspace and controlled agents

- Design user/workspace/tenant and sharing policy before enabling JupyterHub,
  JupyterLab and Jupyter-AI.
- Add isolated user kernels and user-selected AI connections with private
  credentials. Build deterministic orchestration first; then narrow, read-only
  agents with allowlisted tools, bounded runs, audit, schema validation and
  approval gates for curated changes.

## Phase 6 — Deployment security and operational readiness

- Threat model intended deployment; add hardened identity/OIDC, least privilege,
  device/workload posture, TLS/mTLS, encryption and managed key lifecycle,
  audit/revocation, backup/restore and tenant-isolation controls.
- Assess FIPS 203/204/205 support, hybrid migration and module validation needs;
  maintain strong conventional crypto until deployment compatibility is proven.
- Validate Windows/Linux repeatability, offline operation, graceful partial
  feeds, resource boundaries, dependency pinning, SBOM, performance and
  security tests. Document residual risks before shared deployment.

## Recommended first implementation slice

Implement Phase 1 after approval. The existing repository already has the
crosswalk tables, human review decisions, Sigma tables, Sigma coverage query,
actor facts and assessment prompt, so this has high analyst value without
waiting for new feeds. Keep it to actor relationship visibility, detection
coverage visibility, evidence-bounded assessment retrieval, shared prompts,
tests and documentation. Do not add graph/vector infrastructure or new feeds
in this slice.
