# Current state

Audit basis: repository files present on 2026-09-29, including the application,
ingestion and resolution code, schema, fine-tuning artifacts, notebooks plan,
tests, CI and pre-commit configuration. The four-gate preflight was run from
this checkout. No live feed refresh or model inference was run.

## What exists

- Local Flask application with Library pages, dashboard, IOC text-file scan,
  chat, previews and optional Google OIDC sign-in. The main DuckDB connection
  is read-only in the web app; NVD cache and saved chats are separate writable
  files. Anonymous chat stays in browser session storage.
- Deterministic ingestion for ATT&CK Enterprise, CAPEC, CISA KEV, MISP Galaxy,
  SigmaHQ rules, abuse.ch URLhaus/MalwareBazaar/Feodo, and curated naming notes.
  NVD is fetched on demand and cached. Parsers have targeted data-quality
  checks; data and model files are local and gitignored.
- Conservative ATT&CK↔MISP matching with exact matches, pending fuzzy
  candidates, explicit human promotion/rejection, and ambiguity reports.
- Chat entity extraction and retrieval are deterministic. LLM responses use
  retrieved facts, direct/derived labels, a retrieved-fact source panel, and
  fabricated-ID warnings. CVE→CWE→CAPEC→ATT&CK and name-based IOC links are
  disclosed as derived; Sigma author tags are not independently verified by
  MITRE.
- Existing tests cover parser, retrieval, chat, route, UI helper and alias
  behavior. CI and pre-commit specify pylint, strict mypy, Bandit and pytest.
- The current user-selected model setup is the abliterated Llama 3.1 8B
  derivative. This records the user's explicit clarification; it overrides
  the earlier model clause in `PROJECT_VISION.md`, which has now been updated.
  The 4.92 GB Q4_K_M GGUF and local DuckDB snapshots are present in this
  checkout. Evidence-only retrieval and citation rules remain.
- The project software has a PolyForm Noncommercial License file; third-party
  dataset terms remain separate and are not granted by that license.

## Partially implemented

- Actor identity evidence is now shown on actor pages and included in actor
  retrieval: mutual exact lexical matches, analyst-promoted/rejected decisions,
  fuzzy candidates, recomputed one-to-many/many-to-one collisions, and
  unmatched actors. Similarity is explicitly not attribution. Collision data
  is recomputed from source alias tables using resolver matching functions;
  the generated Markdown report is not parsed. This remains the existing
  one-to-one schema, not a temporal/partial-overlap relationship model.
- Sigma author-tag coverage is shown for actors and techniques and retrieved
  for actor questions. It is explicitly labeled as author claims, not
  MITRE-confirmed or environment-validated detection coverage. Untagged rule
  counts and uncovered techniques are visible, and an absent rule is not
  described as proof no detection exists.
- Actor assessments now use bounded evidence retrieval with explicit gaps for
  unsupported campaign, IOC, current-activity and victimology sections.
  Techniques, their listed mitigations, Sigma tags and identity states are
  grounded in retrieved records. One canonical prompt/rubric module is shared
  by runtime and fine-tuning data generation.
- A 24-entry `data/seed/source_catalog.json`, refresh wrapper, status display,
  and source-specific entity/observation/claim schema were added as initial
  scaffolding. Registry fields required by the vision are incomplete; most
  entries have not had current terms/schema/rate-limit review. The new graph
  tables are not populated by current ingestors. No vector index exists.
- The refresh wrapper schedules only existing ingestors: KEV, MISP Galaxy,
  IOC bundle, ATT&CK, CAPEC, Sigma and alias resolution. It does not implement
  source-level incremental checkpoints, parser versions, accepted/rejected
  row metrics, content hashes or source snapshots. External scheduling is
  left to the operator.
- Fine-tuning data generation exists for response discipline, but teacher
  synthesis and training/export are not complete. Runtime and training now
  import their prompt and rubric definitions from `app/prompts.py`.
- Google sign-in exists for saved chat access only. It is not a multi-user
  zero-trust deployment, PKI/mTLS system, or device-posture control.

## Documented but not wired in

- Broader threat-source integrations (NVD batch sync, EPSS, CVEProject,
  Vulnrichment, government/vendor reporting, ThreatFox, CIRCL, YARA and others).
- JupyterHub, JupyterLab, Jupyter-AI, user-built agents, shared workspaces and
  provider-agnostic user AI credentials.
- Graph exploration, semantic/vector retrieval, campaign timelines, hunt
  records, evidence-for/against analysis, change intelligence and audience
  specific assessment modes.
- Threat modeling, audited tenant/workspace access, encrypted persistent
  analyst data/backups, TLS/mTLS deployment, managed secrets, endpoint posture,
  SBOM and PQC evaluation.

## Missing or unresolved

- Complete source registry with per-source legal/use classification, canonical
  terms URL, redistribution scope, rate limit, schema/version, parser version,
  freshness and quality fields. Source terms and reuse status remain unknown
  until verified from publisher primary documentation. Unknown-term sources
  must remain disabled in the target system.
- Target analytical entities and temporal evidence model beyond the initial
  three graph-ready tables: reports, claims with full evidence/counterevidence,
  campaigns, infrastructure/observations, victims/sectors, hunts, hypotheses,
  hunt steps, findings and analyst feedback.
- Product requirements and measurable acceptance criteria for personas,
  lifecycle, hunt workflow, non-goals, quality measures and security posture.
- Operational exposure model, tenant model, deployment target, backup/key
  management, threat model and residual-risk review.

## Correctness and maintenance concerns

- Model identity and actual quantization/context/GPU layers are not shown or
  logged as required by the vision. The model is
  not auto-downloaded, which is good; user must provision it.
- `intel.lookup_recent_kev()` calls KEV inclusion “confirmed to be actively
  exploited in the wild”; a catalog inclusion is evidence of known exploitation,
  not a measurement of current activity or frequency. Avoid “active right now”
  without dated current reporting.
- Dashboard rankings are ATT&CK relationship counts, not current operational
  activity. Overview code labels this limitation; UI language must retain it.
- External fetching has request timeouts and upload size limits, but there is
  no common SSRF-resistant retrieval layer, response/decompression bound and
  strict schema validation across every feed. Sigma tar member parsing avoids
  extraction, but needs archive/resource limits.
- Google OAuth/session handling is local-app scope. Production HTTPS, secure
  cookie policy, CSRF/rate limits, authorization model, account lifecycle and
  audit logging are not established here.
- `ingest/feeds.py` and `ingest/malpedia.py` are empty placeholders while the
  README calls them “not yet implemented.”
- `PROJECT_VISION.md` contains a model requirement that conflicts with the
  user's later explicit request for the abliterated model; the worktree has
  been aligned to the user's latest requirement. The staged index still
  contains the earlier wording until the user stages/reviews the document.
- `data/cti.duckdb` and `data/nvd_cache.duckdb` are present locally; the 261
  tests passed against the current test setup, including database-backed tests.

## Quality gate result

The preflight baseline before implementation identified and fixed the existing
`ingest/update.py` findings: an unused `pathlib` import and 103-character line
for pylint, plus an `Any` return from `_catalog()` and an unannotated `failed`
list for strict mypy. The final `python preflight.py` passed: pylint 10.00/10,
strict mypy clean across 38 files, Bandit reported no issues, and all 261 tests
passed. Pylint emitted a cache-permission warning for the user profile, but the
analysis completed successfully. No live feed refresh or model inference was
run.
