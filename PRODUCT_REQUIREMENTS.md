# Product requirements

Status: draft derived from `PROJECT_VISION.md` and the user's later model
clarification. Nothing here claims planned functionality is implemented.

## Product and personas

APT_Watch is a local-first cyber threat-intelligence and threat-hunting
workbench. It supports:

- **Threat analyst / hunter:** assess actors, campaigns, CVEs and evidence;
  plan repeatable hunts and record findings.
- **Detection engineer:** inspect technique coverage, telemetry needs, Sigma
  and YARA rules, and gaps without treating a rule as guaranteed detection.
- **Intelligence lead:** prioritize collection, review confidence and source
  gaps, and disseminate executive or analyst products.
- **Researcher / data scientist:** explore reproducible data, compare sources,
  develop notebooks and optional custom agents.
- **Administrator / source steward:** review source terms, configure collection,
  manage identities and access, and audit changes.

## Intelligence questions

Users should be able to ask and investigate:

- Which source-defined actors may be the same, overlap, or be related, and what
  evidence supports or contradicts each proposed relationship?
- What campaigns, motivations, capabilities, targeting, victimology, TTPs,
  tools, malware, infrastructure and indicators are reported, by whom and when?
- What changed in actor reporting, campaigns, exploitation, indicators,
  detections or source status over a selected period?
- Is a vulnerability exploited or reported as a zero-day; what evidence,
  actors/campaigns, products, CVSS severity, EPSS probability, KEV status and
  ransomware reporting apply?
- Which of our products, versions, assets and exposures are relevant, and what
  patches, mitigations, compensating controls, telemetry, detections and hunt
  steps should we consider?
- What behaviors have Sigma/YARA coverage, what telemetry is required, and
  where are the unaddressed detection gaps?
- What hypothesis can be hunted, what evidence supports/refutes it, what is
  the confidence and outcome, and what should be learned or reused?

## Functional requirements

### Collection and lifecycle

- Maintain a machine-readable registry with the fields specified in
  `PROJECT_VISION.md`. A source with unknown terms stays disabled. Do not
  scrape disallowed sites; prefer documented APIs and RSS/Atom.
- Each enabled source must state its unique intelligence value and collection
  requirement. Avoid duplicate-volume feeds without independent evidence.
- Ingest with bounded, schema-validated, versioned parsers; preserve source
  identity, stable record ID, original link, times, version/hash, accepted and
  rejected counts, quality result and run history.
- Normalize without losing source-specific names, claims, handling labels,
  provenance or history. Keep full articles out of the product unless terms
  permit it; store permitted metadata/excerpts, hashes and canonical links.
- Support requirement prioritization, collection planning, validation,
  corroboration, analysis, production, audience-specific dissemination and
  analyst feedback.

### Evidence, analysis and hunting

- Preserve source-specific entities and temporal observations; model aliases,
  claims, campaigns, tools, infrastructure, indicators, vulnerabilities,
  weaknesses, patterns, ATT&CK behavior, detections, mitigations, victims and
  geography.
- Every claim must be traceable to an exact source record and carry direct /
  derived / analyst-assessed status, times, confidence, derivation path,
  supporting and contradicting evidence, source-independence concerns, review
  status, and superseded/retracted state.
- Support actor dossiers, campaign timelines, vulnerability triage, detection
  engineering, change intelligence and structured analysis (competing
  hypotheses, evidence matrices, assumptions, gaps and rationale).
- Support the hunt lifecycle: hypothesis/question, scope/assumptions, required
  telemetry, related intelligence and ATT&CK behavior, queries, evidence,
  findings/confidence, recommended action, outcome and lessons learned.
- Keep analyst approval for curated identity, attribution and confidence
  changes. Similarity, clustering and LLM output are advisory, never attribution.
- Use deterministic rules, parsing, SQL and statistics where sufficient. Add
  ML only with a defined decision, non-ML baseline, temporal-safe evaluation,
  versioning, calibrated/explainable outputs and analyst correction.

### Assistant and user experience

- Preserve the chatbot-centered UI and existing Library, dashboard, scan and
  chat features. Provide quick lookup, actor/campaign assessment, vulnerability
  triage, detection analysis, hunt planning, evidence review and executive
  summary modes.
- The local model is the user's selected abliterated Meta Llama 3.1 8B Instruct
  derivative, intentionally chosen to avoid model-level refusal of exploit
  discussion. This clarification supersedes the earlier prohibition, now
  resolved in the working copy of `PROJECT_VISION.md`. Record model identity/path, quant,
  context and GPU-layer settings. Keep it local/configurable; do not auto-fetch
  weights or accept a license for the user.
- Model answers must synthesize retrieved evidence only, distinguish direct
  facts, derived correlations, analyst assessments, suggestions, unknowns and
  conflicts, cite only retrieved sources, and state uncertainty/staleness.
  AI must not silently make attribution or operational decisions.
- Keep inference separate from retrieval and preserve fabricated-identifier
  detection. Fine-tuning may teach response discipline, not volatile CTI facts.
  Evaluate base and tuned models on a reproducible held-out suite.
- If/when agents are added, first build deterministic inspectable orchestration.
  Each agent has a narrow role, allowlisted tools, read-only default, bounded
  time/iterations, typed I/O, audit logs, citations, validated writes and human
  approval for curated intelligence changes. Treat ingested content as
  untrusted and defend against prompt injection.

### Analyst workspace

- Add JupyterHub, JupyterLab and Jupyter-AI for personal analyst feature work.
- Allow user-authored, integrated data-gathering/reporting agents; optional
  controlled sharing and collaboration; user-selected trusted AI provider and
  private user-owned credentials.
- Isolate kernels and agents and enforce per-user identity, data/tool
  authorization, resources, network access and explicit sharing boundaries.

## Nonfunctional requirements

- Project software is for academic and personal noncommercial use under the
  selected noncommercial license. This does not grant rights to third-party
  feeds or reports; review each source's terms independently.
- Local/offline after source/model provisioning; no paid source or cloud AI is
  required for core operation. Optional keyed providers degrade gracefully.
- DuckDB remains the local analytical store unless measured evidence justifies
  migration. Flask and existing UI capabilities are extended, not replaced.
- Windows and Linux; reproducible setup and ingestion; partial service
  availability; bounded uploads, responses, decompression and compute.
- Main intelligence DB remains read-only to the web application; writable
  caches and analyst data are separate. Keep secrets out of source control.
- Safe HTML/text handling, SSRF-resistant retrieval, per-source schema
  validation, checksums/versioning, pinned dependencies and SBOM.
- Security design includes authentication, least privilege, endpoint posture,
  TLS, at-rest encryption, key lifecycle, audit/revocation, threat modeling,
  and feasible mTLS/PQC. No Qiskit/Cirq dependency for PQC/application use.
- Retain contracts, strict typing, Bandit, pylint and pytest gates; changes
  should be small and testable.
- Measure freshness, source/behavior coverage, false positives, corroboration,
  detection coverage, hunt yield, time saved and analyst feedback.

## Explicit non-goals

- A raw feed aggregator, ATT&CK-only browser or generic RAG chatbot.
- Treating public access as permission to republish, or requiring paid feeds for
  core operation.
- Automatically merging actors by name, asserting attribution from similarity,
  or presenting model/ML output as a confirmed fact.
- Autonomous agents that mutate intelligence or execute operational actions
  without analyst approval.
- Bypassing source terms, unrestricted article republishing, or silently
  sharing a user's AI credentials/data with collaborators.
- A dedicated graph database or vector index before workload evidence shows
  their value; DuckDB, explicit relations and exact structured retrieval come
  first.
- Adding ML for appearance or ranking “most active” without dated reporting,
  a defined observation window and measured method.

## Acceptance criteria

1. A clean setup works on Windows and Linux with the main DB readable and the
   reasoning model local; startup does not fetch model weights or accept terms.
2. The registry validates all required source fields and blocks unreviewed
   terms; source failures leave last success/freshness intact and do not stop
   independent feeds.
3. Actor/campaign/CVE answers trace every claim to source-record evidence and
   time; contradictions, derivations, stale data, confidence and gaps remain
   visible. Similarity never silently becomes attribution.
4. Actor dossiers and campaign assessments only render sections with retrieved
   support and show missing evidence. Crosswalk and Sigma coverage are exposed
   and labeled with their source/author semantics.
5. CVE triage distinguishes CVSS severity, EPSS probability, KEV exploitation,
   ransomware evidence, product relevance and inferred ATT&CK relationships.
6. A hunt can be created, reviewed and closed with hypothesis, scope, telemetry,
   query, evidence, finding, confidence, action and outcome; metrics can be
   calculated from persisted records.
7. Each change feed can show what changed, when, in which source, and whether a
   record was retracted or superseded.
8. Chat answers cite only retrieved records, preserve uncertainty and direct /
   derived distinctions, reject ungrounded IDs, and treat source content as
   data rather than instructions.
9. Shared workspaces enforce identity, per-resource authorization, kernel/agent
   isolation and credential separation; security tests cover those boundaries.
10. CI/pre-commit pass pylint, mypy, Bandit and pytest. Evaluation reports
    source freshness/coverage, answer grounding, false positives, corroboration,
    detection gaps, hunt yield and analyst feedback.
