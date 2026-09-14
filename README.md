# APT_Watch

Ingests MITRE ATT&CK, CISA KEV, and MITRE CAPEC data into a local DuckDB
database for querying threat actors, techniques, software, mitigations, and
actively-exploited CVEs — browsable through a Flask UI, and queryable in
plain English through a local-LLM chat feature where every answer cites the
real data it came from.

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/kagesensei/APT_Watch.git
cd APT_Watch
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # macOS/Linux
pip install -r requirements.txt
```

## Data ingest

Run each ingest script once to build `data/cti.duckdb`:

```bash
python ingest/attack.py       # MITRE ATT&CK Enterprise (actors, techniques, software, mitigations)
python ingest/capec.py        # MITRE CAPEC (attack patterns; the CVE->technique crosswalk)
python ingest/cve.py          # CISA Known Exploited Vulnerabilities catalog
python ingest/ioc.py          # IOC feeds: URLhaus, MalwareBazaar, Feodo Tracker (no signup needed)
python ingest/naming.py       # curated vendor naming-convention data (data/seed/*.json, no network)
python ingest/misp_galaxy.py  # MISP Galaxy threat-actor cluster (independent actor/alias list)
python ingest/sigma.py        # SigmaHQ/sigma detection rules, tagged with ATT&CK techniques/actors
python resolve/aliases.py     # cross-walks actor against misp_actor -- run by hand, after both above
```

| table | source | description |
|---|---|---|
| `actor` | ATT&CK | groups (intrusion sets) |
| `actor_technique` | ATT&CK | techniques used by each actor |
| `actor_software` | ATT&CK | software (malware/tools) used by each actor |
| `technique_mitigation` | ATT&CK | mitigations mapped to each technique |
| `capec` | CAPEC | attack patterns |
| `capec_cwe` | CAPEC | which weaknesses (CWEs) each pattern relates to |
| `capec_technique` | CAPEC | which ATT&CK techniques each pattern maps to |
| `kev` | CISA | actively-exploited CVEs, remediation deadlines, ransomware use |
| `kev_cwe` | CISA | which weaknesses (CWEs) each KEV CVE involves |
| `ioc_url` | URLhaus | malicious URLs |
| `ioc_hash` | MalwareBazaar | file hashes (MD5/SHA1/SHA256), tagged with a malware family |
| `ioc_c2` | Feodo Tracker | active botnet C2 IPs, tagged with a malware family |
| `ioc_software` | (crosswalk) | IOC malware family name matched against `actor_software.software_name` |
| `naming_convention` | curated (`data/seed/naming_conventions.json`) | what a vendor's naming-scheme word denotes, e.g. CrowdStrike's "Panda" = China, "Bear" = Russia |
| `actor_alias_note` | curated (`data/seed/actor_alias_notes.json`) | documented etymology for specific aliases, e.g. why "Comment Crew" |
| `misp_actor` | MISP Galaxy | threat-actor cluster: canonical name, description, country, references |
| `actor_alias` | MISP Galaxy | one row per canonical name/synonym, keyed to `misp_actor.misp_uuid` |
| `actor_xwalk` | (computed by `resolve/aliases.py`) | mutual 1-to-1 exact-match cross-walk between `actor` and `misp_actor`, plus any pair promoted via `data/seed/actor_xwalk_manual.json` (`match_method='manual'`) |
| `actor_xwalk_candidates` | (computed by `resolve/aliases.py`) | fuzzy-matched (RapidFuzz >= 90) candidates awaiting manual review, never auto-promoted |
| `actor_xwalk_rejected` | curated (`data/seed/actor_xwalk_manual.json`) | fuzzy candidates a human reviewed and declined to promote, kept with their reasoning rather than silently dropped |
| `sigma_rule` | SigmaHQ/sigma | detection rule metadata (title, status, level, logsource, description) |
| `sigma_rule_technique` | SigmaHQ/sigma | which ATT&CK techniques each rule's tags claim to detect |
| `sigma_rule_actor` | SigmaHQ/sigma | which ATT&CK groups each rule's tags reference |

Revoked/deprecated ATT&CK and CAPEC objects are excluded; SigmaHQ's
`deprecated`/`unsupported` rule directories are excluded the same way (see
`ingest/sigma.py`'s docstring). Each script prints row counts and runs a
data quality check — comparing its tables against the publisher's own
totals (ATT&CK/CAPEC entity counts, the CISA catalog's published `count`,
SigmaHQ's own file count) for the feed-based scripts, or against the seed
file's own row count for `ingest/naming.py` — exiting non-zero if any check
fails. `resolve/aliases.py` has its own quality checks (no duplicate
`attack_stix_id`/`misp_uuid` in `actor_xwalk`) and writes a review report to
`data/reports/alias_resolution.md` rather than resolving ambiguous matches
itself. Full schema reference: `model/schema.sql`.

**Naming conventions are curated, not fetched:** unlike the other tables
above, no feed publishes "what does Panda mean" — `naming_convention` and
`actor_alias_note` are hand-researched and reviewed like code
(`data/seed/*.json`), covering only entries confirmed with reasonably high
confidence. They're deliberately not comprehensive; extend the seed files
and re-run `ingest/naming.py` to add more. Chat surfaces these as
`naming_note` facts (see `intel.naming_convention_facts`/`alias_note_facts`),
and the actor Library page shows them under "What the names mean."

**Important caveat:** MITRE does not publish a CVE-to-ATT&CK mapping. The
CVE→technique link used throughout this app is *computed* by this project via
CVE→CWE→CAPEC→ATT&CK (CAPEC attack patterns carry both CWE and ATT&CK
mappings). It's a reasonable, widely-used correlation — but it's an inference,
not a fact any single source states directly. The app tags every fact this
way as **derived** and never presents it as if MITRE/NVD/CISA said it outright.

**Same caveat applies to IOCs:** no public feed publishes a CVE-to-indicator
mapping either. `intel.lookup_ioc_for_cve` searches the IOC tables for CISA
KEV's own stated `vendor_project`/`product` name (a direct fact) — a name
match, not confirmed evidence a given hash/URL/IP relates to exploitation of
that CVE, always marked derived. Most CVEs will correctly return zero IOC
matches; that's the honest answer for a name-based correlation over three
small "recent" feeds, not a bug.

**The ATT&CK <-> MISP actor cross-walk is intentionally partial:**
`resolve/aliases.py` only auto-writes a mutual one-to-one exact match to
`actor_xwalk` (115 of 176 ATT&CK groups, as of the run in
`data/reports/alias_resolution.md`). A name shared by more than one group on
either side — MISP's single "Lazarus Group" entry overlapping five distinct
ATT&CK groups is the sharpest example — is a real naming collision, not
something to silently pick a winner for, so it's reported instead. Fuzzy
matches (RapidFuzz >= 90) land in `actor_xwalk_candidates` for human review
and are never auto-promoted. Nothing in the app queries either table yet.

**Manual review decisions are curated, not re-derived:** a human reviewing an
open fuzzy candidate records their promote/reject decision — with sources —
in `data/seed/actor_xwalk_manual.json`, the same hand-edited, git-tracked
pattern as the naming seed files. `resolve/aliases.py` re-applies it on every
run: a `"promoted"` entry becomes an `actor_xwalk` row with
`match_method='manual'`; a `"rejected"` entry becomes an `actor_xwalk_rejected`
row, keeping the reasoning instead of just deleting the candidate. Either way
the pair is removed from `actor_xwalk_candidates`, since a reviewed match
shouldn't still look pending. As of this repo's three reviewed candidates:
G0020 Equation and G0142 Confucius were promoted (MISP's own "Equation Group"
reference list cites G0020 directly; "Confucious" is a documented misspelling
of "Confucius"); G0114 Chimera was rejected against MISP's "WET PANDA" — the
RapidFuzz 100 score was a `token_set_ratio` artifact ("Chimera" is a lexical
subset of "Red Chimera"), not evidence of a shared identity, and no source
connects the two beyond the coincidental name overlap.

**Sigma rule -> ATT&CK mappings are the rule authors' own claims, not a
MITRE-verified fact:** `sigma_rule_technique`/`sigma_rule_actor` come
straight from each rule's own `attack.tNNNN`/`attack.gNNNN` tags — useful
signal, but self-reported by whoever wrote that Sigma rule, not cross-checked
against ATT&CK's own data the way the CVE crosswalk above is.

Query the result with any DuckDB client, e.g.:

```bash
python -c "import duckdb; print(duckdb.connect('data/cti.duckdb').sql('SELECT * FROM actor LIMIT 5'))"
```

## Web interface

Once `data/cti.duckdb` exists, run the Flask app:

```bash
pip install -r requirements.txt
python main.py
```

By default `python main.py` starts straight up — it does **not** run the
pylint/mypy/bandit/pytest gate (see "Code quality and security" below for
where that gate actually runs: a pre-commit hook and CI). Set
`APTWATCH_RUN_PREFLIGHT=1` if you want that same gate to run once before the
dev server starts, as an optional local sanity check; it needs
`requirements-dev.txt` installed and takes several seconds.

Then open http://127.0.0.1:5000/ — **Chat is the home page.** Everything else
(Actors, Techniques, Software, Mitigations, CVEs, and an Overview dashboard)
lives under the **Library** dropdown in the nav bar, at `/library/...`:

- **Actors** — ATT&CK groups, their aliases, techniques used, and software used
- **Techniques** — which actors use each technique and which mitigations apply to it
- **Software** — malware/tools and which actors use them
- **Mitigations** — which techniques each mitigation addresses
- **CVEs** — CISA KEV entries plus the same CWE→CAPEC→ATT&CK crosswalk chat uses,
  so what chat says about a CVE and what its Library page shows are always the
  same underlying query (`intel.lookup_cve`)

`main.py` runs the built-in Flask dev server, for local use only. Debug mode
(the interactive Werkzeug debugger, which allows arbitrary code execution
from the browser) is **off by default** — set `APTWATCH_DEBUG=1` to enable it
for local development. Custom error pages are included for 400, 403, 404,
405, and 500 responses (plus a generic fallback for any other HTTP error).

## Dashboard

The **Dashboard** page (`/dashboard`) is a situational snapshot of the threat
terrain — not a chat answer, not a single-entity browse page, a landing view
for "what does the data look like right now":

- Stat tiles: total actors, techniques, software, mitigations, KEV CVEs, IOC
  indicators, and the **crosswalk coverage** figure — what fraction of KEV
  CVEs actually resolve to an ATT&CK technique via the CWE→CAPEC crosswalk.
  This is the same data-quality signal used throughout chat, surfaced here as
  an ongoing metric rather than a one-off fact.
- Three ranking charts: top techniques by actor count, most active actors (by
  distinct technique count), and top software by actor count.
- A weekly stacked chart of KEV additions, split ransomware-linked vs. not.

Charts are hand-built inline SVG (`app/charts.py`) — no external charting
library, keeping the app self-contained. Colors follow the `dataviz` skill's
method: the three ranking charts use one sequential hue (the app's existing
`--accent` teal, not subject to categorical rules since it's a single series);
the 2-series weekly chart uses two categorical hues from the skill's
documented default palette, chosen in fixed order and validated with
`scripts/validate_palette.js` against this app's dark surface before use —
not eyeballed. Every chart has a native per-bar/segment tooltip (SVG
`<title>`) and an accessible "View as table" fallback with the same data.

## Chat

The home page answers free-text questions — "What's a concerning CVE being
actively exploited right now?", "What TTPs exploit CVE-2024-3400 and how do I
mitigate it?", "What mitigates T1055?", "What techniques does APT29 use?" —
using a local LLM restricted to facts pulled from `data/cti.duckdb` plus a
live NVD lookup for any specific CVE named. It does not answer from the
model's own training knowledge: if nothing relevant is in the database, it
says so instead of guessing. Open-ended questions that don't name a specific
CVE/technique/actor (anything matching a "concerning/recent/critical/active/..."
keyword gate in `app/nlp.py`) fall back to the most notable current entries in
the CISA KEV catalog (`intel.lookup_recent_kev`) so the chat has something
concrete to reason about instead of always saying "no data."

Pipeline for each question (see `app/nlp.py`, `app/intel.py`, `app/llm.py`,
`app/chat.py`):

1. **Extract** CVE/technique/mitigation IDs by regex, and actor/software
   names via word-boundary/fuzzy matching against `actor`/`actor_software`
   (`RapidFuzz`) — this is a small, deterministic layer, not a general-purpose
   NLP model. If the question names nothing on its own (a follow-up like
   "what mitigates this CVE?"), extraction is retried against the last few
   messages too — the frontend sends a rolling `history` array with each
   request — so references to something already discussed still resolve.
2. **Retrieve** structured facts for each entity found, each one tagged
   `[DIRECT]` (stated outright by MITRE/NVD/CISA) or `[DERIVED]` (reached via
   the CVE→CWE→CAPEC→ATT&CK crosswalk above).
3. **Answer**: the facts are handed to a local LLM with a system prompt that
   forbids it from using anything else, and requires it to flag derived facts
   as inferred when it uses them.
4. **Verify**: the model's reply is scanned for any CVE/CWE/CAPEC/technique/
   mitigation/group ID that doesn't appear anywhere in the facts it was given.
   Testing showed the model will occasionally invent a plausible-looking ID
   (e.g. a CAPEC number) despite the system prompt telling it not to — this
   check catches that and appends a visible warning naming the unverified
   identifier, rather than silently letting it through.
5. **Cite**: the "Sources" panel under each answer is built directly from the
   retrieved facts — not parsed out of the model's text — so citations stay
   accurate even if the model's wording is imperfect.

The chat page is a 3-column layout: a left sidebar of saved chats, the chat
itself in the center, and a right-hand **view panel** on the right. Any CVE,
technique, mitigation, or actor ID mentioned in a reply is clickable — but
only if it was one of the IDs actually verified against the retrieved facts
(`app/linkify.py` reuses the same `llm.allowed_ids()` check the hallucination
guard uses, so an unverified/fabricated ID never gets a link either). Clicking
one fetches `/api/preview/<type>/<id>` (`app/preview.py`) and renders a short
preview in the view panel — no page navigation — with an "Open full page"
link to the real Library page for the full detail.

### Model setup

Chat needs a local GGUF model file and `llama-cpp-python`. Tested with
[`mlabonne/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF`](https://huggingface.co/mlabonne/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF)
at `Q4_K_M` quantization (~4.9GB, fits an 8GB GPU with headroom):

```bash
mkdir models
curl -L -o "models/meta-llama-3.1-8b-instruct-abliterated.Q4_K_M.gguf" "https://huggingface.co/mlabonne/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF/resolve/main/meta-llama-3.1-8b-instruct-abliterated.Q4_K_M.gguf"
```

`app/llm.py` looks for the model at `models/meta-llama-3.1-8b-instruct-abliterated.Q4_K_M.gguf`
by default; point it elsewhere with the `APTWATCH_MODEL_PATH` env var. Any
other GGUF instruct model works too — just set the env var. Other tunables:
`APTWATCH_MODEL_CTX` (default 8192) and `APTWATCH_MODEL_GPU_LAYERS` (default
`-1`, i.e. offload everything to GPU; set `0` to force CPU-only).

**GPU (NVIDIA, Windows):** `requirements.txt` pins a CUDA-enabled
`llama-cpp-python` wheel plus the lightweight `nvidia-cuda-runtime-cu12` /
`nvidia-cublas-cu12` pip packages (the CUDA *runtime* libraries only — no need
to install the full CUDA Toolkit). `app/llm.py` also works around a real
Windows/Python 3.10 ctypes quirk where `llama_cpp`'s own DLL loader fails to
resolve the CUDA runtime even with the right directories registered; the
workaround pre-loads the DLL chain before `llama_cpp` imports. If you don't
have an NVIDIA GPU, set `APTWATCH_MODEL_GPU_LAYERS=0` to run on CPU (slower,
but no extra setup).

The model file and `data/nvd_cache.duckdb` (the on-demand NVD lookup cache —
kept as a separate file so the main read-only `data/cti.duckdb` connection
never needs write access) are both gitignored.

## Scan

The **Scan** page (`/scan`) lets you upload a text file — scan output, a log,
a list of indicators — and checks it against the ingested IOC feeds. It
recognizes file hashes (MD5/SHA1/SHA256), IPv4 addresses, and URLs (the same
extraction `app/nlp.py` uses for chat); domains alone are deliberately not
extracted, too high a false-positive rate without more context. The file is
read into memory for that one request and **never written to disk** — capped
at 5MB (`MAX_CONTENT_LENGTH`) and ~2MB of decoded text. A file that doesn't
decode as mostly-valid UTF-8 text is rejected rather than scanned as garbage.

You can also paste a single hash/IP/URL directly into a chat question — the
same `intel.lookup_ioc()` backs both paths, and an exact match there is a
**direct** fact (not derived): the indicator either is or isn't in the feeds.

## Accounts & saved chats

- **Not signed in:** chats are saved in the browser's `sessionStorage` only —
  never sent to the server. They persist across page reloads but disappear
  once the browser tab/session ends, by design.
- **Signed in with Google:** chats are saved server-side as
  `data/chats/<google_sub>.json` (one file per user; gitignored — it's user
  data, not app data) and are available from any device once signed in.

Google sign-in is optional and the app works fully without it (the sign-in
button in the nav simply doesn't appear if it isn't configured). To enable it:

1. In [Google Cloud Console](https://console.cloud.google.com/) → APIs &
   Services → Credentials, create an OAuth 2.0 Client ID (type: Web
   application).
2. Add `http://127.0.0.1:5000/auth/callback/google` as an authorized redirect URI.
3. Create a `.env` file in the project root (gitignored) with:
   ```
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   APTWATCH_SECRET_KEY=any-random-string
   ```
   `main.py` loads this automatically via `python-dotenv`. `APTWATCH_SECRET_KEY`
   signs Flask's session cookie; without it the app still runs, using a random
   key generated at startup (with a warning) — fine for a quick local test,
   but it means every restart signs everyone out.

Facebook/other providers aren't implemented yet — Facebook Login requires
HTTPS and app review even in development mode, which is more setup than fits
a local dev app right now.

## Testing

```bash
pytest
```

192 tests covering entity extraction, the CVE→CWE→CAPEC→ATT&CK crosswalk
(both success and dead-end branches), IOC lookups, the chart builders, the
design-by-contract helpers in `contracts.py`, naming-convention/alias-etymology
lookups, the MISP Galaxy/Sigma parsers and the alias resolver (all three
against small fixture files under `tests/fixtures/`, never a live download),
and every Flask route — run in a few seconds against your locally built
`data/cti.duckdb` (see Data ingest above; DB-dependent tests skip
automatically if it doesn't exist yet), with the local LLM and NVD network
calls mocked out. See `TESTING.md` for what each test file covers and a
manual walkthrough for the parts that need a browser or the local LLM (chat
answer quality, dashboard visuals, Google sign-in).

## Code quality and security

This codebase follows an adaptation of NASA/JPL's "Power of 10" rules for
safety-critical code — see `POWER10.md` for what each rule means here and
why. In short: small, single-purpose functions; every loop's bound is
either obvious or enforced by `contracts.bounded()`; every DB/API return
value is checked (`contracts.not_none()` and friends); and `pylint`, `mypy
--strict`, and `bandit` all run alongside `pytest` in two places:

- **CI** (`.github/workflows/ci.yml`) runs all four, as separate steps, on
  every push.
- **A pre-commit hook** (`.pre-commit-config.yaml`, running `preflight.py`)
  runs all four together on every `git commit`, so a broken checkout is
  caught before it's even pushed, not just before it's merged. Install it
  once per clone:

  ```bash
  pip install -r requirements-dev.txt
  pre-commit install
  ```

  `git commit --no-verify` bypasses it for a deliberate work-in-progress
  commit, the same as any other pre-commit hook.

`python main.py` does **not** run this gate by default (see "Web
interface" above) — starting the dev server and verifying code quality are
separate concerns here, kept out of each other's way.

To run the checks by hand:

```bash
pip install -r requirements-dev.txt
pylint app ingest resolve contracts.py main.py preflight.py
mypy .
bandit -c pyproject.toml -r app ingest resolve contracts.py main.py preflight.py
pytest
```

## Project layout

- `ingest/attack.py`, `ingest/capec.py`, `ingest/cve.py`, `ingest/ioc.py`,
  `ingest/misp_galaxy.py`, `ingest/sigma.py` — implemented ingest pipelines
  (see Data ingest above)
- `ingest/naming.py`, `data/seed/*.json` — curated vendor naming-convention data (no network source)
- `ingest/common.py` — shared fetch/count/data-quality-exit helpers for the ingest scripts above
- `ingest/feeds.py`, `ingest/malpedia.py` — additional intel source ingests (not yet implemented)
- `resolve/aliases.py` — cross-walks ATT&CK actors against MISP Galaxy's actor list
  (`actor_xwalk`/`actor_xwalk_candidates`/`actor_xwalk_rejected`); run by hand, writes
  `data/reports/alias_resolution.md`; re-applies hand-reviewed promote/reject decisions from
  `data/seed/actor_xwalk_manual.json` on every run
- `contracts.py` — design-by-contract helpers (`precondition`/`postcondition`/`not_none`/`bounded`) used across `app/`, `ingest/`, and `resolve/`; see `POWER10.md`
- `model/schema.sql` — full schema reference for both database files
- `CLAUDE.md` — repo guidance for AI assistants: commands, conventions, current phase status
- `tests/` — pytest suite (see Testing above); fixture files for the ingest/resolve parsers live in `tests/fixtures/`; `TESTING.md` — what it covers plus a manual walkthrough
- `app/` — Flask application:
  - `routes.py` (mounted at `/library`), `templates/*.html` (excl. `chat.html`, `scan.html`) — the browsing UI, including the CVE list/detail pages
  - `chat.py` (mounted at `/`) — the chat home page, `/ask` API, and the `/api/chats/*` saved-chat CRUD API
  - `scan.py` (mounted at `/scan`) — the IOC file-scan page and `/scan/upload` API
  - `dashboard.py` (mounted at `/dashboard`), `templates/dashboard.html` — the Threat Terrain dashboard
  - `charts.py` — dependency-free inline-SVG chart builders for the dashboard
  - `nlp.py` — entity extraction for chat and the scan page (CVE/technique/mitigation IDs, actor/software fuzzy matching, hash/IP/URL indicators)
  - `intel.py` — fact retrieval + source citation for chat, the CVE Library page, and IOC lookups (the only module that queries the DB for facts); also naming-convention/alias-etymology facts (why "Comment Crew", what "Panda" means)
  - `llm.py` — local LLM loading, prompting, the fabricated-ID guard, and per-category context budgeting
  - `linkify.py` — turns verified IDs in an answer into clickable Library links
  - `preview.py` — `/api/preview/<type>/<id>` API backing the view panel
  - `auth.py` — Google OAuth (Authlib), session-based `current_user()`, `login_required`
  - `chats_store.py` — reads/writes `data/chats/<user_id>.json`
  - `templates/chat.html`, `static/js/chat.js` — the 3-column chat page's markup/JS
  - `templates/scan.html`, `static/js/scan.js` — the scan page's markup/JS
  - `db.py`, `cache.py` — read-only main DB connection, writable NVD cache connection
  - `queries.py` — small shared DB query helpers (`count`, `overview_counts`, `searchable_list`) used by `routes.py`, `preview.py`, `dashboard.py`, and `intel.py`; also `sigma_coverage_for_actor()` (data-layer only, no route/UI yet)
- `main.py` — Flask app entry point; loads `.env` via `python-dotenv`; runs the preflight gate only if `APTWATCH_RUN_PREFLIGHT=1`
- `preflight.py` — the pylint/mypy/bandit/pytest quality gate, run by the pre-commit hook and (as separate steps) by CI
- `.pre-commit-config.yaml` — runs `preflight.py` on every `git commit` (`pre-commit install` once per clone)
- `models/` — local GGUF model files (gitignored)
- `data/cti.duckdb` — built database, gitignored; run the ingest scripts (see Data ingest above) to build it locally
- `data/nvd_cache.duckdb` — on-demand NVD lookup cache (gitignored)
- `data/chats/` — per-user saved chats for signed-in users (gitignored)
- `data/raw/` — downloaded source data (regenerated by ingest scripts, not committed)
- `data/reports/alias_resolution.md` — `resolve/aliases.py`'s human-review report (committed; regenerate by re-running it)
