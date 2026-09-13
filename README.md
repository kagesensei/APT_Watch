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
python ingest/attack.py   # MITRE ATT&CK Enterprise (actors, techniques, software, mitigations)
python ingest/capec.py    # MITRE CAPEC (attack patterns; the CVE->technique crosswalk)
python ingest/cve.py      # CISA Known Exploited Vulnerabilities catalog
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

Revoked/deprecated ATT&CK and CAPEC objects are excluded. Each script prints
row counts and runs a data quality check comparing its tables against the
publisher's own totals (ATT&CK/CAPEC entity counts, the CISA catalog's
published `count`), exiting non-zero if any check fails. Full schema
reference: `model/schema.sql`.

**Important caveat:** MITRE does not publish a CVE-to-ATT&CK mapping. The
CVE→technique link used throughout this app is *computed* by this project via
CVE→CWE→CAPEC→ATT&CK (CAPEC attack patterns carry both CWE and ATT&CK
mappings). It's a reasonable, widely-used correlation — but it's an inference,
not a fact any single source states directly. The app tags every fact this
way as **derived** and never presents it as if MITRE/NVD/CISA said it outright.

Query the result with any DuckDB client, e.g.:

```bash
python -c "import duckdb; print(duckdb.connect('data/cti.duckdb').sql('SELECT * FROM actor LIMIT 5'))"
```

## Web interface

Once `data/cti.duckdb` exists, run the Flask app:

```bash
python main.py
```

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

`main.py` runs the built-in Flask dev server with debug mode on, for local use
only. Custom error pages are included for 400, 403, 404, 405, and 500
responses (plus a generic fallback for any other HTTP error).

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

## Project layout

- `ingest/attack.py`, `ingest/capec.py`, `ingest/cve.py` — implemented ingest
  pipelines (see Data ingest above)
- `ingest/feeds.py`, `ingest/malpedia.py`, `ingest/misp_galaxy.py` — additional
  intel source ingests (not yet implemented)
- `resolve/aliases.py` — actor alias resolution across sources (not yet implemented)
- `model/schema.sql` — full schema reference for both database files
- `app/` — Flask application:
  - `routes.py` (mounted at `/library`), `templates/*.html` (excl. `chat.html`) — the browsing UI, including the CVE list/detail pages
  - `chat.py` (mounted at `/`) — the chat home page, `/ask` API, and the `/api/chats/*` saved-chat CRUD API
  - `nlp.py` — entity extraction for chat
  - `intel.py` — fact retrieval + source citation for chat and the CVE Library page (the only module that queries the DB for facts)
  - `llm.py` — local LLM loading, prompting, and the fabricated-ID guard
  - `linkify.py` — turns verified IDs in an answer into clickable Library links
  - `preview.py` — `/api/preview/<type>/<id>` API backing the view panel
  - `auth.py` — Google OAuth (Authlib), session-based `current_user()`, `login_required`
  - `chats_store.py` — reads/writes `data/chats/<user_id>.json`
  - `templates/chat.html`, `static/js/chat.js` — the 3-column chat page's markup/JS
  - `db.py`, `cache.py` — read-only main DB connection, writable NVD cache connection
- `main.py` — Flask app entry point; loads `.env` via `python-dotenv`
- `models/` — local GGUF model files (gitignored)
- `data/cti.duckdb` — built database, committed as a snapshot
- `data/nvd_cache.duckdb` — on-demand NVD lookup cache (gitignored)
- `data/chats/` — per-user saved chats for signed-in users (gitignored)
- `data/raw/` — downloaded source data (regenerated by ingest scripts, not committed)
