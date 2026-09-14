# Testing APT_Watch

Two layers: an automated pytest suite (`tests/`) covering the pure-logic and
data-layer code, and a manual walkthrough for the parts that need a browser
or the local LLM.

## 1. Automated tests

```bash
.venv\Scripts\activate
pip install -r requirements.txt   # now includes pytest
pytest
```

150 tests, ~4s, no network and no GPU/model required. They run against your
locally built `data/cti.duckdb` (read-only, gitignored — not committed) plus
temp/mocked files for anything that writes (NVD cache, saved chats) — nothing
in `data/` is modified. If `data/cti.duckdb` doesn't exist yet, DB-dependent
tests skip automatically (`tests/conftest.py`); run the ingest scripts first
(see README's "Data ingest" section) to get full coverage.

What's covered, by file:

| file | covers |
|---|---|
| `tests/test_contracts.py` | design-by-contract helpers (`precondition`/`postcondition`/`invariant`/`not_none`/`bounded`) — see `POWER10.md` |
| `tests/test_nlp.py` | CVE/technique/mitigation ID regexes, IOC extraction (hash/IP/URL), actor/software fuzzy matching, naming-convention term matching |
| `tests/test_linkify.py` | ID→Library-URL resolution, XSS-safe escaping, unverified-ID guard |
| `tests/test_llm.py` | context-budget tiering/caps, fabricated-ID detection — no model load |
| `tests/test_intel.py` | every `intel.lookup_*` function against real data, incl. both CVE→CWE→CAPEC→ATT&CK crosswalk dead-end branches, the WannaCry hash → Lazarus Group IOC chain, and naming-convention/alias-etymology facts (APT1 → "Comment Panda"/"Comment Crew") |
| `tests/test_charts.py` | inline-SVG chart builders: escaping, truncation, zero-value/empty-data edge cases |
| `tests/test_routes_*.py` | Flask routes via `test_client()`: Library pages, Dashboard, Scan upload, `/ask`, saved-chats auth |

Network and the local LLM are mocked throughout (`intel.requests.get`,
`llm.answer`) so the suite is deterministic and fast — it deliberately does
**not** judge answer quality, since that's a model-behavior question, not a
correctness one. That's what part 2 is for.

## 2. Static analysis and security

```bash
pip install -r requirements-dev.txt
pylint app ingest resolve contracts.py main.py preflight.py   # style/design, target: 10.00/10
mypy .                                                          # --strict; target: zero errors
bandit -c pyproject.toml -r app ingest resolve contracts.py main.py preflight.py   # target: zero issues
```

These check what pytest can't: unchecked return values, unbounded loops,
function/argument-count limits, and injection-shaped patterns. All four
commands above (these three plus `pytest`) run in CI
(`.github/workflows/ci.yml`) on every push — see `POWER10.md` for the
reasoning behind each rule and the few narrow, commented exceptions
(`# nosec B608` on the handful of queries whose WHERE clause shape, never
its data, is assembled at runtime).

They also run together, via `preflight.py`, as a pre-commit hook on every
`git commit` — install it once per clone with `pre-commit install`
(`.pre-commit-config.yaml`); bypass it for a deliberate work-in-progress
commit with `git commit --no-verify`. `python main.py` does **not** run
this gate by default; set `APTWATCH_RUN_PREFLIGHT=1` to run it once before
the dev server starts, as an optional local sanity check.

## 3. Manual walkthrough

Requires the app running (`python main.py`) against a real
`data/cti.duckdb`. The GGUF model is only needed for step 4.

### Library pages

1. Open `http://127.0.0.1:5000/library/` — stat tiles should show non-zero
   counts for actors/techniques/software/mitigations/CVEs.
2. `/library/actors` — search a known group name (e.g. "Lazarus"); confirm
   the row appears and the count updates.
3. Click into an actor detail page — techniques and software lists should be
   populated, and every technique ID should be clickable through to
   `/library/techniques/<id>`.
4. Open APT1's page specifically — a "What the names mean" section should
   explain that "Panda" denotes suspected China-nexus activity and why the
   group is called "Comment Crew" (see `data/seed/actor_alias_notes.json`).
5. `/library/cves` — open a CVE detail page. You should see either an
   ATT&CK-technique crosswalk section, or (for most CVEs) an explicit
   coverage-gap note explaining *why* none was found — never a silent blank.
6. Visit a nonexistent ID (`/library/actors/does-not-exist`) — should render
   the custom 404 page, not a stack trace.

### Dashboard

1. Open `/dashboard/` — five stat tiles plus a crosswalk-coverage
   percentage, three horizontal ranking charts, and a weekly stacked KEV
   chart should all render.
2. Hover a bar — a native tooltip (label + value) should appear.
3. Confirm the "View as table" fallback under each chart shows the same
   numbers as the chart.
4. Resize the window narrow (phone width) — charts and stat tiles should
   reflow, not overflow horizontally.

### Scan page

1. Open `/scan`, upload a `.txt` file containing this known-bad hash:
   `3044416f2a33213a25eddda36cf89533d6edf2fed6ea018ee858238099e545de`
   — expect a "matched" result citing MalwareBazaar/WannaCry, plus a derived
   note linking it to Lazarus Group.
2. Upload a file with a made-up hash/IP/URL — expect "not matched", not an
   error.
3. Upload a binary file (e.g. a `.png`) — expect a clean 400
   "doesn't look like a text file" error, not a crash.
4. Try a file over ~5MB — expect a clean rejection, not a timeout.

### Chat (needs the GGUF model — see README's "Model setup")

Ask each of these and check the answer only uses facts with citations in the
Sources panel, and that DERIVED facts are called out as inferred:

1. `What mitigates T1055?` — direct facts only, no crosswalk language.
2. Name a specific KEV CVE (`/library/cves` for one) — chat should surface
   NVD/KEV facts, and either a crosswalk technique or the explicit dead-end
   explanation, matching what that CVE's Library page showed.
3. `What techniques does APT29 use?` — actor-technique facts.
4. `What does Comment Panda mean?` and `Why is APT1 called Comment Crew?` —
   should answer with the naming-convention meaning ("Panda" = suspected
   China-nexus) and the etymology note, not "I don't know." Also try a term
   alone with no actor named, e.g. `What does Bear mean in threat actor
   names?` — should still answer generically (CrowdStrike/Microsoft/etc.
   meanings), since `app/nlp.py` matches naming-scheme words independently
   of any specific actor.
5. `What's a concerning CVE being actively exploited right now?` — no entity
   named, so this should trigger the general-KEV fallback (`app/nlp.py`
   keyword gate) rather than "no data."
6. Ask a follow-up with no entity of its own, e.g. `what mitigates this?`
   right after a CVE/technique question — it should resolve against the
   prior turn (rolling `history`), not lose context.
7. Click any highlighted CVE/technique/mitigation/actor ID in a reply —
   the right-hand view panel should populate without a page navigation.
8. Watch for the "⚠️ Verification warning" banner — it should be rare, but
   if the model invents an ID not in Sources, it must appear rather than the
   ID silently going unflagged (this is the one behavior worth actively
   trying to provoke: ask something adjacent to a real ID, e.g. a technique
   number one digit off from a real one, and see whether the guard catches
   it if the model takes the bait).

### Accounts (optional — only if Google OAuth is configured)

1. Signed out: start a chat, reload the page — chat should persist
   (sessionStorage) until the tab closes, and must never appear under
   another browser/profile.
2. Sign in with Google, save a chat, sign out, sign back in — the chat
   should reappear (server-side, `data/chats/<google_sub>.json`).
