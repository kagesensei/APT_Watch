Guidance for Claude Code (or any AI assistant) working in this repository.

## What this is

APT_Watch: a local Flask app + DuckDB warehouse of MITRE ATT&CK, CISA KEV,
MITRE CAPEC, public IOC feeds, MISP Galaxy actor data, and SigmaHQ/sigma
detection rules, queryable via a browsable Library UI and a local-LLM chat
feature. See `README.md` for the full feature tour.

## Setup and everyday commands

```bash
pip install -r requirements.txt        # runtime deps
pip install -r requirements-dev.txt    # + pylint/mypy/bandit/pytest/pre-commit
pre-commit install                     # one-time per clone: gate every commit

# Build the database. Order matters only for resolve/aliases.py, which
# reads both actor (from attack.py) and misp_actor/actor_alias (from
# misp_galaxy.py) and will error if either hasn't been run yet.
python ingest/attack.py
python ingest/capec.py
python ingest/cve.py
python ingest/ioc.py
python ingest/naming.py
python ingest/misp_galaxy.py
python ingest/sigma.py
python resolve/aliases.py   # run by hand; not part of any automated ingest chain

python main.py   # run the app (the pylint/mypy/bandit/pytest gate is opt-in
                  # here: set APTWATCH_RUN_PREFLIGHT=1; it always runs via
                  # the pre-commit hook and in CI regardless)
pytest            # run the test suite
```

## Code conventions

This codebase follows an adapted version of NASA/JPL's "Power of 10" rules
for safety-critical code -- see `POWER10.md` for the full mapping. In
short: type hints and a docstring on every function; `contracts.py`'s
`precondition`/`postcondition`/`not_none` instead of bare `assert`; every
ingest script gets a data-quality check against something the publisher or
source itself states, and exits non-zero on failure; `pylint`, `mypy
--strict`, and `bandit` must stay at zero warnings (enforced by the
pre-commit hook and CI -- see `.github/workflows/ci.yml`).

**Sourcing rule for any threat-intel fact** (a naming convention, an actor
alias, a technique/rule mapping, etc.): never fill a gap from assumed
knowledge. Every such record needs a `source_url` and `retrieved` date
naming a source actually checked in the session that added it. If a source
can't be found, or doesn't confirm the claim, leave the record out rather
than guess -- see `data/seed/*.json` and `POWER10.md` for the pattern this
follows.

`ingest/*.py` and `resolve/aliases.py` are run directly, not imported as a
package (there's no `__init__.py` in either directory) -- each adds the
project root (for `contracts`) and, for `resolve/aliases.py`, `ingest/`
itself (for its shared `common.py` helpers) to `sys.path` at the top of the
file. Tests importing these modules do the same (see `tests/conftest.py`)
and use small fixture files under `tests/fixtures/`, never a live download.

## Current phase

Mid-way through a threat-intel data expansion effort. Phases 1-4 are done
and merged:

1. **Housekeeping** -- `data/cti.duckdb` is no longer committed (built
   locally by the ingest scripts); `python main.py` no longer runs the
   quality gate by default (`APTWATCH_RUN_PREFLIGHT=1` opts in); a
   pre-commit hook runs it on every commit instead; `data/seed/*.json`
   (naming conventions, alias etymology) is source-verified, with
   `source_url`/`retrieved` on every row.
2. **MISP Galaxy ingest** -- `ingest/misp_galaxy.py` loads MISP's
   threat-actor cluster into `misp_actor`/`actor_alias`.
3. **Alias resolution** -- `resolve/aliases.py` cross-walks ATT&CK actors
   against MISP's list into `actor_xwalk` (mutual 1-to-1 exact matches
   only) and `actor_xwalk_candidates` (fuzzy matches, for manual review,
   never auto-promoted); every 1-to-many/many-to-one collision is reported,
   not guessed at, in `data/reports/alias_resolution.md`. Human review
   decisions on fuzzy candidates are recorded in
   `data/seed/actor_xwalk_manual.json` (same curated/git-tracked pattern as
   the naming seed files) and re-applied on every run: `"promoted"` becomes
   an `actor_xwalk` row with `match_method='manual'`, `"rejected"` becomes
   an `actor_xwalk_rejected` row with the reasoning kept, not discarded.
4. **Sigma rules ingest** -- `ingest/sigma.py` loads SigmaHQ/sigma's
   detection rules into `sigma_rule`/`sigma_rule_technique`/
   `sigma_rule_actor`; `app/queries.sigma_coverage_for_actor()` answers
   "which of this actor's techniques have a covering Sigma rule, and which
   don't" -- no UI yet.

**Not started yet:**

- An activity feed (recent ingest runs / data changes, surfaced somewhere
  in the app).
- Actor similarity (e.g. technique/software overlap scoring between
  actors, beyond the MISP alias cross-walk resolve/aliases.py already
  does).
- A YARA rule corpus, analogous to the Sigma ingest above, mapped to the
  same actor/technique tables.
- Wiring `actor_xwalk` and `sigma_coverage_for_actor` into the Flask app
  itself -- both are currently data-layer only, with no route or template.
