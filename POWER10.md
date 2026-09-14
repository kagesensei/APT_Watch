# Power of 10, adapted for this codebase

Gerard Holzmann's ["The Power of 10: Rules for Developing Safety-Critical
Code"](https://spinroot.com/gerard/pdf/P10.pdf) (NASA/JPL) was written for C
in flight software: no OS, no heap after startup, no garbage collector. This
project is a Flask web app running under CPython, so a few of the original
rules don't have a literal Python equivalent. What follows is the adapted
version actually enforced in this repo -- every rule below maps to a real,
checked rule in `pyproject.toml`, `contracts.py`, or CI, not just a guideline.

| # | Original (C / JPL) | Applied here |
|---|---|---|
| 1 | No `goto`, `setjmp`/`longjmp`, direct or indirect recursion | No recursion (checked by hand; nothing in this codebase needs it -- ATT&CK/CAPEC/CWE data is tree-shaped but always walked iteratively). Control flow stays simple: early returns are fine, deep `if`/`elif` chains are not (pylint `too-many-branches`, `too-many-nested-blocks`). |
| 2 | Every loop must have a fixed upper bound | Every loop's bound must be evident at the loop, either because it iterates a literal/constant-size collection, or via `contracts.bounded()` when the source is untrusted or unbounded in principle (an HTTP response, an uploaded file's regex matches, a DB result set with no `LIMIT`). |
| 3 | No dynamic memory allocation after initialization | Not applicable under a GC'd runtime. Adapted as: no unbounded in-memory accumulation of untrusted input (`app/scan.py`'s `MAX_CHARS` cap, `MAX_CONTENT_LENGTH` in `app/__init__.py`), and no caches that grow without an eviction policy or bound. |
| 4 | No function longer than what prints on one sheet of paper (~60 lines) | Enforced via pylint's `max-module-lines`/statement checks and a house limit of **60 statement-lines per function**, checked in CI with `pylint --max-branches=12 --max-statements=60` (see `pyproject.toml`). Long procedures are split by sub-task. |
| 5 | Minimum assertion density: ~2 per function, checked at runtime | Every public function that takes untrusted or externally-shaped input (route handlers, ingest parsers, `intel.py` lookups) calls `contracts.precondition()` on its inputs and, where the result's shape matters to the caller, `contracts.postcondition()` before returning. Plain `assert` is not used for this (see `contracts.py` docstring: `-O` strips it). |
| 6 | Declare data objects at the smallest possible scope | No module-level mutable state beyond what Flask/DuckDB require (a connection factory, a blueprint). Pylint's `redefined-outer-name` and a ban on function-level `global`/`nonlocal` outside the two call sites that need it (`app/cache.py`, `app/db.py`'s `g` handling, which is Flask's own scoping primitive) enforce this. |
| 7 | Check the return value of every non-void function; check every parameter | mypy `strict = true` makes an unchecked/ignored return type a type error at the call site for anything typed `Optional`/a union. Every DB call result is checked for `None`/empty before use. Every route parameter is validated with `contracts.precondition()` before use in a query. Bandit's `B608` (SQL string building) additionally forces every SQL statement onto parameterized queries. |
| 8 | Restrict the preprocessor to header guards and simple macros | No literal preprocessor in Python. Adapted as: no `exec`/`eval` (bandit `B102`/`B307`, pylint `eval-used`/`exec-used`), no metaclass or `__getattr__`-based magic, no monkey-patching of stdlib or third-party modules. |
| 9 | Restrict pointer use: one level of dereferencing, no function pointers except a documented allowlist | Adapted as: no dynamic attribute-path chains, and callables passed as data (route handlers registered on a `Blueprint`, the one dispatch table in `app/nlp.py`'s IOC-type-to-extractor map) are the only higher-order-function use, and are enumerated up front rather than constructed dynamically. |
| 10 | Compile with all warnings enabled, in pedantic mode, with zero warnings; run a static analyzer daily | `pylint` (near-default rule set, see `pyproject.toml`), `mypy --strict`, and `bandit` all run in CI (`.github/workflows/ci.yml`) on every push/PR, alongside `pytest`, and together via `preflight.py` as a pre-commit hook (`.pre-commit-config.yaml`) on every commit. A merge is blocked on any of the four failing; a commit is too, unless made with `--no-verify`. |

## Running the checks locally

```
pip install -r requirements-dev.txt
pylint app ingest resolve contracts.py main.py preflight.py
mypy .
bandit -c pyproject.toml -r app ingest resolve contracts.py main.py preflight.py
pytest
```

`pre-commit install` (once per clone) wires `preflight.py` up to run all
four together on every `git commit`. `python main.py` does not run this
gate by default -- set `APTWATCH_RUN_PREFLIGHT=1` to run it once before the
dev server starts, as an optional local sanity check.

## `contracts.py`

Shared precondition/postcondition/invariant/bounded-loop helpers, used
instead of `assert` so checks survive `-O`. See its module docstring for why.

## Known, deliberate deviations

- **Flask's decorator-based routing** is itself a form of registered
  function-pointer table (rule 9) and dynamic dispatch; it's accepted as the
  one framework-level exception because Flask *is* the dispatch mechanism
  for this app, the table is static and defined once at import time, and
  hand-rolling routing would violate rule 1 (simpler, more auditable control
  flow) far more than it satisfies rule 9.
- **DuckDB/SQLAlchemy-style query building** stays as parameterized SQL
  strings (not an ORM); rule 8's intent (no unchecked textual substitution)
  is met by never interpolating a value into SQL text -- only `?`
  placeholders are used, which bandit and manual review both check.
