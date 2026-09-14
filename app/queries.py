"""Small DB query helpers shared across app/routes.py, app/preview.py,
app/dashboard.py, and app/intel.py.
"""

from typing import NamedTuple, Sequence, TypedDict

import duckdb

from contracts import not_none, precondition


def count(
    db: duckdb.DuckDBPyConnection, sql: str, params: Sequence[object] | None = None
) -> int:
    """Run a COUNT(...) query and return its scalar result.

    A COUNT query always returns exactly one row by SQL's own semantics, so
    a None result would mean something is badly wrong with the connection
    or the query -- not_none() turns that into an immediate, clear failure
    instead of a confusing "NoneType is not subscriptable" deeper in a
    template.
    """
    row = db.execute(sql, params or []).fetchone()
    return int(not_none(row, f"COUNT query returned no row: {sql!r}")[0])


class OverviewCounts(TypedDict):
    """Total distinct entity counts shown on both the Library index and the dashboard."""

    actors: int
    techniques: int
    software: int
    mitigations: int
    cves: int


def overview_counts(db: duckdb.DuckDBPyConnection) -> OverviewCounts:
    """Total distinct entity counts across the ingested ATT&CK/KEV dataset."""
    return {
        "actors": count(db, "SELECT COUNT(*) FROM actor"),
        "techniques": count(db, "SELECT COUNT(DISTINCT technique_id) FROM actor_technique"),
        "software": count(db, "SELECT COUNT(DISTINCT software_id) FROM actor_software"),
        "mitigations": count(db, "SELECT COUNT(DISTINCT mitigation_id) FROM technique_mitigation"),
        "cves": count(db, "SELECT COUNT(DISTINCT cve_id) FROM kev"),
    }


def in_placeholders(count_of_values: int) -> str:
    """A `?,?,...` placeholder list for a SQL `IN (...)` clause of this many
    values. Only the *number* of values is dynamic here; every value itself
    is still bound through the driver's own parameter list, never
    interpolated into the SQL text -- callers still need a `# nosec B608`
    at their own f-string, since bandit's syntactic scan can't see that far,
    but the actual safety guarantee (no value ever touches the SQL text)
    lives here.
    """
    precondition(count_of_values > 0, "count_of_values must be positive")
    return ",".join("?" * count_of_values)


def technique_name(db: duckdb.DuckDBPyConnection, technique_id: str) -> str | None:
    """The documented name for an ATT&CK technique ID, or None if unknown."""
    row = db.execute(
        "SELECT DISTINCT technique_name FROM actor_technique WHERE technique_id = ?",
        [technique_id],
    ).fetchone()
    return row[0] if row else None


def mitigation_name(db: duckdb.DuckDBPyConnection, mitigation_id: str) -> str | None:
    """The documented name for an ATT&CK mitigation ID, or None if unknown."""
    row = db.execute(
        "SELECT DISTINCT mitigation_name FROM technique_mitigation WHERE mitigation_id = ?",
        [mitigation_id],
    ).fetchone()
    return row[0] if row else None


class ListQuery(NamedTuple):
    """The fixed, literal parts of one app/routes.py list page's query --
    never request data (see searchable_list's docstring).
    """

    table: str
    count_expr: str
    select_columns: str
    search_columns: Sequence[str]
    order_by: str


def searchable_list(
    db: duckdb.DuckDBPyConnection, spec: ListQuery, q: str, size: int, offset: int
) -> tuple[int, list[tuple[object, ...]]]:
    """A paginated `SELECT ... FROM table [WHERE col ILIKE ? OR ...] ORDER BY
    ... LIMIT ? OFFSET ?`, with an optional multi-column search filter.

    Every field of `spec` is always a literal string from this module's own
    call sites in app/routes.py -- never request data. Only `q`'s value
    flows into the query, and always as a `?`-bound parameter, never
    interpolated into the SQL text. Bandit's B608 can't verify that a WHERE
    clause built from an f-string is safe from a purely syntactic scan,
    hence the explicit, narrow suppression below -- the one place in this
    app where a query's shape (not its data) is assembled at runtime, from a
    fixed, closed set of call sites.
    """
    precondition(
        bool(spec.table) and bool(spec.select_columns) and bool(spec.order_by),
        "table, select_columns, and order_by must not be empty",
    )
    if q and spec.search_columns:
        where = "WHERE " + " OR ".join(f"{col} ILIKE ?" for col in spec.search_columns)
        params: list[object] = [f"%{q}%"] * len(spec.search_columns)
    else:
        where = ""
        params = []

    total = count(db, f"SELECT {spec.count_expr} FROM {spec.table} {where}", params)  # nosec B608
    rows = db.execute(
        f"SELECT {spec.select_columns} FROM {spec.table} {where} "  # nosec B608
        f"ORDER BY {spec.order_by} LIMIT ? OFFSET ?",
        [*params, size, offset],
    ).fetchall()
    return total, rows
