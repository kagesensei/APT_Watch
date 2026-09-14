"""Design-by-contract helpers used across app/, ingest/, and resolve/.

Power of 10 rule 5 asks for a minimum assertion density, and rule 7 asks
that every return value and parameter be checked. Python's own ``assert``
is unsuitable for either: it is compiled out entirely when the interpreter
runs with ``-O``/``-OO``, so a stripped assert silently disables the check
it was meant to enforce. Every helper below is a plain function -- it always
runs and always raises ``ContractViolation`` (never the bare ``AssertionError``
a caller might reflexively catch) when the condition it checks does not hold.
"""

from __future__ import annotations

from typing import Iterable, Iterator, NoReturn, TypeVar

T = TypeVar("T")


class ContractViolation(AssertionError):
    """A precondition, postcondition, invariant, or loop bound was violated."""


def precondition(condition: bool, message: str) -> None:
    """Fail fast when a function's input requirement does not hold."""
    if not condition:
        raise ContractViolation(f"precondition failed: {message}")


def postcondition(condition: bool, message: str) -> None:
    """Fail fast when a function's own output guarantee does not hold."""
    if not condition:
        raise ContractViolation(f"postcondition failed: {message}")


def invariant(condition: bool, message: str) -> None:
    """Fail fast when a loop or object invariant does not hold."""
    if not condition:
        raise ContractViolation(f"invariant failed: {message}")


def unreachable(message: str = "unreachable code executed") -> NoReturn:
    """Mark a branch that must never run, e.g. an exhaustive if/elif chain."""
    raise ContractViolation(message)


def not_none(value: T | None, message: str = "value must not be None") -> T:
    """Narrow an Optional to its value, raising ContractViolation if it's None.

    Used at call sites like a DB ``fetchone()`` where the query's own
    semantics (an unconditional ``COUNT(*)``, a lookup on a primary key
    known to exist) guarantee a row -- this documents that guarantee where
    the value is used, satisfying rule 7's "check every return value"
    instead of silently indexing a value that is, as far as the type
    checker can tell, possibly ``None``.
    """
    if value is None:
        raise ContractViolation(message)
    return value


def bounded(iterable: Iterable[T], max_iterations: int) -> Iterator[T]:
    """Cap an iteration so untrusted or unbounded input can't create an
    unbounded loop (Power of 10 rule 2). Use this only where the loop bound
    is not already obvious from a fixed-size input (a literal range, a
    tuple of column names, a short constant list) -- those loops are
    self-evidently bounded and wrapping them here would just add noise.

    Raises ContractViolation if more than max_iterations items are produced.
    """
    precondition(max_iterations > 0, "max_iterations must be positive")
    count = 0
    for item in iterable:
        count += 1
        if count > max_iterations:
            raise ContractViolation(
                f"loop exceeded bound of {max_iterations} iterations"
            )
        yield item
