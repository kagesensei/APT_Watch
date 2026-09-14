import pytest

from contracts import (
    ContractViolation,
    bounded,
    invariant,
    not_none,
    postcondition,
    precondition,
    unreachable,
)


def test_precondition_passes_silently_when_true():
    precondition(True, "unused")


def test_precondition_raises_with_message_when_false():
    with pytest.raises(ContractViolation, match="precondition failed: x must be positive"):
        precondition(False, "x must be positive")


def test_postcondition_raises_when_false():
    with pytest.raises(ContractViolation, match="postcondition failed:"):
        postcondition(1 == 2, "unreachable arithmetic")


def test_invariant_raises_when_false():
    with pytest.raises(ContractViolation, match="invariant failed:"):
        invariant(False, "loop state corrupted")


def test_unreachable_always_raises():
    with pytest.raises(ContractViolation, match="unreachable"):
        unreachable()


def test_unreachable_carries_custom_message():
    with pytest.raises(ContractViolation, match="no branch matched"):
        unreachable("no branch matched")


def test_bounded_yields_items_within_the_limit():
    assert list(bounded([1, 2, 3], max_iterations=3)) == [1, 2, 3]


def test_bounded_raises_once_the_limit_is_exceeded():
    with pytest.raises(ContractViolation, match="exceeded bound of 2"):
        list(bounded([1, 2, 3], max_iterations=2))


def test_bounded_rejects_a_non_positive_limit():
    with pytest.raises(ContractViolation, match="must be positive"):
        list(bounded([1], max_iterations=0))


def test_contract_violation_is_an_assertion_error():
    assert issubclass(ContractViolation, AssertionError)


def test_not_none_returns_the_value_when_present():
    assert not_none((1, 2), "unused") == (1, 2)


def test_not_none_raises_when_none():
    with pytest.raises(ContractViolation, match="row must exist"):
        not_none(None, "row must exist")


def test_not_none_uses_a_default_message():
    with pytest.raises(ContractViolation, match="value must not be None"):
        not_none(None)
