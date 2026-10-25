from dataclasses import FrozenInstanceError

import pytest

from vintar.core.budget import RequestBudget, RequestBudgetExceededError


def test_budget_initial_state():
    budget = RequestBudget(max_requests=5)

    assert budget.used_requests == 0
    assert budget.remaining == 5


def test_budget_consumption():
    budget = RequestBudget(max_requests=3)

    budget.consume()
    budget.consume()

    assert budget.used_requests == 2
    assert budget.remaining == 1


def test_budget_limit():
    budget = RequestBudget(max_requests=2)

    budget.consume()
    budget.consume()

    with pytest.raises(RequestBudgetExceededError):
        budget.consume()

    assert budget.used_requests == 2
    assert budget.remaining == 0


def test_minimum_budget():
    budget = RequestBudget(max_requests=1)

    budget.consume()

    assert budget.used_requests == 1
    assert budget.remaining == 0

    with pytest.raises(RequestBudgetExceededError):
        budget.consume()


def test_budget_cannot_be_modified():
    budget = RequestBudget(max_requests=1)

    with pytest.raises(FrozenInstanceError):
        budget.max_requests = 100

    with pytest.raises(FrozenInstanceError):
        budget.used_requests = 0

    with pytest.raises(FrozenInstanceError):
        budget._used_requests = 0


def test_repeated_budget_exceeded():
    budget = RequestBudget(max_requests=1)
    budget.consume()

    for _ in range(2):
        with pytest.raises(RequestBudgetExceededError):
            budget.consume()

    assert budget.used_requests == 1
    assert budget.remaining == 0


@pytest.mark.parametrize(
    "value",
    [0, -1, 1.5, True, False, 1.0, "1", None],
)
def test_invalid_budget(value):
    with pytest.raises(ValueError):
        RequestBudget(max_requests=value)


def test_budget_hash_remains_stable_after_consumption():
    budget = RequestBudget(max_requests=1)
    budgets = {budget}

    hash_before = hash(budget)

    budget.consume()

    assert hash(budget) == hash_before
    assert budget in budgets
