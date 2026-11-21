"""Shared actionable regression orchestration errors."""


class BatchRequestBudgetError(ValueError):
    """The trusted aggregate budget cannot cover the selected cases."""
