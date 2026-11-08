from dataclasses import dataclass

from vintar.core.models import HttpResult

MIN_ANCHOR_SIZE = 8
MAX_CHANGED_SIZE = 128


@dataclass(frozen=True, slots=True)
class DynamicRegion:
    """Byte-size metadata for one possible localized-difference envelope.

    The envelope may contain multiple changes and does not identify their cause.
    """

    prefix_size: int
    suffix_size: int
    first_changed_size: int
    second_changed_size: int


def detect_dynamic_region(
    first: HttpResult,
    second: HttpResult,
) -> DynamicRegion | None:
    """Identify a small changing region between two HTTP responses.

    Does not normalize responses, identify nonces or timestamps, or determine
    SQLi vulnerability. The thresholds are conservative byte-size heuristics,
    not semantic evidence.
    Returns only offsets and sizes, never response content.
    """
    if not isinstance(first, HttpResult) or not isinstance(second, HttpResult):
        raise TypeError("Both responses must be HttpResult objects.")

    for response in (first, second):
        if type(response.body) is not bytes:
            raise TypeError("Response bodies must be immutable bytes.")
        if type(response.status_code) is not int:
            raise TypeError("Response status codes must be integers.")
        if not 100 <= response.status_code <= 599:
            raise ValueError("Invalid HTTP status code.")
        if type(response.truncated) is not bool:
            raise TypeError("Response truncated flags must be booleans.")

    if first.truncated or second.truncated:
        return None

    if first.status_code != second.status_code:
        return None

    left = first.body
    right = second.body

    if left == right:
        return None

    shortest = min(len(left), len(right))
    prefix = 0

    while prefix < shortest and left[prefix] == right[prefix]:
        prefix += 1

    suffix = 0
    remaining = shortest - prefix

    while suffix < remaining and left[-(suffix + 1)] == right[-(suffix + 1)]:
        suffix += 1

    if prefix < MIN_ANCHOR_SIZE or suffix < MIN_ANCHOR_SIZE:
        return None

    first_changed = len(left) - prefix - suffix
    second_changed = len(right) - prefix - suffix

    largest_change = max(first_changed, second_changed)
    largest_body = max(len(left), len(right))

    if largest_change > MAX_CHANGED_SIZE:
        return None

    if largest_change * 4 > largest_body:
        return None

    return DynamicRegion(
        prefix_size=prefix,
        suffix_size=suffix,
        first_changed_size=first_changed,
        second_changed_size=second_changed,
    )
