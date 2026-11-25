"""JSON object parsing shared by report validators."""


class DuplicateJsonKeyError(ValueError):
    """An object contains repeated JSON member names."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON member names at every object depth."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError("Duplicate JSON member name.")
        result[key] = value
    return result
