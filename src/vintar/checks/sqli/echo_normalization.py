"""Normalize only context-bound echoes of complete Boolean probe values."""

from dataclasses import dataclass

MIN_ECHO_VALUE_BYTES = 3
ECHO_CONTEXT_BYTES = 16
_PLACEHOLDER = b"\x00VINTAR_BOOLEAN_ECHO\x00"


@dataclass(frozen=True, slots=True)
class EchoInput:
    """One response body and the complete query value sent for it."""

    body: bytes
    value: str


@dataclass(frozen=True, slots=True)
class NormalizedEcho:
    """One comparison body plus bounded normalization metadata."""

    body: bytes
    applied: bool
    echo_count: int


@dataclass(frozen=True, slots=True)
class _Occurrence:
    start: int
    end: int
    prefix: bytes
    suffix: bytes


def _variants(value: str) -> tuple[bytes, ...]:
    raw = value.encode("utf-8")
    apostrophe_escaped = value.replace("'", "&#39;").encode("utf-8")
    return tuple(dict.fromkeys((raw, apostrophe_escaped)))


def _occurrences(item: EchoInput) -> tuple[_Occurrence, ...]:
    if len(item.value.encode("utf-8")) < MIN_ECHO_VALUE_BYTES:
        return ()
    found: list[_Occurrence] = []
    for variant in _variants(item.value):
        start = 0
        while True:
            index = item.body.find(variant, start)
            if index < 0:
                break
            end = index + len(variant)
            found.append(
                _Occurrence(
                    start=index,
                    end=end,
                    prefix=item.body[max(0, index - ECHO_CONTEXT_BYTES) : index],
                    suffix=item.body[end : end + ECHO_CONTEXT_BYTES],
                )
            )
            start = end
    return tuple(sorted(found, key=lambda occurrence: occurrence.start))


def _bound_short_occurrences(
    item: EchoInput,
    contexts: tuple[tuple[bytes, bytes], ...],
) -> tuple[_Occurrence, ...]:
    variants = _variants(item.value)
    found: list[_Occurrence] = []
    cursor = 0
    for prefix, suffix in contexts:
        matches: list[_Occurrence] = []
        for variant in variants:
            needle = prefix + variant + suffix
            start = 0
            while True:
                index = item.body.find(needle, start)
                if index < 0:
                    break
                value_start = index + len(prefix)
                matches.append(
                    _Occurrence(
                        start=value_start,
                        end=value_start + len(variant),
                        prefix=prefix,
                        suffix=suffix,
                    )
                )
                start = index + len(needle)
        unique = {
            (match.start, match.end, match.prefix, match.suffix): match
            for match in matches
            if match.start >= cursor
        }
        if len(unique) != 1:
            return ()
        match = next(iter(unique.values()))
        found.append(match)
        cursor = match.end
    return tuple(found)


def _replace(
    item: EchoInput,
    occurrences: tuple[_Occurrence, ...],
    replacement: bytes,
) -> NormalizedEcho:
    pieces: list[bytes] = []
    cursor = 0
    for occurrence in occurrences:
        pieces.extend((item.body[cursor : occurrence.start], replacement))
        cursor = occurrence.end
    pieces.append(item.body[cursor:])
    body = b"".join(pieces)
    changed = body != item.body
    return NormalizedEcho(
        body=body,
        applied=changed,
        echo_count=len(occurrences) if changed else 0,
    )


def normalize_context_bound_echoes(
    inputs: tuple[EchoInput, ...],
) -> tuple[NormalizedEcho, ...]:
    """Return all-or-nothing normalization across one comparison set.

    Values shorter than ``MIN_ECHO_VALUE_BYTES`` are never replaced. A short
    value can serve as the canonical representation only when longer values
    identify one unique, ordered set of matching contexts in every body.
    """
    if not inputs:
        return ()
    eligible = tuple(
        index
        for index, item in enumerate(inputs)
        if len(item.value.encode("utf-8")) >= MIN_ECHO_VALUE_BYTES
    )
    if not eligible:
        return tuple(NormalizedEcho(item.body, False, 0) for item in inputs)

    located: list[tuple[_Occurrence, ...] | None] = [None] * len(inputs)
    for index in eligible:
        located[index] = _occurrences(inputs[index])
    reference = located[eligible[0]]
    if not reference:
        return tuple(NormalizedEcho(item.body, False, 0) for item in inputs)
    contexts = tuple((item.prefix, item.suffix) for item in reference)
    if any(
        tuple((item.prefix, item.suffix) for item in located[index] or ()) != contexts
        for index in eligible
    ):
        return tuple(NormalizedEcho(item.body, False, 0) for item in inputs)

    short_values: set[bytes] = set()
    for index, item in enumerate(inputs):
        if located[index] is not None:
            continue
        occurrences = _bound_short_occurrences(item, contexts)
        if tuple((entry.prefix, entry.suffix) for entry in occurrences) != contexts:
            return tuple(NormalizedEcho(value.body, False, 0) for value in inputs)
        located[index] = occurrences
        short_values.add(item.value.encode("utf-8"))
    if len(short_values) > 1:
        return tuple(NormalizedEcho(item.body, False, 0) for item in inputs)

    replacement = next(iter(short_values), _PLACEHOLDER)
    return tuple(
        _replace(item, occurrences or (), replacement)
        for item, occurrences in zip(inputs, located, strict=True)
    )
