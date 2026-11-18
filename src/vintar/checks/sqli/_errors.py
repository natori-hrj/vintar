"""Keep internal verification failures out of public diagnostics."""

from collections.abc import Iterator
from contextlib import contextmanager


class _UnexpectedVerificationError(Exception):
    """An unexpected failure at a verification boundary."""


@contextmanager
def redact_runtime_errors(
    message: str,
    *,
    passthrough: tuple[type[Exception], ...] = (),
) -> Iterator[None]:
    try:
        try:
            yield
        except passthrough:
            raise
        except (TypeError, ValueError):
            raise RuntimeError(message) from None
        except Exception as exc:
            raise _UnexpectedVerificationError(message) from exc
    except _UnexpectedVerificationError:
        raise RuntimeError(message) from None
