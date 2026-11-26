#!/usr/bin/env python3
"""Validate one bounded Case Schema v2 TOML artifact."""

import sys
import tomllib
from pathlib import Path
from typing import BinaryIO

from vintar.regression.cases import MAX_CASE_BYTES
from vintar.regression.cases_v2 import PostJsonRegressionCase, parse_case_v2_mapping

_ERROR = (
    "Vintar: Case Schema v2 validation failed. Re-materialize the case from the "
    "current spec and explicit POST JSON review."
)


def _read_bounded(stream: BinaryIO) -> bytes:
    data = stream.read(MAX_CASE_BYTES + 1)
    if len(data) > MAX_CASE_BYTES:
        raise ValueError("Case exceeds its size limit. Re-materialize a smaller case.")
    return data


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError
        with Path(sys.argv[1]).open("rb") as stream:
            data = _read_bounded(stream)
        value: object = tomllib.loads(data.decode("utf-8"))
        if not isinstance(parse_case_v2_mapping(value), PostJsonRegressionCase):
            raise TypeError
        return 0
    except (OSError, UnicodeError, TypeError, ValueError, RecursionError):
        print(_ERROR, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
