"""Reviewed, offline DBMS error signatures for error-based SQLi analysis."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

ERROR_SCAN_LIMIT = 1_048_576


@dataclass(frozen=True, slots=True)
class ErrorSignature:
    """One strong, reviewed DBMS diagnostic signature."""

    signature_id: str
    dbms: str
    pattern: re.Pattern[bytes]

    def __post_init__(self) -> None:
        if (
            type(self.signature_id) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]*", self.signature_id) is None
        ):
            raise ValueError(
                "Invalid error signature ID. Use a stable lowercase identifier."
            )
        if (
            type(self.dbms) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]*", self.dbms) is None
        ):
            raise ValueError("Invalid DBMS family. Use a stable lowercase identifier.")
        if (
            type(self.pattern) is not re.Pattern
            or type(self.pattern.pattern) is not bytes
        ):
            raise TypeError(
                "Invalid error signature pattern. Supply a compiled bytes pattern."
            )
        if (
            self.pattern.flags & re.IGNORECASE == 0
            or self.pattern.flags & re.ASCII == 0
        ):
            raise ValueError(
                "Invalid error signature flags. Compile bytes patterns with ASCII and IGNORECASE."
            )


def _signature(signature_id: str, dbms: str, pattern: bytes) -> ErrorSignature:
    return ErrorSignature(
        signature_id=signature_id,
        dbms=dbms,
        pattern=re.compile(pattern, re.ASCII | re.IGNORECASE),
    )


ERROR_SIGNATURES: Mapping[str, ErrorSignature] = MappingProxyType(
    {
        item.signature_id: item
        for item in (
            _signature(
                "mssql_syntax_error",
                "mssql",
                rb"(?:Microsoft (?:OLE DB Provider|ODBC SQL Server Driver)[^\r\n]{0,128}SQL Server[^\r\n]{0,128}(?:Incorrect syntax near|Unclosed quotation mark)|SQLServerException:[^\r\n]{0,128}(?:Incorrect syntax near|Unclosed quotation mark))",
            ),
            _signature(
                "mysql_syntax_error_1064",
                "mysql",
                rb"(?:SQLSTATE\[42000\][^\r\n]{0,96}(?:1064|SQL syntax)|You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version)",
            ),
            _signature(
                "oracle_syntax_error",
                "oracle",
                rb"(?:ORA-00917:\s{0,16}missing comma|ORA-00933:\s{0,16}SQL command not properly ended|ORA-01756:\s{0,16}quoted string not properly terminated)",
            ),
            _signature(
                "postgresql_syntax_error",
                "postgresql",
                rb"(?:org\.postgresql\.util\.PSQLException|PG::SyntaxError):\s{0,16}ERROR:\s{0,16}syntax error at or near",
            ),
            _signature(
                "sqlite_operational_syntax",
                "sqlite",
                rb"(?:sqlite3\.)?OperationalError:\s{0,16}(?:near\s{1,8}[^\r\n]{0,128}\s{1,8}syntax error|unrecognized token:)",
            ),
        )
    }
)

ERROR_SIGNATURE_IDS = tuple(sorted(ERROR_SIGNATURES))
ERROR_SIGNATURE_DBMS_NAMES = tuple(
    sorted({signature.dbms for signature in ERROR_SIGNATURES.values()})
)


def get_error_signature(signature_id: object) -> ErrorSignature:
    """Return one exact reviewed signature without accepting aliases."""
    if type(signature_id) is not str or signature_id not in ERROR_SIGNATURES:
        valid = ", ".join(ERROR_SIGNATURE_IDS)
        raise ValueError(f"Unknown error signature. Use one of: {valid}.")
    return ERROR_SIGNATURES[signature_id]
