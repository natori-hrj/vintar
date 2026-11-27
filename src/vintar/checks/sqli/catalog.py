"""Internal, versioned catalog of reviewed built-in SQLi probe content."""

from dataclasses import dataclass, field
from types import MappingProxyType

from vintar.checks.sqli.probe_families import ProbeFamilyRef

_CATALOG_VERSION = 1
_QUERY = "query"
_APPEND = "append"
_REPLACE = "replace"


class CatalogResolutionError(ValueError):
    """A stable, content-free catalog resolution diagnostic."""


@dataclass(frozen=True, slots=True, repr=False)
class _CatalogFamily:
    family_id: str
    catalog_version: int
    check_type: str
    supported_locations: frozenset[str]
    supported_modes: frozenset[str]
    request_count: int
    probes: tuple[str, ...] = field(repr=False)
    expected_delay_seconds: float | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedProbePlan:
    """Internal probe inputs resolved at the loader-to-planner boundary."""

    family_id: str
    catalog_version: int
    check_type: str
    request_count: int
    probes: tuple[str, ...] = field(repr=False)
    expected_delay_seconds: float | None = field(default=None, repr=False)


def _family(
    family_id: str,
    check_type: str,
    request_count: int,
    probes: tuple[str, ...],
    *,
    expected_delay_seconds: float | None = None,
) -> _CatalogFamily:
    return _CatalogFamily(
        family_id=family_id,
        catalog_version=_CATALOG_VERSION,
        check_type=check_type,
        supported_locations=frozenset({_QUERY}),
        supported_modes=frozenset({_APPEND, _REPLACE}),
        request_count=request_count,
        probes=probes,
        expected_delay_seconds=expected_delay_seconds,
    )


_FAMILIES = MappingProxyType(
    {
        ("boolean.numeric", 1): _family(
            "boolean.numeric",
            "sqli.boolean",
            18,
            (
                " AND 1=1-- ",
                " AND 1=2-- ",
                " AND 2<3-- ",
                " AND 2>3-- ",
                " AND 7=7-- ",
            ),
        ),
        ("boolean.string-quoted", 1): _family(
            "boolean.string-quoted",
            "sqli.boolean",
            18,
            (
                "' AND 1=1-- ",
                "' AND 1=2-- ",
                "' AND 2<3-- ",
                "' AND 2>3-- ",
                "' AND 7=7-- ",
            ),
        ),
        ("time.mysql.numeric", 1): _family(
            "time.mysql.numeric",
            "sqli.time",
            9,
            (
                " AND IF(1=1,SLEEP(0.5),0)",
                " AND IF(1=2,SLEEP(0.5),0)",
            ),
            expected_delay_seconds=0.5,
        ),
        ("time.mysql.string-quoted", 1): _family(
            "time.mysql.string-quoted",
            "sqli.time",
            9,
            (
                "' AND IF(1=1,SLEEP(0.5),0)-- ",
                "' AND IF(1=2,SLEEP(0.5),0)-- ",
            ),
            expected_delay_seconds=0.5,
        ),
        ("time.postgresql.numeric", 1): _family(
            "time.postgresql.numeric",
            "sqli.time",
            9,
            (
                " AND (SELECT COUNT(*) FROM pg_sleep(0.5))=1-- ",
                " AND (SELECT COUNT(*) FROM pg_sleep(0))=1-- ",
            ),
            expected_delay_seconds=0.5,
        ),
        ("time.postgresql.string-quoted", 1): _family(
            "time.postgresql.string-quoted",
            "sqli.time",
            9,
            (
                "' AND (SELECT COUNT(*) FROM pg_sleep(0.5))=1-- ",
                "' AND (SELECT COUNT(*) FROM pg_sleep(0))=1-- ",
            ),
            expected_delay_seconds=0.5,
        ),
        ("error.numeric", 1): _family("error.numeric", "sqli.error", 4, (")",)),
        ("error.string-quoted", 1): _family(
            "error.string-quoted", "sqli.error", 4, ("'",)
        ),
    }
)


def _resolve_probe_family(
    ref: ProbeFamilyRef,
    *,
    check_type: str,
    location: str,
    mode: str,
    request_count: int,
) -> ResolvedProbePlan:
    if type(ref) is not ProbeFamilyRef:
        raise TypeError("Probe family reference must be a ProbeFamilyRef.")
    family = _FAMILIES.get((ref.name, ref.version))
    if family is None:
        raise CatalogResolutionError(
            "probe_family_unknown: Why: the requested family and version are not "
            "present in the internal catalog. Instead: use a documented family name "
            "and explicit supported version."
        )
    if check_type != family.check_type:
        raise CatalogResolutionError(
            "probe_family_check_type_mismatch: Why: the family does not support the "
            "requested check type. Instead: choose a family documented for that check type."
        )
    if location not in family.supported_locations:
        raise CatalogResolutionError(
            "probe_family_location_unsupported: Why: the family does not support the "
            "requested injection location. Instead: choose a documented supported location."
        )
    if mode not in family.supported_modes:
        raise CatalogResolutionError(
            "probe_family_mode_unsupported: Why: the family does not support the "
            "requested injection mode. Instead: choose a documented supported mode."
        )
    if request_count != family.request_count:
        raise CatalogResolutionError(
            "probe_family_request_count_mismatch: Why: the request limit does not match "
            "the fixed family plan. Instead: use the documented exact request count."
        )
    return ResolvedProbePlan(
        family_id=family.family_id,
        catalog_version=family.catalog_version,
        check_type=family.check_type,
        request_count=family.request_count,
        probes=family.probes,
        expected_delay_seconds=family.expected_delay_seconds,
    )


def _materialize_legacy_boolean_family(
    name: object,
) -> tuple[str, str, str, str, str]:
    """Expand one legacy Schema v1 preset at its sole approved boundary."""
    if type(name) is not str or name not in {"numeric", "string-quoted"}:
        raise CatalogResolutionError(
            "legacy_boolean_family_unknown: Why: the legacy preset name is not "
            "supported. Instead: use one of: numeric, string-quoted."
        )
    plan = _resolve_probe_family(
        ProbeFamilyRef(name=f"boolean.{name}", version=1),
        check_type="sqli.boolean",
        location=_QUERY,
        mode=_APPEND,
        request_count=18,
    )
    first, second, third, fourth, fifth = plan.probes
    return first, second, third, fourth, fifth
