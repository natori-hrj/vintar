"""Contracts for the internal, versioned SQLi probe catalog."""

import dataclasses
import logging

import pytest

from vintar.checks.sqli import ProbeFamilyRef
from vintar.checks.sqli.catalog import (
    CatalogResolutionError,
    ResolvedProbePlan,
    _materialize_legacy_boolean_family,
    _resolve_probe_family,
)


def resolve(ref: ProbeFamilyRef, check_type: str, requests: int) -> ResolvedProbePlan:
    return _resolve_probe_family(
        ref,
        check_type=check_type,
        location="query",
        mode="append",
        request_count=requests,
    )


@pytest.mark.parametrize(
    ("name", "check_type", "requests"),
    [
        ("boolean.numeric", "sqli.boolean", 18),
        ("boolean.string-quoted", "sqli.boolean", 18),
        ("time.mysql.numeric", "sqli.time", 9),
        ("time.mysql.string-quoted", "sqli.time", 9),
        ("time.postgresql.numeric", "sqli.time", 9),
        ("time.postgresql.string-quoted", "sqli.time", 9),
        ("error.numeric", "sqli.error", 4),
        ("error.string-quoted", "sqli.error", 4),
    ],
)
def test_catalog_resolves_exact_supported_families(name, check_type, requests):
    plan = resolve(ProbeFamilyRef(name, 1), check_type, requests)

    assert plan.family_id == name
    assert plan.catalog_version == 1
    assert plan.check_type == check_type
    assert plan.request_count == requests
    assert plan.expected_delay_seconds == (0.5 if check_type == "sqli.time" else None)


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"ref": ProbeFamilyRef("boolean.missing", 1)}, "probe_family_unknown"),
        ({"ref": ProbeFamilyRef("boolean.numeric", 2)}, "probe_family_unknown"),
        ({"check_type": "sqli.time"}, "probe_family_check_type_mismatch"),
        ({"location": "header"}, "probe_family_location_unsupported"),
        ({"mode": "invalid"}, "probe_family_mode_unsupported"),
        ({"request_count": 6}, "probe_family_request_count_mismatch"),
    ],
)
def test_catalog_resolution_fails_closed_with_actionable_diagnostic(kwargs, code):
    arguments = {
        "ref": ProbeFamilyRef("boolean.numeric", 1),
        "check_type": "sqli.boolean",
        "location": "query",
        "mode": "append",
        "request_count": 18,
    }
    arguments.update(kwargs)

    with pytest.raises(CatalogResolutionError) as captured:
        _resolve_probe_family(**arguments)

    message = str(captured.value)
    assert message.startswith(code)
    assert "Why:" in message
    assert "Instead:" in message


@pytest.mark.parametrize(
    ("name", "version"),
    [("Uppercase", 1), ("bad_name", 1), ("", 1), ("boolean.numeric", 0)],
)
def test_probe_family_ref_requires_exact_name_and_version(name, version):
    with pytest.raises(ValueError, match=r"Why:.*Instead:"):
        ProbeFamilyRef(name, version)


def test_resolved_plan_is_not_a_serializable_public_contract():
    plan = resolve(ProbeFamilyRef("boolean.numeric", 1), "sqli.boolean", 18)

    assert repr(plan).startswith(
        "<vintar.checks.sqli.catalog.ResolvedProbePlan object at "
    )
    assert not hasattr(plan, "to_dict")
    assert not hasattr(plan, "to_json")
    assert dataclasses.is_dataclass(plan)


def test_catalog_content_does_not_leak_through_repr_errors_or_logs(caplog):
    plan = resolve(ProbeFamilyRef("boolean.numeric", 1), "sqli.boolean", 18)
    content = plan.probes[0]

    with caplog.at_level(logging.DEBUG):
        logging.getLogger("vintar.test").debug("resolved %r", plan)
        with pytest.raises(CatalogResolutionError) as captured:
            resolve(ProbeFamilyRef("boolean.numeric", 2), "sqli.boolean", 18)

    assert content not in repr(plan)
    assert content not in str(captured.value)
    assert content not in caplog.text


def test_legacy_boolean_expansion_is_exact_and_versioned():
    numeric = _materialize_legacy_boolean_family("numeric")
    quoted = _materialize_legacy_boolean_family("string-quoted")

    assert len(numeric) == len(quoted) == 5
    assert len(set(numeric)) == len(set(quoted)) == 5


@pytest.mark.parametrize("name", ["unknown", 1, None])
def test_legacy_boolean_expansion_rejects_unknown_names_without_content(name):
    with pytest.raises(CatalogResolutionError, match=r"Why:.*Instead:"):
        _materialize_legacy_boolean_family(name)
