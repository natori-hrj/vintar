"""Trusted POST JSON runtime policy parsing and source selection."""

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from vintar.regression import file_io
from vintar.regression.post_json_policy import (
    MAX_POLICY_BYTES,
    PostJsonPolicyError,
    load_post_json_runtime_policy,
    parse_post_json_runtime_policy,
)

CANARY = "policy-canary-must-never-appear"


def policy_value() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_type": "post_json_execution",
        "identities": [
            {
                "identity_id": "reviewed-user",
                "credential_kind": "bearer",
                "env_var": "VINTAR_TEST_TOKEN",
                "header_name": "Authorization",
            }
        ],
        "approvals": [
            {
                "case_id": "post-json-boolean",
                "identity_id": "reviewed-user",
                "credential_kind": "bearer",
                "credential_env_var": "VINTAR_TEST_TOKEN",
                "method": "POST",
                "path": "/items",
                "origin": "https://golden.invalid",
                "operation_definition_sha256": "0" * 64,
                "baseline_body_sha256": (
                    "5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d"
                ),
                "allowed_environment_classes": ["isolated_test", "local"],
                "allowed_side_effect": "no_side_effect",
            }
        ],
        "limits": {
            "max_requests": 48,
            "max_requests_per_second": 2.0,
            "max_timeout_seconds": 10.0,
            "max_response_size": 1_048_576,
            "max_time_execution_seconds": 45.0,
        },
    }


def policy_bytes(value: dict[str, object] | None = None) -> bytes:
    return json.dumps(value or policy_value(), separators=(",", ":")).encode()


def test_policy_is_closed_strict_typed_and_repr_is_redacted():
    policy = parse_post_json_runtime_policy(policy_bytes())
    assert policy.approvals[0].allowed_environment_classes == {
        "isolated_test",
        "local",
    }
    assert policy.limits.max_requests == 48
    assert "golden.invalid" not in repr(policy)
    assert "5e5c0546" not in repr(policy)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(schema_version=True),
        lambda value: value["limits"].update(max_requests=True),
        lambda value: value["approvals"][0].update(method="GET"),
        lambda value: value["approvals"][0].update(path="/items?unsafe=1"),
        lambda value: value["approvals"][0].update(allowed_side_effect="mutating"),
        lambda value: value["approvals"][0].update(
            allowed_environment_classes=["isolated_test", "isolated_test"]
        ),
    ],
)
def test_policy_rejects_unknown_keys_wrong_types_and_unsafe_values(mutate):
    value = policy_value()
    mutate(value)
    with pytest.raises(PostJsonPolicyError, match="post_json_policy_schema_invalid"):
        parse_post_json_runtime_policy(policy_bytes(value))


def test_policy_rejects_missing_keys_bool_as_int_and_duplicate_approvals():
    missing = policy_value()
    missing.pop("limits")
    boolean = policy_value()
    boolean["limits"]["max_requests"] = True
    duplicate = policy_value()
    duplicate["approvals"].append(dict(duplicate["approvals"][0]))

    for value in (missing, boolean, duplicate):
        with pytest.raises(
            PostJsonPolicyError, match="post_json_policy_schema_invalid"
        ):
            parse_post_json_runtime_policy(policy_bytes(value))


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_policy_rejects_non_finite_json_numbers(constant):
    source = policy_bytes().replace(
        b'"max_requests_per_second":2.0',
        b'"max_requests_per_second":' + constant.encode(),
    )
    with pytest.raises(PostJsonPolicyError, match="post_json_policy_schema_invalid"):
        parse_post_json_runtime_policy(source)


@pytest.mark.parametrize("source", [b"", b" " * (MAX_POLICY_BYTES + 1)])
def test_policy_rejects_empty_and_oversize_inline_sources(source):
    with pytest.raises(PostJsonPolicyError, match="post_json_policy_source_invalid"):
        parse_post_json_runtime_policy(source)


def test_policy_rejects_duplicate_json_names_without_echoing_values():
    source = (
        b'{"schema_version":1,"schema_version":1,"policy_type":"'
        + CANARY.encode()
        + b'","approvals":[],"limits":{}}'
    )
    with pytest.raises(PostJsonPolicyError) as caught:
        parse_post_json_runtime_policy(source)
    assert CANARY not in str(caught.value)


def test_inline_environment_has_full_precedence_without_file_fallback(tmp_path):
    valid_file = tmp_path / "policy.json"
    valid_file.write_bytes(policy_bytes())
    environ = {
        "VINTAR_RUNTIME_POLICY_JSON": "not-json-" + CANARY,
        "VINTAR_RUNTIME_POLICY_FILE": str(valid_file),
    }
    with pytest.raises(PostJsonPolicyError) as caught:
        load_post_json_runtime_policy(environ)
    assert CANARY not in str(caught.value)


def test_policy_file_is_regular_bounded_and_not_a_symlink(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_bytes(policy_bytes())
    loaded = load_post_json_runtime_policy(
        {"VINTAR_RUNTIME_POLICY_FILE": str(policy_file)}
    )
    assert loaded.schema_version == 1

    link = tmp_path / "policy-link.json"
    link.symlink_to(policy_file)
    with pytest.raises(PostJsonPolicyError, match="post_json_policy_unreadable"):
        load_post_json_runtime_policy({"VINTAR_RUNTIME_POLICY_FILE": str(link)})


def test_policy_file_rejects_fifo_and_directory_without_blocking(tmp_path):
    fifo = tmp_path / "policy.fifo"
    os.mkfifo(fifo)
    directory = tmp_path / "policy-directory"
    directory.mkdir()

    for path in (fifo, directory):
        with pytest.raises(PostJsonPolicyError, match="post_json_policy_unreadable"):
            load_post_json_runtime_policy({"VINTAR_RUNTIME_POLICY_FILE": str(path)})


def test_policy_path_swap_reads_originally_opened_descriptor(tmp_path, monkeypatch):
    policy_file = tmp_path / "policy.json"
    policy_file.write_bytes(policy_bytes())
    replacement = tmp_path / "replacement.json"
    replacement.write_text("not-the-approved-policy", encoding="utf-8")
    real_open = file_io._open

    def open_then_swap(path, flags):
        descriptor = real_open(path, flags)
        os.replace(replacement, policy_file)
        return descriptor

    monkeypatch.setattr(file_io, "_open", open_then_swap)
    loaded = load_post_json_runtime_policy(
        {"VINTAR_RUNTIME_POLICY_FILE": str(policy_file)}
    )

    assert loaded.policy_type == "post_json_execution"
    assert policy_file.read_text(encoding="utf-8") == "not-the-approved-policy"


def test_policy_growth_is_bounded_by_limit_plus_one(monkeypatch):
    descriptor = 73
    requested: list[int] = []
    total = 0

    def fake_open(_path, flags):
        assert flags & getattr(os, "O_NOFOLLOW", 0)
        assert flags & getattr(os, "O_CLOEXEC", 0)
        assert flags & getattr(os, "O_NONBLOCK", 0)
        return descriptor

    def fake_fstat(received):
        assert received == descriptor
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=1)

    def fake_read(received, size):
        nonlocal total
        assert received == descriptor
        requested.append(size)
        total += size
        return b"x" * size

    closed: list[int] = []
    monkeypatch.setattr(file_io, "_open", fake_open)
    monkeypatch.setattr(file_io, "_fstat", fake_fstat)
    monkeypatch.setattr(file_io, "_read", fake_read)
    monkeypatch.setattr(file_io, "_close", closed.append)

    with pytest.raises(
        PostJsonPolicyError, match="post_json_policy_unreadable"
    ) as caught:
        load_post_json_runtime_policy(
            {"VINTAR_RUNTIME_POLICY_FILE": "/fixed/policy-canary.json"}
        )

    assert total == MAX_POLICY_BYTES + 1
    assert requested
    assert all(size <= MAX_POLICY_BYTES + 1 for size in requested)
    assert closed == [descriptor]
    assert "policy-canary" not in str(caught.value)


def test_policy_file_accepts_exactly_maximum_bytes(tmp_path):
    source = policy_bytes()
    source += b" " * (MAX_POLICY_BYTES - len(source))
    assert len(source) == MAX_POLICY_BYTES
    policy_file = tmp_path / "policy.json"
    policy_file.write_bytes(source)

    loaded = load_post_json_runtime_policy(
        {"VINTAR_RUNTIME_POLICY_FILE": str(policy_file)}
    )
    assert loaded.schema_version == 1


def test_missing_no_follow_rejects_reader_and_policy_before_open(monkeypatch):
    opened: list[str] = []

    def forbidden_open(*_args, **_kwargs):
        opened.append("opened")
        raise AssertionError("open must not be reached")

    monkeypatch.delattr(file_io.os, "O_NOFOLLOW", raising=False)
    monkeypatch.setattr(file_io, "_open", forbidden_open)
    path = "/fixed/policy-path-canary.json"

    with pytest.raises(file_io.NoFollowUnavailableError) as reader_error:
        file_io.read_bounded_regular_file(path, MAX_POLICY_BYTES)
    assert str(reader_error.value) == (
        "This platform cannot open files without following symlinks. "
        "Use a trusted non-file input or a platform with O_NOFOLLOW support."
    )

    with pytest.raises(PostJsonPolicyError) as policy_error:
        load_post_json_runtime_policy({"VINTAR_RUNTIME_POLICY_FILE": path})
    assert str(policy_error.value) == (
        "post_json_policy_unreadable: This platform cannot open policy files "
        "without following symlinks. Supply the policy through "
        "VINTAR_RUNTIME_POLICY_JSON instead."
    )
    assert "policy-path-canary" not in str(policy_error.value)
    assert opened == []


def test_policy_file_rejects_directory_oversize_and_non_utf8(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    oversize = tmp_path / "oversize.json"
    oversize.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
    non_utf8 = tmp_path / "non-utf8.json"
    non_utf8.write_bytes(b"\xff")

    for path, code in (
        (directory, "post_json_policy_unreadable"),
        (oversize, "post_json_policy_unreadable"),
        (non_utf8, "post_json_policy_schema_invalid"),
    ):
        with pytest.raises(PostJsonPolicyError, match=code):
            load_post_json_runtime_policy({"VINTAR_RUNTIME_POLICY_FILE": str(path)})


def test_policy_source_is_required_and_never_reads_unselected_file(
    tmp_path, monkeypatch
):
    with pytest.raises(PostJsonPolicyError, match="post_json_runtime_policy_required"):
        load_post_json_runtime_policy({})

    def forbidden(_self: Path) -> bytes:
        raise AssertionError("file source must not be read")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    loaded = load_post_json_runtime_policy(
        {"VINTAR_RUNTIME_POLICY_JSON": policy_bytes().decode()}
    )
    assert loaded.policy_type == "post_json_execution"


def test_environment_canary_is_absent_from_repr_exception_and_process_environment(
    monkeypatch,
):
    monkeypatch.setenv("VINTAR_RUNTIME_POLICY_JSON", CANARY)
    with pytest.raises(PostJsonPolicyError) as caught:
        load_post_json_runtime_policy(os.environ)
    assert CANARY not in str(caught.value)
    assert CANARY not in repr(caught.value)
