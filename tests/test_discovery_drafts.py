"""Contract tests for offline review draft exports."""

import json
import os
import tomllib
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from vintar.cli import app
from vintar.regression import discovery_drafts
from vintar.regression.cases import load_regression_case
from vintar.regression.discovery import input_id, load_inventory
from vintar.regression.discovery_drafts import (
    DraftExportError,
    draft_files,
    write_drafts,
)

FIXTURE = Path(__file__).parent / "fixtures" / "discovery" / "openapi30.json"


def spec_and_review(tmp_path, *, count=1):
    spec = tmp_path / "spec.json"
    spec.write_bytes(FIXTURE.read_bytes())
    inventory = load_inventory(spec)
    identifiers = [
        input_id(op, item)
        for op in inventory.operations
        for item in op.inputs
        if op.compatible and item.compatible
    ][:count]
    review = tmp_path / "review.toml"
    review.write_text(
        f"version = 1\napproved = {json.dumps(identifiers)}\n", encoding="utf-8"
    )
    return spec, review, draft_files(inventory, frozenset(identifiers), Path(spec.name))


def invoke(spec, review, destination):
    return CliRunner().invoke(
        app,
        [
            "discover",
            "--spec",
            str(spec),
            "--selection",
            str(review),
            "--drafts-dir",
            str(destination),
        ],
    )


def test_export_is_idempotent_and_verify_explains_missing_decisions(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    spec, review, drafts = spec_and_review(tmp_path)
    directory = tmp_path / "drafts"
    result = invoke(spec, review, directory)
    assert result.exit_code == 0
    assert json.loads(result.stdout)["drafts"] == list(drafts)
    [name] = drafts
    output = directory / name
    before = output.stat()
    assert output.read_bytes() == drafts[name]
    assert invoke(spec, review, directory).exit_code == 0
    assert (output.stat().st_ino, output.stat().st_mtime_ns) == (
        before.st_ino,
        before.st_mtime_ns,
    )
    assert (
        tomllib.loads(output.read_text(encoding="utf-8"))["source"]["file"]
        == "spec.json"
    )

    with pytest.raises(ValueError, match="Review draft cannot be verified") as caught:
        load_regression_case(output)
    for decision in (
        "baseline query values",
        "authorization",
        "probe inputs",
        "expected verdict",
        "trusted limits",
    ):
        assert decision in str(caught.value)

    result = CliRunner().invoke(
        app,
        ["verify", "--cases", str(output), "--authorized"],
        env={
            "VINTAR_TARGET_ORIGIN": "http://fixture.invalid",
            "VINTAR_ALLOWED_ORIGIN": "http://fixture.invalid",
        },
    )
    assert result.exit_code == 2 and result.stdout == ""
    assert "Use a reviewed Schema v1 case" in result.stderr


def test_preflight_detects_later_conflict_before_any_write(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    spec, review, drafts = spec_and_review(tmp_path, count=2)
    first, last = drafts
    destination = tmp_path / "drafts"
    destination.mkdir()
    (destination / last).write_bytes(b"existing notes")
    result = invoke(spec, review, destination)
    assert result.exit_code == 2 and "already has different content" in result.stderr
    assert not (destination / first).exists()
    assert (destination / last).read_bytes() == b"existing notes"


@pytest.mark.parametrize(
    "alias", ["directory-symlink", "file-symlink", "input-hardlink", "input-path"]
)
def test_output_rejects_symlinks_and_input_aliases(tmp_path, alias):
    spec, review, drafts = spec_and_review(tmp_path)
    [name] = drafts
    destination = tmp_path / "drafts"
    real = tmp_path / "real"
    real.mkdir()
    if alias == "directory-symlink":
        destination.symlink_to(real, target_is_directory=True)
    else:
        destination.mkdir()
        if alias == "file-symlink":
            (destination / name).symlink_to(spec)
        elif alias == "input-hardlink":
            (destination / name).hardlink_to(review)
        else:
            review = review.rename(destination / name)
    before = review.read_bytes()
    with pytest.raises(DraftExportError, match=r"symlink|aliases an input"):
        write_drafts(destination, drafts, (spec, review))
    assert review.read_bytes() == before


def test_spec_must_be_within_current_directory(tmp_path, monkeypatch):
    spec, review, _ = spec_and_review(tmp_path)
    working = tmp_path / "working"
    working.mkdir()
    monkeypatch.chdir(working)
    output = working / "drafts"
    result = invoke(spec, review, output)
    assert result.exit_code == 2 and not output.exists()
    assert "Run from a directory that contains the spec" in result.stderr


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--output", "report.json", "--drafts-dir", "drafts"],
        ["--drafts-dir", "drafts"],
    ],
)
def test_draft_cli_validates_option_combinations(extra):
    result = CliRunner().invoke(app, ["discover", "--spec", "spec.json", *extra])
    assert result.exit_code == 2
    assert (
        "Choose exactly one" in result.stderr
        or "Supply a reviewed selection file" in result.stderr
    )


def test_secret_fields_are_excluded_and_json_yaml_drafts_match(tmp_path):
    sentinels = {
        "example": "example-value-sentinel",
        "default": "default-value-sentinel",
        "server": "server-url-sentinel",
        "credential": "credential-value-sentinel",
        "extension": "extension-value-sentinel",
    }
    name = 'café"\\\x7f'
    document = {
        "openapi": "3.1.2",
        "servers": [{"url": f"https://{sentinels['server']}.invalid"}],
        "components": {
            "securitySchemes": {
                "key": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Key",
                    "x-value": sentinels["credential"],
                }
            }
        },
        "paths": {
            "/a": {
                "get": {
                    "parameters": [
                        {
                            "name": name,
                            "in": "query",
                            "schema": {
                                "type": "string",
                                "default": sentinels["default"],
                            },
                            "example": sentinels["example"],
                        }
                    ],
                    "x-extension": sentinels["extension"],
                }
            }
        },
    }
    json_spec, yaml_spec = tmp_path / "spec.json", tmp_path / "spec.yaml"
    json_spec.write_text(json.dumps(document), encoding="utf-8")
    yaml_spec.write_text(yaml.safe_dump(document), encoding="utf-8")
    normalized = []
    for spec in (json_spec, yaml_spec):
        inventory = load_inventory(spec)
        [operation] = inventory.operations
        [item] = operation.inputs
        drafts = draft_files(
            inventory, frozenset({input_id(operation, item)}), Path(spec.name)
        )
        [content] = drafts.values()
        assert all(value.encode() not in content for value in sentinels.values())
        draft = tomllib.loads(content.decode())
        assert draft["query_parameter"] == draft["query_parameters"][0]["name"] == name
        assert draft["source"].pop("file") == spec.name
        normalized.append((list(drafts), draft))
    assert normalized[0] == normalized[1]


def test_exclusive_creation_preserves_file_created_after_preflight(
    tmp_path, monkeypatch
):
    spec, review, drafts = spec_and_review(tmp_path)
    [name] = drafts
    destination = tmp_path / "drafts"
    original_link = os.link

    def link_after_race(temporary, final):
        assert temporary.parent == destination
        assert temporary.read_bytes() == drafts[name]
        final.write_bytes(b"other writer")
        original_link(temporary, final)

    monkeypatch.setattr(discovery_drafts.os, "link", link_after_race)
    with pytest.raises(DraftExportError, match="appeared during export"):
        write_drafts(destination, drafts, (spec, review))
    assert (destination / name).read_bytes() == b"other writer"
    assert sorted(path.name for path in destination.iterdir()) == [name]


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_partial_temp_write_is_cleaned_and_rerun_succeeds(
    tmp_path, monkeypatch, failure
):
    spec, review, drafts = spec_and_review(tmp_path)
    [name] = drafts
    destination = tmp_path / "drafts"
    real_tempfile = discovery_drafts.NamedTemporaryFile

    @contextmanager
    def failing_tempfile(**kwargs):
        with real_tempfile(**kwargs) as stream:
            real_write = stream.write

            def partial_write(data):
                real_write(data[: len(data) // 2])
                stream.flush()
                raise failure("simulated failure")

            stream.write = partial_write
            yield stream

    with monkeypatch.context() as patch:
        patch.setattr(discovery_drafts, "NamedTemporaryFile", failing_tempfile)
        with pytest.raises(failure, match="simulated failure"):
            write_drafts(destination, drafts, (spec, review))

    assert list(destination.iterdir()) == []
    write_drafts(destination, drafts, (spec, review))
    assert (destination / name).read_bytes() == drafts[name]
    assert sorted(path.name for path in destination.iterdir()) == [name]


def test_non_utf8_spec_path_requires_rename_before_writing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    spec, review, _ = spec_and_review(tmp_path)
    spec = spec.rename(tmp_path / os.fsdecode(b"spec-\xff.json"))
    inventory = load_inventory(spec)
    first = inventory.operations[0]
    selected = frozenset({input_id(first, first.inputs[0])})
    [expected_name] = selected
    assert expected_name in review.read_text(encoding="utf-8")

    with pytest.raises(DraftExportError, match="Rename the file") as caught:
        draft_files(inventory, selected, Path(spec.name))
    assert ascii(spec.name) in str(caught.value)

    output = tmp_path / "drafts"
    result = invoke(spec, review, output)
    assert result.exit_code == 2 and result.stdout == ""
    assert ascii(spec.name) in result.stderr
    assert "Rename the file" in result.stderr
    assert not output.exists()
