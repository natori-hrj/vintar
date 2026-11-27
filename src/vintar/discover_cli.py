"""Offline discovery CLI and report output."""

import json
import os
from dataclasses import asdict
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Annotated

import typer

from vintar.regression.discovery import (
    LOCATIONS,
    DiscoveryError,
    Input,
    Inventory,
    SelectionError,
    input_id,
    load_inventory,
    load_selection,
)
from vintar.regression.discovery_drafts import (
    DraftExportError,
    draft_files,
    write_drafts,
)


class OutputConflictError(ValueError):
    """The report destination conflicts with an input."""


def _encode_path(value: object) -> str:
    if isinstance(value, Path):
        return value.as_posix()
    raise TypeError("Expected a source path in the inventory report.")


def _report(inventory: Inventory, selected: frozenset[str]) -> str:
    report = asdict(inventory)
    for operation, record in zip(
        inventory.operations, report["operations"], strict=True
    ):
        del record["declared_id"]
        if operation.compatibility_blocker is None:
            del record["compatibility_blocker"]
        else:
            record["compatibility_status"] = "unverified"
        for item, entry in zip(operation.inputs, record["inputs"], strict=True):
            del entry["body_path"], entry["schema_types"], entry["skeleton_reason"]
            identifier = input_id(operation, item)
            entry["id"] = identifier
            entry["selected"] = identifier in selected
    report.update(schema_version=1, report_type="discovery_inventory")
    return (
        json.dumps(
            report, default=_encode_path, sort_keys=True, indent=2, ensure_ascii=True
        )
        + "\n"
    )


def _parameter(item: Input) -> dict[str, object]:
    reason = item.skeleton_reason
    status = "supported" if reason == "declared_schema" else "held"
    location = item.location
    name = item.name
    if item.ignored_reason is not None:
        status, reason = "ignored", "reserved_header"
    if location == "body":
        location = "json_body"
        kind, token = item.body_path[-1]
        name = "*" if kind == "items" else token
    return {
        "location": location,
        "name": name,
        "required": item.required,
        "schema_types": item.schema_types,
        "pointer": item.source.pointer,
        "baseline_presence": "unverified",
        "status": status,
        "reason": reason,
    }


def _serialize_skeleton(inventory: Inventory) -> str:
    operations = [
        {
            "operation_id": operation.declared_id,
            "method": operation.method,
            "path": operation.path,
            "identity": "unassigned",
            "approval": "unassigned",
            "probe_family": "unselected",
            "side_effect_review": "pending_review",
            "executable": False,
            "parameters": [
                _parameter(item)
                for item in operation.inputs
                if item.location in LOCATIONS
                or (
                    item.location == "body"
                    and item.body_path[0] == ("media", "application/json")
                    and len(item.body_path) > 1
                )
            ],
        }
        for operation in inventory.operations
    ]
    return (
        json.dumps(
            {"schema_version": 1, "operations": operations}, indent=2, sort_keys=True
        )
        + "\n"
    )


def _write_report(output: Path, inputs: tuple[Path, ...], report: str) -> None:
    output = output.parent.resolve() / output.name
    for input_path in inputs:
        if output.resolve() == input_path.resolve() or (
            output.exists() and output.samefile(input_path)
        ):
            raise OutputConflictError(
                "Output conflicts with the spec or selection. Choose a separate report path."
            )
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w", dir=output.parent, encoding="utf-8", newline="\n", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(report)
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def discover_command(
    spec: Annotated[
        Path, typer.Option("--spec", help="Local OpenAPI JSON or YAML file.")
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Destination for the JSON inventory."),
    ] = None,
    selection: Annotated[
        Path | None,
        typer.Option("--selection", help="Reviewer-approved input IDs in TOML."),
    ] = None,
    drafts_dir: Annotated[
        Path | None,
        typer.Option("--drafts-dir", help="Directory for offline review drafts."),
    ] = None,
    skeleton_output: Annotated[
        Path | None,
        typer.Option(
            "--skeleton-output", help="Destination for metadata-only skeletons."
        ),
    ] = None,
) -> None:
    """Inventory a local OpenAPI spec for review."""
    try:
        if skeleton_output is not None:
            if output is not None or drafts_dir is not None or selection is not None:
                raise DraftExportError(
                    "--skeleton-output cannot be combined with other discovery options."
                )
            _write_report(
                skeleton_output, (spec,), _serialize_skeleton(load_inventory(spec))
            )
            return
        if (output is None) == (drafts_dir is None):
            raise DraftExportError("Choose exactly one of --output or --drafts-dir.")
        source_file = None
        if drafts_dir is not None:
            if selection is None:
                raise DraftExportError(
                    "Draft export requires --selection. Supply a reviewed selection file."
                )
            resolved_spec = spec.resolve()
            working_directory = Path.cwd()
            if not resolved_spec.is_relative_to(working_directory):
                raise DraftExportError(
                    "Spec is outside the current working directory. Run from a directory that contains the spec."
                )
            source_file = resolved_spec.relative_to(working_directory)
        inventory = load_inventory(spec)
        selected = (
            load_selection(selection, inventory)
            if selection is not None
            else frozenset()
        )
        inputs = (spec, selection) if selection is not None else (spec,)
        if drafts_dir is not None and source_file is not None:
            drafts = draft_files(inventory, selected, source_file)
            write_drafts(drafts_dir, drafts, inputs)
            typer.echo(
                json.dumps(
                    {
                        "schema_version": 1,
                        "report_type": "discovery_draft_summary",
                        "drafts": sorted(drafts),
                    },
                    sort_keys=True,
                )
            )
            return
        if output is not None:
            _write_report(output, inputs, _report(inventory, selected))
        typer.echo(
            json.dumps(
                {
                    "schema_version": 1,
                    "report_type": "discovery_summary",
                    "operations": len(inventory.operations),
                    "held": len(inventory.held),
                    "ignored": sum(
                        item.ignored_reason is not None
                        for op in inventory.operations
                        for item in op.inputs
                    ),
                    "selected": len(selected),
                },
                sort_keys=True,
            )
        )
    except KeyboardInterrupt as exc:
        typer.echo(
            "Error: discovery was interrupted. Rerun to regenerate the report.",
            err=True,
        )
        raise typer.Exit(130) from exc
    except (SelectionError, OutputConflictError, DraftExportError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except DiscoveryError as exc:
        typer.echo(
            "Error: invalid OpenAPI spec. Check the local file format, declarations, references, and limits.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except (OSError, RuntimeError) as exc:
        artifact = "review drafts" if drafts_dir is not None else "the discovery report"
        typer.echo(
            f"Error: cannot write {artifact}. Choose a writable output path.",
            err=True,
        )
        raise typer.Exit(2) from exc
