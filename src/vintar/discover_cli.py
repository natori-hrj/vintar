"""Offline discovery CLI and report output."""

import json
import os
from dataclasses import asdict
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Annotated

import typer

from vintar.regression.discovery import (
    DiscoveryError,
    Inventory,
    SelectionError,
    input_id,
    load_inventory,
    load_selection,
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
        if operation.compatibility_blocker is None:
            del record["compatibility_blocker"]
        else:
            record["compatibility_status"] = "unverified"
        for item, entry in zip(operation.inputs, record["inputs"], strict=True):
            del entry["body_path"]
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
        Path, typer.Option("--output", help="Destination for the JSON inventory.")
    ],
    selection: Annotated[
        Path | None,
        typer.Option("--selection", help="Reviewer-approved input IDs in TOML."),
    ] = None,
) -> None:
    """Inventory a local OpenAPI spec for review."""
    try:
        inventory = load_inventory(spec)
        selected = (
            load_selection(selection, inventory)
            if selection is not None
            else frozenset()
        )
        inputs = (spec, selection) if selection is not None else (spec,)
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
    except (SelectionError, OutputConflictError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except DiscoveryError as exc:
        typer.echo(
            "Error: invalid OpenAPI spec. Check the local file format, declarations, references, and limits.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except (OSError, RuntimeError) as exc:
        typer.echo(
            "Error: cannot write the discovery report. Choose a writable output path.",
            err=True,
        )
        raise typer.Exit(2) from exc
