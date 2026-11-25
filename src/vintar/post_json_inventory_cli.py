"""Offline CLI for POST JSON request-body capability inventory."""

import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Annotated

import typer

from vintar.regression.discovery import DiscoveryError
from vintar.regression.post_json_inventory import analyze_post_json, serialize_report


class PostJsonInventoryOutputError(ValueError):
    """The inventory output cannot be safely written."""


def _write_report(spec: Path, output: Path, content: str) -> None:
    destination = output.parent.resolve() / output.name
    if destination.resolve() == spec.resolve() or (
        destination.exists() and destination.samefile(spec)
    ):
        raise PostJsonInventoryOutputError(
            "Output conflicts with the spec. Choose a separate report path."
        )
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            dir=destination.parent,
            encoding="utf-8",
            newline="\n",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def inventory_post_json_command(
    spec: Annotated[
        Path, typer.Option("--spec", help="Local OpenAPI JSON or YAML file.")
    ],
    output: Annotated[
        Path, typer.Option("--output", help="Destination for the JSON report.")
    ],
) -> None:
    """Inventory POST application/json request bodies offline."""
    try:
        report = analyze_post_json(spec)
        _write_report(spec, output, serialize_report(report))
    except KeyboardInterrupt as exc:
        typer.echo(
            "Error: POST JSON inventory was interrupted. Rerun to regenerate the report.",
            err=True,
        )
        raise typer.Exit(130) from exc
    except PostJsonInventoryOutputError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except DiscoveryError as exc:
        typer.echo(
            "Error: invalid or unreadable OpenAPI spec. Check the local file format, declarations, references, and limits, then try again.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except (OSError, RuntimeError) as exc:
        typer.echo(
            "Error: cannot write the POST JSON inventory. Choose a writable output path separate from the spec.",
            err=True,
        )
        raise typer.Exit(2) from exc
    counts = report.counts
    typer.echo(
        "POST JSON inventory: "
        f"{counts.operations} operations; "
        f"{counts.case_generatable} case-generatable; "
        f"{counts.fields} fields; "
        f"{counts.injectable_fields} injectable; "
        f"{counts.diagnostics} diagnostics."
    )
