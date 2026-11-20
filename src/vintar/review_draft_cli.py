"""Offline command for recording draft review decisions."""

import json
from pathlib import Path
from typing import Annotated

import typer

from vintar.regression.discovery import DiscoveryError
from vintar.regression.discovery_drafts import DraftExportError
from vintar.regression.discovery_review import (
    DraftReviewError,
    build_review,
    write_review,
)


def review_draft_command(
    spec: Annotated[Path, typer.Option("--spec")],
    draft: Annotated[Path, typer.Option("--draft")],
    answers: Annotated[Path, typer.Option("--answers")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Review a discovery draft offline and export a decision report."""
    try:
        report = build_review(spec, draft, answers)
        write_review(output, report, (spec, draft, answers))
    except (DraftReviewError, DraftExportError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except (DiscoveryError, OSError, RuntimeError) as exc:
        typer.echo(
            "Error: cannot complete offline review. Check the local spec, draft, answers, and writable output path.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except KeyboardInterrupt as exc:
        typer.echo(
            "Error: review interrupted. Rerun the command to finish writing the report.",
            err=True,
        )
        raise typer.Exit(130) from exc
    typer.echo(
        json.dumps(
            {
                "schema_version": 1,
                "report_type": "discovery_draft_review_summary",
                "input_id": report["input_id"],
            },
            sort_keys=True,
        )
    )
