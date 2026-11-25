"""Offline CLI for explicit POST JSON discovery review."""

import json
from pathlib import Path
from typing import Annotated

import typer

from vintar.regression.discovery import DiscoveryError
from vintar.regression.discovery_drafts import DraftExportError
from vintar.regression.post_json_review import (
    PostJsonReviewError,
    build_post_json_review,
    write_post_json_review,
)


def review_post_json_command(
    spec: Annotated[Path, typer.Option("--spec")],
    inventory: Annotated[Path, typer.Option("--inventory")],
    answers: Annotated[Path, typer.Option("--answers")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Record one explicit POST JSON review decision offline."""
    try:
        report = build_post_json_review(spec, inventory, answers)
        write_post_json_review(output, report, (spec, inventory, answers))
    except (PostJsonReviewError, DraftExportError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except (DiscoveryError, OSError, RuntimeError) as exc:
        typer.echo(
            "Error: cannot complete offline POST JSON review. Check the local spec, current inventory, answers, and writable output path.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except KeyboardInterrupt as exc:
        typer.echo(
            "Error: POST JSON review was interrupted. Rerun to regenerate the review artifact.",
            err=True,
        )
        raise typer.Exit(130) from exc
    typer.echo(
        json.dumps(
            {
                "schema_version": 1,
                "report_type": "post_json_discovery_review_summary",
                "candidate_id": report["candidate_id"],
            },
            sort_keys=True,
        )
    )
