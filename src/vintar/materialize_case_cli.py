"""Offline command for materializing reviewed Schema v1 cases."""

import json
from pathlib import Path
from typing import Annotated

import typer

from vintar.regression.case_materialization import (
    CaseMaterializationError,
    materialize_case,
    write_materialized_case,
)
from vintar.regression.discovery import DiscoveryError
from vintar.regression.discovery_review import DraftReviewError


def materialize_case_command(
    spec: Annotated[Path, typer.Option("--spec")],
    draft: Annotated[Path, typer.Option("--draft")],
    answers: Annotated[Path, typer.Option("--answers")],
    review: Annotated[Path, typer.Option("--review")],
    config: Annotated[Path, typer.Option("--config")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Materialize reviewed discovery decisions into a Schema v1 case."""
    try:
        case = materialize_case(spec, draft, answers, review, config)
        write_materialized_case(
            output,
            case,
            (spec, draft, answers, review, config),
        )
    except (CaseMaterializationError, DraftReviewError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except (DiscoveryError, OSError, RuntimeError, ValueError) as exc:
        typer.echo(
            "Error: cannot materialize the case. Check the local spec, draft, answers, review, config, and writable output path.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except KeyboardInterrupt as exc:
        typer.echo(
            "Error: case materialization interrupted. Rerun the command to finish writing the case.",
            err=True,
        )
        raise typer.Exit(130) from exc
    typer.echo(
        json.dumps(
            {
                "schema_version": 1,
                "report_type": "regression_case_materialization_summary",
                "case_id": case.case_id,
            },
            sort_keys=True,
        )
    )
