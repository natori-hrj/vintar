"""Offline CLI for materializing reviewed POST JSON Case Schema v2 files."""

import json
from pathlib import Path
from typing import Annotated

import typer

from vintar.regression.discovery import DiscoveryError
from vintar.regression.discovery_drafts import DraftExportError
from vintar.regression.post_json_case_materialization import (
    PostJsonCaseMaterializationError,
    materialize_post_json_case,
    write_materialized_post_json_case,
)


def materialize_post_json_case_command(
    spec: Annotated[Path, typer.Option("--spec")],
    inventory: Annotated[Path, typer.Option("--inventory")],
    answers: Annotated[Path, typer.Option("--answers")],
    review: Annotated[Path, typer.Option("--review")],
    config: Annotated[Path, typer.Option("--config")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Materialize one explicitly reviewed POST JSON candidate offline."""
    try:
        case = materialize_post_json_case(spec, inventory, answers, review, config)
        write_materialized_post_json_case(
            output, case, (spec, inventory, answers, review, config)
        )
    except (PostJsonCaseMaterializationError, DraftExportError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except (DiscoveryError, OSError, RuntimeError, ValueError) as exc:
        typer.echo(
            "Error: post_json_materialization_failed: Case materialization could not complete. Check the current local inputs and an unused writable output path.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except KeyboardInterrupt as exc:
        typer.echo(
            "Error: post_json_materialization_interrupted: Materialization was interrupted. Rerun the command; no partial case was published.",
            err=True,
        )
        raise typer.Exit(130) from exc
    typer.echo(
        json.dumps(
            {
                "schema_version": 2,
                "report_type": "post_json_case_materialization_summary",
                "case_id": case.case_id,
                "check_type": case.check_type,
                "candidate_id": case.candidate_id,
            },
            sort_keys=True,
        )
    )
