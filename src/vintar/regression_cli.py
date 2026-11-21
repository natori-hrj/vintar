"""CI-oriented CLI for authorized regression verification."""

import os
import stat
import sys
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression import (
    MAX_BATCH_CASES,
    AnyRegressionCase,
    CIExitCode,
    TrustedExecutionPolicy,
    batch_exit_code,
    load_regression_case,
    regression_batch_report_json,
    run_regression_batch,
)
from vintar.regression.binding import bind_runtime_target, parse_runtime_origin
from vintar.regression.cases import ReviewDraftError
from vintar.regression.errors import BatchRequestBudgetError
from vintar.regression.runner import TimeExecutionPolicyError, TimeRequestBudgetError

_GENERIC_ERROR = "Error: regression verification could not be completed."
_AUTH_ERROR = "Error: explicit testing authorization is required."
_OUTPUT_ERROR = "Error: regression report output failed."
_CANCEL_ERROR = "Error: regression verification was cancelled."


def _case_paths(source: str) -> tuple[Path, ...]:
    """Select bounded TOML inputs without following symlink entries."""
    if type(source) is not str or not source:
        raise ValueError("Invalid case source.")

    root = Path(source)
    metadata = os.lstat(root)

    if stat.S_ISREG(metadata.st_mode):
        if root.suffix == ".json":
            raise ReviewDraftError(
                "JSON reports cannot be verified. Supply a separately reviewed Schema v1 TOML case to --cases."
            )
        if root.suffix != ".toml":
            raise ValueError("Expected TOML case file.")
        return (root,)

    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Invalid case source.")

    selected: list[Path] = []

    with os.scandir(root) as entries:
        for entry in entries:
            if not entry.name.endswith(".toml"):
                continue

            if not entry.is_file(follow_symlinks=False):
                raise ValueError("Invalid TOML directory entry.")

            selected.append(Path(entry.path))

            if len(selected) > MAX_BATCH_CASES:
                raise ValueError("Too many regression cases.")

    if not selected:
        raise ValueError("No regression cases found.")

    return tuple(sorted(selected, key=lambda p: p.name))


def _load_bound_cases(
    source: str,
    *,
    target: AllowedOrigin,
    trusted_scope: ScopePolicy,
) -> tuple[AnyRegressionCase, ...]:
    """Load and bind every case before starting network execution."""
    return tuple(
        bind_runtime_target(
            load_regression_case(path),
            target=target,
            trusted_scope=trusted_scope,
        )
        for path in _case_paths(source)
    )


def _emit_json(payload: str) -> None:
    """Write one JSON document followed by a newline."""
    sys.stdout.write(payload + "\n")
    sys.stdout.flush()


def _abort(message: str, code: int = 2) -> NoReturn:
    """Emit only fixed, non-sensitive diagnostics."""
    typer.echo(message, err=True)
    raise typer.Exit(code=code)


def verify_command(
    cases: Annotated[
        str,
        typer.Option(
            "--cases",
            help="TOML file or nonrecursive directory.",
        ),
    ],
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Attest explicit testing authorization.",
        ),
    ] = False,
    max_requests: Annotated[
        int,
        typer.Option("--max-requests", min=1, max=768),
    ] = 48,
    rps: Annotated[
        float,
        typer.Option("--rps", min=0.1, max=10.0),
    ] = 2.0,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, max=60.0),
    ] = 10.0,
    time_deadline: Annotated[
        float,
        typer.Option(
            "--time-deadline",
            min=0.1,
            max=120.0,
            help="Trusted overall deadline in seconds for each time SQLi case.",
        ),
    ] = 45.0,
    max_response_size: Annotated[
        int,
        typer.Option(
            "--max-response-size",
            min=1,
            max=1_048_576,
        ),
    ] = 1_048_576,
    pretty: Annotated[
        bool,
        typer.Option(
            "--pretty",
            help="Indent the JSON report.",
        ),
    ] = False,
) -> None:
    """Run authorized regression cases using runtime target binding.

    VINTAR_TARGET_ORIGIN and VINTAR_ALLOWED_ORIGIN are required.
    They are environment-only inputs so command-line arguments cannot
    override the trusted allowed origin or expose origins in process lists.

    Case-defined origins do not grant permission to send HTTP.
    The --authorized flag is an attestation, not proof of consent.

    DNS-resolved destination IPs are not checked. Sensitive CI
    environments require network-level egress restrictions.

    Environment variables are only trusted when controlled by
    a trusted workflow and isolated from untrusted PR code.
    """
    if not authorized:
        _abort(_AUTH_ERROR)

    target_origin = os.environ.get("VINTAR_TARGET_ORIGIN")
    allow_origin = os.environ.get("VINTAR_ALLOWED_ORIGIN")

    if not target_origin or not allow_origin:
        _abort(_GENERIC_ERROR)

    try:
        target = parse_runtime_origin(target_origin)
        allowed = parse_runtime_origin(allow_origin)

        trusted_scope = ScopePolicy(allowed_origins=frozenset({allowed}))

        # Reject target/permission mismatch before loading cases
        # or initiating network activity.
        if target not in trusted_scope.allowed_origins:
            raise ValueError("Runtime target is not authorized.")

        policy = TrustedExecutionPolicy(
            scope=trusted_scope,
            max_requests=max_requests,
            max_requests_per_second=rps,
            max_timeout_seconds=timeout,
            max_time_execution_seconds=time_deadline,
            max_response_size=max_response_size,
        )

        selected = _load_bound_cases(
            cases,
            target=target,
            trusted_scope=trusted_scope,
        )

        # The batch runner preflights all cases and limits
        # before the first HTTP request.
        result = run_regression_batch(
            list(selected),
            policy=policy,
        )

        payload = regression_batch_report_json(
            result,
            pretty=pretty,
        )
        exit_code = int(batch_exit_code(result))

    except KeyboardInterrupt:
        _abort(_CANCEL_ERROR, code=130)
    except ReviewDraftError as exc:
        _abort(f"Error: {exc}", code=int(CIExitCode.ERROR))
    except BatchRequestBudgetError:
        _abort(
            "Error: the trusted batch request budget cannot cover every selected case. Increase --max-requests to the sum of the case budgets, or run fewer cases.",
            code=int(CIExitCode.ERROR),
        )
    except TimeRequestBudgetError:
        _abort(
            "Error: fewer than nine trusted requests remain for the time case. Increase --max-requests to cover every selected case, or run fewer cases.",
            code=int(CIExitCode.ERROR),
        )
    except TimeExecutionPolicyError:
        _abort(
            "Error: the trusted time deadline cannot accommodate the case timeout and request rate. Increase --time-deadline, increase --rps, or use a shorter valid --timeout.",
            code=int(CIExitCode.ERROR),
        )
    except (OSError, ValueError):
        _abort(_GENERIC_ERROR, code=int(CIExitCode.ERROR))
    except Exception as exc:
        typer.echo(_GENERIC_ERROR, err=True)
        raise typer.Exit(code=int(CIExitCode.ERROR)) from exc

    try:
        _emit_json(payload)
    except (BrokenPipeError, OSError, UnicodeError):
        _abort(_OUTPUT_ERROR, code=int(CIExitCode.ERROR))
    except KeyboardInterrupt:
        _abort(_CANCEL_ERROR, code=130)

    raise typer.Exit(code=exit_code)
