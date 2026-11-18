"""Authorized, bounded SQLi verification CLI."""

from typing import Annotated

import httpx
import typer

from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.checks.sqli.report import verification_report_json
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy, validate_scope
from vintar.core.template import validate_template

sqli_app = typer.Typer(
    help="Authorized SQL injection verification commands.",
    no_args_is_help=True,
)

PROBE_BUDGET = 6
_GENERIC_ERROR = "Error: SQLi verification could not be completed."


def _parse_origin(value: str) -> AllowedOrigin:
    """Accept only an explicit HTTP(S) origin, without a path."""
    url = httpx.URL(value)

    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.username
        or url.password
        or url.path not in {"", "/"}
        or url.query
        or url.fragment
    ):
        raise ValueError("Invalid allowed origin.")

    return AllowedOrigin(
        scheme=url.scheme,
        host=url.host,
        port=(
            url.port if url.port is not None else (443 if url.scheme == "https" else 80)
        ),
    )


def _parse_params(items: list[str]) -> tuple[tuple[str, str], ...]:
    params: list[tuple[str, str]] = []

    for item in items:
        if "=" not in item:
            raise ValueError("Invalid query parameter.")

        name, value = item.split("=", 1)
        if not name:
            raise ValueError("Invalid query parameter name.")

        params.append((name, value))

    return tuple(params)


@sqli_app.command("verify")
def sqli_verify(
    url: Annotated[str, typer.Option("--url")],
    allow_origin: Annotated[str, typer.Option("--allow-origin")],
    inject_param: Annotated[str, typer.Option("--inject-param")],
    true_payload: Annotated[str, typer.Option("--true-payload")],
    false_payload: Annotated[str, typer.Option("--false-payload")],
    param: Annotated[
        list[str] | None,
        typer.Option("--param", help="Query parameter name=value; repeatable."),
    ] = None,
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help=(
                "Attest that you have explicit testing authorization; "
                "this flag does not verify permission."
            ),
        ),
    ] = False,
    append: Annotated[
        bool,
        typer.Option("--append", help="Append rather than replace the value."),
    ] = False,
    occurrence: Annotated[
        int,
        typer.Option("--occurrence", min=0),
    ] = 0,
    rps: Annotated[
        float,
        typer.Option("--rps", min=0.1, max=10.0),
    ] = 2.0,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, max=60.0),
    ] = 10.0,
    pretty: Annotated[
        bool,
        typer.Option("--pretty", help="Indent JSON output."),
    ] = False,
) -> None:
    """Run a six-probe Boolean SQLi check on an authorized target."""
    if not authorized:
        typer.echo(
            "Error: explicit authorization is required.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        origin = _parse_origin(allow_origin)
        scope = ScopePolicy(allowed_origins=frozenset({origin}))

        template = RequestTemplate(
            method="GET",
            url=url,
            params=_parse_params(param or []),
        )

        point = InjectionPoint(
            location=InjectionLocation.QUERY,
            name=inject_param,
            occurrence=occurrence,
            mode=(InjectionMode.APPEND if append else InjectionMode.REPLACE),
        )

        # Validate before any network operation.
        validate_template(template)
        validate_scope(template.url, scope)

        context = ExecutionContext(
            scope=scope,
            budget=RequestBudget(PROBE_BUDGET),
            timeout=timeout,
            rate_limiter=RateLimiter(requests_per_second=rps),
        )

        result = verify_boolean_sqli(
            check_id="cli-sqli",
            template=template,
            point=point,
            true_payload=true_payload,
            false_payload=false_payload,
            context=context,
        )

        report = verification_report_json(result, pretty=pretty)

    except KeyboardInterrupt:
        typer.echo("Error: SQLi verification was cancelled.", err=True)
        raise typer.Exit(code=130) from None
    except (ValueError, httpx.InvalidURL):
        typer.echo(_GENERIC_ERROR, err=True)
        raise typer.Exit(code=2) from None
    except Exception as exc:
        typer.echo(_GENERIC_ERROR, err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(report)
