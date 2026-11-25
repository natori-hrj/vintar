"""Vintar command-line interface."""

from importlib import metadata
from typing import Annotated

import httpx
import typer
from rich.console import Console

from vintar.core.http import send_request
from vintar.discover_cli import discover_command
from vintar.materialize_case_cli import materialize_case_command
from vintar.post_json_inventory_cli import inventory_post_json_command
from vintar.regression_cli import verify_command
from vintar.review_draft_cli import review_draft_command
from vintar.sqli_cli import sqli_app

app = typer.Typer(
    name="vintar",
    no_args_is_help=True,
)

http_app = typer.Typer(help="HTTP inspection commands.")
app.add_typer(http_app, name="http")
app.add_typer(sqli_app, name="sqli")
app.command("verify")(verify_command)
app.command("discover")(discover_command)
app.command("review-draft")(review_draft_command)
app.command("materialize-case")(materialize_case_command)
app.command("inventory-post-json")(inventory_post_json_command)

console = Console()


@app.callback()
def main() -> None:
    """vintar - security regression tests for CI pipelines."""


@app.command()
def version() -> None:
    """Show the current version."""
    console.print(f"[bold cyan]Vintar[/bold cyan] v{metadata.version('vintar')}")


@http_app.command("send")
def http_send(
    method: str,
    url: str,
    body: Annotated[
        str | None,
        typer.Option("--body", help="Request body."),
    ] = None,
    header: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            "-H",
            help="Custom HTTP header (Name: Value).",
        ),
    ] = None,
    cookie: Annotated[
        list[str] | None,
        typer.Option(
            "--cookie",
            "-C",
            help="Cookie (name=value).",
        ),
    ] = None,
    param: Annotated[
        list[str] | None,
        typer.Option(
            "--param",
            "-p",
            help="Query parameter (name=value); repeatable.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            "-t",
            help="Request timeout in seconds (max 60).",
            min=0.1,
            max=60.0,
        ),
    ] = 10.0,
) -> None:
    """Send a GET or POST request and inspect the response."""
    method = method.upper()

    if method not in {"GET", "POST"}:
        console.print("[red]Only GET and POST are supported.[/red]")
        raise typer.Exit(code=1)

    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    for item in header or []:
        if ":" not in item:
            console.print(f"[red]Invalid header:[/red] {item}")
            raise typer.Exit(code=1)

        name, value = item.split(":", 1)
        name = name.strip()

        if not name:
            console.print("[red]Header name cannot be empty.[/red]")
            raise typer.Exit(code=1)

        headers[name] = value.strip()

    for item in cookie or []:
        if "=" not in item:
            console.print(f"[red]Invalid cookies:[/red] {item}")
            raise typer.Exit(code=1)

        name, value = item.split("=", 1)
        name = name.strip()

        if not name:
            console.print("[red]Cookie name cannot be empty.[/red]")
            raise typer.Exit(code=1)

        cookies[name] = value

    params: list[tuple[str, str]] = []

    for item in param or []:
        if "=" not in item:
            console.print(f"[red]Invalid parameter:[/red] {item}")
            raise typer.Exit(code=1)

        name, value = item.split("=", 1)

        if not name:
            console.print("[red]Parameter name cannot be empty.[/red]")
            raise typer.Exit(code=1)

        params.append((name, value))

    try:
        result = send_request(
            method=method,
            url=url,
            body=body,
            headers=headers or None,
            cookies=cookies or None,
            params=params or None,
            timeout=timeout,
        )
    except (httpx.RequestError, httpx.InvalidURL, ValueError) as exc:
        console.print(f"[red]Request failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[cyan]Target:[/cyan] {url}")
    console.print(f"[cyan]Method:[/cyan] {method}")
    console.print(f"[cyan]Status:[/cyan] {result.status_code}")
    console.print(f"[cyan]Response time:[/cyan] {result.elapsed:.3f}s")
    console.print(f"[cyan]Content size:[/cyan] {result.size} bytes")


if __name__ == "__main__":
    app()
