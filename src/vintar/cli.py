from typing import Annotated

import httpx
import typer
from rich.console import Console

from vintar.core.http import send_request

## cli command
app = typer.Typer(
    name="vintar",
    help="Vintar - Precision Security Toolkit",
    no_args_is_help=True,
)

http_app = typer.Typer(help="HTTP inspection commands.")
app.add_typer(http_app, name="http")

console = Console()


@app.callback()
def main() -> None:
    """Precision Security Toolkit."""


@app.command()
def version() -> None:
    """Show the current version."""
    console.print("[bold cyan]Vintar[/bold cyan] v0.1.0")


@http_app.command("send")
def http_send(
    method: str,
    url: str,
    body: Annotated[
        str | None,
        typer.Option("--body", help="HTTP request body."),
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
            help="Query parameter (name=value). Rpeatable.",
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
    """Send a GET request and inspect the response."""
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
    console.print(f"[cyan]Satus:[/cyan] {result.status_code}")
    console.print(f"[cyan]Response time:[/cyan] {result.elapsed:.3f}s")
    console.print(f"[cyan]Content size:[/cyan] {result.size} bytes")


if __name__ == "__main__":
    app()
