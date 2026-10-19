import typer
import httpx
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
    body: str | None = typer.Option(
        None,
        "--body",
        help="HTTP request body.",
    ),
) -> None:
    """Send a GET request and inspect the response."""
    method = method.upper()

    if method not in {"GET", "POST"}:
        console.print("[red]Only GET and POST are supported.[/red]")
        raise typer.Exit(code=1)

    try:
        status, elapsed, size = send_request(
            method,
            url,
            body=body,
        )
    except (httpx.RequestError, httpx.InvalidURL) as exc:
        console.print(f"[red]Request failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[cyan]Target:[/cyan] {url}")
    console.print(f"[cyan]Method:[/cyan] {method}")
    console.print(f"[cyan]Satus:[/cyan] {status}")
    console.print(f"[cyan]Response time:[/cyan] {elapsed:.3f}s")
    console.print(f"[cyan]Content size:[/cyan] {size} bytes")



if __name__ == "__main__":
    app()
