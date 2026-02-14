"""Command-line interface for the Data Flow Analyser."""

from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from data_flow_analyser import __version__

app = typer.Typer(help="Data Flow Analyser command-line interface.")
console = Console()


def version_callback(value: bool) -> None:
    """Print the package version when requested."""
    if value:
        console.print(__version__)
        raise typer.Exit()


@app.callback()
def callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the Data Flow Analyser version and exit.",
    ),
) -> None:
    """Data Flow Analyser command-line interface."""


@app.command()
def healthcheck() -> None:
    """Confirm that the engine is ready."""
    console.print(Panel("Data Flow Analyser engine ready", style="green"))


def main() -> None:
    """Run the command-line application."""
    app()


if __name__ == "__main__":
    main()
