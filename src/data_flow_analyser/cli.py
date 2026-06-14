"""Command-line interface for the Data Flow Analyser."""

import logging
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from data_flow_analyser import __version__
from data_flow_analyser.exporter import ReportExporter
from data_flow_analyser.pipeline import AuditPipeline

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


@app.command()
def audit(
    flows: Path = typer.Option(
        ...,
        "--capture",
        "-c",
        help="Path to input mitmproxy flow capture file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    doc: List[Path] = typer.Option(
        ...,
        "--doc",
        "-d",
        help="Path(s) to privacy policy, DPA, or disclosure document(s) (supports multiple entries).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    out_json: Optional[Path] = typer.Option(
        None,
        "--out-json",
        help="Path to write structured JSON audit report.",
    ),
    out_md: Optional[Path] = typer.Option(
        None,
        "--out-md",
        help="Path to write Markdown audit report.",
    ),
    model: str = typer.Option(
        "gpt-5.4-mini",
        "--model",
        help="LiteLLM model name to use for analysis.",
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        help="API Key for LLM provider (optional if configured in environment).",
    ),
    api_base: Optional[str] = typer.Option(
        None,
        "--api-base",
        help="Custom API base URL for LiteLLM (optional).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable debug logging output.",
    ),
) -> None:
    """Run an end-to-end technical privacy cross-reference audit."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    with console.status("[bold green]Executing privacy audit pipeline...", spinner="dots"):
        pipeline = AuditPipeline(
            llm_model=model,
            api_key=api_key,
            api_base=api_base,
        )

        report = pipeline.run(
            flow_file_path=flows,
            documents=doc,
        )

    markdown_str = ReportExporter.to_markdown(report)

    if out_json:
        ReportExporter.to_json_file(report, out_json)
        console.print(f"[bold green]✓[/bold green] JSON report written to: {out_json}")

    if out_md:
        ReportExporter.to_markdown_file(report, out_md)
        console.print(f"[bold green]✓[/bold green] Markdown report written to: {out_md}")

    if not out_json and not out_md:
        console.print(Panel(Markdown(markdown_str), title="Audit Results", expand=False))


def main() -> None:
    """Run the command-line application."""
    app()


if __name__ == "__main__":
    main()
