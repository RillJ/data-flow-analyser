# Copyright 2026 Julian Calvin Rill
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from data_flow_analyser import __version__
from data_flow_analyser.exporter import ReportExporter
from data_flow_analyser.pipeline import AuditPipeline, PIPELINE_STAGES
from data_flow_analyser.endpoint_inventory import inventory_flows, load_excluded_domains
from data_flow_analyser.parsers.mitm_parser import parse_flow_file
from data_flow_analyser.models.schemas import ConsentOutcome

app = typer.Typer(help="Data Flow Analyser command-line interface.")
console = Console()
logger = logging.getLogger(__name__)


def configure_logging(verbose: bool, log_file: Optional[Path] = None) -> None:
    """Configure console and optional file diagnostics for one CLI invocation."""
    level = logging.DEBUG if verbose else logging.WARNING
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        handlers=handlers,
        force=True,
    )


def parse_iso8601_timestamp(value: Optional[str], option_name: str) -> Optional[datetime]:
    """Parse a timezone-aware consent timestamp supplied to the CLI."""
    if value is None:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise typer.BadParameter(
            "must be an ISO-8601 timestamp, for example 2026-08-13T10:15:00+02:00",
            param_hint=option_name,
        ) from error
    if timestamp.tzinfo is None:
        raise typer.BadParameter(
            "must include a timezone offset, for example +02:00 or Z",
            param_hint=option_name,
        )
    return timestamp


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


def endpoint_inventory_to_markdown(payload: dict) -> str:
    """Render a deterministic endpoint inventory as Markdown."""
    lines = [
        "# Endpoint Inventory",
        "",
        f"**Capture:** `{payload['capture']}`  ",
        f"**Flows:** {payload['flow_count']}  ",
        f"**Endpoints:** {payload['endpoint_count']}",
        "",
        "| Domain | Flows | Methods | Paths | First Seen | Last Seen |",
        "| --- | ---: | --- | --- | --- | --- |",
    ]
    if not payload["endpoints"]:
        lines.append("| _None_ | 0 |  |  |  |  |")
    else:
        for item in payload["endpoints"]:
            methods = ", ".join(
                f"{name} ({count})" for name, count in item["methods"].items()
            )
            paths = ", ".join(
                f"`{path}` ({count})" for path, count in item["paths"].items()
            )
            lines.append(
                f"| `{item['domain']}` | {item['flow_count']} | {methods} | {paths} | "
                f"{item['first_seen'] or 'Unknown'} | {item['last_seen'] or 'Unknown'} |"
            )
    return "\n".join(lines) + "\n"


@app.command("endpoints")
def endpoints(
    flows: Path = typer.Option(
        ...,
        "--capture",
        "-c",
        help="Path to input mitmproxy flow or HAR capture file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    out_json: Optional[Path] = typer.Option(
        None,
        "--out-json",
        help="Path to write the endpoint inventory as JSON.",
    ),
    out_md: Optional[Path] = typer.Option(
        None,
        "--out-md",
        help="Path to write the endpoint inventory as Markdown.",
    ),
) -> None:
    """List every destination host in a capture for exclusion review."""
    parsed_flows = parse_flow_file(flows)
    inventory = inventory_flows(parsed_flows)
    payload = {
        "capture": str(flows),
        "flow_count": len(parsed_flows),
        "endpoint_count": len(inventory),
        "endpoints": inventory,
    }

    output_stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    json_output_path = out_json or Path.cwd() / f"endpoints-{output_stamp}.json"
    markdown_output_path = out_md or Path.cwd() / f"endpoints-{output_stamp}.md"

    json_output_path.parent.mkdir(parents=True, exist_ok=True)
    json_output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"[bold green]✓[/bold green] Endpoint inventory written to: {json_output_path}")

    markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_output_path.write_text(
        endpoint_inventory_to_markdown(payload), encoding="utf-8"
    )
    console.print(f"[bold green]✓[/bold green] Endpoint inventory written to: {markdown_output_path}")

    table = Table(title=f"Endpoints in {flows}")
    table.add_column("Domain")
    table.add_column("Flows", justify="right")
    table.add_column("Methods")
    table.add_column("Paths")
    for item in inventory:
        methods = ", ".join(f"{name} ({count})" for name, count in item["methods"].items())
        paths = ", ".join(item["paths"].keys())
        table.add_row(item["domain"], str(item["flow_count"]), methods, paths)
    console.print(table)


@app.command()
def audit(
    flows: Path = typer.Option(
        ...,
        "--capture",
        "-c",
        help="Path to input mitmproxy flow or HAR capture file.",
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
    seed_json: Optional[Path] = typer.Option(
        None,
        "--seed-file",
        "-s",
        help="Path to JSON file containing seed key-value pairs (e.g. {\"email\": \"user@test.com\"}).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    exclude_json: Optional[Path] = typer.Option(
        None,
        "--exclude-file",
        help='JSON file of domains to ignore, e.g. {"domains": ["mozilla.org"]}.',
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
    temperature: float = typer.Option(
        1.0,
        "--temperature",
        min=0.0,
        max=2.0,
        help="LLM sampling temperature; 1.0 is the reproducible default.",
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
    presidio_language: str = typer.Option(
        "en",
        "--presidio-language",
        help="ISO-639-1 language for Presidio NLP detection (requires the matching spaCy model).",
    ),
    presidio_full_ner: bool = typer.Option(
        False,
        "--presidio-full-ner",
        help="Run spaCy NER on large values too; slower, but may improve accuracy.",
    ),
    consent_decided_at: Optional[str] = typer.Option(
        None,
        "--consent-decided-at",
        help="ISO-8601 timestamp when the consent banner was answered (for example 2026-08-13T10:15:00+02:00).",
    ),
    consent_outcome: ConsentOutcome = typer.Option(
        ConsentOutcome.NECESSARY_ONLY,
        "--consent-outcome",
        help="Outcome for non-essential processing: necessary_only or non_essential_granted.",
    ),
    consent_withdrawn_at: Optional[str] = typer.Option(
        None,
        "--consent-withdrawn-at",
        help="ISO-8601 timestamp when consent was withdrawn (for example 2026-08-13T10:40:00+02:00).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed intermediary pipeline diagnostics.",
    ),
    log_file: Optional[Path] = typer.Option(
        None,
        "--log-file",
        help="Write diagnostics to this file; defaults to audit-YYYYMMDD-HHMMSS.log in the current directory.",
    ),
) -> None:
    """Run an end-to-end technical privacy cross-reference audit."""
    output_stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    log_output_path = log_file or Path.cwd() / f"audit-{output_stamp}.log"
    configure_logging(verbose, log_output_path)
    logger.info("Logging to %s (verbose=%s)", log_output_path, verbose)

    decided_at = parse_iso8601_timestamp(consent_decided_at, "--consent-decided-at")
    withdrawn_at = parse_iso8601_timestamp(consent_withdrawn_at, "--consent-withdrawn-at")
    if decided_at and withdrawn_at and withdrawn_at < decided_at:
        raise typer.BadParameter(
            "must be after --consent-decided-at",
            param_hint="--consent-withdrawn-at",
        )

    progress: Optional[Progress] = None
    progress_task_id = None

    def update_progress(stage: str) -> None:
        if progress is not None and progress_task_id is not None:
            progress.update(progress_task_id, advance=1, description=stage)

    progress_context = (
        Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        if not verbose
        else None
    )

    with progress_context or console.status(
        "[bold green]Executing privacy audit pipeline...", spinner="dots"
    ):
        if progress_context is not None:
            progress = progress_context
            progress_task_id = progress.add_task(
                PIPELINE_STAGES[0], total=len(PIPELINE_STAGES)
            )
        pipeline = AuditPipeline(
            llm_model=model,
            temperature=temperature,
            api_key=api_key,
            api_base=api_base,
            presidio_language=presidio_language,
            presidio_full_ner=presidio_full_ner,
        )

        seed_data = None
        if seed_json:
            seed_data = json.loads(seed_json.read_text(encoding="utf-8"))

        excluded_domains = set()
        if exclude_json:
            try:
                excluded_domains = load_excluded_domains(
                    json.loads(exclude_json.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError, ValueError) as error:
                raise typer.BadParameter(
                    f"invalid exclusion file: {error}", param_hint="--exclude-file"
                ) from error

        report = pipeline.run(
            flow_file_path=flows,
            documents=doc,
            seed_data=seed_data,
            excluded_domains=sorted(excluded_domains),
            consent_decided_at=decided_at,
            consent_withdrawn_at=withdrawn_at,
            consent_outcome=consent_outcome,
            progress_callback=update_progress if not verbose else None,
        )

        if progress is not None and progress_task_id is not None:
            progress.update(
                progress_task_id,
                completed=len(PIPELINE_STAGES),
                description="Audit complete",
            )

    markdown_str = ReportExporter.to_markdown(report)
    json_output_path = out_json or Path.cwd() / f"audit-{output_stamp}.json"
    markdown_output_path = out_md or Path.cwd() / f"audit-{output_stamp}.md"

    ReportExporter.to_json_file(report, json_output_path)
    console.print(f"[bold green]✓[/bold green] JSON report written to: {json_output_path}")

    ReportExporter.to_markdown_file(report, markdown_output_path)
    console.print(f"[bold green]✓[/bold green] Markdown report written to: {markdown_output_path}")

    console.print(Panel(Markdown(markdown_str), title="Audit Results", expand=False))


def main() -> None:
    """Run the command-line application."""
    app()


if __name__ == "__main__":
    main()
