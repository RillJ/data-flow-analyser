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

"""Small local browser interface for the audit pipeline.

The server deliberately uses only the Python standard library. It is intended
for local use, not as a production web service. Uploaded inputs are kept in a
temporary run directory and no authentication or remote binding is provided.
"""

from __future__ import annotations

import html
import json
import logging
import mimetypes
import secrets
import tempfile
from datetime import datetime
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from typing import Callable
from urllib.parse import unquote, urlparse

from dotenv import load_dotenv
from markdown_it import MarkdownIt

from data_flow_analyser.exporter import ReportExporter
from data_flow_analyser.endpoint_inventory import (
    endpoint_inventory_to_markdown,
    inventory_flows,
    load_excluded_domains,
)
from data_flow_analyser.models.schemas import ConsentOutcome
from data_flow_analyser.parsers.mitm_parser import parse_flow_file
from data_flow_analyser.pipeline import AuditPipeline, PIPELINE_STAGES


WEB_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Data Flow Analyser</title>
<style>
:root { color-scheme: light; font: 16px system-ui, sans-serif; background: #f4f6f8; color: #17202a; }
body { max-width: 980px; margin: 2rem auto; padding: 0 1rem; }
body.wide { max-width: 1800px; }
main { background: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 2px 14px #0001; }
h1 { margin-top: 0; } label { display:block; font-weight: 650; margin-top: 1rem; }
fieldset { border:1px solid #d9dee3; border-radius:8px; margin:1.25rem 0; padding:.75rem 1rem 1rem; }
legend { padding:0 .4rem; font-weight:750; color:#243b53; }
input, select, textarea, button { box-sizing:border-box; width:100%; padding:.65rem; margin-top:.35rem; font:inherit; }
textarea { display:block; min-height:5rem; resize:vertical; }
input[type="checkbox"] { width:auto; margin-right:.45rem; }
button { cursor:pointer; background:#1769aa; color:white; border:0; border-radius:6px; font-weight:700; margin-top:1.5rem; }
.hint { color:#566573; font-size:.9rem; } .grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
pre { white-space:pre-wrap; overflow:auto; background:#f7f7f7; padding:1rem; border-radius:8px; }
.markdown { line-height:1.55; overflow:auto; } .markdown table { border-collapse:collapse; width:100%; margin:1rem 0; }
.markdown th, .markdown td { border:1px solid #d9dee3; padding:.45rem .6rem; text-align:left; vertical-align:top; }
.markdown th { background:#f0f3f5; } .markdown code { background:#eef1f3; padding:.1rem .25rem; border-radius:3px; }
.downloads { display:flex; gap:.75rem; flex-wrap:wrap; margin:1rem 0; } .downloads a, .downloads button { width:auto; padding:.6rem .8rem; background:#1769aa; color:white; border-radius:6px; text-decoration:none; margin:0; }
.progress-track { width:100%; height:1.25rem; background:#e5e7eb; border-radius:999px; overflow:hidden; margin:1rem 0 .5rem; }
.progress-bar { height:100%; width:0; background:#1769aa; transition:width .25s ease; }
.progress-label { color:#566573; }
@media (max-width: 700px) { .grid { grid-template-columns:1fr; } }
</style></head><body class="{body_class}"><main>{content}</main>
<script>
const browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
const timeZoneSelect = document.getElementById('consent_timezone');
if (timeZoneSelect) {
  timeZoneSelect.options[0].text = 'Browser local (' + browserTimeZone + ')';
}
function timestampAsIso(value, timeZone) {
  if (!value) return '';
  if (timeZone === 'local') return new Date(value).toISOString();
  if (timeZone === 'UTC') return new Date(value + ':00Z').toISOString();
  const [date, clock] = value.split('T');
  const [year, month, day] = date.split('-').map(Number);
  const [hour, minute] = clock.split(':').map(Number);
  const target = new Date(Date.UTC(year, month - 1, day, hour, minute));
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(target);
  const values = Object.fromEntries(parts.map(part => [part.type, Number(part.value)]));
  const renderedAsUtc = Date.UTC(values.year, values.month - 1, values.day, values.hour, values.minute);
  return new Date(target.getTime() - (renderedAsUtc - target.getTime())).toISOString();
}
function toggleJsonInput(name) {
  const modeElement = document.getElementById(name + '_mode');
  if (!modeElement) return;
  const mode = modeElement.value;
  document.getElementById(name + '_text_container').hidden = mode !== 'text';
  document.getElementById(name + '_file_container').hidden = mode !== 'file';
}
for (const name of ['seed_json', 'exclude_json']) {
  document.getElementById(name + '_mode')?.addEventListener('change', () => toggleJsonInput(name));
  toggleJsonInput(name);
}
document.getElementById('audit_form')?.addEventListener('submit', function () {
  for (const id of ['decided_at', 'withdrawn_at']) {
    const visible = document.getElementById(id + '_display');
    const hidden = document.getElementById(id);
    hidden.value = timestampAsIso(visible.value, timeZoneSelect.value);
  }
});
</script></body></html>"""


def _page(content: str, wide: bool = False) -> str:
    """Insert page content without interpreting CSS braces as format fields."""
    return WEB_PAGE.replace("{content}", content).replace(
        "{body_class}", "wide" if wide else ""
    )


_RUNS: dict[str, Path] = {}
_RUNS_LOCK = Lock()
_JOBS: dict[str, dict[str, object]] = {}
_JOBS_LOCK = Lock()

# js-default keeps tables and strikethrough enabled while treating raw HTML as
# text, which is the safe default for Markdown displayed in this local web UI.
_MARKDOWN = MarkdownIt("js-default")


def _parse_timestamp(value: str | None, label: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 timestamp with a timezone") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone offset")
    return parsed


def _markdown_to_html(markdown: str) -> str:
    """Render Markdown as safe HTML without accepting raw HTML markup."""
    return _MARKDOWN.render(markdown)


def _json_input(
    fields: dict[str, str],
    uploads: dict[str, list[tuple[str, bytes]]],
    text_name: str,
    upload_name: str,
    label: str,
) -> str:
    """Read a JSON value from the selected text or file input mode."""
    if fields.get(f"{text_name}_mode", "text") == "file":
        selected = uploads.get(upload_name, [])
        if not selected:
            raise ValueError(f"Choose a {label} JSON file or switch back to text input.")
        return selected[0][1].decode("utf-8", errors="replace")
    return fields.get(text_name, "")


def run_web_audit(
    fields: dict[str, str],
    uploads: dict[str, list[tuple[str, bytes]]],
    progress_callback: Callable[[str], None] | None = None,
) -> tuple[str, Path]:
    """Run one uploaded audit and return its ID and temporary result directory."""
    captures = uploads.get("capture", [])
    documents = uploads.get("documents", [])
    if not captures or not documents:
        raise ValueError("Choose at least one capture and one disclosure document.")

    run_dir = Path(tempfile.mkdtemp(prefix="data-flow-analyser-web-"))
    capture_paths = []
    for index, (name, content) in enumerate(captures, start=1):
        capture_path = run_dir / f"capture-{index}-{Path(name).name}"
        capture_path.write_bytes(content)
        capture_paths.append(capture_path)
    document_paths = []
    for index, (name, content) in enumerate(documents, start=1):
        document_path = run_dir / f"document-{index}-{Path(name).name}"
        document_path.write_bytes(content)
        document_paths.append(document_path)

    decided_at = _parse_timestamp(fields.get("consent_decided_at"), "Consent decision")
    withdrawn_at = _parse_timestamp(fields.get("consent_withdrawn_at"), "Consent withdrawal")
    outcome = ConsentOutcome(fields.get("consent_outcome", ConsentOutcome.NECESSARY_ONLY.value))
    if decided_at and withdrawn_at and withdrawn_at < decided_at:
        raise ValueError("Consent withdrawal must be after the consent decision.")

    seed_json = _json_input(fields, uploads, "seed_json", "seed_file", "seed input")
    seed_data = None
    if seed_json.strip():
        try:
            seed_data = json.loads(seed_json)
        except json.JSONDecodeError as error:
            raise ValueError(f"Seed input must be valid JSON: {error.msg}") from error
        if not isinstance(seed_data, dict):
            raise ValueError("Seed input must be a JSON object of labels and values.")

    excluded_domains = []
    exclude_json = _json_input(fields, uploads, "exclude_json", "exclude_file", "excluded domains")
    if exclude_json.strip():
        try:
            excluded_domains = sorted(
                load_excluded_domains(json.loads(exclude_json))
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"Exclusion input must be valid JSON: {error}") from error

    log_path = run_dir / "audit.log"
    # Keep the browser form consistent with the CLI: an omitted key/base can
    # be supplied by the normal environment or a nearby .env file.
    load_dotenv()
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
    root_logger = logging.getLogger()
    previous_level = root_logger.level
    verbose = fields.get("verbose") == "on"
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    root_logger.addHandler(handler)
    try:
        pipeline = AuditPipeline(
            llm_model=fields.get("model") or "gpt-5.6-luna",
            temperature=float(fields.get("temperature") or 1.0),
            api_key=fields.get("api_key") or None,
            api_base=fields.get("api_base") or None,
            presidio_language=fields["presidio_language"] if "presidio_language" in fields else "en",
            presidio_full_ner=fields.get("presidio_full_ner") == "on",
        )
        report = pipeline.run(
            flow_file_path=capture_paths,
            documents=document_paths,
            seed_data=seed_data,
            excluded_domains=excluded_domains,
            consent_decided_at=decided_at,
            consent_withdrawn_at=withdrawn_at,
            consent_outcome=outcome,
            progress_callback=progress_callback,
        )
        ReportExporter.to_markdown_file(report, run_dir / "audit.md")
        ReportExporter.to_json_file(report, run_dir / "audit.json")
    finally:
        root_logger.removeHandler(handler)
        root_logger.setLevel(previous_level)
        handler.close()

    run_id = secrets.token_urlsafe(12)
    with _RUNS_LOCK:
        _RUNS[run_id] = run_dir
    return run_id, run_dir


def run_web_endpoint_inventory(uploads: dict[str, list[tuple[str, bytes]]]) -> tuple[str, Path]:
    """Run the deterministic endpoint review used by the CLI endpoints command."""
    captures = uploads.get("capture", [])
    if not captures:
        raise ValueError("Choose at least one capture file first.")
    run_dir = Path(tempfile.mkdtemp(prefix="data-flow-analyser-endpoints-web-"))
    capture_paths = []
    for index, (name, content) in enumerate(captures, start=1):
        capture_path = run_dir / f"capture-{index}-{Path(name).name}"
        capture_path.write_bytes(content)
        capture_paths.append(capture_path)
    parsed_flows = [
        flow
        for capture_path in capture_paths
        for flow in parse_flow_file(capture_path)
    ]
    inventory = inventory_flows(parsed_flows)
    payload = {
        "capture": (
            capture_paths[0].name
            if len(capture_paths) == 1
            else [capture_path.name for capture_path in capture_paths]
        ),
        "flow_count": len(parsed_flows),
        "endpoint_count": len(inventory),
        "endpoints": inventory,
    }
    (run_dir / "endpoints.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (run_dir / "endpoints.md").write_text(
        endpoint_inventory_to_markdown(payload), encoding="utf-8"
    )
    run_id = secrets.token_urlsafe(12)
    with _RUNS_LOCK:
        _RUNS[run_id] = run_dir
    return run_id, run_dir


def _run_audit_job(job_id: str, fields: dict[str, str], uploads: dict[str, list[tuple[str, bytes]]]) -> None:
    """Execute an audit in the background while publishing pipeline stages."""
    def report_progress(stage: str) -> None:
        try:
            completed = PIPELINE_STAGES.index(stage) + 1
        except ValueError:
            completed = 0
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job:
                job.update({"stage": stage, "completed": completed})

    try:
        run_id, _ = run_web_audit(fields, uploads, progress_callback=report_progress)
        with _JOBS_LOCK:
            if job_id in _JOBS:
                _JOBS[job_id].update({"status": "complete", "run_id": run_id, "completed": len(PIPELINE_STAGES), "stage": "Audit complete"})
    except Exception as error:
        logging.getLogger(__name__).exception("Web audit job %s failed", job_id)
        with _JOBS_LOCK:
            if job_id in _JOBS:
                _JOBS[job_id].update({"status": "error", "error": str(error)})


def _progress_page(job_id: str) -> str:
    return _page(f"""
<h1>Audit in progress</h1>
<p>The audit is running in the background. You can leave this page open while the pipeline processes the capture and documents.</p>
<div class="progress-track"><div id="progress_bar" class="progress-bar"></div></div>
<p id="progress_label" class="progress-label">Starting audit…</p>
<script>
async function refreshProgress() {{
  const response = await fetch('/api/progress/{job_id}');
  const job = await response.json();
  const percent = Math.round((job.completed / job.total) * 100);
  document.getElementById('progress_bar').style.width = percent + '%';
  document.getElementById('progress_label').textContent = job.status === 'error' ? 'Error: ' + job.error : job.stage + ' (' + percent + '%)';
  if (job.status === 'complete') {{ window.location.href = '/result/' + job.run_id; return; }}
  if (job.status !== 'error') window.setTimeout(refreshProgress, 750);
}}
refreshProgress();
</script>""")


def _form_page(error: str | None = None) -> str:
    message = f'<p style="color:#a51d2d"><strong>{html.escape(error)}</strong></p>' if error else ""
    return _page(f"""
<h1>Data Flow Analyser</h1><p class="hint">Easy web utility for running technical privacy audits.</p>{message}
<section><h2>Review endpoints first</h2><p class="hint">This deterministic step lists every destination host used to help determine domains to be excluded before the audit pipeline.</p>
<form method="post" action="/endpoints" enctype="multipart/form-data"><label>Capture files <input type="file" name="capture" multiple required></label><p class="hint">Choose one or more mitmproxy flow files or HAR captures. They are appended in selection order.</p><button type="submit">Gather endpoint evidence</button></form></section>
<hr>
<h2>Run audit pipeline</h2>
<form id="audit_form" method="post" action="/run" enctype="multipart/form-data">
<fieldset><legend>Input files</legend>
<label>Capture files <input type="file" name="capture" multiple required></label>
<p class="hint">Choose one or more mitmproxy flow files or HAR captures. They are appended in selection order and analysed as one capture.</p>
<label>Disclosure documents <input type="file" name="documents" multiple required></label>
<p class="hint">Select privacy policies, cookie policies, DPAs, or similar documents. They are used to map observed endpoints, storage, and data flows to the vendor's disclosures.</p>
</fieldset>
<fieldset><legend>Consent metadata</legend>
<label>Timestamp timezone <select id="consent_timezone" name="consent_timezone"><option value="local">Browser local</option><option value="UTC">UTC</option><option value="Europe/Amsterdam">Europe/Amsterdam</option><option value="Europe/London">Europe/London</option><option value="America/New_York">America/New_York</option><option value="America/Los_Angeles">America/Los_Angeles</option><option value="Asia/Tokyo">Asia/Tokyo</option></select></label>
<p class="hint">Defaults to your browser's local timezone. Use this when the capture timestamps were recorded in another timezone.</p>
<div class="grid"><div><label>Consent decision <input id="decided_at_display" type="datetime-local"></label><input id="decided_at" name="consent_decided_at" type="hidden"><p class="hint">Optional: when the consent banner choice was made.</p></div>
<div><label>Consent withdrawal <input id="withdrawn_at_display" type="datetime-local"></label><input id="withdrawn_at" name="consent_withdrawn_at" type="hidden"><p class="hint">Optional: when previously granted consent was withdrawn.</p></div></div>
<label>Consent outcome <select name="consent_outcome"><option value="necessary_only">Necessary only</option><option value="non_essential_granted">Non-essential granted</option></select></label>
<p class="hint"><strong>Necessary only</strong> means optional processing was not accepted (only essential cookies). <strong>Non-essential granted</strong> means the test allowed optional processing (such as analytics).</p>
</fieldset>
<fieldset><legend>LLM and analysis settings</legend>
<div class="grid"><div><label>LLM model <input name="model" value="gpt-5.6-luna"></label></div>
<div><label>Temperature <input name="temperature" type="number" min="0" max="2" step="0.1" value="1.0"></label></div></div>
<div class="grid"><div><label>API key <input name="api_key" type="password" autocomplete="off" placeholder="Optional: uses .env if blank"></label></div>
<div><label>API base <input name="api_base" type="url" placeholder="Optional: custom LiteLLM base URL"></label></div></div>
</fieldset>
<fieldset><legend>Evidence filters and personal data detection</legend>
<label>Seed input JSON <select id="seed_json_mode" name="seed_json_mode"><option value="text" selected>Paste text</option><option value="file">Upload file</option></select></label>
<div id="seed_json_text_container"><label>Seed JSON text <textarea name="seed_json" rows="4" placeholder='{{"email": "research-user@example.org", "account_id": "test-account-123"}}'></textarea></label></div>
<div id="seed_json_file_container" hidden><label>Seed JSON file <input type="file" name="seed_file" accept=".json,application/json"></label></div>
<p class="hint">Optional personal data values to look for when searching network traffic, used for validating personal data flows with vendor disclosures.</p>
<label>Excluded domains JSON <select id="exclude_json_mode" name="exclude_json_mode"><option value="text" selected>Paste text</option><option value="file">Upload file</option></select></label>
<div id="exclude_json_text_container"><label>Excluded domains JSON text <textarea name="exclude_json" rows="3" placeholder='{{"domains": ["mozilla.org", "example.com"]}}'></textarea></label></div>
<div id="exclude_json_file_container" hidden><label>Excluded domains JSON file <input type="file" name="exclude_file" accept=".json,application/json"></label></div>
<p class="hint">Optional domains to remove before analysis, including their subdomains.</p>
<label>Presidio language <select name="presidio_language"><option value="">Disabled</option><option value="en" selected>English</option><option value="nl">Dutch</option><option value="de">German</option><option value="es">Spanish</option><option value="it">Italian</option><option value="fr">French</option></select></label>
<p class="hint">Presidio looks for likely personal data entities such as names, email addresses, locations, dates, IP addresses, and similar patterns in captured values. They are provided as additional evidence to the seed input.</p>
<label><input name="presidio_full_ner" type="checkbox"> Run full Presidio NER on large values (slower)</label>
<p class="hint">To save processing time, by default NER only runs on smaller data flows and regex on larger ones.</p>
</fieldset>
<fieldset><legend>Diagnostics</legend>
<label><input name="verbose" type="checkbox"> Verbose diagnostics</label>
<p class="hint">Timestamps use your browser's local timezone and are sent as ISO-8601 values.</p>
</fieldset>
<button type="submit">Run audit</button></form>""")


class _Handler(BaseHTTPRequestHandler):
    server_version = "DataFlowAnalyserWeb/1.0"

    def _send(self, body: bytes, content_type: str = "text/html; charset=utf-8", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(_form_page().encode())
            return
        parts = [unquote(part) for part in parsed.path.split("/") if part]
        if len(parts) == 2 and parts[0] == "progress":
            with _JOBS_LOCK:
                job_exists = parts[1] in _JOBS
            if job_exists:
                self._send(_progress_page(parts[1]).encode())
                return
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "progress":
            with _JOBS_LOCK:
                job = _JOBS.get(parts[2])
                payload = dict(job) if job else None
            if payload is not None:
                self._send(json.dumps(payload).encode(), "application/json; charset=utf-8")
                return
        if len(parts) == 2 and parts[0] in {"result", "endpoints"}:
            with _RUNS_LOCK:
                run_dir = _RUNS.get(parts[1])
            if run_dir:
                if parts[0] == "result" and (run_dir / "audit.md").is_file():
                    self._send(_result_page(parts[1], run_dir).encode())
                    return
                if parts[0] == "endpoints" and (run_dir / "endpoints.md").is_file():
                    self._send(_endpoint_result_page(parts[1], run_dir).encode())
                    return
        if len(parts) == 3 and parts[0] == "download":
            with _RUNS_LOCK:
                run_dir = _RUNS.get(parts[1])
            if run_dir and parts[2] in {"audit.md", "audit.json", "audit.log", "endpoints.md", "endpoints.json"}:
                path = run_dir / parts[2]
                if path.is_file():
                    body = path.read_bytes()
                    content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
        self._send(b"Not found", "text/plain; charset=utf-8", HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        request_path = urlparse(self.path).path
        if request_path not in {"/run", "/endpoints"}:
            self._send(b"Not found", "text/plain; charset=utf-8", HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            message = BytesParser(policy=policy.HTTP).parsebytes(
                f"Content-Type: {self.headers.get('Content-Type', '')}\r\n\r\n".encode() + self.rfile.read(length)
            )
            fields: dict[str, str] = {}
            uploads: dict[str, list[tuple[str, bytes]]] = {}
            for part in message.iter_parts():
                raw_name = part.get_param("name", header="content-disposition")
                if not isinstance(raw_name, str) or not raw_name:
                    continue
                filename = part.get_filename()
                decoded_payload = part.get_payload(decode=True)
                payload = decoded_payload if isinstance(decoded_payload, bytes) else b""
                if isinstance(filename, str) and filename:
                    uploads.setdefault(raw_name, []).append((filename, payload))
                else:
                    if not payload:
                        raw_payload = part.get_payload()
                        payload = raw_payload.encode("utf-8") if isinstance(raw_payload, str) else b""
                    fields[raw_name] = payload.decode("utf-8", errors="replace")
            if request_path == "/endpoints":
                run_id, _ = run_web_endpoint_inventory(uploads)
                location = f"/endpoints/{run_id}"
            else:
                job_id = secrets.token_urlsafe(12)
                with _JOBS_LOCK:
                    _JOBS[job_id] = {
                        "status": "running",
                        "stage": "Starting audit",
                        "completed": 0,
                        "total": len(PIPELINE_STAGES),
                    }
                Thread(target=_run_audit_job, args=(job_id, fields, uploads), daemon=True).start()
                location = f"/progress/{job_id}"
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", location)
            self.end_headers()
        except Exception as error:  # show actionable validation/errors in the local UI
            self._send(_form_page(str(error)).encode(), status=HTTPStatus.BAD_REQUEST)

    def log_message(self, format: str, *args: object) -> None:
        logging.getLogger(__name__).info("%s - %s", self.address_string(), format % args)


def _result_page(run_id: str, run_dir: Path) -> str:
    markdown = (run_dir / "audit.md").read_text(encoding="utf-8")
    links = " ".join(f'<a href="/download/{run_id}/{name}">Download {name}</a>' for name in ("audit.md", "audit.json", "audit.log"))
    return _page(f'<h1>Audit results</h1><div class="downloads">{links}<button type="button" onclick="window.print()">Print</button></div><article class="markdown">{_markdown_to_html(markdown)}</article><p><a href="/">Run another audit</a></p>', wide=True)


def _endpoint_result_page(run_id: str, run_dir: Path) -> str:
    markdown = (run_dir / "endpoints.md").read_text(encoding="utf-8")
    links = " ".join(
        f'<a href="/download/{run_id}/{name}">Download {name}</a>'
        for name in ("endpoints.md", "endpoints.json")
    )
    return _page(
        f'<h1>Endpoint evidence</h1><div class="downloads">{links}'
        f'<button type="button" onclick="window.print()">Print</button></div>'
        f'<article class="markdown">{_markdown_to_html(markdown)}</article>'
        f'<p><a href="/">Continue to full audit</a></p>',
        wide=True,
    )


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Start the local browser interface until interrupted."""
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"Data Flow Analyser web interface: http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping web interface.")
    finally:
        server.server_close()
