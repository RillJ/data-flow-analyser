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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from data_flow_analyser.web import (
    _form_page,
    _markdown_to_html,
    _parse_timestamp,
    _progress_page,
    run_web_audit,
    run_web_endpoint_inventory,
)


def test_form_page_contains_local_upload_and_consent_controls():
    page = _form_page()

    assert 'enctype="multipart/form-data"' in page
    assert 'name="capture"' in page
    assert 'name="capture" multiple' in page
    assert 'id="audit_form"' in page
    assert "<legend>Input files</legend>" in page
    assert "<legend>Consent metadata</legend>" in page
    assert "<legend>LLM and analysis settings</legend>" in page
    assert "<legend>Evidence filters and personal data detection</legend>" in page
    assert "<legend>Diagnostics</legend>" in page
    assert 'name="documents" multiple' in page
    assert 'name="consent_outcome"' in page
    assert 'id="consent_timezone"' in page
    assert 'value="local"' in page
    assert 'name="seed_json"' in page
    assert 'name="exclude_json"' in page
    assert 'name="seed_json_mode"' in page
    assert 'name="exclude_json_mode"' in page
    assert 'name="seed_file"' in page
    assert 'name="exclude_file"' in page
    assert "toggleJsonInput" in page
    assert 'name="temperature"' in page
    assert 'name="api_key"' in page
    assert 'name="api_base"' in page
    assert 'name="presidio_language"' in page
    assert 'value="">Disabled</option>' in page
    assert 'name="presidio_full_ner"' in page
    assert 'name="verbose"' in page
    assert 'action="/endpoints"' in page
    assert "Gather endpoint evidence" in page
    assert "timestampAsIso" in page
    assert "getElementById('audit_form')" in page


def test_parse_timestamp_requires_timezone():
    assert _parse_timestamp("2026-08-08T10:15:00+02:00", "decision") == datetime(
        2026, 8, 8, 10, 15, tzinfo=timezone(timedelta(hours=2))
    )


def test_markdown_is_rendered_as_safe_html():
    rendered = _markdown_to_html("# Endpoints\n\n**Count:** 1 and _one finding_\n\n| Domain | Flows |\n| --- | ---: |\n| `api.example.com` | 1 |")

    assert "<h1>Endpoints</h1>" in rendered
    assert "<strong>Count:</strong> 1" in rendered
    assert "<em>one finding</em>" in rendered
    assert "<table>" in rendered
    assert "<code>api.example.com</code>" in rendered
    assert "<script>" not in _markdown_to_html("<script>alert(1)</script>")


def test_progress_page_polls_job_status():
    page = _progress_page("job-123")

    assert "progress-track" in page
    assert "/api/progress/job-123" in page
    assert "window.location.href = '/result/'" in page


def test_run_web_audit_reuses_pipeline_and_writes_three_artifacts(tmp_path):
    report = MagicMock()

    def write_markdown(value, path):
        Path(path).write_text("# Browser report", encoding="utf-8")

    def write_json(value, path):
        Path(path).write_text("{}", encoding="utf-8")

    with (
        patch("data_flow_analyser.web.AuditPipeline") as pipeline_class,
        patch("data_flow_analyser.web.ReportExporter.to_markdown_file", side_effect=write_markdown),
        patch("data_flow_analyser.web.ReportExporter.to_json_file", side_effect=write_json),
    ):
        pipeline_class.return_value.run.return_value = report
        run_id, run_dir = run_web_audit(
            {
                "consent_decided_at": "2026-08-08T10:15:00+02:00",
                "consent_outcome": "necessary_only",
                "model": "test-model",
                "temperature": "0.2",
                "api_key": "secret",
                "api_base": "https://llm.example.test/v1",
                "presidio_language": "nl",
                "presidio_full_ner": "on",
                "verbose": "on",
                "seed_json": '{"email": "test@example.org"}',
                "exclude_json": '{"domains": ["example.com"]}',
            },
            {
                "capture": [("capture.har", b"capture")],
                "documents": [("policy.txt", b"policy"), ("dpa.txt", b"dpa")],
            },
        )

    assert run_id
    assert (run_dir / "audit.md").read_text(encoding="utf-8") == "# Browser report"
    assert (run_dir / "audit.json").is_file()
    assert (run_dir / "audit.log").is_file()
    pipeline_class.return_value.run.assert_called_once()
    call = pipeline_class.return_value.run.call_args.kwargs
    assert len(call["documents"]) == 2
    assert call["consent_decided_at"].tzinfo is not None
    assert call["seed_data"] == {"email": "test@example.org"}
    assert call["excluded_domains"] == ["example.com"]
    pipeline_class.assert_called_once_with(
        llm_model="test-model",
        temperature=0.2,
        api_key="secret",
        api_base="https://llm.example.test/v1",
        presidio_language="nl",
        presidio_full_ner=True,
    )


def test_endpoint_inventory_reuses_deterministic_endpoint_logic(tmp_path):
    inventory = [{
        "domain": "api.example.com",
        "flow_count": 1,
        "methods": {"GET": 1},
        "paths": {"/collect": 1},
        "first_seen": None,
        "last_seen": None,
    }]
    with (
        patch("data_flow_analyser.web.parse_flow_file", return_value=[]),
        patch("data_flow_analyser.web.inventory_flows", return_value=inventory),
    ):
        run_id, run_dir = run_web_endpoint_inventory({"capture": [("capture.har", b"capture")]})

    assert run_id
    assert json.loads((run_dir / "endpoints.json").read_text(encoding="utf-8"))["endpoints"] == inventory
    assert "# Endpoint Inventory" in (run_dir / "endpoints.md").read_text(encoding="utf-8")


def test_web_audit_passes_multiple_captures_in_upload_order():
    report = MagicMock()
    with (
        patch("data_flow_analyser.web.AuditPipeline") as pipeline_class,
        patch("data_flow_analyser.web.ReportExporter.to_markdown_file"),
        patch("data_flow_analyser.web.ReportExporter.to_json_file"),
    ):
        pipeline_class.return_value.run.return_value = report
        run_web_audit(
            {},
            {
                "capture": [("before.flow", b"before"), ("after.flow", b"after")],
                "documents": [("policy.txt", b"policy")],
            },
        )

    capture_paths = pipeline_class.return_value.run.call_args.kwargs["flow_file_path"]
    assert [path.name for path in capture_paths] == [
        "capture-1-before.flow",
        "capture-2-after.flow",
    ]
