# Copyright 2026 Julian Calvin Rill
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

import json
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from data_flow_analyser.cli import app


runner = CliRunner()


def test_audit_generates_log_file_alongside_reports(tmp_path, monkeypatch):
    flow_file = tmp_path / "capture.flow"
    flow_file.write_text("mock capture", encoding="utf-8")
    document = tmp_path / "policy.txt"
    document.write_text("mock policy", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    report = MagicMock()
    pipeline = MagicMock()
    pipeline.run.return_value = report

    with (
        patch("data_flow_analyser.cli.AuditPipeline", return_value=pipeline),
        patch("data_flow_analyser.cli.ReportExporter.to_markdown", return_value=""),
        patch("data_flow_analyser.cli.ReportExporter.to_json_file"),
        patch("data_flow_analyser.cli.ReportExporter.to_markdown_file"),
    ):
        result = runner.invoke(
            app,
            ["audit", "--capture", str(flow_file), "--doc", str(document)],
        )

    assert result.exit_code == 0, result.stdout
    log_files = list(tmp_path.glob("audit-*.log"))
    assert len(log_files) == 1
    assert log_files[0].name.endswith(".log")


def test_audit_allows_explicit_log_file(tmp_path, monkeypatch):
    flow_file = tmp_path / "capture.flow"
    flow_file.write_text("mock capture", encoding="utf-8")
    document = tmp_path / "policy.txt"
    document.write_text("mock policy", encoding="utf-8")
    explicit_log = tmp_path / "research" / "run.log"
    monkeypatch.chdir(tmp_path)

    pipeline = MagicMock()
    pipeline.run.return_value = MagicMock()

    with (
        patch("data_flow_analyser.cli.AuditPipeline", return_value=pipeline),
        patch("data_flow_analyser.cli.ReportExporter.to_markdown", return_value=""),
        patch("data_flow_analyser.cli.ReportExporter.to_json_file"),
        patch("data_flow_analyser.cli.ReportExporter.to_markdown_file"),
    ):
        result = runner.invoke(
            app,
            [
                "audit",
                "--capture",
                str(flow_file),
                "--doc",
                str(document),
                "--log-file",
                str(explicit_log),
            ],
        )

    assert result.exit_code == 0, result.stdout
    assert explicit_log.is_file()
    assert not list(tmp_path.glob("audit-*.log"))


def test_endpoints_exports_timestamped_json_and_markdown_and_displays_table(
    tmp_path, monkeypatch
):
    flow_file = tmp_path / "capture.flow"
    flow_file.write_text("mock capture", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    inventory = [{
        "domain": "api.example.com",
        "flow_count": 2,
        "methods": {"GET": 2},
        "paths": {"/collect": 2},
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:01:00+00:00",
    }]

    with (
        patch("data_flow_analyser.cli.parse_flow_file", return_value=[]),
        patch("data_flow_analyser.cli.inventory_flows", return_value=inventory),
    ):
        result = runner.invoke(app, ["endpoints", "--capture", str(flow_file)])

    assert result.exit_code == 0, result.stdout
    assert "api.example.com" in result.stdout
    json_files = list(tmp_path.glob("endpoints-*.json"))
    markdown_files = list(tmp_path.glob("endpoints-*.md"))
    assert len(json_files) == 1
    assert len(markdown_files) == 1
    assert json.loads(json_files[0].read_text(encoding="utf-8"))["endpoints"] == inventory
    assert "# Endpoint Inventory" in markdown_files[0].read_text(encoding="utf-8")


def test_endpoints_allows_explicit_json_and_markdown_paths(tmp_path, monkeypatch):
    flow_file = tmp_path / "capture.flow"
    flow_file.write_text("mock capture", encoding="utf-8")
    explicit_json = tmp_path / "exports" / "inventory.json"
    explicit_markdown = tmp_path / "exports" / "inventory.md"
    monkeypatch.chdir(tmp_path)

    with (
        patch("data_flow_analyser.cli.parse_flow_file", return_value=[]),
        patch("data_flow_analyser.cli.inventory_flows", return_value=[]),
    ):
        result = runner.invoke(
            app,
            [
                "endpoints",
                "--capture",
                str(flow_file),
                "--out-json",
                str(explicit_json),
                "--out-md",
                str(explicit_markdown),
            ],
        )

    assert result.exit_code == 0, result.stdout
    assert explicit_json.is_file()
    assert explicit_markdown.is_file()
    assert not list(tmp_path.glob("endpoints-*.json"))
    assert not list(tmp_path.glob("endpoints-*.md"))


def test_endpoints_appends_multiple_capture_inputs_in_order(tmp_path, monkeypatch):
    first = tmp_path / "first.flow"
    second = tmp_path / "second.flow"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with (
        patch(
            "data_flow_analyser.cli.parse_flow_file",
            side_effect=[["first-flow"], ["second-flow"]],
        ) as parse,
        patch("data_flow_analyser.cli.inventory_flows", return_value=[]),
    ):
        result = runner.invoke(
            app,
            ["endpoints", "--capture", str(first), "--capture", str(second)],
        )

    assert result.exit_code == 0, result.stdout
    assert [call.args[0] for call in parse.call_args_list] == [first, second]
