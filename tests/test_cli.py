# Copyright 2026 Julian Calvin Rill
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

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
