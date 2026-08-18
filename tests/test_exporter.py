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

from data_flow_analyser.exporter import ReportExporter
from data_flow_analyser.models.schemas import FullAuditReport


def test_json_export_handles_lone_unicode_surrogates(tmp_path):
    report = FullAuditReport(audit_title="Audit", summary="bad\udcfa")
    output = tmp_path / "report.json"

    ReportExporter.to_json_file(report, output)

    exported = json.loads(output.read_text(encoding="utf-8"))
    assert exported["summary"] == r"bad\udcfa"
