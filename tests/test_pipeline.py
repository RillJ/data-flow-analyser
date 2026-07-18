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
from unittest.mock import MagicMock, patch

from data_flow_analyser.models.schemas import FullAuditReport
from data_flow_analyser.pipeline import AuditPipeline


@patch("data_flow_analyser.engines.cross_referencer.completion")
@patch("data_flow_analyser.engines.document_ingestor.completion")
@patch("data_flow_analyser.pipeline.parse_flow_file")
def test_pipeline_execution(
    mock_parse_flow_file: MagicMock,
    mock_ingestor_completion: MagicMock,
    mock_crossref_completion: MagicMock,
    tmp_path,
):
    """Verifies that the audit pipeline runs correctly when given multiple documents."""
    mock_flow = MagicMock()
    mock_flow.flow_id = "flow-001"
    mock_flow.host = "api.mixpanel.com"
    mock_flow.url = "https://api.mixpanel.com/track"
    mock_flow.request_headers = {"Host": "api.mixpanel.com"}
    mock_flow.request_body = '{"email": "user@test.com"}'
    mock_flow.cookies_sent = {}
    mock_flow.cookies_set = {"mp_id": "123"}
    mock_flow.response_headers = {"Set-Cookie": "mp_id=123; Max-Age=315360000"}
    mock_flow.timestamp = None

    mock_parse_flow_file.return_value = [mock_flow]

    # Mock Document Ingestor LLM Response
    mock_ingestor_response = MagicMock()
    mock_ingestor_response.choices = [
        MagicMock(
            message=MagicMock(
                content=json.dumps({
                    "document_title": "Aggregated Documents",
                    "raw_document_length": 100,
                    "declared_categories": [],
                    "declared_subprocessors": [],
                    "declared_storage_items": [
                        {
                            "name": "mp_id",
                            "storage_type": "cookie",
                            "provider": "Mixpanel",
                            "purpose": "Analytics",
                            "stated_lifespan": "30 days",
                            "citation_excerpt": "We store mp_id for 30 days."
                        }
                    ],
                    "international_transfer_mechanisms": [],
                    "stated_retention_summary": None,
                })
            )
        )
    ]
    mock_ingestor_completion.return_value = mock_ingestor_response

    # Mock CrossReferencer LLM Response
    mock_crossref_response = MagicMock()
    mock_crossref_response.choices = [
        MagicMock(
            message=MagicMock(
                content=json.dumps({
                    "audit_title": "Technical Discrepancy Audit",
                    "summary": "Found undocumented third party transmitting personal data.",
                    "endpoint_classifications": [
                        {
                            "domain": "api.mixpanel.com",
                            "classification": "undocumented_third_party",
                            "reasoning": "Not mentioned in policy.",
                            "citation_excerpt": None,
                        }
                    ],
                    "storage_classifications": [
                        {
                            "name": "mp_id",
                            "storage_type": "cookie",
                            "observed_lifespan_days": 3650.0,
                            "classification": "excessive_lifespan",
                            "reasoning": "Cookie 'mp_id' has an observed lifespan of 10 years (3650 days), exceeding declared retention of 30 days.",
                        }
                    ],
                    "discrepancies": [
                        {
                            "discrepancy_id": "DISC-001",
                            "title": "Unannounced Subprocessor Data Flow",
                            "category": "undocumented_endpoint",
                            "likelihood": "reasonable_possibility",
                            "severity_impact": "some_impact",
                            "potential_harms": ["loss_of_control"],
                            "assessment_basis": "Undocumented third-party transfer observed.",
                            "observed_evidence": "Transmitted user email to api.mixpanel.com",
                            "declared_claim_quote": "Not declared",
                        }
                    ],
                })
            )
        )
    ]
    mock_crossref_completion.return_value = mock_crossref_response

    flow_file = tmp_path / "traffic.flow"
    flow_file.write_text("mock mitmproxy dump", encoding="utf-8")

    doc1 = tmp_path / "privacy.txt"
    doc1.write_text("We respect user privacy.", encoding="utf-8")
    doc2 = tmp_path / "cookies.md"
    doc2.write_text("Cookies stored up to 30 days.", encoding="utf-8")

    pipeline = AuditPipeline(llm_model="gpt-5.4-mini")
    report = pipeline.run(
        flow_file_path=flow_file,
        documents=[doc1, doc2],
        seed_data={"email": "user@test.com"},
    )

    assert isinstance(report, FullAuditReport)
    assert report.total_flows_analysed == 1
    assert report.total_discrepancies_found == 1
    assert report.discrepancies[0].discrepancy_id == "DISC-001"
    assert report.provenance.model == "gpt-5.4-mini"
    assert "capture" in report.provenance.input_hashes
    
    # Verify storage classifications were evaluated and included
    assert len(report.storage_classifications) == 1
    assert report.storage_classifications[0].name == "mp_id"
    assert report.storage_classifications[0].classification.value == "excessive_lifespan"

    # Verify both documents were ingested
    ingestor_call_kwargs = mock_ingestor_completion.call_args[1]
    ingestor_prompt = ingestor_call_kwargs["messages"][1]["content"]
    assert "privacy.txt" in ingestor_prompt or "We respect user privacy." in ingestor_prompt
    assert "cookies.md" in ingestor_prompt or "Cookies stored up to 30 days." in ingestor_prompt
