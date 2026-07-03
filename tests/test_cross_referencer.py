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

from data_flow_analyser.engines.cross_referencer import LLMCrossReferencer
from data_flow_analyser.models.schemas import (
    DiscrepancyCategory,
    DiscrepancySeverity,
    EndpointClassificationType,
    StorageClassificationResult,
    StorageClassificationType,
    StorageTechnologyType,
)


def test_parse_audit_report_json():
    referencer = LLMCrossReferencer()

    mock_fallback_storage = [
        StorageClassificationResult(
            name="_ga",
            storage_type=StorageTechnologyType.COOKIE,
            observed_lifespan_days=730.0,
            classification=StorageClassificationType.DOCUMENTED,
            reasoning="Cookie '_ga' matches declared storage item '_ga'.",
        )
    ]

    mock_llm_output = """
    {
      "audit_title": "Technical Discrepancy Audit - ACME Portal",
      "summary": "Observed high-risk data flows to an undocumented third-party endpoint with plaintext personal data.",
      "endpoint_classifications": [
        {
          "domain": "acme.com",
          "classification": "internal",
          "reasoning": "Primary application domain.",
          "citation_excerpt": "Our website at acme.com operates primary services."
        },
        {
          "domain": "api.mixpanel.com",
          "classification": "documented_subprocessor",
          "reasoning": "Listed under analytics subprocessors.",
          "citation_excerpt": "We engage Mixpanel for usage metrics."
        },
        {
          "domain": "tracker.unseen-ads.com",
          "classification": "undocumented_third_party",
          "reasoning": "No mention of unseen-ads.com in DPA or Privacy Policy.",
          "citation_excerpt": null
        }
      ],
      "storage_classifications": [
        {
          "name": "_ga",
          "storage_type": "cookie",
          "observed_lifespan_days": 730.0,
          "classification": "documented",
          "reasoning": "Cookie '_ga' is disclosed in policy documentation."
        },
        {
          "name": "unannounced_tracker_id",
          "storage_type": "cookie",
          "observed_lifespan_days": 180.0,
          "classification": "undocumented",
          "reasoning": "Cookie was observed in traffic but is missing from cookie policy."
        }
      ],
      "discrepancies": [
        {
          "discrepancy_id": "DISC-001",
          "title": "Plaintext Email Leak to Undocumented Subprocessor",
          "category": "plaintext_personal_data_leak",
          "severity": "CRITICAL",
          "observed_evidence": "User email (user@example.com) transmitted in request payload to tracker.unseen-ads.com.",
              "declared_claim_quote": "None declared for unseen-ads.com"
        }
      ]
    }
    """

    report = referencer._parse_audit_report(
        mock_llm_output,
        flow_count=12,
        fallback_storage=mock_fallback_storage,
    )

    assert report.audit_title == "Technical Discrepancy Audit - ACME Portal"
    assert report.total_flows_analyzed == 12

    # Verify Endpoint Classifications
    assert len(report.endpoint_classifications) == 3
    assert report.endpoint_classifications[0].classification == EndpointClassificationType.INTERNAL
    assert (
        report.endpoint_classifications[2].classification
        == EndpointClassificationType.UNDOCUMENTED_THIRD_PARTY
    )

    # Verify Storage Mechanisms & Cookies
    assert len(report.storage_classifications) == 2
    assert report.storage_classifications[0].name == "_ga"
    assert (
        report.storage_classifications[0].classification
        == StorageClassificationType.DOCUMENTED
    )
    assert report.storage_classifications[1].name == "unannounced_tracker_id"
    assert (
        report.storage_classifications[1].classification
        == StorageClassificationType.UNDOCUMENTED
    )

    # Verify Compliance Discrepancies
    assert len(report.discrepancies) == 1
    disc = report.discrepancies[0]
    assert disc.category == DiscrepancyCategory.PLAINTEXT_PERSONAL_DATA_LEAK
    assert disc.severity == DiscrepancySeverity.CRITICAL
    assert "user@example.com" in disc.observed_evidence


def test_parse_audit_report_storage_fallback():
    referencer = LLMCrossReferencer()

    mock_fallback_storage = [
        StorageClassificationResult(
            name="_session_id",
            storage_type=StorageTechnologyType.COOKIE,
            observed_lifespan_days=None,
            classification=StorageClassificationType.UNDOCUMENTED,
            reasoning="Cookie '_session_id' was observed in traffic but missing from policy.",
        )
    ]

    # LLM JSON output missing storage_classifications entirely
    mock_llm_output_no_storage = """
    {
      "audit_title": "Technical Discrepancy Audit",
      "summary": "Basic audit summary.",
      "endpoint_classifications": [],
      "discrepancies": []
    }
    """

    report = referencer._parse_audit_report(
        mock_llm_output_no_storage,
        flow_count=5,
        fallback_storage=mock_fallback_storage,
    )

    # Asserts fallback storage was applied when missing from LLM response
    assert len(report.storage_classifications) == 1
    assert report.storage_classifications[0].name == "_session_id"
    assert (
        report.storage_classifications[0].classification
        == StorageClassificationType.UNDOCUMENTED
    )
