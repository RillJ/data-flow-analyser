from data_flow_analyser.engines.cross_referencer import LLMCrossReferencer
from data_flow_analyser.models.schemas import (
    DiscrepancyCategory,
    DiscrepancySeverity,
    EndpointClassificationType,
)


def test_parse_audit_report_json():
    referencer = LLMCrossReferencer()

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
      "discrepancies": [
        {
          "discrepancy_id": "DISC-001",
          "title": "Plaintext Email Leak to Undocumented Subprocessor",
          "category": "plaintext_personal_data_leak",
          "severity": "CRITICAL",
          "observed_evidence": "User email (user@example.com) transmitted in request payload to tracker.unseen-ads.com.",
          "declared_claim_quote": "None declared for unseen-ads.com",
          "remediation_recommendation": "Halt traffic to unseen-ads.com or update DPA to include processing purpose."
        }
      ]
    }
    """

    report = referencer._parse_audit_report(mock_llm_output, flow_count=12)

    assert report.audit_title == "Technical Discrepancy Audit - ACME Portal"
    assert report.total_flows_analyzed == 12
    assert len(report.endpoint_classifications) == 3
    assert report.endpoint_classifications[0].classification == EndpointClassificationType.INTERNAL
    assert report.endpoint_classifications[2].classification == EndpointClassificationType.UNDOCUMENTED_THIRD_PARTY
    
    assert len(report.discrepancies) == 1
    disc = report.discrepancies[0]
    assert disc.category == DiscrepancyCategory.PLAINTEXT_PERSONAL_DATA_LEAK
    assert disc.severity == DiscrepancySeverity.CRITICAL
    assert "user@example.com" in disc.observed_evidence