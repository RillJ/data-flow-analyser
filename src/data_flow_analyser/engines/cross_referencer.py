import json
from typing import Any, Dict, List, Optional, cast
from litellm import ModelResponse, completion

from data_flow_analyser.models.schemas import (
    ComplianceDiscrepancy,
    CookieLongevityResult,
    DiscrepancyCategory,
    DiscrepancySeverity,
    DocumentAnalysisResult,
    EndpointClassificationResult,
    EndpointClassificationType,
    FullAuditReport,
    NetworkFlow,
    ObservedEndpoint,
    TrackingToken,
)

SYSTEM_PROMPT = """
You are an expert Privacy Legal Auditor conducting a technical Data Protection Impact Assessment (DPIA).
Your task is to cross-reference technical evidence gathered from observed network traffic against a vendor's legal document disclosures (Privacy Policy, DPA, Cookie Policy).

You must produce an auditable report evaluating:
1. ENDPOINT CLASSIFICATION: Classify each observed domain into one of:
   - "internal": Primary domain or first-party infrastructure.
   - "documented_subprocessor": Subprocessor explicitly listed in the policy/DPA.
   - "undocumented_third_party": Third-party host not mentioned in vendor documents.
   - "tracker_unconsented": Known advertising/tracking domain operating without explicit consent documentation.

2. COMPLIANCE DISCREPANCIES: Compare observed network facts against policy claims. Look for:
   - Undocumented endpoints receiving data.
   - Personal data transmission (plaintext or hashed) sent to third parties or without consent.
   - Data collection exceeding stated categories (like: ACCOUNT_DATA sent to DIAGNOSTIC_DATA endpoints).
   - Cookies or LocalStorage keys observed but unannounced, or with actual lifespans exceeding declared durations.
   - International data transfers to third countries (like: US) without disclosed transfer safeguards.

For EVERY discrepancy, provide the exact technical evidence observed and cite the verbatim policy quote (or 'Not declared' if missing).

Respond strictly in JSON matching this schema:
{
  "audit_title": "Technical Privacy Discrepancy Audit",
  "summary": "Factual summary of technical findings and disclosure gaps",
  "endpoint_classifications": [
    {
      "domain": "example.com",
      "classification": "internal|documented_subprocessor|undocumented_third_party|tracker_unconsented",
      "reasoning": "Detailed justification based solely on policy context",
      "citation_excerpt": "Verbatim quote from policy if documented, else null"
    }
  ],
  "discrepancies": [
    {
      "discrepancy_id": "DISC-001",
      "title": "Short descriptive title",
      "category": "undocumented_endpoint|unannounced_data_collection|purpose_mismatch|storage_lifespan_excessive|unannounced_storage|unsafe_third_country_transfer|plaintext_personal_data_leak",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "observed_evidence": "Factual description of wire observations",
      "declared_claim_quote": "Verbatim quote from policy or 'Not declared'",
      "remediation_recommendation": "Actionable technical step to reconcile documentation with reality"
    }
  ]
}
"""


class LLMCrossReferencer:
    """
    Cross-references observed network traffic metadata against extracted legal document claims
    using LiteLLM to detect technical policy discrepancies.
    """

    def __init__(
        self,
        model: str = "gpt-5.4-mini",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
    ):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base

    def cross_reference_audit(
        self,
        doc_analysis: DocumentAnalysisResult,
        flows: List[NetworkFlow],
        endpoints: List[ObservedEndpoint],
        seed_matches: Optional[List[Dict[str, Any]]] = None,
        entropy_tokens: Optional[List[TrackingToken]] = None,
        cookie_results: Optional[List[CookieLongevityResult]] = None,
    ) -> FullAuditReport:
        """
        Executes an LLM-based technical cross-reference between observed evidence and policy claims.
        """
        seed_matches = seed_matches or []
        entropy_tokens = entropy_tokens or []
        cookie_results = cookie_results or []

        evidence_summary = self._prepare_evidence_summary(
            flows, endpoints, seed_matches, entropy_tokens, cookie_results
        )

        document_context = doc_analysis.model_dump(mode="json")

        prompt_content = f"""
        === DECLARED POLICY DOCUMENTATION ===
        Title: {doc_analysis.document_title}
        Document Length: {doc_analysis.raw_document_length} characters

        Declared Categories:
        {json.dumps(document_context.get('declared_categories', []), indent=2)}

        Declared Subprocessors:
        {json.dumps(document_context.get('declared_subprocessors', []), indent=2)}

        Declared Storage Items:
        {json.dumps(document_context.get('declared_storage_items', []), indent=2)}

        International Transfer Safeguards Declared: {doc_analysis.international_transfer_mechanisms}
        Retention Summary Declared: {doc_analysis.stated_retention_summary or 'None specified'}

        === OBSERVED NETWORK EVIDENCE ===
        Total Flows Captured: {len(flows)}
        Observed Evidence Summary:
        {json.dumps(evidence_summary, indent=2)}
        """

        try:
            response = cast(
                ModelResponse,
                completion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt_content}
                    ],
                    response_format={"type": "json_object"},
                    api_key=self.api_key,
                    api_base=self.api_base,
                )
            )

            if not response.choices or not response.choices[0].message:
                return FullAuditReport(
                    audit_title="Technical Audit (Failed)",
                    summary="Failed to get response choices from LLM.",
                    total_flows_analyzed=len(flows)
                )

            raw_json_str: Optional[str] = response.choices[0].message.content
            if not raw_json_str:
                return FullAuditReport(
                    audit_title="Technical Audit (Empty Response)",
                    summary="LLM returned empty output.",
                    total_flows_analyzed=len(flows)
                )

            return self._parse_audit_report(raw_json_str, len(flows))

        except Exception as e:
            print(f"[Warning] LLM Cross-Referencer execution failed ({self.model}): {e}")
            return FullAuditReport(
                audit_title="Technical Privacy Audit",
                summary=f"Analysis encountered an execution error: {str(e)}",
                total_flows_analyzed=len(flows)
            )

    def _prepare_evidence_summary(
        self,
        flows: List[NetworkFlow],
        endpoints: List[ObservedEndpoint],
        seed_matches: List[Dict[str, Any]],
        entropy_tokens: List[TrackingToken],
        cookie_results: List[CookieLongevityResult],
    ) -> Dict[str, Any]:
        """Summarizes low-level network vectors into a clean structure for the prompt."""
        endpoint_summary = [
            {
                "domain": ep.domain,
                "ip": ep.ip_address,
                "country": ep.country_code,
                "parent_entity": ep.parent_entity,
                "category": ep.category,
                "asn_org": ep.asn_org,
                "is_third_country_transfer": ep.is_third_country_transfer,
                "is_undocumented": ep.is_undocumented,
            }
            for ep in endpoints
        ]

        seed_summary = []
        for match in seed_matches:
            if isinstance(match, dict):
                seed_summary.append({
                    "matched_value": match.get("matched_value") or match.get("raw_value") or match.get("value"),
                    "type": match.get("field_type") or match.get("key") or match.get("type", "unknown"),
                    "location": match.get("location") or match.get("found_in", "unknown"),
                    "is_hashed": match.get("is_hashed", False),
                })
            else:
                seed_summary.append({
                    "matched_value": getattr(match, "matched_value", getattr(match, "raw_value", str(match))),
                    "type": getattr(match, "field_type", getattr(match, "key", "unknown")),
                    "location": getattr(match, "location", "unknown"),
                    "is_hashed": getattr(match, "is_hashed", False),
                })

        entropy_summary = [
            {
                "token": tok.token[:16] + "..." if len(tok.token) > 16 else tok.token,
                "location": tok.location,
                "entropy": tok.entropy,
            }
            for tok in entropy_tokens
        ]

        cookie_summary = [
            {
                "name": c.cookie_name,
                "lifespan_days": c.lifespan_days,
                "is_excessive": c.is_excessive_longevity,
            }
            for c in cookie_results
        ]

        return {
            "observed_endpoints": endpoint_summary,
            "personal_data_seed_leaks": seed_summary,
            "high_entropy_tokens": entropy_summary,
            "set_cookie_longevity": cookie_summary,
        }

    def _parse_audit_report(self, raw_json_str: str, flow_count: int) -> FullAuditReport:
        """Parses LLM output into typed FullAuditReport schema."""
        try:
            data = json.loads(raw_json_str)

            endpoint_classifications = []
            for item in data.get("endpoint_classifications", []):
                cls_type_str = item.get("classification", "undocumented_third_party").lower()
                try:
                    cls_type = EndpointClassificationType(cls_type_str)
                except ValueError:
                    cls_type = EndpointClassificationType.UNDOCUMENTED_THIRD_PARTY

                endpoint_classifications.append(
                    EndpointClassificationResult(
                        domain=item.get("domain", "unknown"),
                        classification=cls_type,
                        reasoning=item.get("reasoning", ""),
                        citation_excerpt=item.get("citation_excerpt"),
                    )
                )

            discrepancies = []
            for disc in data.get("discrepancies", []):
                cat_str = disc.get("category", "undocumented_endpoint").lower()
                try:
                    cat = DiscrepancyCategory(cat_str)
                except ValueError:
                    cat = DiscrepancyCategory.UNDOCUMENTED_ENDPOINT

                sev_str = disc.get("severity", "MEDIUM").upper()
                try:
                    sev = DiscrepancySeverity(sev_str)
                except ValueError:
                    sev = DiscrepancySeverity.MEDIUM

                discrepancies.append(
                    ComplianceDiscrepancy(
                        discrepancy_id=disc.get("discrepancy_id", f"DISC-{len(discrepancies)+1:03d}"),
                        title=disc.get("title", "Discrepancy Found"),
                        category=cat,
                        severity=sev,
                        observed_evidence=disc.get("observed_evidence", ""),
                        declared_claim_quote=disc.get("declared_claim_quote"),
                        remediation_recommendation=disc.get("remediation_recommendation", ""),
                    )
                )

            return FullAuditReport(
                audit_title=data.get("audit_title", "Technical Privacy Discrepancy Audit"),
                summary=data.get("summary", ""),
                endpoint_classifications=endpoint_classifications,
                discrepancies=discrepancies,
                total_flows_analyzed=flow_count,
                total_discrepancies_found=len(discrepancies),
                requires_human_verification=True,
            )

        except (json.JSONDecodeError, KeyError, TypeError):
            return FullAuditReport(
                audit_title="Technical Privacy Audit (Parsing Fallback)",
                summary="Raw LLM output could not be fully parsed into structured JSON.",
                total_flows_analyzed=flow_count,
            )