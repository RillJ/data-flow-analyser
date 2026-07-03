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
from typing import Any, Dict, List, Optional, cast
from litellm import ModelResponse, completion

from data_flow_analyser.engines.storage_profiler import StorageProfiler
from data_flow_analyser.models.schemas import (
    ComplianceDiscrepancy,
    CookieLongevityResult,
    DiscrepancyCategory,
    DiscrepancySeverity,
    DocumentAnalysisResult,
    EndpointClassificationResult,
    EndpointClassificationType,
    FullAuditReport,
    FingerprintPersistenceFinding,
    FingerprintVector,
    FingerprintAnalysisSummary,
    SeedMatchEvidence,
    NetworkFlow,
    ObservedEndpoint,
    StorageClassificationResult,
    StorageClassificationType,
    StorageTechnologyType,
    TrackingToken,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are an expert Privacy Legal Auditor conducting a technical Data Protection Impact Assessment (DPIA).
Your task is to cross-reference technical evidence gathered from observed network traffic against a vendor's legal document disclosures (Privacy Policy, DPA, Cookie Policy).

You must produce an auditable report evaluating:
1. ENDPOINT CLASSIFICATION: Classify each observed domain into one of:
   - "internal": Primary domain or first-party infrastructure.
   - "documented_subprocessor": Subprocessor explicitly listed in the policy/DPA.
   - "undocumented_third_party": Third-party host not mentioned in vendor documents.
   - "tracker_unconsented": Known advertising/tracking domain operating without explicit consent documentation.

2. STORAGE MECHANISM CLASSIFICATION: Classify each observed cookie or storage mechanism into one of:
   - "documented": Explicitly disclosed in policy/cookie documentation with matching duration/purpose.
   - "undocumented": Cookie/storage item observed in traffic but absent from declarations.
   - "excessive_lifespan": Cookie duration exceeds stated lifespan or 90-day recommended window.
   - "purpose_mismatch": Observed usage conflicts with declared storage purpose.

3. COMPLIANCE DISCREPANCIES: Compare observed network facts against policy claims. Look for:
   - Undocumented endpoints receiving data.
   - Personal data transmission (plaintext or hashed) sent to third parties or without consent.
   - Data collection exceeding stated categories (like: ACCOUNT_DATA sent to DIAGNOSTIC_DATA endpoints).
   - Cookies or LocalStorage keys observed but unannounced, or with actual lifespans exceeding declared durations.
   - International data transfers to third countries (like: US) without disclosed transfer safeguards.
   - Candidate browser/device fingerprint vectors, especially those observed before consent or after withdrawal.

Fingerprint vectors are technical candidates based on attribute co-occurrence, not proof of unique identification. Only treat a consent-phase finding as evidence when the supplied phase is explicit; do not infer missing consent states.

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
  "storage_classifications": [
    {
      "name": "_ga",
      "storage_type": "cookie|local_storage|session_storage|pixel_beacon|indexed_db|other",
      "observed_lifespan_days": 730.0,
      "classification": "documented|undocumented|excessive_lifespan|purpose_mismatch",
      "reasoning": "Detailed justification comparing wire traffic with cookie policy disclosures"
    }
  ],
  "discrepancies": [
    {
      "discrepancy_id": "DISC-001",
      "title": "Short descriptive title",
      "category": "undocumented_endpoint|unannounced_data_collection|purpose_mismatch|storage_lifespan_excessive|unannounced_storage|unsafe_third_country_transfer|plaintext_personal_data_leak|fingerprinting_candidate|fingerprinting_after_withdrawal",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "observed_evidence": "Factual description of wire observations",
      "declared_claim_quote": "Verbatim quote from policy or 'Not declared'"
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
        self.storage_profiler = StorageProfiler()

    def cross_reference_audit(
        self,
        doc_analysis: DocumentAnalysisResult,
        flows: List[NetworkFlow],
        endpoints: List[ObservedEndpoint],
        seed_matches: Optional[List[Dict[str, Any]]] = None,
        entropy_tokens: Optional[List[TrackingToken]] = None,
        cookie_results: Optional[List[CookieLongevityResult]] = None,
        fingerprint_vectors: Optional[List[FingerprintVector]] = None,
        fingerprint_persistence_findings: Optional[List[FingerprintPersistenceFinding]] = None,
        fingerprint_summary: Optional[FingerprintAnalysisSummary] = None,
    ) -> FullAuditReport:
        """
        Executes an LLM-based technical cross-reference between observed evidence and policy claims.
        """
        seed_matches = seed_matches or []
        entropy_tokens = entropy_tokens or []
        cookie_results = cookie_results or []
        fingerprint_vectors = fingerprint_vectors or []
        fingerprint_persistence_findings = fingerprint_persistence_findings or []
        fingerprint_summary = fingerprint_summary or FingerprintAnalysisSummary()
        logger.debug("Cross-reference started: flows=%d endpoints=%d seed_matches=%d tokens=%d cookie_records=%d fingerprint_vectors=%d phase_findings=%d", len(flows), len(endpoints), len(seed_matches), len(entropy_tokens), len(cookie_results), len(fingerprint_vectors), len(fingerprint_persistence_findings))

        # Run rule-based storage profiling first to reconcile observed storage against policy
        rule_based_storage_eval = self.storage_profiler.reconcile_storage(
            flows=flows,
            cookie_results=cookie_results,
            declared_storage=doc_analysis.declared_storage_items,
        )

        evidence_summary = self._prepare_evidence_summary(
            flows,
            endpoints,
            seed_matches,
            entropy_tokens,
            cookie_results,
            rule_based_storage_eval,
            fingerprint_vectors,
            fingerprint_persistence_findings,
        )
        logger.debug("Evidence summary prepared: endpoints=%d seed_leaks=%d entropy_tokens=%d storage_items=%d fingerprint_vectors=%d phase_findings=%d", len(evidence_summary["observed_endpoints"]), len(evidence_summary["personal_data_seed_leaks"]), len(evidence_summary["high_entropy_tokens"]), len(evidence_summary["observed_storage_evaluations"]), len(evidence_summary["fingerprint_vectors"]), len(evidence_summary["fingerprint_consent_phase_findings"]))

        document_context = doc_analysis.model_dump(mode="json")

        prompt_content = f"""
        === DECLARED POLICY DOCUMENTATION ===
        Title: {doc_analysis.document_title}
        Document Length: {doc_analysis.raw_document_length} characters

        Declared Data Categories:
        {json.dumps(document_context.get('declared_categories', []), indent=2)}

        Declared Subprocessors:
        {json.dumps(document_context.get('declared_subprocessors', []), indent=2)}

        Declared Storage Items (Cookies / Web Storage):
        {json.dumps(document_context.get('declared_storage_items', []), indent=2)}

        International Transfer Safeguards Declared: {doc_analysis.international_transfer_mechanisms}
        Retention Summary Declared: {doc_analysis.stated_retention_summary or 'None specified'}

        === OBSERVED NETWORK EVIDENCE ===
        Total Flows Captured: {len(flows)}
        Observed Evidence Summary:
        {json.dumps(evidence_summary, indent=2)}
        """

        try:
            logger.debug(
                "LLM request (cross_referencer) BEGIN: model=%s messages=2 response_format=json_object",
                self.model,
            )
            logger.debug("LLM request (cross_referencer) system prompt:\n%s", SYSTEM_PROMPT)
            logger.debug("LLM request (cross_referencer) user prompt:\n%s", prompt_content)
            logger.debug("LLM request (cross_referencer) END")
            response = cast(
                ModelResponse,
                completion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt_content},
                    ],
                    response_format={"type": "json_object"},
                    api_key=self.api_key,
                    api_base=self.api_base,
                ),
            )
            logger.debug("Cross-reference LLM response received: choices=%d", len(response.choices or []))

            if not response.choices or not response.choices[0].message:
                return FullAuditReport(
                    audit_title="Technical Audit (Failed)",
                    summary="Failed to get response choices from LLM.",
                    total_flows_analyzed=len(flows),
                    fingerprint_vectors=fingerprint_vectors,
                    fingerprint_persistence_findings=fingerprint_persistence_findings,
                )

            raw_json_str: Optional[str] = response.choices[0].message.content
            if not raw_json_str:
                return FullAuditReport(
                    audit_title="Technical Audit (Empty Response)",
                    summary="LLM returned empty output.",
                    total_flows_analyzed=len(flows),
                    fingerprint_vectors=fingerprint_vectors,
                    fingerprint_persistence_findings=fingerprint_persistence_findings,
                )

            report = self._parse_audit_report(raw_json_str, len(flows), rule_based_storage_eval)
            report.fingerprint_vectors = fingerprint_vectors
            report.fingerprint_persistence_findings = fingerprint_persistence_findings
            report.fingerprint_summary = fingerprint_summary
            report.observed_endpoints = endpoints
            report.tracking_tokens = entropy_tokens
            report.cookie_longevity_results = cookie_results
            report.seed_matches = [SeedMatchEvidence(**match) for match in seed_matches]
            logger.debug("Cross-reference report parsed: endpoint_results=%d storage_results=%d discrepancies=%d", len(report.endpoint_classifications), len(report.storage_classifications), len(report.discrepancies))
            return report

        except Exception as e:
            logger.exception("Cross-reference execution failed: model=%s error=%s", self.model, e)
            return FullAuditReport(
                audit_title="Technical Privacy Audit",
                summary=f"Analysis encountered an execution error: {str(e)}",
                storage_classifications=rule_based_storage_eval,
                total_flows_analyzed=len(flows),
                fingerprint_vectors=fingerprint_vectors,
                fingerprint_persistence_findings=fingerprint_persistence_findings,
            )

    def _prepare_evidence_summary(
        self,
        flows: List[NetworkFlow],
        endpoints: List[ObservedEndpoint],
        seed_matches: List[Dict[str, Any]],
        entropy_tokens: List[TrackingToken],
        cookie_results: List[CookieLongevityResult],
        storage_evaluations: List[StorageClassificationResult],
        fingerprint_vectors: List[FingerprintVector],
        fingerprint_persistence_findings: List[FingerprintPersistenceFinding],
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
                seed_summary.append(
                    {
                        "matched_value": match.get("matched_value")
                        or match.get("raw_value")
                        or match.get("value"),
                        "type": match.get("field_type")
                        or match.get("key")
                        or match.get("type", "unknown"),
                        "location": match.get("location") or match.get("found_in", "unknown"),
                        "is_hashed": match.get("is_hashed", False),
                    }
                )
            else:
                seed_summary.append(
                    {
                        "matched_value": getattr(
                            match, "matched_value", getattr(match, "raw_value", str(match))
                        ),
                        "type": getattr(match, "field_type", getattr(match, "key", "unknown")),
                        "location": getattr(match, "location", "unknown"),
                        "is_hashed": getattr(match, "is_hashed", False),
                    }
                )

        entropy_summary = [
            {
                "token": tok.token[:16] + "..." if len(tok.token) > 16 else tok.token,
                "location": tok.location,
                "entropy": tok.entropy,
                "occurrences": tok.occurrences,
            }
            for tok in entropy_tokens
        ]

        storage_summary = [
            {
                "name": item.name,
                "type": item.storage_type.value,
                "observed_lifespan_days": item.observed_lifespan_days,
                "classification": item.classification.value,
                "reasoning": item.reasoning,
            }
            for item in storage_evaluations
        ]

        fingerprint_summary = [
            {
                "flow_id": vector.flow_id,
                "endpoint": vector.endpoint,
                "consent_phase": vector.consent_phase.value,
                "matched_categories": vector.matched_categories,
                "attributes": [attribute.model_dump() for attribute in vector.attributes],
                "payload_locations": vector.payload_locations,
                "attribute_count": vector.attribute_count,
                "heuristic_score": vector.heuristic_score,
                "is_candidate": vector.is_candidate,
                "scoring_method": vector.scoring_method,
            }
            for vector in fingerprint_vectors
            if vector.is_candidate
        ]
        persistence_summary = [finding.model_dump(mode="json") for finding in fingerprint_persistence_findings]

        return {
            "observed_endpoints": endpoint_summary,
            "personal_data_seed_leaks": seed_summary,
            "high_entropy_tokens": entropy_summary,
            "observed_storage_evaluations": storage_summary,
            "fingerprint_vectors": fingerprint_summary,
            "fingerprint_consent_phase_findings": persistence_summary,
        }

    def _parse_audit_report(
        self,
        raw_json_str: str,
        flow_count: int,
        fallback_storage: List[StorageClassificationResult],
    ) -> FullAuditReport:
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

            storage_classifications = []
            for item in data.get("storage_classifications", []):
                st_type_str = item.get("storage_type", "cookie").lower()
                try:
                    st_type = StorageTechnologyType(st_type_str)
                except ValueError:
                    st_type = StorageTechnologyType.COOKIE

                cls_type_str = item.get("classification", "undocumented").lower()
                try:
                    cls_type = StorageClassificationType(cls_type_str)
                except ValueError:
                    cls_type = StorageClassificationType.UNDOCUMENTED

                storage_classifications.append(
                    StorageClassificationResult(
                        name=item.get("name", "unknown"),
                        storage_type=st_type,
                        observed_lifespan_days=item.get("observed_lifespan_days"),
                        classification=cls_type,
                        reasoning=item.get("reasoning", ""),
                    )
                )

            # Fallback to rule-based storage classifications if LLM returned none
            if not storage_classifications:
                storage_classifications = fallback_storage

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
                        discrepancy_id=disc.get(
                            "discrepancy_id", f"DISC-{len(discrepancies)+1:03d}"
                        ),
                        title=disc.get("title", "Discrepancy Found"),
                        category=cat,
                        severity=sev,
                        observed_evidence=disc.get("observed_evidence", ""),
                        declared_claim_quote=disc.get("declared_claim_quote"),
                    )
                )

            return FullAuditReport(
                audit_title=data.get("audit_title", "Technical Privacy Discrepancy Audit"),
                summary=data.get("summary", ""),
                endpoint_classifications=endpoint_classifications,
                storage_classifications=storage_classifications,
                discrepancies=discrepancies,
                total_flows_analyzed=flow_count,
                total_discrepancies_found=len(discrepancies),
                requires_human_verification=True,
            )

        except (json.JSONDecodeError, KeyError, TypeError):
            return FullAuditReport(
                audit_title="Technical Privacy Audit (Parsing Fallback)",
                summary="Raw LLM output could not be fully parsed into structured JSON.",
                storage_classifications=fallback_storage,
                total_flows_analyzed=flow_count,
            )
