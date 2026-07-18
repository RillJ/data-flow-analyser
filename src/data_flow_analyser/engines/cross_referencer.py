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
    HarmLikelihood,
    ImpactSeverity,
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
from data_flow_analyser.engines.risk_evaluator import assess_risk

logger = logging.getLogger(__name__)


GDPR_RECITAL_75_RISK_DEFINITION = """
GDPR Recital 75 — Risks to the Rights and Freedoms of Natural Persons

The risk to the rights and freedoms of natural persons, of varying likelihood and
severity, may result from personal data processing which could lead to physical,
material or non-material damage, in particular: discrimination; identity theft or
fraud; financial loss; damage to reputation; loss of confidentiality; unauthorised
reversal of pseudonymisation; any other significant economic or social disadvantage;
depriving data subjects of their rights and freedoms or preventing them from
exercising control over their personal data; processing special-category data or
criminal-conviction data; evaluating personal aspects such as performance, economic
situation, health, preferences, interests, reliability, behaviour, location or
movements to create or use profiles; processing personal data of vulnerable people,
particularly children; or processing a large amount of personal data affecting a
large number of data subjects.
"""

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

RISK ASSESSMENT — GDPR RECITAL 75
Before rating each discrepancy, identify which Recital 75 harm categories are
supported by the observed technical evidence. Consider physical, material, and
non-material damage and risks to the rights and freedoms of natural persons. Do
not treat a policy mismatch alone as proof of a particular harm; explain the
evidential connection and use an empty list when no category is supported.

Use `potential_harms` for supported categories such as discrimination, identity
theft or fraud, financial loss, reputational damage, loss of confidentiality,
unauthorised reversal of pseudonymisation, significant economic or social
disadvantage, loss of control or inability to exercise rights, special-category
data, profiling, vulnerable data subjects (including children), and large-scale
processing. Explain the connection in `assessment_basis`. Then provide the
likelihood and severity inputs.

The following is the governing definition supplied for this assessment:
""" + GDPR_RECITAL_75_RISK_DEFINITION + """

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
      "likelihood": "remote|reasonable_possibility|more_likely_than_not",
      "severity_impact": "minimal_impact|some_impact|serious_harm",
      "potential_harms": ["loss_of_control"],
      "assessment_basis": "Factual basis for the two ratings",
      "observed_evidence": "Factual description of wire observations",
      "declared_claim_quote": "Verbatim quote from policy or 'Not declared'",
      "evidence_references": [
        "flow-id-123",
        "observed_endpoints.example.com",
        "observed_storage_evaluations.example_cookie",
        "fingerprint_vectors.flow-id-123"
      ]
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
        temperature: float = 1.0,
    ):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.temperature = temperature
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
        observed_domains: Optional[List[str]] = None,
        observed_flow_ids: Optional[List[str]] = None,
        observed_endpoint_identifiers: Optional[List[str]] = None,
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
                    temperature=self.temperature,
                    api_key=self.api_key,
                    api_base=self.api_base,
                ),
            )
            logger.debug("Cross-reference LLM response received: choices=%d", len(response.choices or []))

            if not response.choices or not response.choices[0].message:
                return FullAuditReport(
                    audit_title="Technical Audit (Failed)",
                    summary="Failed to get response choices from LLM.",
                    total_flows_analysed=len(flows),
                    fingerprint_vectors=fingerprint_vectors,
                    fingerprint_persistence_findings=fingerprint_persistence_findings,
                    analysis_status="failed",
                    warnings=["The LLM returned no response choices."],
                )

            raw_json_str: Optional[str] = response.choices[0].message.content
            if not raw_json_str:
                return FullAuditReport(
                    audit_title="Technical Audit (Empty Response)",
                    summary="LLM returned empty output.",
                    total_flows_analysed=len(flows),
                    fingerprint_vectors=fingerprint_vectors,
                    fingerprint_persistence_findings=fingerprint_persistence_findings,
                    analysis_status="failed",
                    warnings=["The LLM returned an empty response."],
                )

            report = self._parse_audit_report(
                raw_json_str,
                len(flows),
                rule_based_storage_eval,
                observed_domains=observed_domains,
                observed_flow_ids=observed_flow_ids,
                observed_endpoint_identifiers=observed_endpoint_identifiers,
                observed_storage_names=[item.name for item in rule_based_storage_eval],
                fingerprint_flow_ids=[vector.flow_id for vector in fingerprint_vectors],
            )
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
                total_flows_analysed=len(flows),
                fingerprint_vectors=fingerprint_vectors,
                fingerprint_persistence_findings=fingerprint_persistence_findings,
                analysis_status="failed",
                warnings=[f"Cross-reference LLM execution failed: {type(e).__name__}"],
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
        observed_domains: Optional[List[str]] = None,
        observed_flow_ids: Optional[List[str]] = None,
        observed_endpoint_identifiers: Optional[List[str]] = None,
        observed_storage_names: Optional[List[str]] = None,
        fingerprint_flow_ids: Optional[List[str]] = None,
    ) -> FullAuditReport:
        """Parses LLM output into typed FullAuditReport schema."""
        warnings: List[str] = []
        try:
            data = json.loads(raw_json_str)
            if not isinstance(data, dict):
                raise TypeError("LLM response must be a JSON object")

            endpoint_classifications = []
            for item in data.get("endpoint_classifications", []):
                if not isinstance(item, dict):
                    warnings.append("Skipped a non-object endpoint classification.")
                    continue
                cls_type_str = str(item.get("classification", "unknown")).lower()
                try:
                    cls_type = EndpointClassificationType(cls_type_str)
                except ValueError:
                    cls_type = EndpointClassificationType.UNKNOWN
                    warnings.append(
                        f"Unknown endpoint classification '{cls_type_str}' for domain '{item.get('domain', 'unknown')}'."
                    )

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
                if not isinstance(item, dict):
                    warnings.append("Skipped a non-object storage classification.")
                    continue
                st_type_str = str(item.get("storage_type", "cookie")).lower()
                try:
                    st_type = StorageTechnologyType(st_type_str)
                except ValueError:
                    st_type = StorageTechnologyType.OTHER
                    warnings.append(
                        f"Unknown storage technology '{st_type_str}' for item '{item.get('name', 'unknown')}'."
                    )

                cls_type_str = str(item.get("classification", "unknown")).lower()
                try:
                    cls_type = StorageClassificationType(cls_type_str)
                except ValueError:
                    cls_type = StorageClassificationType.UNKNOWN
                    warnings.append(
                        f"Unknown storage classification '{cls_type_str}' for item '{item.get('name', 'unknown')}'."
                    )

                storage_classifications.append(
                    StorageClassificationResult(
                        name=item.get("name", "unknown"),
                        storage_type=st_type,
                        observed_lifespan_days=item.get("observed_lifespan_days"),
                        classification=cls_type,
                        reasoning=item.get("reasoning", ""),
                    )
                )

            # Deterministic storage evidence is authoritative. Preserve the
            # complete observed set even if the LLM omits an item, and do not
            # let a conflicting model classification overwrite the rule result.
            if fallback_storage:
                fallback_by_name = {item.name.lower(): item for item in fallback_storage}
                reconciled: List[StorageClassificationResult] = []
                seen_names: set[str] = set()
                for item in storage_classifications:
                    deterministic = fallback_by_name.get(item.name.lower())
                    if deterministic:
                        seen_names.add(item.name.lower())
                        if item.classification != deterministic.classification:
                            warnings.append(
                                f"Deterministic storage classification replaced LLM classification for '{item.name}'."
                            )
                        reconciled.append(deterministic)
                    else:
                        reconciled.append(item)
                for item in fallback_storage:
                    if item.name.lower() not in seen_names and not any(
                        existing.name.lower() == item.name.lower() for existing in reconciled
                    ):
                        reconciled.append(item)
                storage_classifications = reconciled

            discrepancies = []
            for disc in data.get("discrepancies", []):
                if not isinstance(disc, dict):
                    warnings.append("Skipped a non-object discrepancy.")
                    continue
                cat_str = str(disc.get("category", "undocumented_endpoint")).lower()
                try:
                    cat = DiscrepancyCategory(cat_str)
                except ValueError:
                    cat = DiscrepancyCategory.UNDOCUMENTED_ENDPOINT
                    warnings.append(f"Unknown discrepancy category '{cat_str}'.")

                try:
                    likelihood = HarmLikelihood(disc["likelihood"])
                    severity = ImpactSeverity(disc["severity_impact"])
                except (KeyError, ValueError, TypeError):
                    warnings.append(
                        f"Skipped discrepancy '{disc.get('discrepancy_id', 'unknown')}' because likelihood or severity was invalid."
                    )
                    continue
                risk = assess_risk(
                    likelihood,
                    severity,
                    disc.get("potential_harms", []),
                    disc.get("assessment_basis", ""),
                )

                discrepancies.append(
                    ComplianceDiscrepancy(
                        discrepancy_id=disc.get(
                            "discrepancy_id", f"DISC-{len(discrepancies)+1:03d}"
                        ),
                        title=disc.get("title", "Discrepancy Found"),
                        category=cat,
                        risk_assessment=risk,
                        observed_evidence=disc.get("observed_evidence", ""),
                        declared_claim_quote=disc.get("declared_claim_quote"),
                        evidence_references=self._validated_evidence_references(
                            disc.get("evidence_references", []),
                            observed_flow_ids,
                            observed_domains,
                            observed_endpoint_identifiers,
                            observed_storage_names,
                            fingerprint_flow_ids,
                            warnings,
                        ),
                    )
                )

            if observed_domains:
                classified_domains = {item.domain.lower() for item in endpoint_classifications}
                for domain in observed_domains:
                    if domain.lower() not in classified_domains:
                        endpoint_classifications.append(
                            EndpointClassificationResult(
                                domain=domain,
                                classification=EndpointClassificationType.UNKNOWN,
                                reasoning="The LLM did not return a classification for this observed endpoint.",
                            )
                        )
                        warnings.append(f"Missing endpoint classification for observed domain '{domain}'.")

            report = FullAuditReport(
                audit_title=data.get("audit_title", "Technical Privacy Discrepancy Audit"),
                summary=data.get("summary", ""),
                endpoint_classifications=endpoint_classifications,
                storage_classifications=storage_classifications,
                discrepancies=discrepancies,
                total_flows_analysed=flow_count,
                total_discrepancies_found=len(discrepancies),
                requires_human_verification=True,
                analysis_status="partial" if warnings else "complete",
                warnings=warnings,
            )
            return report

        except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
            return FullAuditReport(
                audit_title="Technical Privacy Audit (Parsing Fallback)",
                summary="Raw LLM output could not be fully parsed into structured JSON.",
                storage_classifications=fallback_storage,
                total_flows_analysed=flow_count,
                analysis_status="failed",
                warnings=["Raw LLM output could not be parsed into the report schema."],
            )

    @staticmethod
    def _validated_evidence_references(
        references: Any,
        observed_flow_ids: Optional[List[str]],
        observed_domains: Optional[List[str]],
        observed_endpoint_identifiers: Optional[List[str]],
        observed_storage_names: Optional[List[str]],
        fingerprint_flow_ids: Optional[List[str]],
        warnings: List[str],
    ) -> List[str]:
        if references is None:
            return []
        if not isinstance(references, list):
            warnings.append("Discrepancy evidence_references was not a list.")
            return []
        valid = [str(reference) for reference in references if reference]
        if observed_flow_ids is None:
            return valid
        flow_ids = set(observed_flow_ids)
        domains = set(observed_domains or [])
        endpoint_identifiers = set(observed_endpoint_identifiers or domains)
        storage_names = set(observed_storage_names or [])
        fingerprint_ids = set(fingerprint_flow_ids or [])

        def is_valid(reference: str) -> bool:
            if reference in flow_ids:
                return True
            if reference in endpoint_identifiers:
                return True
            if reference.startswith("observed_endpoints."):
                return reference.removeprefix("observed_endpoints.") in domains
            if reference.startswith("observed_storage_evaluations."):
                return reference.removeprefix("observed_storage_evaluations.") in storage_names
            if reference.startswith("fingerprint_vectors."):
                return reference.removeprefix("fingerprint_vectors.") in fingerprint_ids
            return False

        unknown = [reference for reference in valid if not is_valid(reference)]
        if unknown:
            warnings.append(f"Removed unknown evidence references: {', '.join(unknown)}.")
        return [reference for reference in valid if is_valid(reference)]
