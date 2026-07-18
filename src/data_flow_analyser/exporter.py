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

from pathlib import Path
from typing import Union
from data_flow_analyser.models.schemas import FullAuditReport


class ReportExporter:
    """Exports FullAuditReport objects to JSON, Markdown, and stdout."""

    @staticmethod
    def to_json_file(report: FullAuditReport, output_path: Union[str, Path]) -> None:
        """Serializes the report to a formatted JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    @staticmethod
    def to_markdown(report: FullAuditReport) -> str:
        """Renders the FullAuditReport as a structured Markdown document."""
        md = []
        md.append(f"# {report.audit_title}\n")
        md.append(f"**Analysed Flows:** {report.total_flows_analysed}  ")
        md.append(f"**Discrepancies Found:** {report.total_discrepancies_found}  ")
        md.append(f"**Analysis Status:** {report.analysis_status}  ")
        md.append(f"**Human Verification Required:** {report.requires_human_verification}\n")

        md.append("## Reproducibility Metadata\n")
        provenance = report.provenance
        md.append(f"- **Tool version:** `{provenance.tool_version}`")
        md.append(f"- **LLM model:** `{provenance.model or 'not recorded'}`")
        md.append(f"- **Temperature:** `{provenance.temperature if provenance.temperature is not None else 'not recorded'}`")
        md.append(f"- **External metadata:** `{provenance.external_metadata_mode}`")
        if report.warnings:
            md.append("\n### Analysis Warnings\n")
            for warning in report.warnings:
                md.append(f"- {warning}")
        md.append("")

        md.append("## Executive Summary\n")
        md.append(f"{report.summary}\n")

        md.append("## Endpoint Classifications\n")
        md.append("_Interpretation: compares each observed host with the submitted policy documents. ‘Undocumented’ means no matching declaration was found in those documents; it is not proof that no declaration exists elsewhere._\n")
        if not report.endpoint_classifications:
            md.append("_No endpoint classifications recorded._\n")
        else:
            md.append("| Domain | Classification | Reasoning | Policy Quote |")
            md.append("| --- | --- | --- | --- |")
            for ep in report.endpoint_classifications:
                quote = (ep.citation_excerpt or "N/A").replace("\n", " ")
                md.append(
                    f"| `{ep.domain}` | **{ep.classification.value}** | {ep.reasoning} | _{quote}_ |"
                )
            md.append("\n")

        md.append("## Observed Endpoint Evidence\n")
        md.append("_Interpretation: DNS, GeoIP, ASN, and DDG Tracker Radar enrich the destination identity. Missing values indicate unavailable enrichment or no supplied IP, not that the endpoint is safe._\n")
        if not report.observed_endpoints:
            md.append("_No endpoint profiling records available._\n")
        else:
            md.append("| Domain | IP | Parent Entity (Tracker Radar) | Category | Country | ASN / Organisation | Third-Country Transfer |")
            md.append("| --- | --- | --- | --- | --- | --- | --- |")
            for endpoint in report.observed_endpoints:
                md.append(
                    f"| `{endpoint.domain}` | `{endpoint.ip_address or 'Unknown'}` | "
                    f"{endpoint.parent_entity or 'Unknown'} | {endpoint.category} | "
                    f"{endpoint.country_code or 'Unknown'} | {endpoint.asn_org or 'Unknown'} | "
                    f"{endpoint.is_third_country_transfer} |"
                )
            md.append("\n")

        md.append("## Storage Mechanisms & Cookie Classifications\n")
        md.append("_Interpretation: compares observed cookies and storage mechanisms with policy declarations. A long lifetime is a retention indicator; it is not alone proof that a cookie is a tracker or unlawful._\n")
        if not report.storage_classifications:
            md.append("_No storage mechanisms or cookies recorded/analysed._\n")
        else:
            md.append("| Name | Type | Observed Duration (Days) | Classification | Reasoning |")
            md.append("| --- | --- | --- | --- | --- |")
            for st in report.storage_classifications:
                days_str = f"{st.observed_lifespan_days:.1f}" if st.observed_lifespan_days is not None else "Session/Unknown"
                md.append(
                    f"| `{st.name}` | {st.storage_type.value} | {days_str} | **{st.classification.value}** | {st.reasoning} |"
                )
            md.append("\n")

        md.append("## Entropy and Cookie-Lifetime Evidence\n")
        md.append("_Interpretation: high-entropy values are candidate identifiers. Occurrences and locations show possible reuse; cookie lifetime indicates persistence and requires contextual review._\n")
        total_entropy_occurrences = sum(token.occurrences for token in report.tracking_tokens)
        md.append(f"**Unique high-entropy findings:** {len(report.tracking_tokens)}  ")
        md.append(f"**Total occurrences:** {total_entropy_occurrences}  ")
        md.append(f"**Cookie-lifetime records:** {len(report.cookie_longevity_results)}\n")
        if report.tracking_tokens:
            md.append("| Token Preview | Entropy | Occurrences | Location |")
            md.append("| --- | --- | --- | --- |")
            for token in report.tracking_tokens:
                preview = token.token[:24] + "..." if len(token.token) > 24 else token.token
                md.append(f"| `{preview}` | {token.entropy:.4f} | {token.occurrences} | `{token.location}` |")
            md.append("\n")
        if report.cookie_longevity_results:
            md.append("| Cookie | Lifespan (Days) | Max-Age (Seconds) | Excessive (>90 Days) |")
            md.append("| --- | --- | --- | --- |")
            for cookie in report.cookie_longevity_results:
                days = f"{cookie.lifespan_days:.2f}" if cookie.lifespan_days is not None else "Unknown"
                md.append(
                    f"| `{cookie.cookie_name}` | {days} | {cookie.max_age_seconds or 'Unknown'} | "
                    f"{cookie.is_excessive_longevity} |"
                )
            md.append("\n")

        md.append("## Seed-Match Evidence\n")
        md.append("_Interpretation: a controlled test value, or a recognised encoding/hash of it, was found in traffic. Verify whether the destination and transmission context were authorised for that value._\n")
        if not report.seed_matches:
            md.append("_No controlled seed matches detected._\n")
        else:
            md.append("| Matched Value | Type | Location | Host |")
            md.append("| --- | --- | --- | --- |")
            for match in report.seed_matches:
                md.append(
                    f"| `{match.matched_value}` | {match.field_type} | `{match.location}` | "
                    f"{match.host or 'Unknown'} |"
                )
            md.append("\n")

        md.append("## Browser and Device Fingerprinting Candidates\n")
        md.append("_Interpretation: candidates are heuristic signals from bundled browser/device attributes, not proof of unique fingerprinting. Review the attributes, endpoint, phase, and evidence locations._\n")
        summary = report.fingerprint_summary
        md.append(
            f"**Vectors analysed:** {summary.total_vectors}  "
            f"**Candidates:** {summary.candidate_vectors}  "
            f"**Persistence findings:** {summary.persistence_findings}  "
            f"**Maximum score:** {summary.maximum_heuristic_score:.2f}\n"
        )
        md.append(f"**Candidate rule:** {summary.candidate_rule}  ")
        md.append(f"**Scoring method:** {summary.scoring_method}\n")
        if summary.categories_observed:
            category_stats = ", ".join(
                f"{category}={count}" for category, count in sorted(summary.categories_observed.items())
            )
            md.append(f"**Categories observed:** {category_stats}\n")
        candidate_vectors = [vector for vector in report.fingerprint_vectors if vector.is_candidate]
        if not candidate_vectors:
            md.append("_No fingerprinting candidates detected by the attribute co-occurrence heuristic._\n")
        else:
            md.append("| Endpoint | Consent Phase | Categories | Score | Evidence Locations |")
            md.append("| --- | --- | --- | --- | --- |")
            for vector in candidate_vectors:
                md.append(
                    f"| `{vector.endpoint}` | {vector.consent_phase.value} | "
                    f"{', '.join(vector.matched_categories)} | {vector.heuristic_score:.2f} | "
                    f"{', '.join(vector.payload_locations)} |"
                )
            md.append("\n")

        md.append("## Fingerprinting Consent-Phase Findings\n")
        md.append("_Interpretation: persistence findings are strongest when the same candidate continues after an explicitly recorded withdrawal. An `unknown` phase means timestamps were unavailable or inconclusive; it does not mean consent was denied._\n")
        if not report.fingerprint_persistence_findings:
            md.append("_No candidate vectors were observed in pre-consent or withdrawn phases._\n")
        else:
            for finding in report.fingerprint_persistence_findings:
                md.append(f"- **`{finding.endpoint}`** — {finding.reasoning}")
                md.append(f"  - Phases: {', '.join(phase.value for phase in finding.observed_phases)}")
                md.append(f"  - Flows: {', '.join(finding.flow_ids)}")
            md.append("")

        md.append("## Detected Compliance Discrepancies\n")
        md.append("_Interpretation: review observed evidence first, then the policy comparison, GDPR Recital 75 harm categories, and the indicative likelihood/severity assessment. The risk level prioritises human review and is not a definitive legal conclusion._\n")
        if not report.discrepancies:
            md.append("_No discrepancies detected between observed traffic and policy claims._\n")
        else:
            risk_cells = {(likelihood, severity): [] for likelihood in range(1, 4) for severity in range(1, 4)}
            for disc in report.discrepancies:
                risk = disc.risk_assessment
                risk_cells[(risk.likelihood.score, risk.severity_impact.score)].append(
                    disc.discrepancy_id
                )

            md.append("### Indicative Risk Matrix\n")
            md.append("Risk IDs are placed using their calculated likelihood and severity inputs.\n")
            md.append("| Likelihood \\ Severity | 1 — Minimal impact | 2 — Some impact | 3 — Serious harm |")
            md.append("| --- | --- | --- | --- |")
            for likelihood, label in (
                (1, "1 — Remote"),
                (2, "2 — Reasonable possibility"),
                (3, "3 — More likely than not"),
            ):
                cells = [", ".join(risk_cells[(likelihood, severity)]) or "—" for severity in range(1, 4)]
                md.append(f"| {label} | {cells[0]} | {cells[1]} | {cells[2]} |")
            md.append("\n")

            for disc in report.discrepancies:
                risk = disc.risk_assessment
                md.append(f"### [{risk.indicative_level.value.upper()}] {disc.discrepancy_id}: {disc.title}")
                md.append(f"- **Category:** `{disc.category.value}`")
                md.append(f"- **Indicative risk:** {risk.indicative_level.value} (likelihood {risk.likelihood.score} × severity {risk.severity_impact.score} = {risk.risk_score})")
                md.append(f"- **Potential harms:** {', '.join(risk.potential_harms) or 'Not specified'}")
                md.append(f"- **Assessment basis:** {risk.assessment_basis or 'Not specified'}")
                md.append(f"- **Observed Evidence:** {disc.observed_evidence}")
                md.append(
                    f"- **Declared Policy Claim:** {disc.declared_claim_quote or 'Not declared'}"
                )
                if disc.evidence_references:
                    md.append(
                        f"- **Evidence Flow IDs:** {', '.join(f'`{flow_id}`' for flow_id in disc.evidence_references)}"
                    )
                md.append("")

        return "\n".join(md)

    @classmethod
    def to_markdown_file(cls, report: FullAuditReport, output_path: Union[str, Path]) -> None:
        """Writes the Markdown representation of the report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.to_markdown(report), encoding="utf-8")
