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
        md.append(f"**Analyzed Flows:** {report.total_flows_analyzed}  ")
        md.append(f"**Discrepancies Found:** {report.total_discrepancies_found}  ")
        md.append(f"**Human Verification Required:** {report.requires_human_verification}\n")

        md.append("## Executive Summary\n")
        md.append(f"{report.summary}\n")

        md.append("## Endpoint Classifications\n")
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
        if not report.storage_classifications:
            md.append("_No storage mechanisms or cookies recorded/analyzed._\n")
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
        if not report.fingerprint_persistence_findings:
            md.append("_No candidate vectors were observed in pre-consent or withdrawn phases._\n")
        else:
            for finding in report.fingerprint_persistence_findings:
                md.append(f"- **`{finding.endpoint}`** — {finding.reasoning}")
                md.append(f"  - Phases: {', '.join(phase.value for phase in finding.observed_phases)}")
                md.append(f"  - Flows: {', '.join(finding.flow_ids)}")
            md.append("")

        md.append("## Detected Compliance Discrepancies\n")
        if not report.discrepancies:
            md.append("_No discrepancies detected between observed traffic and policy claims._\n")
        else:
            for disc in report.discrepancies:
                md.append(f"### [{disc.severity.value}] {disc.discrepancy_id}: {disc.title}")
                md.append(f"- **Category:** `{disc.category.value}`")
                md.append(f"- **Observed Evidence:** {disc.observed_evidence}")
                md.append(
                    f"- **Declared Policy Claim:** {disc.declared_claim_quote or 'Not declared'}"
                )
                md.append("")

        return "\n".join(md)

    @classmethod
    def to_markdown_file(cls, report: FullAuditReport, output_path: Union[str, Path]) -> None:
        """Writes the Markdown representation of the report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.to_markdown(report), encoding="utf-8")
