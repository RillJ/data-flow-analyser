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

        md.append("## Browser and Device Fingerprinting Candidates\n")
        if not report.fingerprint_vectors:
            md.append("_No fingerprinting candidates detected by the attribute co-occurrence heuristic._\n")
        else:
            md.append("| Endpoint | Consent Phase | Categories | Score | Evidence Locations |")
            md.append("| --- | --- | --- | --- | --- |")
            for vector in report.fingerprint_vectors:
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
                md.append(f"- **Remediation Recommendation:** {disc.remediation_recommendation}\n")

        return "\n".join(md)

    @classmethod
    def to_markdown_file(cls, report: FullAuditReport, output_path: Union[str, Path]) -> None:
        """Writes the Markdown representation of the report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.to_markdown(report), encoding="utf-8")
