import json
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