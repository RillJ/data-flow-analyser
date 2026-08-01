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
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Union
from data_flow_analyser.models.schemas import FullAuditReport


def _json_safe(value):
    """Make captured values safe for a UTF-8 JSON file."""
    if isinstance(value, str):
        return value.encode("utf-8", errors="backslashreplace").decode("utf-8")
    if isinstance(value, dict):
        return {_json_safe(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _json_default(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


class ReportExporter:
    """Exports FullAuditReport objects to JSON, Markdown, and stdout."""

    @staticmethod
    def to_json_file(report: FullAuditReport, output_path: Union[str, Path]) -> None:
        """Serializes the report to a formatted JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Pydantic's JSON serializer rejects lone surrogates before it can
        # escape them, so sanitize the Python-mode model data first.
        payload = _json_safe(report.model_dump(mode="python"))
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=True, default=_json_default),
            encoding="utf-8",
        )

    @staticmethod
    def to_markdown(report: FullAuditReport) -> str:
        """Renders the FullAuditReport as a structured Markdown document."""
        md = []
        md.append(f"# {report.audit_title}\n")
        md.append(f"**Analysed Flows:** {report.total_flows_analysed}  ")
        md.append(f"**Discrepancies Found:** {report.total_discrepancies_found}  ")
        md.append(f"**Analysis Status:** {report.analysis_status}  ")

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
        md.append("_Compares each observed host with the submitted policy documents. ‘Undocumented’ means no matching declaration was found in those documents; it is not proof that no declaration exists elsewhere._\n")
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
        md.append("_DNS, GeoIP, ASN, and DDG Tracker Radar enrich the destination identity. Missing values indicate unavailable enrichment or no supplied IP, not that the endpoint is safe._\n")
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
        md.append("_Compares observed cookies and storage mechanisms with policy declarations. A long lifetime is a retention indicator; it is not alone proof that a cookie is a tracker or unlawful._\n")
        if not report.storage_classifications:
            md.append("_No storage mechanisms or cookies recorded/analysed._\n")
        else:
            md.append("| Name | Observed Domain(s) | Cookie Domain Attribute(s) | Type | Observed Duration (Days) | Classification | Reasoning |")
            md.append("| --- | --- | --- | --- | --- | --- | --- |")
            for st in report.storage_classifications:
                days_str = f"{st.observed_lifespan_days:.1f}" if st.observed_lifespan_days is not None else "Session/Unknown"
                md.append(
                    f"| `{st.name}` | {', '.join(f'`{domain}`' for domain in st.domains) or 'Unknown'} | "
                    f"{', '.join(f'`{domain}`' for domain in st.cookie_domain_attributes) or 'Not specified'} | "
                    f"{st.storage_type.value} | {days_str} | **{st.classification.value}** | {st.reasoning} |"
                )
            md.append("\n")

        md.append("## Identifier Entropy Evidence\n")
        md.append("_Entropy is only a candidate-identifier signal, not proof of personal data. The table is grouped by endpoint and payload location; raw token evidence remains available in JSON._\n")
        total_entropy_occurrences = sum(token.occurrences for token in report.tracking_tokens)
        md.append(f"**Unique high-entropy findings:** {len(report.tracking_tokens)}  ")
        md.append(f"**Total occurrences:** {total_entropy_occurrences}  ")
        md.append("\n")
        if report.tracking_tokens:
            groups = {}
            for token in report.tracking_tokens:
                key = (token.endpoint or "Unknown", token.location)
                group = groups.setdefault(
                    key,
                    {"tokens": 0, "occurrences": 0, "reused": 0, "min": token.entropy, "max": token.entropy},
                )
                group["tokens"] += 1
                group["occurrences"] += token.occurrences
                group["reused"] += int(token.occurrences > 1)
                group["min"] = min(group["min"], token.entropy)
                group["max"] = max(group["max"], token.entropy)
            md.append("| Endpoint | Location | Distinct Tokens | Total Occurrences | Reused Tokens | Entropy Range |")
            md.append("| --- | --- | ---: | ---: | ---: | --- |")
            for (endpoint, location), group in groups.items():
                md.append(
                    f"| `{endpoint}` | `{location}` | {group['tokens']} | {group['occurrences']} | "
                    f"{group['reused']} | {group['min']:.4f}–{group['max']:.4f} |"
                )
            md.append("\n")
        md.append("## Personal Data Flow Mapping\n")
        md.append("_Grouped automated personal-data evidence mapped to endpoint, direction, payload location, and data label. `seed_match` is controlled-value evidence; `presidio` is a scored candidate and requires human verification. Counts show repeated observations; source flow IDs are retained in JSON for reproduction but omitted here._\n")
        if not report.personal_data_flows:
            md.append("_No personal-data flow evidence detected._\n")
        else:
            md.append("| Count | Method | Direction | Endpoint | Data label | Payload location | Sample value |")
            md.append("| ---: | --- | --- | --- | --- | --- | --- |")
            for evidence in report.personal_data_flows:
                md.append(
                    f"| {evidence.count} | {evidence.detection_method} | "
                    f"{evidence.direction} | `{evidence.endpoint}` | "
                    f"{evidence.data_label} | `{evidence.location}` | "
                    f"`{evidence.sample_value}` |"
                )
            md.append("\n")

        md.append("## Browser and Device Fingerprinting Candidates\n")
        md.append("_Candidates are heuristic signals from bundled browser/device attributes, not proof of unique fingerprinting. Review the attributes, endpoint, phase, and evidence locations._\n")
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
        md.append("_Persistence findings are strongest when the same candidate continues after an explicitly recorded withdrawal. An `unknown` phase means timestamps were unavailable or inconclusive; it does not mean consent was denied._\n")
        if not report.fingerprint_persistence_findings:
            md.append("_No candidate vectors were observed in pre-consent or withdrawn phases._\n")
        else:
            for finding in report.fingerprint_persistence_findings:
                md.append(f"- **`{finding.endpoint}`** — {finding.reasoning}")
                md.append(f"  - Phases: {', '.join(phase.value for phase in finding.observed_phases)}")
                md.append(f"  - Flows: {', '.join(finding.flow_ids)}")
            md.append("")

        md.append("## Detected Compliance Discrepancies\n")
        md.append("_Review observed evidence first, then the policy comparison, GDPR Recital 75 harm categories, and the indicative likelihood/severity assessment. The risk level prioritises human review and is not a definitive legal conclusion._\n")
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
