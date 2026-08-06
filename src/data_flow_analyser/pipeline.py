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

import logging
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from data_flow_analyser.engines.cross_referencer import LLMCrossReferencer
from data_flow_analyser.engines.document_ingestor import PolicyDocumentIngestor
from data_flow_analyser.engines.endpoint_profiler import EndpointProfiler
from data_flow_analyser.engines.fingerprint_profiler import FingerprintProfiler
from data_flow_analyser.engines.entropy import (
    analyse_flow_identifiers,
)
from data_flow_analyser.engines.seed_hasher import (
    generate_seed_hash_map,
    scan_for_seed_matches,
)
from data_flow_analyser.engines.presidio_detector import PresidioPersonalDataDetector
from data_flow_analyser.models.schemas import (
    AnalysisProvenance,
    CookieLongevityResult,
    ConsentOutcome,
    FingerprintPersistenceFinding,
    FingerprintAnalysisSummary,
    FingerprintVector,
    FullAuditReport,
    NetworkFlow,
    ObservedEndpoint,
    SeedData,
    PersonalDataFlowEvidence,
    TrackingToken,
)
from data_flow_analyser import __version__
from data_flow_analyser.parsers.mitm_parser import parse_flow_file
from data_flow_analyser.parsers.decoder import recursive_decode
from data_flow_analyser.endpoint_inventory import host_is_excluded
from data_flow_analyser.engines.endpoint_profiler import normalise_domain, unique_hosts

logger = logging.getLogger("data_flow_analyser.pipeline")

# These are deliberately coarse-grained: they represent work the user can
# understand, rather than implementation details that would make the CLI
# progress display noisy or brittle.
PIPELINE_STAGES = (
    "Parsing network capture",
    "Profiling endpoints",
    "Matching personal data",
    "Detecting personal data",
    "Analysing identifiers",
    "Analysing fingerprint signals",
    "Reading disclosure documents",
    "Analysing disclosure documents",
    "Cross-referencing evidence",
    "Finalising report",
)


class AuditPipeline:
    """
    Unified orchestrator combining all engines and parsers.
    Runs flow parsing, endpoint profiling, personal data seed matching, entropy token extraction,
    cookie lifespan checks, document ingestion, and LLM privacy cross-referencing.
    """

    def __init__(
        self,
        llm_model: str = "gpt-5.4-mini",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        temperature: float = 0.0,
        presidio_language: str = "en",
        presidio_full_ner: bool = False,
    ):
        self.doc_ingestor = PolicyDocumentIngestor(
            model=llm_model, api_key=api_key, api_base=api_base,
            temperature=temperature,
        )
        self.cross_referencer = LLMCrossReferencer(
            model=llm_model, api_key=api_key, api_base=api_base,
            temperature=temperature,
        )
        self.endpoint_profiler = EndpointProfiler()
        self.fingerprint_profiler = FingerprintProfiler()
        self.presidio_detector = PresidioPersonalDataDetector(
            language=presidio_language,
            full_ner=presidio_full_ner,
        )
        self.llm_model = llm_model
        self.api_base = api_base
        self.temperature = temperature

    def run(
        self,
        flow_file_path: Optional[Union[str, Path]] = None,
        documents: Optional[Union[str, Path, Sequence[Union[str, Path]]]] = None,
        seed_data: Optional[Union[SeedData, Dict[str, str]]] = None,
        excluded_domains: Optional[Sequence[str]] = None,
        consent_decided_at: Optional[datetime] = None,
        consent_withdrawn_at: Optional[datetime] = None,
        consent_outcome: ConsentOutcome = ConsentOutcome.NECESSARY_ONLY,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> FullAuditReport:
        """
        Executes the full end-to-end privacy audit pipeline.

        Args:
            flow_file_path: Path to a mitmproxy flow dump or HAR capture file.
            documents: Single file path, text string, or sequence/list of file paths/texts.
            seed_data: User personal data key-value pairs or pre-computed SeedData.
            excluded_domains: Domains whose flows are removed before any analysis.
            consent_decided_at: Optional timestamp at which the user answered the consent banner.
            consent_withdrawn_at: Optional timestamp at which the user withdrew consent.
            consent_outcome: Whether only necessary processing was allowed or non-essential consent was granted.

        Returns:
            FullAuditReport containing endpoint classifications and discrepancy cards.
        """
        target_flow_path = flow_file_path
        if not target_flow_path:
            raise ValueError("Must provide a flow capture file path.")

        target_docs = documents
        if not target_docs:
            raise ValueError("Must provide at least one document or text input.")
        self._validate_consent_timeline(consent_decided_at, consent_withdrawn_at)
        analysis_started_at = datetime.now(timezone.utc)

        def report_progress(stage: str) -> None:
            if progress_callback:
                progress_callback(stage)

        path_str = str(target_flow_path)
        report_progress(PIPELINE_STAGES[0])
        logger.info(f"Loading and parsing network capture file: {path_str}")
        flows: List[NetworkFlow] = parse_flow_file(path_str)
        exclusions = {normalise_domain(domain.removeprefix("*.")) for domain in (excluded_domains or [])}
        if exclusions:
            original_flow_count = len(flows)
            flows = [flow for flow in flows if not host_is_excluded(flow.host, exclusions)]
            logger.info(
                "Excluded %d of %d parsed flows for %d configured domains.",
                original_flow_count - len(flows), original_flow_count, len(exclusions),
            )
        logger.info(f"Extracted {len(flows)} flows for analysis.")
        for index, flow in enumerate(flows, start=1):
            logger.debug(
                "Flow %d/%d parsed: id=%s method=%s host=%s url=%s request_headers=%d "
                "request_body_chars=%d response_status=%s response_headers=%d",
                index, len(flows), flow.flow_id, flow.method, flow.host, flow.url,
                len(flow.request_headers), len(flow.request_body or ""),
                flow.response_status, len(flow.response_headers),
            )

        # Profile observed endpoints
        report_progress(PIPELINE_STAGES[1])
        endpoints: List[ObservedEndpoint] = self._profile_endpoints(flows)
        logger.info(f"Profiled {len(endpoints)} unique domain endpoints.")
        for endpoint in endpoints:
            logger.debug(
                "Endpoint profile: domain=%s category=%s parent_entity=%s ip=%s country=%s",
                endpoint.domain,
                endpoint.category,
                endpoint.parent_entity,
                endpoint.ip_address,
                endpoint.country_code,
            )

        # Personal data seed matching
        report_progress(PIPELINE_STAGES[2])
        seed_matches: List[Dict[str, Any]] = self._scan_seed_matches(flows, seed_data)
        personal_data_flows = self._group_personal_data_flows(seed_matches)
        if seed_matches:
            logger.info(
                "Detected %d personal-data occurrences, grouped into %d evidence records.",
                len(seed_matches), len(personal_data_flows),
            )
        logger.debug("Seed matching complete: occurrences=%d groups=%d", len(seed_matches), len(personal_data_flows))

        # Seed-independent personal-data candidate detection on decoded values.
        report_progress(PIPELINE_STAGES[3])
        presidio_matches = self.presidio_detector.detect_flows(flows)
        self._attach_cookie_context(presidio_matches, flows)
        personal_data_flows = self._group_personal_data_flows(seed_matches + presidio_matches)
        if presidio_matches:
            logger.info("Detected %d additional Presidio personal data candidates.", len(presidio_matches))

        # Entropy tokens & cookie longevity
        report_progress(PIPELINE_STAGES[4])
        entropy_tokens: List[TrackingToken] = []
        cookie_results: List[CookieLongevityResult] = []

        for flow in flows:
            tokens, cookies = analyse_flow_identifiers(
                flow,
                reference_time=analysis_started_at,
            )
            tokens = [
                token.model_copy(
                    update={"endpoint": flow.host, "flow_ids": [flow.flow_id]}
                )
                for token in tokens
            ]
            entropy_tokens.extend(tokens)
            cookie_results.extend(cookies)
            logger.debug(
                "Identifier analysis: flow_id=%s entropy_tokens=%d cookie_records=%d",
                flow.flow_id, len(tokens), len(cookies),
            )

        logger.info(
            f"Extracted {len(entropy_tokens)} high-entropy tokens "
            f"and {len(cookie_results)} set-cookie longevity records."
        )
        entropy_tokens = self._aggregate_tracking_tokens(entropy_tokens)
        logger.info("Reduced entropy evidence to %d unique token/location findings.", len(entropy_tokens))

        fingerprint_vectors: List[FingerprintVector]
        fingerprint_findings: List[FingerprintPersistenceFinding]
        report_progress(PIPELINE_STAGES[5])
        fingerprint_vectors, fingerprint_findings = self.fingerprint_profiler.analyse_flows(
            flows,
            consent_decided_at=consent_decided_at,
            consent_withdrawn_at=consent_withdrawn_at,
            consent_outcome=consent_outcome,
        )
        candidate_count = sum(vector.is_candidate for vector in fingerprint_vectors)
        fingerprint_summary = self._summarise_fingerprints(
            fingerprint_vectors, fingerprint_findings
        )
        logger.info(
            "Extracted %d fingerprint candidate vectors and %d consent-phase findings.",
            candidate_count, len(fingerprint_findings),
        )

        # Ingest disclosure document(s)
        report_progress(PIPELINE_STAGES[6])
        combined_text, auto_title = self._aggregate_documents(target_docs)
        logger.info(f"Analysing documentation: '{auto_title}' ({len(combined_text)} chars)")

        report_progress(PIPELINE_STAGES[7])
        doc_analysis = self.doc_ingestor.analyse_document_text(
            text_content=combined_text,
            document_title=auto_title,
        )

        # Cross-reference technical evidence vs. declared claims
        report_progress(PIPELINE_STAGES[8])
        logger.info("Executing LLM technical cross-referencing audit...")
        report = self.cross_referencer.cross_reference_audit(
            doc_analysis=doc_analysis,
            flows=flows,
            endpoints=endpoints,
            personal_data_flows=personal_data_flows,
            entropy_tokens=entropy_tokens,
            cookie_results=cookie_results,
            fingerprint_vectors=fingerprint_vectors,
            fingerprint_persistence_findings=fingerprint_findings,
            fingerprint_summary=fingerprint_summary,
            observed_domains=[endpoint.domain for endpoint in endpoints],
            observed_flow_ids=[flow.flow_id for flow in flows],
            observed_endpoint_identifiers=[
                identifier
                for endpoint in endpoints
                for identifier in (endpoint.domain, endpoint.ip_address)
                if identifier
            ],
        )
        # Preserve deterministic evidence in the report independently of LLM success.
        report.fingerprint_vectors = fingerprint_vectors
        report.fingerprint_persistence_findings = fingerprint_findings
        report.fingerprint_summary = fingerprint_summary
        report.observed_endpoints = endpoints
        report.tracking_tokens = entropy_tokens
        report.cookie_longevity_results = cookie_results
        report.personal_data_flows = personal_data_flows
        if doc_analysis.warnings:
            report.warnings = doc_analysis.warnings + report.warnings
        if self.presidio_detector.warning:
            report.warnings.append(self.presidio_detector.warning)
            if report.analysis_status == "complete":
                report.analysis_status = "partial"
        if doc_analysis.analysis_status == "failed":
            report.analysis_status = "failed"
        elif doc_analysis.analysis_status == "partial" and report.analysis_status == "complete":
            report.analysis_status = "partial"
        report.provenance = AnalysisProvenance(
            tool_version=__version__,
            model=self.llm_model,
            api_base=self.api_base,
            temperature=self.temperature,
            analysis_started_at=analysis_started_at,
            analysis_finished_at=datetime.now(timezone.utc),
            reference_time=analysis_started_at,
            input_hashes=self._input_hashes(target_flow_path, target_docs, seed_data, exclusions),
            excluded_domains=sorted(exclusions),
        )

        report_progress(PIPELINE_STAGES[9])
        logger.info(f"Audit completed. Found {report.total_discrepancies_found} discrepancies.")
        return report

    @staticmethod
    def _sha256_bytes(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @classmethod
    def _input_hashes(
        cls,
        flow_file_path: Union[str, Path],
        documents: Union[str, Path, Sequence[Union[str, Path]]],
        seed_data: Optional[Union[SeedData, Dict[str, str]]],
        excluded_domains: Optional[Sequence[str]] = None,
    ) -> Dict[str, str]:
        """Create non-sensitive hashes for the inputs used by an analysis."""
        hashes: Dict[str, str] = {}
        capture_path = Path(flow_file_path)
        if capture_path.is_file():
            hashes["capture"] = cls._sha256_bytes(capture_path.read_bytes())

        doc_list = [documents] if isinstance(documents, (str, Path)) else list(documents)
        for index, document in enumerate(doc_list, start=1):
            if isinstance(document, Path) or (isinstance(document, str) and Path(document).is_file()):
                document_path = Path(document)
                content = document_path.read_bytes()
                name = document_path.name
            else:
                content = str(document).encode("utf-8")
                name = f"inline-{index}"
            hashes[f"document:{index}:{name}"] = cls._sha256_bytes(content)

        if seed_data:
            if isinstance(seed_data, SeedData):
                serialised = seed_data.model_dump(mode="json")
            else:
                serialised = seed_data
            hashes["seed_data"] = cls._sha256_bytes(
                json.dumps(serialised, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
        if excluded_domains:
            hashes["excluded_domains"] = cls._sha256_bytes(
                json.dumps(sorted(excluded_domains), separators=(",", ":")).encode("utf-8")
            )
        return hashes

    @staticmethod
    def _summarise_fingerprints(
        vectors: List[FingerprintVector],
        findings: List[FingerprintPersistenceFinding],
    ) -> FingerprintAnalysisSummary:
        categories: Dict[str, int] = {}
        phases: Dict[str, int] = {}
        for vector in vectors:
            phases[vector.consent_phase.value] = phases.get(vector.consent_phase.value, 0) + 1
            for category in vector.matched_categories:
                categories[category] = categories.get(category, 0) + 1
        return FingerprintAnalysisSummary(
            total_vectors=len(vectors),
            candidate_vectors=sum(vector.is_candidate for vector in vectors),
            categories_observed=categories,
            consent_phases=phases,
            persistence_findings=len(findings),
            maximum_heuristic_score=max(
                (vector.heuristic_score for vector in vectors), default=0.0
            ),
        )

    @staticmethod
    def _aggregate_tracking_tokens(
        tokens: List[TrackingToken],
    ) -> List[TrackingToken]:
        """Collapse repeated entropy findings while retaining occurrence counts."""
        aggregated: Dict[tuple[str, str, Optional[str]], TrackingToken] = {}
        for token in tokens:
            key = (token.token, token.location, token.endpoint)
            if key in aggregated:
                aggregated[key].occurrences += token.occurrences
                for flow_id in token.flow_ids:
                    if flow_id not in aggregated[key].flow_ids:
                        aggregated[key].flow_ids.append(flow_id)
            else:
                aggregated[key] = token.model_copy()
        return list(aggregated.values())

    @staticmethod
    def _validate_consent_timeline(
        consent_decided_at: Optional[datetime], consent_withdrawn_at: Optional[datetime]
    ) -> None:
        """Ensure optional consent events are timezone-aware and chronologically valid."""
        for name, timestamp in (
            ("consent_decided_at", consent_decided_at),
            ("consent_withdrawn_at", consent_withdrawn_at),
        ):
            if timestamp and timestamp.tzinfo is None:
                raise ValueError(f"{name} must include a timezone offset.")
        if consent_decided_at and consent_withdrawn_at and consent_withdrawn_at < consent_decided_at:
            raise ValueError("consent_withdrawn_at must be after consent_decided_at.")

    def _aggregate_documents(
        self, documents: Union[str, Path, Sequence[Union[str, Path]]]
    ) -> tuple[str, str]:
        """Loads and combines single or multiple document paths or raw string inputs."""
        doc_list: Sequence[Union[str, Path]]
        if isinstance(documents, (str, Path)):
            doc_list = [documents]
        else:
            doc_list = documents

        text_blocks: List[str] = []
        titles: List[str] = []

        for idx, doc in enumerate(doc_list, start=1):
            if isinstance(doc, Path) or (isinstance(doc, str) and Path(doc).is_file()):
                p = Path(doc)
                content = p.read_text(encoding="utf-8", errors="ignore")
                titles.append(p.name)
                text_blocks.append(f"=== DOCUMENT SOURCE [{idx}]: {p.name} ===\n{content}")
            else:
                raw_str = str(doc)
                titles.append(f"Inline Content #{idx}")
                text_blocks.append(f"=== DOCUMENT SOURCE [{idx}]: Text Input ===\n{raw_str}")

        combined_text = "\n\n".join(text_blocks)
        combined_title = " + ".join(titles) if titles else "Vendor Disclosures"
        logger.debug("Documents aggregated: count=%d title=%s chars=%d", len(text_blocks), combined_title, len(combined_text))
        return combined_text, combined_title

    def _profile_endpoints(self, flows: List[NetworkFlow]) -> List[ObservedEndpoint]:
        """Profiles unique host domains observed across network flows."""
        endpoints: List[ObservedEndpoint] = []
        for index, host in enumerate(unique_hosts(flows), start=1):
            logger.debug("Profiling endpoint %d: host=%s", index, host)
            resolved_ip = self.endpoint_profiler.resolve_domain_ip(host)
            profiled = self.endpoint_profiler.profile_endpoint(
                domain=host,
                ip_address=resolved_ip,
            )
            endpoints.append(profiled)

        return endpoints

    def _scan_seed_matches(
        self,
        flows: List[NetworkFlow],
        seed_input: Optional[Union[SeedData, Dict[str, str]]],
    ) -> List[Dict[str, Any]]:
        """Scan decoded request and response evidence and retain its flow mapping."""
        if not seed_input:
            return []

        if isinstance(seed_input, SeedData):
            seed_data = seed_input
        else:
            seed_data = generate_seed_hash_map(seed_input)

        matches: List[Dict[str, Any]] = []

        for flow in flows:
            targets = [
                ("request", "url", flow.url),
                ("request", "headers", flow.request_headers),
                ("request", "body", flow.request_body),
                ("request", "cookies", flow.cookies_sent),
                ("response", "headers", flow.response_headers),
                ("response", "body", flow.response_body),
                ("response", "cookies", flow.cookies_set),
            ]

            for direction, location_name, target_payload in targets:
                if not target_payload:
                    continue
                # Scan both the captured representation and recursively decoded values.
                # This catches URL/base64-wrapped values without losing the original
                # token that was actually observed on the wire.
                decoded_payload = recursive_decode(target_payload)
                found_tuples = scan_for_seed_matches(target_payload, seed_data)
                if decoded_payload != target_payload:
                    found_tuples.extend(scan_for_seed_matches(decoded_payload, seed_data))
                if found_tuples:
                    logger.debug(
                        "Seed matches: flow_id=%s direction=%s location=%s count=%d",
                        flow.flow_id, direction, location_name, len(found_tuples),
                    )
                seen: set[tuple[str, str]] = set()
                for matched_val, label in found_tuples:
                    if (matched_val, label) in seen:
                        continue
                    seen.add((matched_val, label))
                    matches.append(
                        {
                            "flow_id": flow.flow_id,
                            "direction": direction,
                            "data_label": label.split(" (")[0],
                            "matched_value": matched_val,
                            "field_type": label,
                            "location": f"flow[{flow.flow_id}].{direction}.{location_name}",
                            "host": flow.host,
                            "cookies_sent": dict(flow.cookies_sent),
                        }
                    )

        return matches

    @staticmethod
    def _attach_cookie_context(
        matches: List[Dict[str, Any]], flows: List[NetworkFlow]
    ) -> None:
        """Attach request cookies for each Presidio match's source flow."""
        cookies_by_flow = {flow.flow_id: dict(flow.cookies_sent) for flow in flows}
        for match in matches:
            match["cookies_sent"] = cookies_by_flow.get(match.get("flow_id", ""), {})

    @staticmethod
    def _group_personal_data_flows(
        matches: List[Dict[str, Any]],
    ) -> List[PersonalDataFlowEvidence]:
        """Aggregate repeated matches while retaining every source flow ID."""
        grouped: Dict[tuple[str, str, str, str, str], Dict[str, Any]] = {}
        for match in matches:
            endpoint = match.get("host") or match.get("endpoint")
            if not endpoint:
                logger.debug("Skipping personal-data match without endpoint: %s", match)
                continue
            key = (
                endpoint,
                match["direction"],
                match["location"].rsplit(".", 1)[-1],
                match["data_label"],
                match.get("detection_method", "seed_match"),
            )
            if key not in grouped:
                grouped[key] = {
                    "endpoint": endpoint,
                    "direction": match["direction"],
                    "location": match["location"].rsplit("].", 1)[-1],
                    "data_label": match["data_label"],
                    "sample_value": match["matched_value"],
                    "matched_values": [],
                    "detection_method": match.get("detection_method", "seed_match"),
                    "count": 0,
                    "flow_ids": [],
                    "cookies_sent": {},
                    "cookies_by_flow": {},
                }
            grouped[key]["count"] += 1
            if match["matched_value"] not in grouped[key]["matched_values"]:
                grouped[key]["matched_values"].append(match["matched_value"])
            if match["flow_id"] not in grouped[key]["flow_ids"]:
                grouped[key]["flow_ids"].append(match["flow_id"])
            flow_id = match["flow_id"]
            flow_cookies = dict(match.get("cookies_sent") or {})
            grouped[key]["cookies_by_flow"][flow_id] = flow_cookies
            for cookie_name, cookie_value in flow_cookies.items():
                grouped[key]["cookies_sent"].setdefault(cookie_name, cookie_value)

        return sorted(
            (PersonalDataFlowEvidence(**item) for item in grouped.values()),
            key=lambda evidence: (
                -evidence.count,
                evidence.endpoint,
                evidence.direction,
                evidence.location,
                evidence.data_label,
            ),
        )
