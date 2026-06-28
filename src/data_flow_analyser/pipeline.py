import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

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
from data_flow_analyser.models.schemas import (
    CookieLongevityResult,
    FingerprintPersistenceFinding,
    FingerprintVector,
    FullAuditReport,
    NetworkFlow,
    ObservedEndpoint,
    SeedData,
    TrackingToken,
)
from data_flow_analyser.parsers.mitm_parser import parse_flow_file

logger = logging.getLogger("data_flow_analyser.pipeline")


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
    ):
        self.doc_ingestor = PolicyDocumentIngestor(
            model=llm_model, api_key=api_key, api_base=api_base
        )
        self.cross_referencer = LLMCrossReferencer(
            model=llm_model, api_key=api_key, api_base=api_base
        )
        self.endpoint_profiler = EndpointProfiler()
        self.fingerprint_profiler = FingerprintProfiler()

    def run(
        self,
        flow_file_path: Optional[Union[str, Path]] = None,
        documents: Optional[Union[str, Path, Sequence[Union[str, Path]]]] = None,
        seed_data: Optional[Union[SeedData, Dict[str, str]]] = None,
        consent_granted_at: Optional[datetime] = None,
        consent_withdrawn_at: Optional[datetime] = None,
    ) -> FullAuditReport:
        """
        Executes the full end-to-end privacy audit pipeline.

        Args:
            flow_file_path: Path to the mitmproxy capture dump file.
            documents: Single file path, text string, or sequence/list of file paths/texts.
            seed_data: User PII key-value pairs or pre-computed SeedData.
            consent_granted_at: Optional timestamp at which the user gave consent.
            consent_withdrawn_at: Optional timestamp at which the user withdrew consent.

        Returns:
            FullAuditReport containing endpoint classifications and discrepancy cards.
        """
        target_flow_path = flow_file_path
        if not target_flow_path:
            raise ValueError("Must provide a flow capture file path.")

        target_docs = documents
        if not target_docs:
            raise ValueError("Must provide at least one document or text input.")
        self._validate_consent_timeline(consent_granted_at, consent_withdrawn_at)

        path_str = str(target_flow_path)
        logger.info(f"Loading and parsing mitmproxy flow capture file: {path_str}")
        flows: List[NetworkFlow] = parse_flow_file(path_str)
        logger.info(f"Extracted {len(flows)} total network flows.")
        for index, flow in enumerate(flows, start=1):
            logger.debug(
                "Flow %d/%d parsed: id=%s method=%s host=%s url=%s request_headers=%d "
                "request_body_chars=%d response_status=%s response_headers=%d",
                index, len(flows), flow.flow_id, flow.method, flow.host, flow.url,
                len(flow.request_headers), len(flow.request_body or ""),
                flow.response_status, len(flow.response_headers),
            )

        # Profile observed endpoints
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
        seed_matches: List[Dict[str, Any]] = self._scan_seed_matches(flows, seed_data)
        if seed_matches:
            logger.info(f"Detected {len(seed_matches)} personal data seed occurrences in network flows.")
        logger.debug("Seed matching complete: %d matches", len(seed_matches))

        # Entropy tokens & cookie longevity
        entropy_tokens: List[TrackingToken] = []
        cookie_results: List[CookieLongevityResult] = []

        for flow in flows:
            tokens, cookies = analyse_flow_identifiers(flow)
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

        fingerprint_vectors: List[FingerprintVector]
        fingerprint_findings: List[FingerprintPersistenceFinding]
        fingerprint_vectors, fingerprint_findings = self.fingerprint_profiler.analyse_flows(
            flows,
            consent_granted_at=consent_granted_at,
            consent_withdrawn_at=consent_withdrawn_at,
        )
        candidate_count = sum(vector.is_candidate for vector in fingerprint_vectors)
        logger.info(
            "Extracted %d fingerprint candidate vectors and %d consent-phase findings.",
            candidate_count, len(fingerprint_findings),
        )

        # Ingest disclosure document(s)
        combined_text, auto_title = self._aggregate_documents(target_docs)
        logger.info(f"Analysing documentation: '{auto_title}' ({len(combined_text)} chars)")

        doc_analysis = self.doc_ingestor.analyse_document_text(
            text_content=combined_text,
            document_title=auto_title,
        )

        # Cross-reference technical evidence vs. declared claims
        logger.info("Executing LLM technical cross-referencing audit...")
        report = self.cross_referencer.cross_reference_audit(
            doc_analysis=doc_analysis,
            flows=flows,
            endpoints=endpoints,
            seed_matches=seed_matches,
            entropy_tokens=entropy_tokens,
            cookie_results=cookie_results,
            fingerprint_vectors=fingerprint_vectors,
            fingerprint_persistence_findings=fingerprint_findings,
        )

        logger.info(f"Audit completed. Found {report.total_discrepancies_found} discrepancies.")
        return report

    @staticmethod
    def _validate_consent_timeline(
        consent_granted_at: Optional[datetime], consent_withdrawn_at: Optional[datetime]
    ) -> None:
        """Ensure optional consent events are timezone-aware and chronologically valid."""
        for name, timestamp in (
            ("consent_granted_at", consent_granted_at),
            ("consent_withdrawn_at", consent_withdrawn_at),
        ):
            if timestamp and timestamp.tzinfo is None:
                raise ValueError(f"{name} must include a timezone offset.")
        if consent_granted_at and consent_withdrawn_at and consent_withdrawn_at < consent_granted_at:
            raise ValueError("consent_withdrawn_at must be after consent_granted_at.")

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
        seen_hosts: set[str] = set()

        for flow in flows:
            host = flow.host
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                logger.debug("Profiling endpoint %d: host=%s", len(seen_hosts), host)
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
        """Pre-computes personal data seed lookup map and scans flow headers, URLs, and bodies."""
        if not seed_input:
            return []

        if isinstance(seed_input, SeedData):
            seed_data = seed_input
        else:
            seed_data = generate_seed_hash_map(seed_input)

        matches: List[Dict[str, Any]] = []

        for flow in flows:
            targets = [
                ("url", flow.url),
                ("request_headers", flow.request_headers),
                ("request_body", flow.request_body),
                ("cookies_sent", flow.cookies_sent),
            ]

            for location_name, target_payload in targets:
                if not target_payload:
                    continue
                found_tuples = scan_for_seed_matches(target_payload, seed_data)
                if found_tuples:
                    logger.debug(
                        "Seed matches: flow_id=%s location=%s count=%d",
                        flow.flow_id, location_name, len(found_tuples),
                    )
                for matched_val, label in found_tuples:
                    matches.append(
                        {
                            "matched_value": matched_val,
                            "field_type": label,
                            "location": f"flow[{flow.flow_id}].{location_name}",
                            "host": flow.host,
                        }
                    )

        return matches
