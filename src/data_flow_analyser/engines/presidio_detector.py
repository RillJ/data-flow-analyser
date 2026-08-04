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

"""Optional seed-independent personal-data detection using Presidio by Data Privacy Stack."""

import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from data_flow_analyser.models.schemas import NetworkFlow
from data_flow_analyser.parsers.decoder import recursive_decode

logger = logging.getLogger("data_flow_analyser.presidio_detector")

# Country-specific recognisers outside this set are excluded by the default
# European profile. Global recognisers (for example PERSON, IBAN_CODE,
# MAC_ADDRESS, CRYPTO, and URL) are discovered dynamically from Presidio.
NON_EUROPEAN_ENTITY_PREFIXES = (
    "US_", "AU_", "CA_", "IN_", "KR_", "NG_", "PH_", "SG_", "ZA_", "TH_"
)

EUROPEAN_ENTITY_PREFIXES = (
    # Presidio currently has no built-in NL_* recognisers, but keep NL in the
    # European scope so future Dutch-specific recognisers are retained.
    "UK_", "ES_", "IT_", "PL_", "FI_", "SE_", "DE_", "TR_", "NL_"
)

SPACY_MODELS = {
    "en": "en_core_web_lg",
    "nl": "nl_core_news_lg",
    "de": "de_core_news_lg",
    "es": "es_core_news_lg",
    "it": "it_core_news_lg",
    "fr": "fr_core_news_lg",
}

IGNORED_NER_LABELS = [
    "CARDINAL", "EVENT", "FAC", "LANGUAGE", "LAW", "MONEY", "ORDINAL",
    "PERCENT", "PRODUCT", "QUANTITY", "TIME", "WORK_OF_ART", "ORG",
]

# These entity types are backed by the spaCy NER recogniser in the standard
# Presidio setup. NER is useful for short human-readable values, but it is the
# expensive part of scanning large HTML/JSON responses. Regex/checksum-based
# recognisers remain useful on those large values (emails, IPs, IBANs, etc.).
# The names below match Presidio's actual spaCy recogniser labels (not spaCy's
# raw labels, e.g. ORGANIZATION rather than ORG).
NER_ENTITY_TYPES = {
    "PERSON", "LOCATION", "DATE_TIME", "NRP", "EMAIL", "ID", "AGE",
    "ORGANIZATION",
}


class PresidioPersonalDataDetector:
    """Run Presidio over decoded scalar values while preserving flow context."""

    def __init__(
        self,
        score_threshold: float = 0.65,
        language: str = "en",
        max_unique_values: int = 25000,
        max_values_per_flow: int = 250,
        full_ner: bool = False,
        max_text_length: int = 50000,
        chunk_overlap: int = 512,
        max_ner_text_length: int = 10000,
    ):
        self.score_threshold = score_threshold
        self.language = language
        self.max_unique_values = max_unique_values
        self.max_values_per_flow = max_values_per_flow
        self.full_ner = full_ner
        self.max_text_length = max(1, max_text_length)
        self.chunk_overlap = max(0, min(chunk_overlap, self.max_text_length - 1))
        self.max_ner_text_length = max(1, max_ner_text_length)
        # AnalyzerEngine is an optional runtime dependency. ``Any`` keeps
        # static type checkers from treating this deliberately lazy field as
        # permanently None while still allowing the dependency-free fallback.
        self.analyser: Any = None
        self.deterministic_analyser: Any = None
        self.entities: Optional[List[str]] = None
        self._non_ner_entities: Optional[List[str]] = None
        self.warning: Optional[str] = None
        # Cached spans contain entity type, start offset, and end offset.
        # Scores are intentionally not retained because callers only need the
        # matched span and the cache is also used by the deterministic path.
        self._analysis_cache: Dict[str, List[Tuple[str, int, int]]] = {}
        self._limit_reached = False
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider, NoOpNlpEngine

            model_name = SPACY_MODELS.get(language)
            if not model_name:
                raise ValueError(
                    f"Unsupported Presidio language '{language}'. "
                    f"Supported configured languages: {', '.join(sorted(SPACY_MODELS))}."
                )
            # Presidio loads recognisers for several countries while building
            # its default registry, even when only one language is configured.
            # Those startup messages are harmless. Suppress them during setup
            # while keeping genuine runtime warnings visible.
            presidio_logger = logging.getLogger("presidio-analyzer")
            previous_presidio_level = presidio_logger.level
            presidio_logger.setLevel(logging.ERROR)
            nlp_provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": language, "model_name": model_name}],
                    "ner_model_configuration": {
                        "labels_to_ignore": IGNORED_NER_LABELS,
                    },
                }
            )
            try:
                self.analyser = AnalyzerEngine(
                    nlp_engine=nlp_provider.create_engine(),
                    supported_languages=[language],
                )
                self.deterministic_analyser = AnalyzerEngine(
                    nlp_engine=NoOpNlpEngine(
                        [{"lang_code": language, "model_name": "presidio-no-op"}]
                    ),
                    supported_languages=[language],
                )
            finally:
                # The no-op analyzer emits one INFO line per deterministic
                # scan (and DEBUG timing for every recognizer). Keep warnings,
                # but prevent large captures from flooding the terminal.
                presidio_logger.setLevel(
                    max(previous_presidio_level, logging.WARNING)
                )
            try:
                available_entities = self.analyser.get_supported_entities(language=language)
            except AttributeError:
                # Older Presidio releases may not expose this convenience method;
                # None asks AnalyzerEngine to use all registered types.
                available_entities = []
            self.entities = [
                entity
                for entity in available_entities
                if not entity.startswith(NON_EUROPEAN_ENTITY_PREFIXES)
                or entity.startswith(EUROPEAN_ENTITY_PREFIXES)
            ]
            if not self.entities:
                self.entities = None
            if self.entities is not None:
                deterministic_entities = set(
                    self.deterministic_analyser.get_supported_entities(language=language)
                )
                self._non_ner_entities = [
                    entity for entity in self.entities
                    if entity not in NER_ENTITY_TYPES and entity in deterministic_entities
                ]
            logger.info(
                "Presidio entity scope: language=%s entities=%d",
                language, len(self.entities) if self.entities is not None else len(available_entities),
            )
        except Exception as error:  # optional dependency/model failure
            self.warning = (
                "Presidio personal-data detection is unavailable: "
                f"{type(error).__name__}: {error}. Install presidio-analyzer and an NLP model."
            )
            logger.warning(self.warning)

    @property
    def available(self) -> bool:
        return self.analyser is not None

    def detect_flows(self, flows: Iterable[NetworkFlow]) -> List[Dict[str, Any]]:
        """Return ungrouped Presidio detections mapped to flow and endpoint."""
        if not self.analyser:
            logger.debug("Presidio detection skipped: analyser unavailable")
            return []

        flow_list = list(flows)
        logger.debug(
            "Presidio detection started: flows=%d max_values_per_flow=%d "
            "max_unique_values=%d max_ner_text_length=%d full_ner=%s",
            len(flow_list), self.max_values_per_flow, self.max_unique_values,
            self.max_ner_text_length, self.full_ner,
        )
        detections: List[Dict[str, Any]] = []
        for flow_index, flow in enumerate(flow_list, start=1):
            flow_findings_before = len(detections)
            logger.debug(
                "Presidio flow %d/%d started: flow_id=%s endpoint=%s",
                flow_index, len(flow_list), flow.flow_id, flow.host,
            )
            values_seen = 0
            for direction, location, payload in self._flow_payloads(flow):
                payload_values_before = values_seen
                for value_location, value in self._scalar_values(payload, location):
                    values_seen += 1
                    if values_seen > self.max_values_per_flow:
                        self._limit_reached = True
                        break
                    if len(value.strip()) < 3:
                        continue
                    results = self._analyse_value(value, flow.flow_id, value_location)
                    for entity_type, start, end in results:
                        matched_value = value[start:end]
                        if not matched_value.strip():
                            continue
                        detections.append(
                            {
                                "flow_id": flow.flow_id,
                                "endpoint": flow.host,
                                "direction": direction,
                                "location": value_location,
                                "data_label": entity_type.lower(),
                                "sample_value": matched_value,
                                "matched_value": matched_value,
                                "detection_method": "presidio",
                            }
                        )
                logger.debug(
                    "Presidio payload complete: flow_id=%s direction=%s "
                    "location=%s values=%d findings=%d",
                    flow.flow_id, direction, location,
                    values_seen - payload_values_before,
                    len(detections) - flow_findings_before,
                )
            logger.debug(
                "Presidio flow %d/%d complete: flow_id=%s values=%d "
                "findings=%d cache=%d",
                flow_index, len(flow_list), flow.flow_id, values_seen,
                len(detections) - flow_findings_before, len(self._analysis_cache),
            )
        if self._limit_reached:
            self.warning = (
                self.warning or ""
            ) + (
                " Presidio applied safety limits while scanning this capture "
                f"(max {self.max_values_per_flow} values per flow and "
                f"{self.max_unique_values} unique values)."
            )
        logger.info("Presidio detection complete: findings=%d", len(detections))
        return detections

    def _analyse_value(
        self, value: str, flow_id: str, location: str
    ) -> List[Tuple[str, int, int]]:
        """Analyse each distinct scalar at most once and cache its spans."""
        if value in self._analysis_cache:
            return self._analysis_cache[value]
        if len(self._analysis_cache) >= self.max_unique_values:
            self._limit_reached = True
            return []
        try:
            cached = []
            seen_spans = set()
            analyser = self.analyser
            entities = self.entities
            if len(value) > self.max_ner_text_length and not self.full_ner:
                # Large bodies are analysed once with deterministic
                # recognisers. This avoids both spaCy's max_length limit and
                # the overhead of making dozens of regex-only chunk calls.
                entities = self._non_ner_entities
                analyser = self.deterministic_analyser
                logger.debug(
                    "Presidio large value: flow_id=%s location=%s chars=%d "
                    "mode=deterministic entities=%d",
                    flow_id, location, len(value), len(entities or []),
                )
                if not entities:
                    self._analysis_cache[value] = []
                    return []
            # Regex recognizers can become extremely slow on multi-megabyte
            # bodies when given the entire payload at once. Chunk deterministic
            # scans as well; overlap preserves matches crossing a boundary.
            chunks = (
                self._text_chunks(value)
                if self.full_ner or len(value) > self.max_text_length
                else [(0, value)]
            )
            for offset, chunk in chunks:
                results = analyser.analyze(
                    text=chunk,
                    language=self.language,
                    entities=entities,
                    score_threshold=self.score_threshold,
                )
                for result in results:
                    span = (result.entity_type, offset + result.start, offset + result.end)
                    if span in seen_spans:
                        continue
                    seen_spans.add(span)
                    cached.append(span)
            self._analysis_cache[value] = cached
            return cached
        except Exception as error:
            logger.debug(
                "Presidio analysis failed: flow_id=%s location=%s error=%s",
                flow_id, location, error,
            )
            self._analysis_cache[value] = []
            return []

    def _text_chunks(self, value: str) -> Iterable[Tuple[int, str]]:
        """Yield bounded overlapping chunks for the explicitly requested full-NER mode."""
        if len(value) <= self.max_text_length:
            yield 0, value
            return
        step = self.max_text_length - self.chunk_overlap
        for start in range(0, len(value), step):
            end = min(start + self.max_text_length, len(value))
            yield start, value[start:end]
            if end == len(value):
                break

    @staticmethod
    def _flow_payloads(flow: NetworkFlow) -> Iterable[Tuple[str, str, Any]]:
        query = dict(parse_qsl(urlsplit(flow.url).query, keep_blank_values=True))
        if query:
            yield "request", "request.url_query", query
        for direction, location, values in (
            ("request", "request.headers", flow.request_headers),
            ("request", "request.body", flow.request_body),
            ("request", "request.cookies", flow.cookies_sent),
            ("response", "response.headers", flow.response_headers),
            ("response", "response.body", flow.response_body),
            ("response", "response.cookies", flow.cookies_set),
        ):
            if values:
                yield direction, location, values

    @staticmethod
    def _scalar_values(payload: Any, parent: str) -> Iterable[Tuple[str, str]]:
        # Decode the payload container once. The previous implementation
        # decoded the entire nested object again at every recursion level,
        # causing repeated depth-limit messages and quadratic work.
        if isinstance(payload, dict):
            for key, value in payload.items():
                yield from PresidioPersonalDataDetector._scalar_values(value, f"{parent}.{key}")
        elif isinstance(payload, list):
            for index, value in enumerate(payload):
                yield from PresidioPersonalDataDetector._scalar_values(value, f"{parent}[{index}]")
        elif isinstance(payload, str) and payload.strip():
            decoded = recursive_decode(payload)
            if isinstance(decoded, dict) or isinstance(decoded, list):
                yield from PresidioPersonalDataDetector._scalar_values(decoded, parent)
            elif isinstance(decoded, str) and decoded.strip():
                yield parent, decoded
