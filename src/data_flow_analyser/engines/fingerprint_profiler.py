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

import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from data_flow_analyser.models.schemas import (
    ConsentPhase,
    FingerprintAttribute,
    FingerprintPersistenceFinding,
    FingerprintVector,
    NetworkFlow,
)
from data_flow_analyser.parsers.decoder import recursive_decode

logger = logging.getLogger(__name__)

# Key names are normalised to lowercase letters/digits before comparison.
FINGERPRINT_TAXONOMY: Dict[str, Sequence[str]] = {
    "display": (
        "screen", "screenwidth", "screenheight", "screenres", "resolution",
        "viewport", "viewportwidth", "viewportheight", "devicepixelratio", "dpr",
        "sw", "sh", "sr",
    ),
    "locale_time": ("timezone", "timezoneoffset", "tz", "offset", "language", "languages", "lang", "locale"),
    "hardware_os": (
        "cpu", "cores", "hardwareconcurrency", "devicememory", "memory", "ram",
        "gpu", "renderer", "platform", "architecture", "arch",
    ),
    "canvas": ("canvas", "canvashash", "fpcanvas"),
    "audio": ("audio", "audiohash", "oscillator", "audiocontext"),
    "webgl": ("webgl", "webglvendor", "webglrenderer"),
    "system_capabilities": (
        "touch", "maxtouchpoints", "pdfviewer", "donottrack", "plugins",
        "cookieenabled", "webdriver",
    ),
}

HEADER_KEYS = {
    "user-agent", "accept-language", "viewport-width", "width", "dpr",
    "device-memory", "sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness",
    "sec-ch-ua-full-version-list", "sec-ch-ua-mobile", "sec-ch-ua-model",
    "sec-ch-ua-platform", "sec-ch-ua-platform-version",
}
HEADER_CATEGORY_OVERRIDES = {
    "user-agent": "hardware_os",
    "accept-language": "locale_time",
}
HIGH_SIGNAL_CATEGORIES = {"canvas", "audio", "webgl"}


def classify_consent_phase(
    timestamp: datetime,
    consent_granted_at: Optional[datetime] = None,
    consent_withdrawn_at: Optional[datetime] = None,
) -> ConsentPhase:
    """Assign a flow to a phase using optional, user-supplied consent events."""
    if consent_withdrawn_at and timestamp >= consent_withdrawn_at:
        return ConsentPhase.WITHDRAWN
    if consent_granted_at:
        if timestamp < consent_granted_at:
            return ConsentPhase.PRE_CONSENT
        return ConsentPhase.CONSENTED
    return ConsentPhase.UNKNOWN


class FingerprintProfiler:
    """Extracts request attributes and identifies bundled fingerprinting signals."""

    def analyse_flows(
        self,
        flows: Iterable[NetworkFlow],
        consent_granted_at: Optional[datetime] = None,
        consent_withdrawn_at: Optional[datetime] = None,
    ) -> Tuple[List[FingerprintVector], List[FingerprintPersistenceFinding]]:
        vectors = [
            self.analyse_flow(
                flow,
                classify_consent_phase(
                    flow.timestamp, consent_granted_at, consent_withdrawn_at
                ),
            )
            for flow in flows
        ]
        candidates = [vector for vector in vectors if vector.is_candidate]
        findings = self._find_persistence(candidates)
        logger.debug(
            "Fingerprint profiling complete: vectors=%d candidates=%d persistence_findings=%d",
            len(vectors), len(candidates), len(findings),
        )
        return vectors, findings

    def analyse_flow(self, flow: NetworkFlow, consent_phase: ConsentPhase) -> FingerprintVector:
        """Analyse one flow's query, selected headers, and recursively decoded body."""
        attributes = self._extract_attributes(flow)
        categories = sorted({attribute.category for attribute in attributes})
        high_signal_count = len(set(categories) & HIGH_SIGNAL_CATEGORIES)
        attribute_count = len(categories)
        is_candidate = attribute_count >= 4 or (
            high_signal_count >= 1 and attribute_count >= 2
        )
        heuristic_score = self._heuristic_score(attribute_count, high_signal_count)
        signature = self._signature(flow.host, attributes)
        locations = sorted({attribute.location for attribute in attributes})
        vector = FingerprintVector(
            flow_id=flow.flow_id,
            endpoint=flow.host,
            consent_phase=consent_phase,
            matched_categories=categories,
            attributes=attributes,
            payload_locations=locations,
            attribute_count=attribute_count,
            heuristic_score=heuristic_score,
            is_candidate=is_candidate,
            signature=signature,
        )
        logger.debug(
            "Fingerprint vector: flow_id=%s endpoint=%s phase=%s categories=%s candidate=%s score=%.2f",
            flow.flow_id, flow.host, consent_phase.value, categories, is_candidate, heuristic_score,
        )
        return vector

    def _extract_attributes(self, flow: NetworkFlow) -> List[FingerprintAttribute]:
        values: List[Tuple[str, str, str]] = []
        values.extend((key, value, "url_query") for key, value in parse_qsl(urlsplit(flow.url).query, keep_blank_values=True))
        values.extend(
            (key, value, "request_headers")
            for key, value in flow.request_headers.items()
            if key.lower() in HEADER_KEYS
        )
        values.extend(self._body_values(flow.request_body, flow.request_headers))

        attributes: List[FingerprintAttribute] = []
        for key, value, location in values:
            category = HEADER_CATEGORY_OVERRIDES.get(key.lower()) or self._categorise_key(key)
            if category and value:
                attributes.append(
                    FingerprintAttribute(
                        category=category, key=key, value=value, location=location
                    )
                )
        return attributes

    def _body_values(
        self, body: Optional[str], request_headers: Dict[str, str]
    ) -> List[Tuple[str, str, str]]:
        if not body:
            return []
        decoded = recursive_decode(body)
        values = list(self._flatten(decoded, "request_body"))
        content_type = next(
            (value for key, value in request_headers.items() if key.lower() == "content-type"),
            "",
        ).lower()
        if isinstance(decoded, str) and ("x-www-form-urlencoded" in content_type or "=" in decoded):
            values.extend(
                (f"request_body.{key}", value, "request_body")
                for key, value in parse_qsl(decoded, keep_blank_values=True)
            )
        return values

    def _flatten(self, value: Any, path: str) -> Iterable[Tuple[str, str, str]]:
        if isinstance(value, dict):
            for key, nested in value.items():
                yield from self._flatten(nested, f"{path}.{key}")
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                yield from self._flatten(nested, f"{path}[{index}]")
        elif isinstance(value, (str, int, float, bool)):
            yield path, str(value), "request_body"

    @staticmethod
    def _categorise_key(key: str) -> Optional[str]:
        normalised = re.sub(r"[^a-z0-9]", "", key.lower())
        parts = {part for part in re.split(r"[^a-z0-9]+", key.lower()) if part}
        category_order = (
            "canvas", "audio", "webgl", "display", "locale_time",
            "hardware_os", "system_capabilities",
        )
        for category in category_order:
            patterns = FINGERPRINT_TAXONOMY[category]
            for pattern in patterns:
                if pattern in {"sw", "sh", "sr", "tz"}:
                    if pattern in parts:
                        return category
                elif pattern in normalised:
                    return category
        return None

    @staticmethod
    def _heuristic_score(attribute_count: int, high_signal_count: int) -> float:
        score = 0.1 * attribute_count + 0.2 * high_signal_count
        return round(min(score, 1.0), 2)

    @staticmethod
    def _signature(endpoint: str, attributes: List[FingerprintAttribute]) -> str:
        material = {
            "endpoint": endpoint,
            "attributes": sorted(
                (attribute.category, attribute.key, attribute.value)
                for attribute in attributes
            ),
        }
        encoded = json.dumps(material, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _find_persistence(
        vectors: List[FingerprintVector],
    ) -> List[FingerprintPersistenceFinding]:
        grouped: Dict[Tuple[str, str], List[FingerprintVector]] = {}
        for vector in vectors:
            grouped.setdefault((vector.endpoint, vector.signature), []).append(vector)

        findings: List[FingerprintPersistenceFinding] = []
        for (endpoint, signature), matching_vectors in grouped.items():
            phases = sorted({vector.consent_phase for vector in matching_vectors}, key=lambda phase: phase.value)
            phase_set = set(phases)
            before_consent = ConsentPhase.PRE_CONSENT in phase_set
            after_withdrawal = ConsentPhase.WITHDRAWN in phase_set
            persists_after_withdrawal = after_withdrawal and ConsentPhase.CONSENTED in phase_set
            if not (before_consent or after_withdrawal):
                continue
            findings.append(
                FingerprintPersistenceFinding(
                    endpoint=endpoint,
                    signature=signature,
                    observed_phases=phases,
                    flow_ids=[vector.flow_id for vector in matching_vectors],
                    observed_before_consent=before_consent,
                    observed_after_withdrawal=after_withdrawal,
                    persists_after_withdrawal=persists_after_withdrawal,
                    reasoning=(
                        "Identical candidate vector observed in both consented and withdrawn phases."
                        if persists_after_withdrawal
                        else "Candidate vector observed in a phase without recorded consent."
                    ),
                )
            )
        return findings
