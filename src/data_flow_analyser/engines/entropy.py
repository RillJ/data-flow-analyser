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

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from data_flow_analyser.models.schemas import (
    CookieLongevityResult,
    NetworkFlow,
    TrackingToken,
)
from data_flow_analyser.parsers.decoder import recursive_decode

# Standard duration threshold: 90 days in seconds
NINETY_DAYS_SECONDS = 90 * 24 * 60 * 60  # 7,776,000 seconds
logger = logging.getLogger(__name__)

IDENTIFIER_HEADER_NAMES = {
    "authorization", "cookie", "proxy-authorization", "x-api-key",
    "x-client-id", "x-device-id", "x-request-id", "x-session-id",
    "x-trace-id", "traceparent", "tracestate",
}
IDENTIFIER_HEADER_HINTS = ("id", "token", "session", "visitor", "device", "client", "trace")


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy H(X) = -sum(P(x_i) * log2(P(x_i))) for a string.
    Returns 0.0 for empty or single-character strings.
    """
    if not text or len(text) <= 1:
        return 0.0

    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def parse_set_cookie_longevity(
    set_cookie_header: str,
    flow_timestamp: Optional[datetime] = None
) -> List[CookieLongevityResult]:
    """
    Parses Set-Cookie directives to calculate cookie lifespan and flag long-lived cookies (> 90 days).
    """
    results: List[CookieLongevityResult] = []
    if not set_cookie_header:
        return results

    reference_time = flow_timestamp or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)

    directives = [d.strip() for d in set_cookie_header.split(";") if d.strip()]
    if not directives:
        return results

    # First directive is name=value
    name_val_part = directives[0]
    if "=" not in name_val_part:
        return results

    cookie_name, cookie_val = name_val_part.split("=", 1)
    cookie_name = cookie_name.strip()
    cookie_val = cookie_val.strip()

    max_age_seconds: Optional[int] = None
    expires_dt: Optional[datetime] = None
    lifespan_days: Optional[float] = None

    for directive in directives[1:]:
        if "=" in directive:
            d_key, d_val = directive.split("=", 1)
            d_key = d_key.strip().lower()
            d_val = d_val.strip()

            if d_key == "max-age":
                try:
                    max_age_seconds = int(d_val)
                    lifespan_days = round(max_age_seconds / (24 * 3600), 2)
                except ValueError:
                    pass
            elif d_key == "expires" and max_age_seconds is None:
                try:
                    expires_dt = parsedate_to_datetime(d_val)
                    if expires_dt.tzinfo is None:
                        expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                    delta = expires_dt - reference_time
                    max_age_seconds = int(delta.total_seconds())
                    lifespan_days = round(max_age_seconds / (24 * 3600), 2)
                except Exception:
                    pass

    is_excessive = False
    if max_age_seconds is not None and max_age_seconds > NINETY_DAYS_SECONDS:
        is_excessive = True
    logger.debug("Cookie longevity: name=%s lifespan_days=%s excessive=%s", cookie_name, lifespan_days, is_excessive)

    results.append(
        CookieLongevityResult(
            cookie_name=cookie_name,
            cookie_value=cookie_val,
            max_age_seconds=max_age_seconds,
            expires_at=expires_dt,
            lifespan_days=lifespan_days,
            is_excessive_longevity=is_excessive,
        )
    )

    return results


def extract_high_entropy_tokens(
    payload: Any,
    parent_key: str = "root",
    min_length: int = 8,
    entropy_threshold: float = 3.5
) -> List[TrackingToken]:
    """
    Recursively inspects query params, headers, cookies, or JSON body payloads
    for high-entropy tokens (H(X) >= entropy_threshold).
    """
    tokens: List[TrackingToken] = []

    if isinstance(payload, dict):
        for k, v in payload.items():
            current_loc = f"{parent_key}.{k}" if parent_key != "root" else k
            tokens.extend(extract_high_entropy_tokens(v, current_loc, min_length, entropy_threshold))
    elif isinstance(payload, list):
        for idx, item in enumerate(payload):
            current_loc = f"{parent_key}[{idx}]"
            tokens.extend(extract_high_entropy_tokens(item, current_loc, min_length, entropy_threshold))
    elif isinstance(payload, str) and len(payload.strip()) >= min_length:
        clean_val = payload.strip()

        # Skip standard plain sentences or full URLs
        if " " in clean_val or clean_val.startswith("http://") or clean_val.startswith("https://"):
            return tokens

        entropy = calculate_shannon_entropy(clean_val)
        if entropy >= entropy_threshold:
            tokens.append(
                TrackingToken(
                    token=clean_val,
                    location=parent_key,
                    entropy=entropy,
                    is_high_entropy=True,
                )
            )

    if tokens:
        logger.debug("High-entropy scan: location=%s tokens=%d", parent_key, len(tokens))
    return tokens


def analyse_flow_identifiers(
    flow: NetworkFlow,
    entropy_threshold: float = 3.5,
    min_length: int = 8
) -> Tuple[List[TrackingToken], List[CookieLongevityResult]]:
    """
    Scans a NetworkFlow's query parameters, cookies, and payload for dynamic tracking
    tokens and evaluates response Set-Cookie headers for excessive longevity.
    """
    high_entropy_tokens: List[TrackingToken] = []
    cookie_longevity_results: List[CookieLongevityResult] = []

    # Inspect sent cookies
    if flow.cookies_sent:
        high_entropy_tokens.extend(
            extract_high_entropy_tokens(
                flow.cookies_sent,
                parent_key="cookies_sent",
                min_length=min_length,
                entropy_threshold=entropy_threshold
            )
        )

    # Inspect URL query parameters and request headers, which frequently carry IDs.
    query_params = parse_qsl(urlsplit(flow.url).query, keep_blank_values=True)
    if query_params:
        high_entropy_tokens.extend(
            extract_high_entropy_tokens(
                {key: value for key, value in query_params},
                parent_key="url_query",
                min_length=min_length,
                entropy_threshold=entropy_threshold,
            )
        )
    identifier_headers = {
        key: value
        for key, value in flow.request_headers.items()
        if key.lower() in IDENTIFIER_HEADER_NAMES
        or any(hint in key.lower() for hint in IDENTIFIER_HEADER_HINTS)
    }
    if identifier_headers:
        high_entropy_tokens.extend(
            extract_high_entropy_tokens(
                identifier_headers,
                parent_key="request_headers",
                min_length=min_length,
                entropy_threshold=entropy_threshold,
            )
        )

    # Inspect Set-Cookie headers
    set_cookie_val = flow.response_headers.get("Set-Cookie") or flow.response_headers.get("set-cookie")
    if set_cookie_val:
        cookie_longevity_results.extend(
            parse_set_cookie_longevity(set_cookie_val, flow.timestamp)
        )

    # Inspect request body
    if flow.request_body:
        decoded_body = recursive_decode(flow.request_body)
        high_entropy_tokens.extend(
            extract_high_entropy_tokens(
                decoded_body,
                parent_key="request_body",
                min_length=min_length,
                entropy_threshold=entropy_threshold
            )
        )

    logger.debug("Identifier analysis complete: flow_id=%s tokens=%d cookies=%d", flow.flow_id, len(high_entropy_tokens), len(cookie_longevity_results))
    return high_entropy_tokens, cookie_longevity_results
