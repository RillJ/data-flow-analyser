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
import logging
import tempfile
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from uuid import uuid4

from mitmproxy.http import HTTPFlow
from mitmproxy.io import FlowReader

from data_flow_analyser.models.schemas import NetworkFlow
from data_flow_analyser.parsers.decoder import recursive_decode
from data_flow_analyser.parsers.har_converter import har_to_flows

logger = logging.getLogger(__name__)


def parse_flow_file(file_path: str | Path) -> List[NetworkFlow]:
    """Parse a mitmproxy flow dump or HAR file.

    HAR files are converted to a temporary mitmproxy flow dump first, keeping
    the rest of the parsing and analysis pipeline format-independent.
    """
    path = Path(file_path)
    if path.suffix.lower() == ".har":
        logger.info("Converting HAR capture to a temporary mitmproxy flow dump: %s", path)
        try:
            with tempfile.NamedTemporaryFile(suffix=".flows") as converted:
                har_to_flows(path, converted.name)
                return _parse_mitmproxy_flow_file(Path(converted.name))
        except (OSError, ValueError) as error:
            logger.warning("Unable to convert HAR file %s: %s", path, error)
            return []

    return _parse_mitmproxy_flow_file(path)


def _parse_mitmproxy_flow_file(path: Path) -> List[NetworkFlow]:
    """Parse a mitmproxy flow dump and skip individual unreadable flows."""

    parsed_flows: List[NetworkFlow] = []
    logger.debug("Flow parsing started: path=%s", path)
    try:
        with path.open("rb") as flow_file:
            reader = FlowReader(flow_file)
            for flow in reader.stream():
                if not isinstance(flow, HTTPFlow):
                    logger.debug("Skipping non-HTTP flow in %s", path)
                    continue

                try:
                    parsed_flows.append(_to_network_flow(flow))
                except (AttributeError, TypeError, ValueError) as error:
                    logger.warning("Skipping malformed HTTP flow in %s: %s", path, error)
    except OSError as error:
        logger.warning("Unable to read flow file %s: %s", path, error)
    except Exception as error:
        logger.warning("Unable to parse mitmproxy flow file %s: %s", path, error)

    logger.debug("Flow parsing complete: path=%s http_flows=%d", path, len(parsed_flows))
    return parsed_flows


def _to_network_flow(flow: HTTPFlow) -> NetworkFlow:
    """Convert one mitmproxy HTTP flow into the common engine schema."""
    request = flow.request
    response = flow.response
    url = request.pretty_url
    url_parts = urlsplit(url)

    network_flow = NetworkFlow(
        flow_id=str(uuid4()),
        timestamp=datetime.fromtimestamp(request.timestamp_start, tz=timezone.utc),
        method=request.method,
        url=url,
        host=request.host,
        path=url_parts.path or "/",
        request_headers=_headers_to_dict(request.headers),
        request_body=_decode_body(_message_text(request)),
        response_status=response.status_code if response is not None else None,
        response_headers=_headers_to_dict(response.headers) if response is not None else {},
        response_body=_decode_body(_message_text(response)) if response is not None else None,
        cookies_sent=_parse_cookie_headers(request.headers.get_all("cookie")),
        cookies_set=_parse_cookie_headers(
            response.headers.get_all("set-cookie") if response is not None else []
        ),
        cookies_set_domain_attributes=_parse_cookie_domain_attributes(
            response.headers.get_all("set-cookie") if response is not None else []
        ),
    )
    logger.debug("HTTP flow converted: host=%s method=%s path=%s request_body_chars=%d response_status=%s cookies_sent=%d cookies_set=%d", network_flow.host, network_flow.method, network_flow.path, len(network_flow.request_body or ""), network_flow.response_status, len(network_flow.cookies_sent), len(network_flow.cookies_set))
    return network_flow


def _headers_to_dict(headers: Any) -> Dict[str, str]:
    """Convert mitmproxy headers to a plain dictionary for model transport."""
    return {name: value for name, value in headers.items()}


def _message_text(message: Any) -> Optional[str]:
    """Return a decoded HTTP message body and preserve absent or empty bodies."""
    if not message or not message.content:
        return None
    return message.get_text(strict=False)


def _decode_body(body: Optional[str]) -> Optional[str]:
    """Recursively decode a payload and serialize structured results as JSON."""
    if body is None:
        return None

    decoded = recursive_decode(body)
    logger.debug("HTTP body decoded: input_chars=%d output_type=%s", len(body), type(decoded).__name__)
    if isinstance(decoded, (dict, list)):
        return json.dumps(decoded, ensure_ascii=False, sort_keys=True)
    return str(decoded)


def _parse_cookie_headers(headers: List[str]) -> Dict[str, str]:
    """Parse Cookie or Set-Cookie header values into name/value pairs."""
    cookies: Dict[str, str] = {}
    for header in headers:
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except (TypeError, ValueError):
            logger.debug("Unable to parse cookie header: %r", header)
            continue
        cookies.update({name: morsel.value for name, morsel in parsed.items()})
    return cookies


def _parse_cookie_domain_attributes(headers: List[str]) -> Dict[str, str]:
    """Extract optional Domain attributes from Set-Cookie headers."""
    domains: Dict[str, str] = {}
    for header in headers:
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except (TypeError, ValueError):
            continue
        for name, morsel in parsed.items():
            if morsel["domain"]:
                domains[name] = morsel["domain"]
    return domains
