"""Load mitmproxy capture files into shared NetworkFlow schemas."""

import json
import logging
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

logger = logging.getLogger(__name__)


def parse_flow_file(file_path: str) -> List[NetworkFlow]:
    """Parse a mitmproxy flow dump and skip individual unreadable flows.

    HAR files are (intentionally) not parsed for now.
    """
    path = Path(file_path)
    if path.suffix.lower() == ".har":
        logger.warning("HAR parsing is not (yet) supported: %s", path)
        return []

    parsed_flows: List[NetworkFlow] = []
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

    return parsed_flows


def _to_network_flow(flow: HTTPFlow) -> NetworkFlow:
    """Convert one mitmproxy HTTP flow into the common engine schema."""
    request = flow.request
    response = flow.response
    url = request.pretty_url
    url_parts = urlsplit(url)

    return NetworkFlow(
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
    )


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
