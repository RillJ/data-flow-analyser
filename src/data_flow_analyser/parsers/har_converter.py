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

import base64
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from mitmproxy import connection, http
from mitmproxy.io import FlowWriter


def har_to_flows(har_path: str | Path, flows_path: str | Path) -> int:
    """Convert a HAR file to a mitmproxy flow dump.

    Returns the number of HAR entries written.  HAR header arrays are kept as
    arrays instead of dictionaries so repeated headers such as ``Set-Cookie``
    are not lost.
    """
    source = Path(har_path)
    destination = Path(flows_path)
    with source.open("r", encoding="utf-8") as har_file:
        har = json.load(har_file)

    if not isinstance(har, Mapping):
        raise ValueError(f"HAR root must be an object: {source}")
    log = har.get("log") or {}
    if not isinstance(log, Mapping):
        raise ValueError(f"HAR log must be an object: {source}")
    entries = log.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError(f"HAR entries must be a list: {source}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as flow_file:
        writer = FlowWriter(flow_file)
        for entry in entries:
            writer.add(_entry_to_flow(entry))

    return len(entries)


def _entry_to_flow(entry: Mapping[str, Any]) -> http.HTTPFlow:
    request_data = entry.get("request") or {}
    response_data = entry.get("response")

    client = connection.Client(peername=("", 0), sockname=("", 0))
    server = connection.Server(address=("", 0))
    flow = http.HTTPFlow(client, server)

    flow.request = http.Request.make(
        method=request_data.get("method", "GET"),
        url=request_data.get("url", ""),
        headers=_headers(request_data.get("headers", [])),
        content=_body(request_data.get("postData")),
    )
    if request_data.get("httpVersion"):
        flow.request.http_version = request_data["httpVersion"]
    _set_timestamp(flow.request, entry.get("startedDateTime"))

    if response_data is not None:
        flow.response = http.Response.make(
            status_code=int(response_data.get("status", 200)),
            headers=_headers(response_data.get("headers", [])),
            content=_body(response_data.get("content")),
        )
        if response_data.get("httpVersion"):
            flow.response.http_version = response_data["httpVersion"]
        _set_timestamp(flow.response, entry.get("startedDateTime"), entry.get("time"))

    return flow


def _headers(headers: Iterable[Mapping[str, Any]]) -> list[tuple[bytes, bytes]]:
    """Convert HAR headers while retaining duplicate names."""
    return [
        (
            str(header.get("name", "")).encode("utf-8"),
            str(header.get("value", "")).encode("utf-8"),
        )
        for header in headers
        if header.get("name") is not None
    ]


def _body(data: Mapping[str, Any] | None) -> bytes:
    if not data:
        return b""
    text = data.get("text") or ""
    if data.get("encoding") == "base64":
        try:
            return base64.b64decode(text)
        except (ValueError, TypeError) as error:
            raise ValueError("Invalid base64 body in HAR entry") from error
    return str(text).encode("utf-8")


def _set_timestamp(message: Any, started_at: str | None, duration_ms: Any = 0) -> None:
    """Set mitmproxy timestamps when a HAR entry provides timing metadata."""
    if not started_at:
        return
    from datetime import datetime

    try:
        timestamp = datetime.fromisoformat(started_at.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return
    message.timestamp_start = timestamp
    try:
        message.timestamp_end = timestamp + float(duration_ms or 0) / 1000
    except (TypeError, ValueError):
        message.timestamp_end = timestamp

