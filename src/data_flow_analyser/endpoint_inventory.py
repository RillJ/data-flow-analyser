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

"""Deterministic inventory of hosts present in a network capture."""

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable

from data_flow_analyser.engines.endpoint_profiler import normalise_domain
from data_flow_analyser.models.schemas import NetworkFlow


def load_excluded_domains(value: Any) -> set[str]:
    """Validate supported exclusion JSON shapes and return normalised domains.

    The preferred file shape is ``{"domains": ["example.org"]}``. A plain
    JSON list is accepted as a convenience for small, hand-maintained files.
    """
    if isinstance(value, dict):
        value = value.get("domains")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError('exclusion JSON must be a list or an object with a "domains" list')

    domains = {normalise_domain(item.removeprefix("*.")) for item in value if item.strip()}
    if any("/" in domain or ":" in domain for domain in domains):
        raise ValueError("excluded values must be hostnames/domains, not URLs")
    return domains


def host_is_excluded(host: str, excluded_domains: Iterable[str]) -> bool:
    """Match an exact host or any subdomain of an excluded domain."""
    candidate = normalise_domain(host)
    return any(candidate == domain or candidate.endswith(f".{domain}") for domain in excluded_domains)


def inventory_flows(flows: Iterable[NetworkFlow]) -> list[dict[str, Any]]:
    """Aggregate flow counts and representative request details by host."""
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"domain": "", "flow_count": 0, "methods": Counter(), "paths": Counter(), "first_seen": None, "last_seen": None}
    )
    for flow in flows:
        domain = normalise_domain(flow.host)
        if not domain:
            continue
        item = grouped[domain]
        item["domain"] = domain
        item["flow_count"] += 1
        item["methods"][flow.method] += 1
        item["paths"][flow.path] += 1
        timestamp = flow.timestamp
        if item["first_seen"] is None or timestamp < item["first_seen"]:
            item["first_seen"] = timestamp
        if item["last_seen"] is None or timestamp > item["last_seen"]:
            item["last_seen"] = timestamp

    result = []
    for domain in sorted(grouped):
        item = grouped[domain]
        result.append({
            "domain": domain,
            "flow_count": item["flow_count"],
            "methods": dict(sorted(item["methods"].items())),
            "paths": dict(sorted(item["paths"].items())),
            "first_seen": item["first_seen"].isoformat() if isinstance(item["first_seen"], datetime) else None,
            "last_seen": item["last_seen"].isoformat() if isinstance(item["last_seen"], datetime) else None,
        })
    return result
