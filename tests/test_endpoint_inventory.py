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

import pytest

from data_flow_analyser.endpoint_inventory import (
    host_is_excluded,
    inventory_flows,
    load_excluded_domains,
)
from data_flow_analyser.models.schemas import NetworkFlow


def _flow(host: str, path: str, method: str = "GET") -> NetworkFlow:
    return NetworkFlow(
        flow_id=f"{host}{path}{method}",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        method=method,
        url=f"https://{host}{path}",
        host=host,
        path=path,
    )


def test_inventory_groups_hosts_and_counts_methods_and_paths():
    result = inventory_flows([
        _flow("API.Example.org.", "/collect"),
        _flow("api.example.org", "/collect"),
        _flow("api.example.org", "/health", "POST"),
    ])

    assert result == [{
        "domain": "api.example.org",
        "flow_count": 3,
        "methods": {"GET": 2, "POST": 1},
        "paths": {"/collect": 2, "/health": 1},
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
    }]


def test_exclusions_match_domain_and_subdomains_but_not_similar_domains():
    excluded = load_excluded_domains({"domains": ["*.mozilla.org", "bitwarden.com"]})

    assert host_is_excluded("push.services.mozilla.org", excluded)
    assert host_is_excluded("BITWARDEN.COM.", excluded)
    assert not host_is_excluded("mozilla.org.example.com", excluded)


@pytest.mark.parametrize("value", [{"domains": "mozilla.org"}, {"hosts": ["mozilla.org"]}])
def test_exclusion_file_requires_domains_list(value):
    with pytest.raises(ValueError):
        load_excluded_domains(value)
