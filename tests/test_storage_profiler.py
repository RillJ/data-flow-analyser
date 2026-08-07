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

from data_flow_analyser.engines.storage_profiler import StorageProfiler
from data_flow_analyser.models.schemas import (
    ConsentOutcome,
    ConsentPhase,
    DeclaredStorageItem,
    NetworkFlow,
)


def _flow(flow_id: str, timestamp: datetime, *, cookies_set=None, cookies_sent=None) -> NetworkFlow:
    return NetworkFlow(
        flow_id=flow_id,
        timestamp=timestamp,
        method="GET",
        url="https://tracker.example/collect",
        host="tracker.example",
        path="/collect",
        cookies_set=cookies_set or {},
        cookies_sent=cookies_sent or {},
    )


def test_storage_profiler_uses_first_cookie_observation_consent_phase():
    decided_at = datetime(2026, 8, 6, 10, tzinfo=timezone.utc)
    flows = [
        _flow(
            "before",
            datetime(2026, 8, 6, 9, 59, tzinfo=timezone.utc),
            cookies_set={"_ga": "abc"},
        ),
        _flow(
            "after",
            datetime(2026, 8, 6, 10, 1, tzinfo=timezone.utc),
            cookies_sent={"_ga": "abc"},
        ),
    ]

    result = StorageProfiler().reconcile_storage(
        flows,
        [],
        [DeclaredStorageItem(name="_ga")],
        consent_decided_at=decided_at,
        consent_outcome=ConsentOutcome.NECESSARY_ONLY,
    )[0]

    assert result.first_observed_phase == ConsentPhase.PRE_CONSENT
    assert result.first_observed_flow_id == "before"
    assert result.first_observed_at == datetime(2026, 8, 6, 9, 59, tzinfo=timezone.utc)
