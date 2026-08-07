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

from base64 import b64encode
from datetime import datetime, timezone

from data_flow_analyser.engines.fingerprint_profiler import (
    FingerprintProfiler,
    classify_consent_phase,
)
from data_flow_analyser.models.schemas import ConsentOutcome, ConsentPhase, NetworkFlow


def _flow(flow_id: str, timestamp: datetime) -> NetworkFlow:
    payload = b64encode(
        b'{"canvas_hash":"e7b92f1a","webgl_renderer":"ANGLE Apple"}'
    ).decode()
    return NetworkFlow(
        flow_id=flow_id,
        timestamp=timestamp,
        method="POST",
        url="https://tracker.example/collect?sw=1920&sh=1080&tz=-120",
        host="tracker.example",
        path="/collect",
        request_headers={"User-Agent": "ExampleBrowser/1.0"},
        request_body=payload,
    )


def test_fingerprint_profiler_combines_query_header_and_decoded_body_attributes():
    profiler = FingerprintProfiler()
    vector = profiler.analyse_flow(
        _flow("flow-1", datetime(2026, 6, 27, 9, tzinfo=timezone.utc)),
        ConsentPhase.PRE_CONSENT,
    )

    assert vector.is_candidate is True
    assert set(vector.matched_categories) == {
        "canvas", "display", "hardware_os", "locale_time", "webgl"
    }
    assert {attribute.location for attribute in vector.attributes} == {
        "url_query", "request_headers", "request_body"
    }
    assert any(attribute.key.endswith("canvas_hash") for attribute in vector.attributes)


def test_fingerprint_profiler_reports_identical_vector_after_withdrawal():
    profiler = FingerprintProfiler()
    decided_at = datetime(2026, 6, 27, 10, tzinfo=timezone.utc)
    withdrawn_at = datetime(2026, 6, 27, 11, tzinfo=timezone.utc)
    flows = [
        _flow("flow-full-consent", datetime(2026, 6, 27, 10, 30, tzinfo=timezone.utc)),
        _flow("flow-withdrawn", datetime(2026, 6, 27, 11, 30, tzinfo=timezone.utc)),
    ]

    vectors, findings = profiler.analyse_flows(flows, decided_at, withdrawn_at, ConsentOutcome.NON_ESSENTIAL_GRANTED)

    assert len(vectors) == 2
    assert len(findings) == 1
    assert findings[0].observed_after_withdrawal is True
    assert findings[0].persists_after_withdrawal is True
    assert findings[0].observed_after_full_consent is True
    assert findings[0].persists_after_full_consent is False
    assert set(findings[0].observed_phases) == {
        ConsentPhase.FULL_CONSENT,
        ConsentPhase.WITHDRAWN,
    }


def test_fingerprint_profiler_reports_candidate_before_and_after_necessary_only_choice():
    profiler = FingerprintProfiler()
    decided_at = datetime(2026, 6, 27, 10, tzinfo=timezone.utc)
    flows = [
        _flow("flow-before", datetime(2026, 6, 27, 9, 30, tzinfo=timezone.utc)),
        _flow("flow-after-necessary-only", datetime(2026, 6, 27, 10, 30, tzinfo=timezone.utc)),
    ]

    vectors, findings = profiler.analyse_flows(flows, decided_at)

    assert [vector.consent_phase for vector in vectors] == [
        ConsentPhase.PRE_CONSENT,
        ConsentPhase.POST_DECISION_NECESSARY_ONLY,
    ]
    assert len(findings) == 1
    assert findings[0].observed_after_necessary_only is True
    assert findings[0].persists_after_necessary_only is True


def test_consent_phase_is_unknown_without_user_supplied_events():
    timestamp = datetime(2026, 6, 27, tzinfo=timezone.utc)
    assert classify_consent_phase(timestamp) == ConsentPhase.UNKNOWN


def test_fingerprint_signature_handles_lone_unicode_surrogates():
    profiler = FingerprintProfiler()
    flow = _flow("flow-malformed-unicode", datetime(2026, 6, 27, tzinfo=timezone.utc))
    flow.request_headers["User-Agent"] = "ExampleBrowser/1.0\udcfa"

    vector = profiler.analyse_flow(flow, ConsentPhase.UNKNOWN)

    assert len(vector.signature) == 64
