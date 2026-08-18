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

from data_flow_analyser.engines.cookie_analysis import parse_set_cookie_longevity
from datetime import datetime, timezone


def test_cookie_longevity_parsing_max_age():
    # One-year cookie: report the observed duration without applying a threshold.
    header = "tracking_id=xyz123; Max-Age=31536000; Path=/; Secure; SameSite=Lax"
    results = parse_set_cookie_longevity(header)

    assert len(results) == 1
    assert results[0].cookie_name == "tracking_id"
    assert results[0].lifespan_days == 365.0
    assert results[0].lifespan_days == 365.0


def test_cookie_longevity_short_lived():
    # One-hour session cookie: report the observed duration.
    header = "session=abc987; Max-Age=3600; Path=/"
    results = parse_set_cookie_longevity(header)

    assert len(results) == 1
    assert results[0].lifespan_days == 0.04


def test_cookie_expiry_requires_explicit_reference_time():
    header = "tracking_id=xyz123; Expires=Wed, 01 Apr 2026 00:00:00 GMT; Path=/"

    without_reference = parse_set_cookie_longevity(header)
    assert without_reference[0].lifespan_days is None

    with_reference = parse_set_cookie_longevity(
        header,
        reference_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert with_reference[0].lifespan_days == 90.0
