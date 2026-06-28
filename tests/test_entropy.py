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

from data_flow_analyser.engines.entropy import (
    calculate_shannon_entropy,
    parse_set_cookie_longevity,
    extract_high_entropy_tokens,
)


def test_shannon_entropy_calculation():
    # Low entropy human readable parameter
    low_entropy = calculate_shannon_entropy("session")
    assert low_entropy < 3.0

    # High entropy pseudorandom UUID string
    high_entropy = calculate_shannon_entropy("a8f9c2d1-4b3e-4f1a-9b2c-3d4e5f6a7b8c")
    assert high_entropy >= 3.5


def test_high_entropy_token_extraction():
    payload = {
        "action": "login_user",
        "visitor_id": "9xK#mP2$vL8q1Z4wY7bN0cQ",
        "meta": {
            "session_token": "4a8e2b9c1d0f3e7a6b5c4d2e1f0a9b8c"
        }
    }

    tokens = extract_high_entropy_tokens(payload, entropy_threshold=3.5)
    locations = [t.location for t in tokens]

    assert len(tokens) == 2
    assert "visitor_id" in locations
    assert "meta.session_token" in locations


def test_cookie_longevity_parsing_max_age():
    # 1-year cookie = 31,536,000 seconds (> 90 days)
    header = "tracking_id=xyz123; Max-Age=31536000; Path=/; Secure; SameSite=Lax"
    results = parse_set_cookie_longevity(header)

    assert len(results) == 1
    assert results[0].cookie_name == "tracking_id"
    assert results[0].lifespan_days == 365.0
    assert results[0].is_excessive_longevity is True


def test_cookie_longevity_short_lived():
    # 1-hour session cookie = 3600 seconds (< 90 days)
    header = "session=abc987; Max-Age=3600; Path=/"
    results = parse_set_cookie_longevity(header)

    assert len(results) == 1
    assert results[0].is_excessive_longevity is False