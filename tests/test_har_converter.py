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

from data_flow_analyser.parsers.har_converter import har_to_flows
from data_flow_analyser.parsers.mitm_parser import parse_flow_file


def test_har_is_converted_and_parsed(tmp_path):
    har_path = tmp_path / "capture.har"
    flows_path = tmp_path / "capture.flows"
    har_path.write_text(json.dumps({
        "log": {"entries": [{
            "startedDateTime": "2026-07-10T10:00:00.000Z",
            "time": 25,
            "request": {
                "method": "POST",
                "url": "https://example.test/collect",
                "headers": [
                    {"name": "Cookie", "value": "sid=abc"},
                    {"name": "X-Test", "value": "one"},
                ],
                "postData": {"text": "email=user%40example.test"},
            },
            "response": {
                "status": 201,
                "headers": [
                    {"name": "Set-Cookie", "value": "a=1"},
                    {"name": "Set-Cookie", "value": "b=2"},
                ],
                "content": {"text": "{\"ok\":true}"},
            },
        }]}
    }), encoding="utf-8")

    assert har_to_flows(har_path, flows_path) == 1
    flows = parse_flow_file(har_path)

    assert len(flows) == 1
    assert flows[0].method == "POST"
    assert flows[0].url == "https://example.test/collect"
    assert flows[0].response_status == 201
    assert flows[0].cookies_sent == {"sid": "abc"}
    assert flows[0].cookies_set == {"a": "1", "b": "2"}


def test_empty_har_is_supported(tmp_path):
    har_path = tmp_path / "empty.har"
    har_path.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")

    assert parse_flow_file(har_path) == []
