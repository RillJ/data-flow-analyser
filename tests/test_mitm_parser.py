"""
Set TEST_MITM_FLOW_FILE in .env to point at your capture, or run it inline like:
    TEST_MITM_FLOW_FILE=path/to/capture.flows pytest tests/test_mitm_parser.py
"""

import os
from typing import List
import pytest

from data_flow_analyser.parsers.mitm_parser import parse_flow_file
from data_flow_analyser.models.schemas import NetworkFlow

from dotenv import load_dotenv
load_dotenv()

FLOW_FILE = os.environ.get("TEST_MITM_FLOW_FILE", ".env_files/test.flows")

pytestmark = pytest.mark.skipif(
    not os.path.exists(FLOW_FILE),
    reason=f"No flow file at '{FLOW_FILE}' (set TEST_MITM_FLOW_FILE to point at one)",
)


@pytest.fixture(scope="module")
def flows():
    return parse_flow_file(FLOW_FILE)


def test_parses_without_raising_and_returns_flows(flows):
    """Parsing the real capture should succeed and yield at least one flow."""
    assert isinstance(flows, list)
    assert len(flows) > 0
 
 
def test_every_flow_has_the_essentials(flows):
    """Each parsed flow should have the core fields downstream code relies on."""
    for flow in flows:
        assert isinstance(flow, NetworkFlow)
        assert flow.flow_id
        assert flow.method
        assert flow.url
        assert flow.host
        assert flow.path.startswith("/")
        assert isinstance(flow.request_headers, dict)
        assert isinstance(flow.response_headers, dict)
        assert isinstance(flow.cookies_sent, dict)
        assert isinstance(flow.cookies_set, dict)
 
 
def test_flow_ids_are_unique(flows):
    """flow_id is meant to uniquely identify a flow."""
    ids = [f.flow_id for f in flows]
    assert len(ids) == len(set(ids))
    