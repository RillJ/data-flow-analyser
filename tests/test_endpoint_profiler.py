import json
import pytest

from data_flow_analyser.engines.endpoint_profiler import DDGTrackerRadar, EndpointProfiler
from unittest.mock import patch, MagicMock
from urllib.error import URLError, HTTPError
from email.message import Message


def _mock_response(status=200, body=b""):
    """Build a context-manager-compatible mock for urllib.request.urlopen."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def test_fetch_and_cache_domain_uses_cache_without_hitting_network():
    """A domain already present in radar_data should be returned directly,
    with no request made to GitHub."""

    radar = DDGTrackerRadar({"doubleclick.net": {"entity": "Google LLC"}})

    with patch("urllib.request.urlopen") as mock_urlopen:
        result = radar.fetch_and_cache_domain("doubleclick.net")
        mock_urlopen.assert_not_called()

    assert result == {"entity": "Google LLC"}


def test_fetch_and_cache_domain_fetches_and_caches_on_success():
    """A successful fetch should hit the correct GitHub raw URL, cache the
    result, and return it."""

    radar = DDGTrackerRadar()
    response = _mock_response(200, json.dumps({"entity": "Meta", "category": "Social"}).encode())
    with patch("urllib.request.urlopen", return_value=response) as mock_urlopen:
        result = radar.fetch_and_cache_domain("facebook.net", region="US")
        requested_url = mock_urlopen.call_args[0][0].full_url

    assert requested_url == (
        "https://raw.githubusercontent.com/duckduckgo/tracker-radar/main"
        "/domains/US/facebook.net.json"
    )
    assert result == {"entity": "Meta", "category": "Social"}
    assert radar.radar_data["facebook.net"] == {"entity": "Meta", "category": "Social"}


@pytest.mark.parametrize("error", [
    HTTPError("url", 404, "Not Found", Message(), None),  # domain not in tracker radar
    URLError("no route to host"),                         # network failure
])
def test_fetch_and_cache_domain_returns_none_on_fetch_errors(error):
    """404s and network errors should be swallowed, returning None and
    leaving the domain uncached rather than raising."""

    radar = DDGTrackerRadar()

    with patch("urllib.request.urlopen", side_effect=error):
        result = radar.fetch_and_cache_domain("example.com")

    assert result is None
    assert "example.com" not in radar.radar_data


def test_fetch_and_cache_domain_returns_none_on_malformed_json():
    """A 200 response with invalid JSON should be treated like any other
    fetch failure: return None instead of raising."""

    radar = DDGTrackerRadar()
    response = _mock_response(200, b"not json{{{")

    with patch("urllib.request.urlopen", return_value=response):
        result = radar.fetch_and_cache_domain("broken.com")

    assert result is None


def test_is_known_tracker_with_auto_fetch_false_never_hits_network():
    """auto_fetch=False should be a pure cache lookup, never triggering a
    network call even for an unknown domain."""

    radar = DDGTrackerRadar()

    with patch("urllib.request.urlopen") as mock_urlopen:
        known = radar.is_known_tracker("unknown.com", auto_fetch=False)
        mock_urlopen.assert_not_called()

    assert known is False


def test_is_known_tracker_with_auto_fetch_true_fetches_and_caches():
    """auto_fetch=True should trigger a fetch for an uncached domain and
    report it as known if the fetch succeeds."""

    radar = DDGTrackerRadar()
    response = _mock_response(200, json.dumps({"entity": "X"}).encode())

    with patch("urllib.request.urlopen", return_value=response):
        known = radar.is_known_tracker("tracker.com", auto_fetch=True)

    assert known is True


def test_get_tracker_metadata_returns_cached_value_without_refetching():
    """Metadata for a domain already in the cache should be returned as-is,
    without triggering a fetch."""

    radar = DDGTrackerRadar({"cached.com": {"entity": "Cached Corp"}})

    with patch("urllib.request.urlopen") as mock_urlopen:
        meta = radar.get_tracker_metadata("cached.com")
        mock_urlopen.assert_not_called()

    assert meta == {"entity": "Cached Corp"}


def test_private_ip_profiling():
    """Private/local IPs should be classified as 'LOCAL' and never trigger
    a third-country transfer, regardless of base_location."""

    profiler = EndpointProfiler()
    endpoint = profiler.profile_endpoint(
        domain="internal-service.local",
        ip_address="192.168.1.50",
        base_location="NL"
    )

    assert endpoint.country_code == "LOCAL"
    assert endpoint.reverse_dns == "local_network"
    assert endpoint.is_third_country_transfer is False


def test_third_country_transfer_detection():
    """A public IP resolving outside the EU/EEA, with an EU/EEA base_location,
    should be flagged as a third-country transfer."""
    
    profiler = EndpointProfiler()
    # Mock GeoIP cache to avoid real network call during fast test run
    profiler._geoip_cache["8.8.8.8"] = {
        "country_code": "US",
        "asn_org": "Google LLC",
        "is_private": False
    }

    endpoint = profiler.profile_endpoint(
        domain="dns.google",
        ip_address="8.8.8.8",
        base_location="NL"
    )

    assert endpoint.country_code == "US"
    assert endpoint.asn_org == "Google LLC"
    assert endpoint.is_third_country_transfer is True  # NL (EU) > US transfer should be flagged


def test_non_eu_base_location_never_flags_transfer():
    """The transfer check is only meaningful when the deployment itself is
    based in the EU/EEA. A US-based instance shouldn't flag anything."""

    profiler = EndpointProfiler()
    profiler._geoip_cache["1.2.3.4"] = {
        "country_code": "CN", "asn_org": "Some ISP", "is_private": False
    }

    endpoint = profiler.profile_endpoint(
        domain="example.com", ip_address="1.2.3.4", base_location="US"
    )

    assert endpoint.is_third_country_transfer is False


def test_intra_eu_transfer_is_not_flagged():
    """NL > DE is a transfer between two EU/EEA countries and must not be
    flagged as a third-country transfer, even though the codes differ."""

    profiler = EndpointProfiler()
    profiler._geoip_cache["5.6.7.8"] = {
        "country_code": "DE", "asn_org": "Deutsche Telekom", "is_private": False
    }

    endpoint = profiler.profile_endpoint(
        domain="example.de", ip_address="5.6.7.8", base_location="NL"
    )

    assert endpoint.is_third_country_transfer is False


def test_profile_endpoint_without_ip_address():
    """With no IP given, all IP-derived fields should stay None instead of
    raising, and no transfer should be flagged."""

    profiler = EndpointProfiler()
    endpoint = profiler.profile_endpoint(domain="example.com", ip_address=None)

    assert endpoint.reverse_dns is None
    assert endpoint.country_code is None
    assert endpoint.asn_org is None
    assert endpoint.is_third_country_transfer is False


def test_geoip_lookup_falls_back_on_network_failure():
    """A timeout or other network error hitting ip-api.com should fall back
    to the default result rather than propagating."""

    profiler = EndpointProfiler()

    with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
        geo = profiler.lookup_ip_geolocation("9.9.9.9")

    assert geo == {"country_code": None, "asn_org": None, "is_private": False}