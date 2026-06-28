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

import ipaddress
import json
import logging
from pathlib import Path
import socket
from typing import Any, Dict, Optional, Tuple
import urllib.error
import urllib.request

from data_flow_analyser.models.schemas import ObservedEndpoint

# List of EU/EEA country codes for third-country transfer checks. Source: https://www.netherlandsworldwide.nl/eu-eea-efta-schengen-countries
EU_EEA_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE", "NO", "IS", "LI"
}

logger = logging.getLogger(__name__)


class DDGTrackerRadar:
    """
    Interface for querying DuckDuckGo Tracker Radar domain data and entity mappings.
    Supports suffix matching and live fetching from GitHub.
    """

    GITHUB_RAW_BASE = "https://raw.githubusercontent.com/duckduckgo/tracker-radar/main"

    def __init__(self, radar_data: Optional[Dict[str, Any]] = None):
        # Maps domain name -> domain metadata dict
        self.radar_data: Dict[str, Any] = radar_data or {}

    @classmethod
    def load_from_directory(cls, dir_path: str) -> "DDGTrackerRadar":
        """
        Loads Tracker Radar domain JSON files from a local directory (e.g. cloned tracker-radar repo).
        """
        radar_map: Dict[str, Any] = {}
        target_dir = Path(dir_path)

        if not target_dir.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        for json_file in target_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    domain = data.get("domain") or json_file.stem
                    radar_map[domain.lower()] = data
            except (json.JSONDecodeError, OSError):
                continue

        return cls(radar_data=radar_map)


    def fetch_and_cache_domain(self, domain: str, region: str = "US") -> Optional[Dict[str, Any]]:
        """
        Dynamically fetches tracker metadata for a single domain from GitHub raw assets.
        Caches result in self.radar_data.
        """
        domain_clean = domain.lower().strip()
        if domain_clean in self.radar_data:
            logger.debug("Tracker Radar cache hit: domain=%s", domain_clean)
            return self.radar_data[domain_clean]

        url = f"{self.GITHUB_RAW_BASE}/domains/{region}/{domain_clean}.json"
        
        try:
            logger.debug("Tracker Radar lookup: domain=%s region=%s", domain_clean, region)
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "DataFlowAnalyser/1.0 (Academic Research)"}
            )
            with urllib.request.urlopen(req, timeout=2.5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    self.radar_data[domain_clean] = data
                    logger.debug(
                        "Tracker Radar result: domain=%s owner=%s categories=%s",
                        domain_clean,
                        data.get("owner", {}).get("name") if isinstance(data.get("owner"), dict) else data.get("entity"),
                        data.get("categories") or data.get("category"),
                    )
                    return data
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as error:
            logger.debug("Tracker Radar lookup failed: domain=%s error=%s", domain_clean, error)

        return None


    def get_tracker_metadata(self, domain: str, auto_fetch: bool = True) -> Optional[Dict[str, Any]]:
        """
        Returns DDG Tracker Radar metadata for an exact domain string.
        """
        domain_clean = domain.lower().strip()

        if domain_clean in self.radar_data:
            return self.radar_data[domain_clean]

        if auto_fetch:
            return self.fetch_and_cache_domain(domain_clean)

        return None


    def lookup_domain(self, domain: str, auto_fetch: bool = True) -> Tuple[Optional[str], str]:
        """
        Performs domain & suffix lookup (e.g. 'sub.ad.doubleclick.net' -> 'doubleclick.net').
        
        Returns:
            Tuple of (parent_entity_name, category)
        """
        clean_domain = domain.lower().strip()
        parts = clean_domain.split(".")

        # Walk down domain hierarchy: sub.ad.doubleclick.net > ad.doubleclick.net -> doubleclick.net
        for i in range(len(parts) - 1):
            sub_domain = ".".join(parts[i:])
            logger.debug("Tracker Radar suffix candidate: input=%s candidate=%s", clean_domain, sub_domain)
            
            meta = self.get_tracker_metadata(sub_domain, auto_fetch=auto_fetch)
            if meta:
                # Extract parent entity (handles DDG schema 'owner.name' or dictionary 'entity')
                entity: Optional[str] = None
                if isinstance(meta.get("owner"), dict):
                    entity = meta["owner"].get("name")
                if not entity and isinstance(meta.get("entity"), str):
                    entity = meta["entity"]

                # Extract category guaranteed to be a str
                category: str = "third_party_tracker"
                categories = meta.get("categories")
                if isinstance(categories, list) and len(categories) > 0 and isinstance(categories[0], str):
                    category = categories[0]
                elif isinstance(meta.get("category"), str):
                    category = meta["category"]

                logger.debug(
                    "Tracker Radar matched: input=%s matched_domain=%s entity=%s category=%s",
                    clean_domain, sub_domain, entity, category,
                )
                return entity, category

        logger.debug("Tracker Radar no match: domain=%s", clean_domain)
        return None, "unknown"


    def is_known_tracker(self, domain: str, auto_fetch: bool = True) -> bool:
        """Checks if a domain or its parent root is registered as a tracker."""
        entity, _ = self.lookup_domain(domain, auto_fetch=auto_fetch)
        return entity is not None


class EndpointProfiler:
    """Enriches IP addresses and domains with Reverse DNS, GeoIP, ASN, and Tracker Metadata."""

    def __init__(self, tracker_radar: Optional[DDGTrackerRadar] = None):
        self.tracker_radar = tracker_radar or DDGTrackerRadar()
        self._dns_cache: Dict[str, Optional[str]] = {}
        self._geoip_cache: Dict[str, Dict[str, Any]] = {}
        self._domain_ip_cache: Dict[str, Optional[str]] = {}

    def resolve_domain_ip(self, domain: str) -> Optional[str]:
        """Resolve a domain to a representative address for IP enrichment."""
        domain_clean = domain.strip().lower()
        if domain_clean in self._domain_ip_cache:
            logger.debug("Domain resolution cache hit: domain=%s ip=%s", domain_clean, self._domain_ip_cache[domain_clean])
            return self._domain_ip_cache[domain_clean]

        try:
            addresses = socket.getaddrinfo(domain_clean, 443, type=socket.SOCK_STREAM)
            candidates: list[str] = []
            for item in addresses:
                sockaddr = item[4]
                if isinstance(sockaddr, tuple) and sockaddr and isinstance(sockaddr[0], str):
                    candidates.append(sockaddr[0])
            # Prefer IPv4 because the configured GeoIP provider handles it most consistently.
            ip_address = next((ip for ip in candidates if "." in ip), candidates[0] if candidates else None)
            self._domain_ip_cache[domain_clean] = ip_address
            logger.debug("Domain resolution result: domain=%s ip=%s candidates=%d", domain_clean, ip_address, len(candidates))
            return ip_address
        except (OSError, socket.gaierror) as error:
            self._domain_ip_cache[domain_clean] = None
            logger.debug("Domain resolution failed: domain=%s error=%s", domain_clean, error)
            return None


    def resolve_reverse_dns(self, ip_address: str) -> Optional[str]:
        """Performs PTR record lookup for an IP address with caching."""
        if ip_address in self._dns_cache:
            logger.debug("Reverse DNS cache hit: ip=%s hostname=%s", ip_address, self._dns_cache[ip_address])
            return self._dns_cache[ip_address]

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                res = "localhost" if ip_obj.is_loopback else "local_network"
                self._dns_cache[ip_address] = res
                logger.debug("Reverse DNS local address: ip=%s hostname=%s", ip_address, res)
                return res

            hostname, _, _ = socket.gethostbyaddr(ip_address)
            self._dns_cache[ip_address] = hostname
            logger.debug("Reverse DNS result: ip=%s hostname=%s", ip_address, hostname)
            return hostname
        except Exception as error:
            self._dns_cache[ip_address] = None
            logger.debug("Reverse DNS failed: ip=%s error=%s", ip_address, error)
            return None


    def lookup_ip_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Looks up country code and ASN organization for an IP address."""
        if ip_address in self._geoip_cache:
            logger.debug("GeoIP cache hit: ip=%s result=%s", ip_address, self._geoip_cache[ip_address])
            return self._geoip_cache[ip_address]

        default_result = {"country_code": None, "asn_org": None, "is_private": False}

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                default_result.update({"country_code": "LOCAL", "asn_org": "Private Network", "is_private": True})
                self._geoip_cache[ip_address] = default_result
                logger.debug("GeoIP local address: ip=%s result=%s", ip_address, default_result)
                return default_result

            url = f"http://ip-api.com/json/{ip_address}?fields=status,countryCode,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "data-flow-analyser/1.0"})
            
            with urllib.request.urlopen(req, timeout=2.0) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    if data.get("status") == "success":
                        res = {
                            "country_code": data.get("countryCode"),
                            "asn_org": data.get("org") or data.get("as"),
                            "is_private": False
                        }
                        self._geoip_cache[ip_address] = res
                        logger.debug("GeoIP result: ip=%s result=%s", ip_address, res)
                        return res
        except Exception as error:
            logger.debug("GeoIP lookup failed: ip=%s error=%s", ip_address, error)

        self._geoip_cache[ip_address] = default_result
        logger.debug("GeoIP fallback result: ip=%s result=%s", ip_address, default_result)
        return default_result


    def profile_endpoint(
        self,
        domain: str,
        ip_address: Optional[str] = None,
        base_location: str = "NL",
        auto_fetch_tracker: bool = True,
        resolve_domain: bool = False,
    ) -> ObservedEndpoint:
        """
        Combines Tracker Radar, Reverse DNS, and GeoIP lookups to build an ObservedEndpoint.
        """
        parent_entity, category = self.tracker_radar.lookup_domain(
            domain, 
            auto_fetch=auto_fetch_tracker
        )
        reverse_dns = None
        country_code = None
        asn_org = None

        if not ip_address and resolve_domain:
            ip_address = self.resolve_domain_ip(domain)

        if ip_address:
            reverse_dns = self.resolve_reverse_dns(ip_address)
            geo_info = self.lookup_ip_geolocation(ip_address)
            country_code = geo_info.get("country_code")
            asn_org = geo_info.get("asn_org")
        else:
            logger.debug("Endpoint profiling: no resolvable IP, skipping reverse DNS and GeoIP: domain=%s", domain)

        is_third_country = False
        if country_code and country_code not in ("LOCAL", None):
            if base_location in EU_EEA_COUNTRIES and country_code not in EU_EEA_COUNTRIES:
                is_third_country = True

        endpoint = ObservedEndpoint(
            domain=domain,
            ip_address=ip_address,
            reverse_dns=reverse_dns,
            parent_entity=parent_entity,
            category=category,
            country_code=country_code,
            asn_org=asn_org,
            is_third_country_transfer=is_third_country,
            is_undocumented=False,
        )

        logger.debug("Endpoint profiler final result: %s", endpoint.model_dump())
        return endpoint
