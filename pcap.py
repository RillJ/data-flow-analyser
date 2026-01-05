from scapy.all import PcapReader, IP, IPv6
from ipwhois import IPWhois
import geoip2.database
import socket
import ipaddress
import csv
from collections import defaultdict
from datetime import datetime

PCAP_FILE = "tcpdump-flows-4dec-clicking-around.pcap"
GEOIP_DB = "GeoLite2-City.mmdb"
OUTPUT_CSV = "pcap_destinations-clicking-around.csv"

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def geoip_lookup(reader, ip):
    try:
        r = reader.city(ip)
        return (
            r.country.name or "",
            r.city.name or "",
            r.location.latitude or "",
            r.location.longitude or "",
        )
    except Exception:
        return ("", "", "", "")


def whois_lookup(ip):
    try:
        data = IPWhois(ip).lookup_rdap(depth=1)
        return (
            data.get("asn", ""),
            data.get("asn_description", ""),
            data.get("network", {}).get("name", ""),
            data.get("network", {}).get("country", ""),
        )
    except Exception:
        return ("", "", "", "")


def extract_stats(pcap_path):
    stats = defaultdict(lambda: {
        "pkt_out": 0,
        "pkt_in": 0,
        "bytes_out": 0,
        "bytes_in": 0,
        "first_seen": None,
        "last_seen": None
    })

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            ts = float(pkt.time)
            size = len(pkt)

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            else:
                continue

            if is_public_ip(dst):
                entry = stats[dst]
                entry["pkt_out"] += 1
                entry["bytes_out"] += size
                entry["first_seen"] = ts if entry["first_seen"] is None else min(entry["first_seen"], ts)
                entry["last_seen"] = ts if entry["last_seen"] is None else max(entry["last_seen"], ts)

            if is_public_ip(src):
                entry = stats[src]
                entry["pkt_in"] += 1
                entry["bytes_in"] += size
                entry["first_seen"] = ts if entry["first_seen"] is None else min(entry["first_seen"], ts)
                entry["last_seen"] = ts if entry["last_seen"] is None else max(entry["last_seen"], ts)

    return stats


def main():
    stats = extract_stats(PCAP_FILE)
    geo_reader = geoip2.database.Reader(GEOIP_DB)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ip_address",
            "packet_count_outbound",
            "packet_count_inbound",
            "byte_count_outbound",
            "byte_count_inbound",
            "time_first_seen",
            "time_last_seen",
            "reverse_dns",
            "country",
            "city",
            "latitude",
            "longitude",
            "asn",
            "asn_org",
            "network_name",
            "whois_country"
        ])

        for ip, data in sorted(
            stats.items(),
            key=lambda x: x[1]["pkt_out"] + x[1]["pkt_in"],
            reverse=True
        ):
            rdns = reverse_dns(ip)
            country, city, lat, lon = geoip_lookup(geo_reader, ip)
            asn, asn_org, net_name, whois_country = whois_lookup(ip)

            writer.writerow([
                ip,
                data["pkt_out"],
                data["pkt_in"],
                data["bytes_out"],
                data["bytes_in"],
                datetime.utcfromtimestamp(data["first_seen"]).isoformat() if data["first_seen"] else "",
                datetime.utcfromtimestamp(data["last_seen"]).isoformat() if data["last_seen"] else "",
                rdns,
                country,
                city,
                lat,
                lon,
                asn,
                asn_org,
                net_name,
                whois_country
            ])

    geo_reader.close()
    print(f"CSV written to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()