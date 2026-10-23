import re
import email.utils
from email.message import EmailMessage
from typing import List, Set, Optional
from datetime import datetime

from app.schemas.email import HopGeolocation
from app.services.geo_service import lookup_ip_geolocation

IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


def parse_received_timestamp(header_str: str) -> Optional[datetime]:
    """Extracts and parses date timestamp usually placed after ';' in Received headers."""
    if ";" in header_str:
        date_part = header_str.split(";")[-1].strip()
        try:
            return email.utils.parsedate_to_datetime(date_part)
        except Exception:
            return None
    return None


def analyze_network_hops(msg: EmailMessage) -> List[HopGeolocation]:
    """
    Parses all Received: headers and X-Originating-IP to reconstruct the network path.
    Enriches each hop with geographical coordinates, ISP, country, city, and hop transit delays.
    """
    hops: List[HopGeolocation] = []
    received_headers = msg.get_all("Received") or []

    # In email delivery, each intermediate MTA prepends a Received: header.
    # Reversing the order produces the true chronological path from sender to recipient.
    reversed_headers = list(reversed(received_headers))
    seen_ips: Set[str] = set()

    previous_time: Optional[datetime] = None
    hop_counter = 1

    for r_hdr in reversed_headers:
        r_str = str(r_hdr).replace("\n", " ").replace("\r", " ")

        # Extract IP addresses
        ips = IPV4_REGEX.findall(r_str)
        if not ips:
            continue

        # Extract 'from <host>'
        from_match = re.search(r'from\s+([^\s\(\)]+)', r_str, re.IGNORECASE)
        hostname = from_match.group(1) if from_match else None

        # Extract 'by <mta>'
        by_match = re.search(r'by\s+([^\s\(\);]+)', r_str, re.IGNORECASE)
        by_mta = by_match.group(1) if by_match else None

        # Extract 'with <protocol>'
        with_match = re.search(r'with\s+([^\s;]+)', r_str, re.IGNORECASE)
        protocol = with_match.group(1) if with_match else "SMTP"

        # Timestamp and delay calculation
        hop_time = parse_received_timestamp(r_str)
        delay_seconds: Optional[float] = None
        if hop_time and previous_time:
            diff = (hop_time - previous_time).total_seconds()
            delay_seconds = max(0.0, diff)
        if hop_time:
            previous_time = hop_time

        timestamp_formatted = hop_time.strftime("%Y-%m-%d %H:%M:%S UTC") if hop_time else None

        for ip in ips:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            # Query Geolocation Service
            geo_info = lookup_ip_geolocation(ip)

            hops.append(
                HopGeolocation(
                    ip=ip,
                    hop_index=hop_counter,
                    hostname=hostname,
                    by=by_mta,
                    protocol=protocol,
                    timestamp=timestamp_formatted,
                    delay_seconds=delay_seconds,
                    country=geo_info.get("country"),
                    country_code=geo_info.get("country_code"),
                    city=geo_info.get("city"),
                    region=geo_info.get("region"),
                    isp=geo_info.get("isp"),
                    org=geo_info.get("org"),
                    lat=geo_info.get("lat"),
                    lon=geo_info.get("lon"),
                    is_private=geo_info.get("is_private", False),
                )
            )
            hop_counter += 1

    # Check X-Originating-IP if present and not already seen
    x_origin = msg.get("X-Originating-IP", "")
    if x_origin:
        origin_ips = IPV4_REGEX.findall(str(x_origin))
        for ip in origin_ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                geo_info = lookup_ip_geolocation(ip)
                hops.insert(
                    0,
                    HopGeolocation(
                        ip=ip,
                        hop_index=1,
                        hostname="X-Originating-IP",
                        by=None,
                        protocol="Header",
                        timestamp=None,
                        delay_seconds=0.0,
                        country=geo_info.get("country"),
                        country_code=geo_info.get("country_code"),
                        city=geo_info.get("city"),
                        region=geo_info.get("region"),
                        isp=geo_info.get("isp"),
                        org=geo_info.get("org"),
                        lat=geo_info.get("lat"),
                        lon=geo_info.get("lon"),
                        is_private=geo_info.get("is_private", False),
                    )
                )

    # Clean sequential indexing
    for idx, h in enumerate(hops, 1):
        h.hop_index = idx

    return hops
