import email
from email import policy
from email.message import EmailMessage
import hashlib
import re
import urllib.parse
import ipaddress
from typing import List, Tuple, Optional, Set
from bs4 import BeautifulSoup
import tldextract

from app.schemas.email import (
    EmailAnalysisResult,
    AuthenticationStatus,
    ExtractedHeader,
    AttachmentMeta,
    ExtractedUrl,
    HopGeolocation,
    ThreatAssessment,
    RiskFactor,
)
from app.services.url_inspector import extract_and_inspect_urls
from app.services.hop_analyzer import analyze_network_hops
from app.services.threat_scorer import evaluate_email_threat

# Suspicious file extensions commonly found in phishing/malware delivery
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".iso", 
    ".img", ".wsf", ".ps1", ".jar", ".cpl", ".msi", ".dll"
}

# Regex patterns for URL & IP address extraction
URL_REGEX = re.compile(
    r'(?:(?:https?|ftp):\/\/)?'  # optional scheme
    r'(?:[a-zA-Z0-9_-]+(?::[a-zA-Z0-9_-]+)?@)?'  # optional credentials
    r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?'  # domain or FQDN
    r'(?:\/[^\s"<>{}\\|^~\[\]`]*)?',  # path/query
    re.IGNORECASE
)

# Strict IPv4 regex
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


def compute_hashes(content_bytes: bytes) -> Tuple[str, str]:
    """Calculate MD5 and SHA-256 cryptographic hashes for forensic integrity."""
    md5 = hashlib.md5(content_bytes).hexdigest()
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    return md5, sha256


def parse_authentication_results(msg: EmailMessage) -> AuthenticationStatus:
    """
    Examines Authentication-Results, Received-SPF, and DKIM-Signature headers
    to determine SPF, DKIM, and DMARC verification statuses.
    """
    auth_status = AuthenticationStatus(spf="NONE", dkim="NONE", dmarc="NONE", details=None)
    
    # 1. Inspect 'Authentication-Results' header
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        auth_status.details = auth_results
        auth_lower = auth_results.lower()
        
        # Check SPF
        if "spf=pass" in auth_lower:
            auth_status.spf = "PASS"
        elif "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
            auth_status.spf = "FAIL" if "spf=fail" in auth_lower else "SOFTFAIL"
        elif "spf=neutral" in auth_lower:
            auth_status.spf = "NEUTRAL"
            
        # Check DKIM
        if "dkim=pass" in auth_lower:
            auth_status.dkim = "PASS"
        elif "dkim=fail" in auth_lower:
            auth_status.dkim = "FAIL"

        # Check DMARC
        if "dmarc=pass" in auth_lower:
            auth_status.dmarc = "PASS"
        elif "dmarc=fail" in auth_lower:
            auth_status.dmarc = "FAIL"

    # 2. Check 'Received-SPF' header if SPF was not set yet
    if auth_status.spf == "NONE":
        spf_hdr = msg.get("Received-SPF", "")
        if spf_hdr:
            spf_lower = spf_hdr.lower()
            if "pass" in spf_lower:
                auth_status.spf = "PASS"
            elif "fail" in spf_lower:
                auth_status.spf = "FAIL"
            elif "softfail" in spf_lower:
                auth_status.spf = "SOFTFAIL"

    # 3. Check presence of DKIM-Signature header
    if auth_status.dkim == "NONE" and msg.get("DKIM-Signature"):
        auth_status.dkim = "PASS"  # Signed; full verification occurs on mail server

    return auth_status


def extract_urls(plain_body: str, html_body: str) -> List[ExtractedUrl]:
    """
    Extracts all unique URLs and domains found in both plaintext and HTML anchors.
    Flags suspicious indicators like IP-based hostnames or high-risk TLDs.
    """
    found_urls: Set[str] = set()

    # Extract href links from HTML body if available
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith(("http://", "https://", "ftp://")):
                    found_urls.add(href)
        except Exception:
            pass

    # Extract regex links from plaintext body
    if plain_body:
        for match in URL_REGEX.findall(plain_body):
            cleaned = match.strip().rstrip(".,;!?:")
            if cleaned.startswith(("http://", "https://")):
                found_urls.add(cleaned)
            elif not cleaned.startswith(("mailto:", "tel:")) and "." in cleaned:
                found_urls.add(f"http://{cleaned}")

    extracted_list: List[ExtractedUrl] = []
    suspicious_tlds = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "cam", "icu", "site"}

    for u in sorted(found_urls):
        try:
            parsed = urllib.parse.urlparse(u)
            extracted = tldextract.extract(u)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain or parsed.netloc

            is_suspicious = False
            reasons = []

            # Check if domain is a raw IP address
            host = parsed.hostname or extracted.domain
            if host and IPV4_REGEX.match(host):
                is_suspicious = True
                reasons.append("URL uses a raw IP address instead of a domain name")

            # Check for suspicious / commonly abused TLDs
            if extracted.suffix and extracted.suffix.lower() in suspicious_tlds:
                is_suspicious = True
                reasons.append(f"Domain uses high-abuse top-level domain (.{extracted.suffix})")

            # Check for embedded credentials or @ symbol in URL
            if "@" in parsed.netloc:
                is_suspicious = True
                reasons.append("URL contains embedded '@' credentials syntax (spoofing indicator)")

            extracted_list.append(
                ExtractedUrl(
                    url=u,
                    domain=domain or host or "unknown",
                    is_suspicious=is_suspicious,
                    reasons=reasons
                )
            )
        except Exception:
            continue

    return extracted_list


def extract_attachments_metadata(msg: EmailMessage) -> List[AttachmentMeta]:
    """Walks through the email payload to inspect and describe all attachments."""
    attachments: List[AttachmentMeta] = []

    for part in msg.walk():
        # Check if this part is an attachment
        filename = part.get_filename()
        content_disposition = part.get("Content-Disposition", "")
        
        if filename or "attachment" in content_disposition.lower():
            fname = filename or "unnamed_attachment"
            content_type = part.get_content_type()
            
            payload = part.get_payload(decode=True)
            size_bytes = len(payload) if payload else 0

            # Check for high-risk file extension
            is_suspicious = any(fname.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

            attachments.append(
                AttachmentMeta(
                    filename=fname,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    is_suspicious_extension=is_suspicious
                )
            )

    return attachments


def extract_body_contents(msg: EmailMessage) -> Tuple[str, str]:
    """Extracts plain text and HTML representations of the email body."""
    plain_text = ""
    html_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in content_disposition:
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if content_type == "text/plain" and not plain_text:
                        plain_text = decoded
                    elif content_type == "text/html" and not html_text:
                        html_text = decoded
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html_text = decoded
                else:
                    plain_text = decoded
        except Exception:
            pass

    # If only HTML exists, strip tags to populate plain text fallback
    if not plain_text and html_text:
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            plain_text = soup.get_text(separator="\n").strip()
        except Exception:
            pass

    return plain_text, html_text


def extract_ip_hops(msg: EmailMessage) -> List[HopGeolocation]:
    """
    Extracts network relay hops from Received: headers and X-Originating-IP.
    Identifies IPs, hostnames, and flags private vs public routable IPs.
    """
    hops: List[HopGeolocation] = []
    received_headers = msg.get_all("Received") or []
    
    # Received headers are prepended by each MTA.
    # Reversing gives chronological hop order from sending origin to recipient.
    hop_index = 1
    seen_ips: Set[str] = set()

    for r_hdr in reversed(received_headers):
        r_str = str(r_hdr)
        ips = IPV4_REGEX.findall(r_str)
        host_match = re.search(r'from\s+([a-zA-Z0-9.-]+)', r_str, re.IGNORECASE)
        hostname = host_match.group(1) if host_match else None

        for ip in ips:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            try:
                ip_obj = ipaddress.ip_address(ip)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
            except ValueError:
                continue

            hops.append(
                HopGeolocation(
                    ip=ip,
                    hop_index=hop_index,
                    hostname=hostname,
                    is_private=is_private,
                )
            )
            hop_index += 1

    # Check X-Originating-IP if present
    x_origin = msg.get("X-Originating-IP", "")
    if x_origin:
        ips = IPV4_REGEX.findall(str(x_origin))
        for ip in ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
                except ValueError:
                    continue
                hops.insert(
                    0,
                    HopGeolocation(
                        ip=ip,
                        hop_index=1,
                        hostname="X-Originating-IP",
                        is_private=is_private,
                    )
                )

    # Re-index hops sequentially
    for idx, hop in enumerate(hops, 1):
        hop.hop_index = idx

    return hops


def parse_email_message(content_bytes: bytes, filename: str = "email.eml") -> EmailAnalysisResult:
    """
    Core forensic parser: ingests raw email bytes, parses RFC 5322 structures,
    extracts headers, authentication status, URLs, attachments, and computes cryptographic hashes.
    """
    md5, sha256 = compute_hashes(content_bytes)

    # Parse message with standard library email parser
    msg: EmailMessage = email.message_from_bytes(content_bytes, policy=policy.default)

    # Extract all RFC headers as a key-value list
    headers: List[ExtractedHeader] = []
    for k, v in msg.items():
        headers.append(ExtractedHeader(name=k, value=str(v)))

    # Primary header fields
    subject = str(msg.get("Subject", "(No Subject)"))
    sender = str(msg.get("From", "Unknown Sender"))
    recipient = str(msg.get("To", "Unknown Recipient"))
    date_header = str(msg.get("Date", ""))
    reply_to = str(msg.get("Reply-To", "")) or None
    return_path = str(msg.get("Return-Path", "")) or None
    message_id = str(msg.get("Message-ID", "")) or None

    # Security authentication status
    auth_status = parse_authentication_results(msg)

    # Body parts
    plain_body, html_body = extract_body_contents(msg)

    # Extracted links & domains with threat intelligence
    urls = extract_and_inspect_urls(plain_body, html_body)

    # Attachments
    attachments = extract_attachments_metadata(msg)

    # IP Routing Hops with network delay and geolocation
    hops = analyze_network_hops(msg)

    # Comprehensive Threat Assessment & Explainable AI Engine
    threat_assessment = evaluate_email_threat(
        subject=subject,
        sender=sender,
        recipient=recipient,
        reply_to=reply_to,
        return_path=return_path,
        auth_status=auth_status,
        urls=urls,
        hops=hops,
        attachments=attachments,
        plain_body=plain_body,
        html_body=html_body,
    )

    # Create HTML snippet (safe preview, first 1000 chars)
    html_snippet = html_body[:1000] if html_body else None

    return EmailAnalysisResult(
        file_name=filename,
        md5=md5,
        sha256=sha256,
        subject=subject,
        sender=sender,
        recipient=recipient,
        date=date_header or None,
        reply_to=reply_to,
        return_path=return_path,
        message_id=message_id,
        authentication=auth_status,
        headers=headers,
        hops=hops,
        urls=urls,
        attachments=attachments,
        body_plain=plain_body,
        body_html_snippet=html_snippet,
        threat=threat_assessment,
    )
