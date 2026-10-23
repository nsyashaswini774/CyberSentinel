import re
import urllib.parse
from typing import List, Dict, Tuple, Set, Optional
from bs4 import BeautifulSoup
import tldextract
from app.schemas.email import ExtractedUrl
from app.services.domain_reputation import evaluate_domain_reputation

# Common URL Shorteners used to mask malicious destinations
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "cutt.ly", "rb.gy", 
    "shorturl.at", "tiny.cc", "lnkd.in", "rebrand.ly"
}

# High-abuse Top-Level Domains frequently utilized in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "cam", 
    "icu", "site", "work", "click", "link", "loan", "vip", "monster", 
    "fit", "rest", "bar", "surf", "casa", "kim", "sbs", "cfd"
}

# Keywords indicative of credential harvesting or urgent phishing
PHISHING_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "security",
    "password", "banking", "secure", "update", "credential", "wallet",
    "authenticate", "confirm", "billing", "authorize", "reset"
}

IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

URL_REGEX = re.compile(
    r'(?:(?:https?|ftp):\/\/)'
    r'(?:[a-zA-Z0-9_-]+(?::[a-zA-Z0-9_-]+)?@)?'
    r'(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
    r'(?::\d+)?'
    r'(?:\/[^\s"<>{}\\|^~\[\]`]*)?'
    r'|'
    r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s"<>{}\\|^~\[\]`]*)?',
    re.IGNORECASE
)

# Homograph character detection (Cyrillic/Greek characters commonly substituted for Latin)
CONFUSABLE_HOMOGLYPHS = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j',
    '\u03bf': 'o', '\u03c1': 'p', '\u03b1': 'a', '\u03b5': 'e',
}


def detect_homograph(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Detects IDN Punycode domains (xn--) or international characters masquerading as ASCII.
    """
    if not domain:
        return False, None

    if "xn--" in domain.lower():
        try:
            decoded = domain.encode("ascii").decode("idna")
            return True, f"IDN Punycode domain detected (resolves to: {decoded})"
        except Exception:
            return True, "Suspicious IDN Punycode encoded domain (xn--)"

    for char in domain:
        if char in CONFUSABLE_HOMOGLYPHS:
            return True, f"Homoglyph character detected: '{char}' (confusable with Latin '{CONFUSABLE_HOMOGLYPHS[char]}')"

    return False, None


def inspect_single_url(url: str, anchor_text: Optional[str] = None) -> ExtractedUrl:
    """
    Performs forensic inspection on a single URL.
    Identifies IP hosts, shorteners, homographs, suspicious TLDs, credential spoofing, and anchor mismatches.
    """
    reasons: List[str] = []
    risk_score = 0.0
    threat_category = "Benign"
    is_shortener = False
    has_homograph = False

    try:
        parsed = urllib.parse.urlparse(url)
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain or parsed.netloc
        host = parsed.hostname or extracted.domain or ""
    except Exception:
        return ExtractedUrl(
            url=url,
            domain="invalid",
            anchor_text=anchor_text,
            is_suspicious=True,
            risk_score=50.0,
            threat_category="Malformed URL",
            reasons=["Malformed or unparseable URL structure"]
        )

    # 1. Check for raw IP address in host
    if host and IPV4_REGEX.match(host):
        risk_score += 40.0
        reasons.append("URL points directly to a raw IP address instead of a registered domain")
        threat_category = "Phishing / Direct IP"

    # 2. Check for URL Shorteners
    domain_lower = domain.lower()
    if domain_lower in KNOWN_SHORTENERS or any(domain_lower.endswith("." + s) for s in KNOWN_SHORTENERS):
        is_shortener = True
        risk_score += 25.0
        reasons.append(f"URL uses shortening service ({domain}) to obscure true destination")
        threat_category = "URL Shortener / Obfuscation"

    # 3. Check for Punycode / Homograph spoofing
    homograph_detected, homograph_reason = detect_homograph(host)
    if homograph_detected:
        has_homograph = True
        risk_score += 45.0
        reasons.append(homograph_reason or "IDN Homograph attack indicator detected")
        threat_category = "Brand Impersonation / Homograph"

    # 4. Check for high-abuse TLDs
    suffix = extracted.suffix.lower() if extracted.suffix else ""
    if suffix in SUSPICIOUS_TLDS:
        risk_score += 25.0
        reasons.append(f"Domain uses high-abuse top-level domain (.{suffix})")
        if threat_category == "Benign":
            threat_category = "Suspicious Domain"

    # 5. Check for credential spoofing via '@' in URL authority
    if "@" in parsed.netloc:
        risk_score += 40.0
        reasons.append("URL contains '@' credential notation used to conceal actual destination host")
        threat_category = "Credential Spoofing"

    # 6. Check for Anchor Text Mismatch (Phishing tactic)
    if anchor_text:
        anchor_clean = anchor_text.strip().lower()
        # If anchor text looks like a domain / URL
        if "." in anchor_clean and not " " in anchor_clean:
            try:
                anchor_extracted = tldextract.extract(anchor_clean)
                anchor_domain = f"{anchor_extracted.domain}.{anchor_extracted.suffix}" if anchor_extracted.suffix else anchor_extracted.domain
                if anchor_domain and domain_lower and anchor_domain != domain_lower:
                    risk_score += 45.0
                    reasons.append(
                        f"Anchor text displays '{anchor_text}' but the link actually navigates to '{domain}'"
                    )
                    threat_category = "Deceptive Link / Mismatched Anchor"
            except Exception:
                pass

    # 7. Check for phishing keywords in URL path or query
    path_and_query = (parsed.path + " " + parsed.query).lower()
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in path_and_query]
    if matched_keywords:
        risk_score += min(20.0, len(matched_keywords) * 10.0)
        reasons.append(f"URL path/parameters contain sensitive keywords: {', '.join(matched_keywords[:3])}")
        if threat_category == "Benign":
            threat_category = "Suspicious Keyword"

    # 8. Check for excessive length / subdomain nesting (evasion / DGA indicator)
    if len(extracted.subdomain.split(".")) > 3:
        risk_score += 15.0
        reasons.append("Excessive subdomain nesting indicative of evasion tactics or DNS tunneling")

    # 9. Deep Domain Reputation & Typosquatting Analysis
    rep_details = evaluate_domain_reputation(url, domain or host)
    for ind in rep_details.threat_indicators:
        if ind not in reasons:
            reasons.append(ind)

    if rep_details.typosquatting_detected and rep_details.impersonated_brand:
        risk_score += 35.0
        threat_category = f"Brand Impersonation ({rep_details.impersonated_brand})"
    elif rep_details.is_high_entropy:
        risk_score += 25.0
        if threat_category == "Benign":
            threat_category = "Algorithmically Generated (DGA)"

    # Final score clamping and classification
    final_score = min(100.0, max(0.0, risk_score))
    is_suspicious = final_score >= 25.0

    return ExtractedUrl(
        url=url,
        domain=domain or host or "unknown",
        anchor_text=anchor_text,
        is_suspicious=is_suspicious,
        risk_score=round(final_score, 1),
        threat_category=threat_category if is_suspicious else "Benign",
        is_shortener=is_shortener,
        has_homograph=has_homograph,
        reputation=rep_details,
        reasons=reasons
    )


def extract_and_inspect_urls(plain_body: str, html_body: str) -> List[ExtractedUrl]:
    """
    Extracts all URLs from HTML anchors (capturing anchor text) and plaintext body,
    runs comprehensive threat inspection, and returns deduplicated results.
    """
    url_map: Dict[str, Tuple[str, Optional[str]]] = {}

    # 1. Parse HTML links and anchor text
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                anchor_text = a.get_text().strip() or None
                if href.startswith(("http://", "https://", "ftp://")):
                    if href not in url_map:
                        url_map[href] = (href, anchor_text)
                    elif not url_map[href][1] and anchor_text:
                        url_map[href] = (href, anchor_text)

            # Also extract unlinked URLs from the HTML text content
            html_text = soup.get_text()
            for match in URL_REGEX.findall(html_text):
                cleaned = match.strip().rstrip(".,;!?:")
                full_url = cleaned
                if not cleaned.startswith(("http://", "https://")):
                    if not cleaned.startswith(("mailto:", "tel:")) and "." in cleaned:
                        full_url = f"http://{cleaned}"
                    else:
                        continue
                if full_url not in url_map:
                    url_map[full_url] = (full_url, None)
        except Exception:
            pass

    # 2. Parse plaintext URLs
    if plain_body:
        for match in URL_REGEX.findall(plain_body):
            cleaned = match.strip().rstrip(".,;!?:")
            full_url = cleaned
            if not cleaned.startswith(("http://", "https://")):
                if not cleaned.startswith(("mailto:", "tel:")) and "." in cleaned:
                    full_url = f"http://{cleaned}"
                else:
                    continue

            if full_url not in url_map:
                url_map[full_url] = (full_url, None)

    results: List[ExtractedUrl] = []
    for raw_url, (url, anchor) in url_map.items():
        inspected = inspect_single_url(url, anchor_text=anchor)
        results.append(inspected)

    # Sort so suspicious URLs appear first, then by risk score descending
    results.sort(key=lambda x: (not x.is_suspicious, -x.risk_score))
    return results
