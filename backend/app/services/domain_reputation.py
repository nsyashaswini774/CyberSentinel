import math
import re
import urllib.parse
from collections import Counter
from typing import Dict, List, Optional, Tuple
import tldextract

from app.schemas.email import DomainReputationDetails

# Target brands commonly spoofed in phishing and BEC attacks
HIGH_TARGET_BRANDS: Dict[str, str] = {
    "paypal": "PayPal",
    "microsoft": "Microsoft",
    "google": "Google",
    "apple": "Apple",
    "amazon": "Amazon",
    "netflix": "Netflix",
    "facebook": "Facebook",
    "meta": "Meta",
    "chase": "Chase Bank",
    "wellsfargo": "Wells Fargo",
    "bankofamerica": "Bank of America",
    "citibank": "Citibank",
    "adobe": "Adobe",
    "dropbox": "Dropbox",
    "dhl": "DHL Logistics",
    "fedex": "FedEx",
    "office365": "Office 365",
    "outlook": "Outlook",
}

# TLD Reputation Tiers
TRUSTED_TLDS = {"gov", "edu", "mil", "int"}
HIGH_ABUSE_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "cam", 
    "icu", "site", "work", "click", "link", "loan", "vip", "monster", 
    "fit", "rest", "bar", "surf", "casa", "kim", "sbs", "cfd", "pw", "cc"
}

# Number-to-letter leetspeak substitutions
LEET_SUBS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b'
}


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy of a string.
    Higher entropy (> 3.5 for standard domain names) indicates high randomness
    consistent with Domain Generation Algorithms (DGA) or disposable attack infrastructure.
    """
    if not text:
        return 0.0
    text_clean = text.lower().replace(".", "").replace("-", "")
    if not text_clean:
        return 0.0
    
    length = len(text_clean)
    counts = Counter(text_clean)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 2)


def normalize_leetspeak(s: str) -> str:
    """Translates common leetspeak substitutions to standard alphabetic characters."""
    return "".join(LEET_SUBS.get(c, c) for c in s.lower())


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes minimum single-character edits required to change one string into the other."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_brand_typosquatting(domain_sld: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Inspects domain second-level name for typosquatting or brand impersonation.
    Detects leetspeak substitutions (e.g. 'paypa1'), small edit distances, and hyphenated brand lures.
    """
    if not domain_sld:
        return False, None, None

    sld_clean = domain_sld.lower()
    sld_normalized = normalize_leetspeak(sld_clean)

    for brand_key, brand_name in HIGH_TARGET_BRANDS.items():
        # Exact match (Legitimate brand domain if on official TLD)
        if sld_clean == brand_key:
            return False, None, None

        # 1. Check for hyphenated or prefixed brand lure (e.g. 'paypal-security', 'login-microsoft')
        if brand_key in sld_clean:
            return True, brand_name, f"Domain embeds brand name '{brand_name}' with suspicious affixes"

        # 2. Check for leetspeak substitution (e.g. 'paypa1', 'micros0ft')
        if brand_key in sld_normalized:
            return True, brand_name, f"Typosquatting detected: Leetspeak substitution mimicking '{brand_name}'"

        # 3. Check small Levenshtein distance (1 edit off for words >= 5 chars, e.g. 'amazn', 'netflx')
        if len(brand_key) >= 5 and abs(len(sld_clean) - len(brand_key)) <= 1:
            dist = levenshtein_distance(sld_clean, brand_key)
            if dist == 1:
                return True, brand_name, f"Typosquatting detected: 1-character variation of '{brand_name}'"

    return False, None, None


def evaluate_domain_reputation(url: str, domain: str) -> DomainReputationDetails:
    """
    Executes deep forensic inspection on a domain:
      - Shannon entropy (DGA detection)
      - Typosquatting / Brand Impersonation
      - TLD Reputation
      - Transport Protocol & Port Safety
    """
    indicators: List[str] = []
    reputation_score = 0.0

    extracted = tldextract.extract(url)
    sld = extracted.domain.lower() if extracted.domain else ""
    tld = extracted.suffix.lower() if extracted.suffix else ""
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""

    parsed = urllib.parse.urlparse(url)

    # 1. Entropy analysis (DGA detection)
    entropy = calculate_shannon_entropy(sld)
    is_high_entropy = False
    if len(sld) >= 8 and entropy >= 3.6:
        is_high_entropy = True
        reputation_score += 30.0
        indicators.append(f"High Shannon entropy ({entropy}) indicates algorithmically generated or randomized domain (DGA)")

    # 2. Typosquatting & Brand Impersonation
    is_typo, brand, typo_reason = detect_brand_typosquatting(sld)
    if is_typo and brand:
        reputation_score += 45.0
        indicators.append(typo_reason or f"Suspected typosquatting targeting {brand}")
    elif subdomain:
        # Check if brand is impersonated in subdomain (e.g., 'paypal.com.attacker.xyz')
        for brand_key, brand_name in HIGH_TARGET_BRANDS.items():
            if brand_key in subdomain and brand_key not in sld:
                is_typo = True
                brand = brand_name
                reputation_score += 40.0
                indicators.append(f"Subdomain impersonates brand '{brand_name}' while root domain is '{domain}'")
                break

    # 3. TLD Reputation Tier
    if tld in TRUSTED_TLDS:
        tld_tier = "Trusted"
        reputation_score = max(0.0, reputation_score - 15.0)
    elif tld in HIGH_ABUSE_TLDS:
        tld_tier = "High-Abuse"
        reputation_score += 25.0
        indicators.append(f"Registered on high-abuse top-level domain (.{tld})")
    else:
        tld_tier = "Standard"

    # 4. Protocol & Port Safety
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port and port not in (80, 443):
        protocol_risk = f"Non-standard Port (:{port})"
        reputation_score += 20.0
        indicators.append(f"Connects via non-standard web port (:{port})")
    elif scheme == "http":
        protocol_risk = "Insecure (HTTP)"
        reputation_score += 10.0
        indicators.append("Unencrypted HTTP protocol without TLS encryption")
    else:
        protocol_risk = "Secure (HTTPS)"

    # Final score and verdict
    final_score = round(min(100.0, max(0.0, reputation_score)), 1)
    if final_score >= 60.0:
        verdict = "High Risk"
    elif final_score >= 35.0:
        verdict = "Suspicious"
    elif final_score >= 15.0:
        verdict = "Neutral"
    else:
        verdict = "Reputable"

    return DomainReputationDetails(
        entropy=entropy,
        is_high_entropy=is_high_entropy,
        impersonated_brand=brand,
        typosquatting_detected=is_typo,
        tld_reputation_tier=tld_tier,
        protocol_risk=protocol_risk,
        reputation_verdict=verdict,
        reputation_score=final_score,
        threat_indicators=indicators,
    )
