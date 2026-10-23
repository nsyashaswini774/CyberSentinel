from typing import List, Dict, Any, Optional
from app.schemas.email import (
    AuthenticationStatus,
    ExtractedUrl,
    HopGeolocation,
    AttachmentMeta,
    RiskFactor,
    ThreatAssessment,
    ThreatSubscores,
)
from app.services.ai_detector import analyze_email_intent


def evaluate_email_threat(
    subject: str,
    sender: str,
    recipient: str,
    reply_to: Optional[str],
    return_path: Optional[str],
    auth_status: AuthenticationStatus,
    urls: List[ExtractedUrl],
    hops: List[HopGeolocation],
    attachments: List[AttachmentMeta],
    plain_body: str,
    html_body: str,
) -> ThreatAssessment:
    """
    Comprehensive Threat Scoring & Explainable AI Engine.
    Evaluates 5 forensic dimensions:
      1. Authentication & Spoofing (max 25)
      2. URLs & Domain Intelligence (max 25)
      3. AI Content & Social Engineering Intent (max 25)
      4. Network Routing & Origin Geolocation (max 15)
      5. Malicious Attachments (max 10)
    Returns a unified ThreatAssessment with subscores and human-readable explainability.
    """
    risk_factors: List[RiskFactor] = []
    explanation_points: List[str] = []

    # =========================================================================
    # Dimension 1: Authentication & Header Spoofing (Max 25 pts)
    # =========================================================================
    auth_points = 0.0

    if auth_status.spf == "FAIL":
        auth_points += 15.0
        risk_factors.append(
            RiskFactor(
                rule="SPF_FAIL",
                severity="HIGH",
                points=15.0,
                description="SPF verification failed: Sending server is unauthorized to transmit on behalf of the domain."
            )
        )
        explanation_points.append("SPF check failed: The transmitting mail server is not authorized by the sender's domain DNS.")
    elif auth_status.spf == "SOFTFAIL":
        auth_points += 8.0
        risk_factors.append(
            RiskFactor(
                rule="SPF_SOFTFAIL",
                severity="MEDIUM",
                points=8.0,
                description="SPF check softfailed: Sending server is likely unauthorized."
            )
        )

    if auth_status.dkim == "FAIL":
        auth_points += 12.0
        risk_factors.append(
            RiskFactor(
                rule="DKIM_FAIL",
                severity="HIGH",
                points=12.0,
                description="DKIM cryptographic signature verification failed: Email contents or headers may have been tampered with in transit."
            )
        )
        explanation_points.append("DKIM cryptographic signature validation failed: Indicates header tampering or spoofed sender identity.")

    if auth_status.dmarc == "FAIL":
        auth_points += 15.0
        risk_factors.append(
            RiskFactor(
                rule="DMARC_FAIL",
                severity="HIGH",
                points=15.0,
                description="DMARC alignment check failed: Domain policy rejects sender alignment."
            )
        )

    # Reply-To domain mismatch check
    if reply_to and sender:
        sender_clean = sender.split("@")[-1].replace(">", "").strip().lower()
        reply_clean = reply_to.split("@")[-1].replace(">", "").strip().lower()
        if sender_clean and reply_clean and sender_clean != reply_clean:
            auth_points += 10.0
            risk_factors.append(
                RiskFactor(
                    rule="REPLY_TO_MISMATCH",
                    severity="MEDIUM",
                    points=10.0,
                    description=f"Reply-To destination ({reply_clean}) diverts responses away from sender domain ({sender_clean})."
                )
            )
            explanation_points.append(f"Mismatched Reply-To address ({reply_to}) diverts responses away from the claimed sender ({sender}).")

    # Display Name Spoofing heuristic (e.g. Display says 'Microsoft Support' but domain is 'evil.xyz')
    brand_keywords = ["microsoft", "google", "paypal", "apple", "amazon", "bank", "support", "helpdesk", "security"]
    sender_lower = sender.lower()
    for brand in brand_keywords:
        if brand in sender_lower:
            sender_domain = sender_lower.split("@")[-1].replace(">", "").strip() if "@" in sender_lower else ""
            if sender_domain and brand not in sender_domain:
                auth_points += 10.0
                risk_factors.append(
                    RiskFactor(
                        rule="DISPLAY_NAME_SPOOFING",
                        severity="HIGH",
                        points=10.0,
                        description=f"Display name references '{brand}' but sending domain is '{sender_domain}'."
                    )
                )
                explanation_points.append(f"Display name masquerades as '{brand}' while sending from an unrelated external domain ({sender_domain}).")
                break

    auth_subscore = min(25.0, auth_points)

    # =========================================================================
    # Dimension 2: URLs & Domain Intelligence (Max 25 pts)
    # =========================================================================
    url_points = 0.0

    # Homograph attacks
    homograph_urls = [u for u in urls if u.has_homograph]
    if homograph_urls:
        url_points += 25.0
        risk_factors.append(
            RiskFactor(
                rule="HOMOGRAPH_ATTACK",
                severity="CRITICAL",
                points=25.0,
                description=f"Detected IDN Punycode or homoglyph character impersonation in URL ({homograph_urls[0].domain})."
            )
        )
        explanation_points.append(f"IDN Punycode / Homograph domain impersonation detected ({homograph_urls[0].domain}) designed to deceive users.")

    # Mismatched deceptive anchor text
    mismatched_urls = [u for u in urls if any("Anchor text displays" in r for r in u.reasons)]
    if mismatched_urls:
        url_points += 20.0
        risk_factors.append(
            RiskFactor(
                rule="MISMATCHED_ANCHOR",
                severity="HIGH",
                points=20.0,
                description="Deceptive link detected: Anchor text displays a legitimate domain while href points elsewhere."
            )
        )
        explanation_points.append("Deceptive anchor link detected: Visible text displays a trusted domain while the actual link points to an external site.")

    # Raw IP host
    raw_ip_urls = [u for u in urls if any("raw IP" in r for r in u.reasons)]
    if raw_ip_urls:
        url_points += 18.0
        risk_factors.append(
            RiskFactor(
                rule="RAW_IP_URL",
                severity="HIGH",
                points=18.0,
                description=f"URL links directly to a raw IP address ({raw_ip_urls[0].domain}) bypassing standard domain reputation."
            )
        )
        explanation_points.append(f"Hyperlink points directly to a raw IP address ({raw_ip_urls[0].domain}) commonly seen in phishing infrastructure.")

    # URL Shorteners
    shortener_urls = [u for u in urls if u.is_shortener]
    if shortener_urls:
        url_points += 12.0
        risk_factors.append(
            RiskFactor(
                rule="URL_SHORTENER",
                severity="MEDIUM",
                points=12.0,
                description=f"Detected {len(shortener_urls)} shortened link(s) concealing destination endpoint."
            )
        )
        explanation_points.append(f"URL shortener detected ({shortener_urls[0].domain}) obscuring final web destination.")

    # High-abuse TLDs
    suspicious_tld_urls = [u for u in urls if any("high-abuse top-level domain" in r for r in u.reasons)]
    if suspicious_tld_urls:
        url_points += 10.0
        risk_factors.append(
            RiskFactor(
                rule="SUSPICIOUS_TLD",
                severity="MEDIUM",
                points=10.0,
                description=f"Hyperlinks utilize high-abuse top-level domains ({suspicious_tld_urls[0].domain})."
            )
        )

    # Typosquatting / Brand Impersonation
    typo_urls = [u for u in urls if u.reputation and u.reputation.typosquatting_detected]
    if typo_urls:
        url_points += 25.0
        brand = typo_urls[0].reputation.impersonated_brand or "Major Brand"
        risk_factors.append(
            RiskFactor(
                rule="BRAND_TYPOSQUATTING",
                severity="CRITICAL",
                points=25.0,
                description=f"Brand typosquatting detected targeting {brand} ({typo_urls[0].domain})."
            )
        )
        explanation_points.append(f"Domain Typosquatting / Impersonation: Hyperlink targets '{brand}' using deceptive character substitutions ({typo_urls[0].domain}).")

    # High Shannon Entropy (DGA / Disposable domains)
    entropy_urls = [u for u in urls if u.reputation and u.reputation.is_high_entropy]
    if entropy_urls:
        url_points += 15.0
        risk_factors.append(
            RiskFactor(
                rule="HIGH_ENTROPY_DGA",
                severity="HIGH",
                points=15.0,
                description=f"Algorithmically generated domain (DGA) pattern detected: {entropy_urls[0].domain} has high Shannon entropy ({entropy_urls[0].reputation.entropy})."
            )
        )
        explanation_points.append(f"High-entropy randomized domain detected ({entropy_urls[0].domain}) indicative of disposable DGA attack infrastructure.")

    url_subscore = min(25.0, url_points)

    # =========================================================================
    # Dimension 3: AI Content & Social Engineering Intent (Max 25 pts)
    # =========================================================================
    ai_result = analyze_email_intent(subject, plain_body or html_body)
    ai_subscore = ai_result["ai_content_score"]
    ai_confidence = ai_result["ai_confidence"]
    intent_category = ai_result["intent_category"]
    flagged_phrases = ai_result["flagged_phrases"]

    if ai_result["ai_content_score"] > 0:
        severity = "CRITICAL" if ai_subscore >= 20.0 else "HIGH" if ai_subscore >= 12.0 else "MEDIUM"
        risk_factors.append(
            RiskFactor(
                rule="AI_SOCIAL_ENGINEERING",
                severity=severity,
                points=ai_subscore,
                description=f"AI Intent Engine detected {intent_category} tactics: {ai_result['ai_explanation']}"
            )
        )
        explanation_points.append(f"AI Language Analysis: {ai_result['ai_explanation']}")

    # =========================================================================
    # Dimension 4: Network Routing & Origin Geolocation (Max 15 pts)
    # =========================================================================
    network_points = 0.0

    # Inspect origin hop
    public_hops = [h for h in hops if not h.is_private]
    if public_hops:
        origin = public_hops[0]
        # Check suspicious ISP/ASN descriptions
        isp_lower = (origin.isp or "").lower()
        if any(term in isp_lower for term in ["tor", "proxy", "vpn", "bulletproof", "anonymous", "suspicious"]):
            network_points += 15.0
            risk_factors.append(
                RiskFactor(
                    rule="SUSPICIOUS_ORIGIN_NETWORK",
                    severity="HIGH",
                    points=15.0,
                    description=f"Origin IP ({origin.ip}) routed through an anonymizing network or high-risk hosting provider ({origin.isp})."
                )
            )
            explanation_points.append(f"Network Forensics: Origin IP ({origin.ip} in {origin.country}) is associated with an anonymous proxy or high-risk provider ({origin.isp}).")

    # Check for abnormal hop delays (> 300s)
    delayed_hops = [h for h in hops if h.delay_seconds and h.delay_seconds > 300]
    if delayed_hops:
        network_points += 5.0
        risk_factors.append(
            RiskFactor(
                rule="ANOMALOUS_HOP_DELAY",
                severity="LOW",
                points=5.0,
                description=f"Detected abnormal transit delay ({delayed_hops[0].delay_seconds}s) between relay servers, suggesting message queuing or manipulation."
            )
        )

    network_subscore = min(15.0, network_points)

    # =========================================================================
    # Dimension 5: Malicious Attachments (Max 10 pts)
    # =========================================================================
    attachment_points = 0.0
    dangerous_attachments = [a for a in attachments if a.is_suspicious_extension]
    if dangerous_attachments:
        attachment_points += 10.0
        names = ", ".join([a.filename for a in dangerous_attachments])
        risk_factors.append(
            RiskFactor(
                rule="DANGEROUS_ATTACHMENT",
                severity="CRITICAL",
                points=10.0,
                description=f"Attached file contains executable or script payload ({names}) associated with malware deployment."
            )
        )
        explanation_points.append(f"Dangerous attachment payload detected ({names}): Contains executable/script extension prone to malware execution.")

    attachment_subscore = min(10.0, attachment_points)

    # =========================================================================
    # Overall Score Synthesis & Level Determination
    # =========================================================================
    total_score = auth_subscore + url_subscore + ai_subscore + network_subscore + attachment_subscore
    total_score = round(min(100.0, max(0.0, total_score)), 1)

    if total_score >= 80.0:
        level = "CRITICAL"
        verdict = "Malicious / Active Attack"
        summary = "Critical threat: Confirmed phishing attack combining spoofing, malicious links, and psychological coercion."
    elif total_score >= 60.0:
        level = "HIGH"
        verdict = "Likely Phishing"
        summary = "High probability of social engineering or credential harvesting based on multiple verified threat indicators."
    elif total_score >= 40.0:
        level = "MEDIUM"
        verdict = "Suspicious"
        summary = "Suspicious email: Exhibits significant anomalies in authentication, links, or linguistic patterns."
    elif total_score >= 20.0:
        level = "LOW"
        verdict = "Low Risk"
        summary = "Minor security flags detected. Standard caution recommended before interacting with links."
    else:
        level = "SAFE"
        verdict = "Legitimate"
        summary = "Clean email: Passes core security checks with no identified spoofing or social engineering indicators."

    subscores = ThreatSubscores(
        authentication=auth_subscore,
        urls_domains=url_subscore,
        ai_content=ai_subscore,
        network_origin=network_subscore,
        attachments=attachment_subscore,
    )

    if not explanation_points:
        explanation_points.append("All email headers, domains, and content patterns align with standard legitimate correspondence.")

    return ThreatAssessment(
        score=total_score,
        level=level,
        verdict=verdict,
        summary=summary,
        ai_confidence=ai_confidence,
        intent_category=intent_category,
        subscores=subscores,
        explanation_points=explanation_points,
        flagged_phrases=flagged_phrases,
        risk_factors=risk_factors,
    )
