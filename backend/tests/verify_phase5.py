import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from app.main import app
from app.services.domain_reputation import (
    calculate_shannon_entropy,
    detect_brand_typosquatting,
    evaluate_domain_reputation,
)
from app.services.url_inspector import inspect_single_url, extract_and_inspect_urls
from app.services.threat_scorer import evaluate_email_threat
from app.schemas.email import AuthenticationStatus, ExtractedUrl, HopGeolocation, AttachmentMeta

client = TestClient(app)

results_summary = {}

def log_result(feature_name: str, passed: bool, details: str = ""):
    status = "PASS" if passed else "FAIL"
    results_summary[feature_name] = (status, details)
    mark = "[PASS]" if passed else "[FAIL]"
    print(f"\n{mark} {feature_name}")
    if details:
        print(f"       Details: {details}")

print("=" * 65)
print("  CYBERSENTINEL AI - PHASE 5 VERIFICATION TEST SUITE")
print("=" * 65)

# 1. Test Shannon Entropy & DGA Detection
try:
    low_entropy = calculate_shannon_entropy("google")
    high_entropy = calculate_shannon_entropy("x8k29zq1m9p0")
    
    assert low_entropy < 3.0, f"Low entropy failed: {low_entropy}"
    assert high_entropy >= 3.4, f"High entropy failed: {high_entropy}"
    
    # Test DGA domain evaluation
    dga_rep = evaluate_domain_reputation("http://x8k29zq1m9p0-sec.xyz/login", "x8k29zq1m9p0-sec.xyz")
    assert dga_rep.is_high_entropy is True
    assert dga_rep.entropy >= 3.6
    assert any("Shannon entropy" in ind for ind in dga_rep.threat_indicators)
    
    log_result("Shannon Entropy & DGA Generation Detection", True, f"Calculated Entropy: Low={low_entropy}, DGA={dga_rep.entropy}")
except Exception as e:
    log_result("Shannon Entropy & DGA Generation Detection", False, str(e))

# 2. Test Typosquatting & Brand Spoofing Engine
try:
    # 2a. Leetspeak typosquatting ('paypa1')
    is_typo_leet, brand_leet, reason_leet = detect_brand_typosquatting("paypa1")
    assert is_typo_leet is True
    assert brand_leet == "PayPal"
    
    # 2b. Levenshtein edit distance 1 ('amazn')
    is_typo_dist, brand_dist, reason_dist = detect_brand_typosquatting("amazn")
    assert is_typo_dist is True
    assert brand_dist == "Amazon"
    
    # 2c. Brand lure affix ('login-microsoft')
    is_typo_affix, brand_affix, reason_affix = detect_brand_typosquatting("login-microsoft")
    assert is_typo_affix is True
    assert brand_affix == "Microsoft"
    
    # 2d. Subdomain spoofing ('paypal.com.attacker-node.xyz')
    sub_rep = evaluate_domain_reputation("https://paypal.com.attacker-node.net/verify", "attacker-node.net")
    assert sub_rep.typosquatting_detected is True
    assert sub_rep.impersonated_brand == "PayPal"
    assert any("Subdomain impersonates" in ind for ind in sub_rep.threat_indicators)
    
    # 2e. Legitimate domain should not be flagged as typosquat
    is_typo_legit, _, _ = detect_brand_typosquatting("paypal")
    assert is_typo_legit is False
    
    log_result("Brand Typosquatting & Impersonation Engine", True, "Detected Leetspeak (paypa1), Levenshtein (amazn), Affix (login-microsoft), Subdomain Spoofing")
except Exception as e:
    log_result("Brand Typosquatting & Impersonation Engine", False, str(e))

# 3. Test TLD Reputation Tiering & Protocol/Port Safety
try:
    # High-abuse TLD + Insecure HTTP
    high_abuse = evaluate_domain_reputation("http://secure-update.top/auth", "secure-update.top")
    assert high_abuse.tld_reputation_tier == "High-Abuse"
    assert high_abuse.protocol_risk == "Insecure (HTTP)"
    assert high_abuse.reputation_score >= 35.0
    
    # Trusted TLD + HTTPS
    trusted_gov = evaluate_domain_reputation("https://treasury.gov/reports", "treasury.gov")
    assert trusted_gov.tld_reputation_tier == "Trusted"
    assert trusted_gov.protocol_risk == "Secure (HTTPS)"
    assert trusted_gov.reputation_score == 0.0
    
    # Non-standard port
    port_rep = evaluate_domain_reputation("https://suspicious-host.org:8443/payload", "suspicious-host.org")
    assert "8443" in port_rep.protocol_risk
    
    log_result("TLD Reputation Tiers & Protocol Safety", True, "High-Abuse (.top), Trusted (.gov), HTTP vs HTTPS, Non-standard Port (:8443)")
except Exception as e:
    log_result("TLD Reputation Tiers & Protocol Safety", False, str(e))

# 4. Test Comprehensive URL Inspection & HTML Extraction
try:
    html_sample = """
    <html>
      <body>
        <p>Dear user,</p>
        <p>Your account has been restricted. Please <a href="http://paypa1-security.top/login">https://paypal.com/verify</a> to unblock.</p>
        <p>Emergency portal: http://192.168.1.100:8080/reset</p>
        <p>Also check bit.ly/3x8q9z for details.</p>
      </body>
    </html>
    """
    plain_sample = "Direct link: https://dga-7xq910kmzv-sec.xyz/auth"
    
    extracted_urls = extract_and_inspect_urls(plain_sample, html_sample)
    assert len(extracted_urls) >= 4, f"Extracted {len(extracted_urls)} URLs"
    
    # Check deceptive anchor text URL
    deceptive_url = next((u for u in extracted_urls if "paypa1-security" in u.url), None)
    assert deceptive_url is not None, "deceptive_url not found"
    assert deceptive_url.is_suspicious is True
    assert deceptive_url.anchor_text == "https://paypal.com/verify"
    assert any("Anchor text displays" in r for r in deceptive_url.reasons), f"Reasons: {deceptive_url.reasons}"
    assert deceptive_url.reputation is not None and deceptive_url.reputation.typosquatting_detected is True
    assert deceptive_url.reputation.impersonated_brand == "PayPal"
    
    # Check IP host URL
    ip_url = next((u for u in extracted_urls if "192.168.1.100" in u.url), None)
    assert ip_url is not None, "ip_url not found"
    assert any("raw IP address" in r for r in ip_url.reasons)
    
    # Check shortener
    short_url = next((u for u in extracted_urls if "bit.ly" in u.url), None)
    assert short_url is not None, "short_url not found"
    assert short_url.is_shortener is True
    
    # Check DGA URL
    dga_url = next((u for u in extracted_urls if "dga-7xq910kmzv" in u.url), None)
    assert dga_url is not None, "dga_url not found"
    assert dga_url.reputation is not None and dga_url.reputation.is_high_entropy is True
    
    log_result("URL Extraction & Forensic Link Inspection", True, f"Parsed {len(extracted_urls)} URLs; Verified Anchor Mismatch, IP Hosts, Shorteners, DGA")
except Exception as e:
    log_result("URL Extraction & Forensic Link Inspection", False, str(e))

# -------------------------------------------------------------
# 5. Test Threat Scorer Integration with Phase 5 Indicators
# -------------------------------------------------------------
try:
    auth_fail = AuthenticationStatus(spf="FAIL", dkim="FAIL", dmarc="FAIL")
    typo_url = inspect_single_url("http://paypa1-security.xyz/login", anchor_text="https://paypal.com")
    
    assessment = evaluate_email_threat(
        subject="URGENT: Suspended Account Verification",
        sender="security@paypa1-support.top",
        recipient="victim@company.com",
        reply_to=None,
        return_path=None,
        auth_status=auth_fail,
        urls=[typo_url],
        hops=[],
        attachments=[],
        plain_body="Your PayPal account has been frozen due to security anomalies. Update your credentials at our portal immediately.",
        html_body=""
    )
    
    assert assessment.score >= 60.0, f"Score was {assessment.score}"
    assert assessment.level in ["HIGH", "CRITICAL"], f"Level was {assessment.level}"
    assert assessment.subscores.urls_domains >= 20.0, f"Subscore was {assessment.subscores.urls_domains}"
    assert any(rf.rule == "BRAND_TYPOSQUATTING" for rf in assessment.risk_factors)
    assert any("typosquatting" in pt.lower() or "paypal" in pt.lower() for pt in assessment.explanation_points)
    
    log_result("Threat Scorer Phase 5 Domain Integration", True, f"Threat Score: {assessment.score}/100, Level: {assessment.level}, URLs Subscore: {assessment.subscores.urls_domains}")
except Exception as e:
    log_result("Threat Scorer Phase 5 Domain Integration", False, str(e))

# -------------------------------------------------------------
# 6. Test End-to-End API Ingestion with Phase 5 Intelligence
# -------------------------------------------------------------
try:
    raw_payload = {
        "raw_content": """Received: from mail.attacker.xyz ([198.51.100.55]) by mx.victim.com with ESMTP; Sun, 13 Sep 2026 09:00:00 +0000
From: Security Center <security@paypa1-support.top>
To: target@victim.com
Subject: Immediate Action Required: Verify Suspended Profile
Authentication-Results: mx.victim.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html

<html>
<body>
<p>Dear customer,</p>
<p>Unusual activity detected. Please <a href="http://paypa1-login.top/account/verify">https://paypal.com/security</a> to restore access.</p>
</body>
</html>
"""
    }
    
    resp = client.post("/api/v1/analyze/raw", json=raw_payload)
    if resp.status_code != 200:
        raise AssertionError(f"Status code {resp.status_code}: {resp.text}")
    data = resp.json()
    
    assert "threat" in data, "No threat in response"
    assert data["threat"]["score"] >= 60.0, f"Score was {data['threat']['score']}"
    assert len(data["urls"]) >= 1, f"Found {len(data['urls'])} URLs"
    
    target_url = data["urls"][0]
    assert target_url["reputation"]["typosquatting_detected"] is True, f"Reputation: {target_url['reputation']}"
    assert target_url["reputation"]["impersonated_brand"] == "PayPal", f"Brand was {target_url['reputation']['impersonated_brand']}"
    assert target_url["reputation"]["tld_reputation_tier"] == "High-Abuse", f"TLD tier: {target_url['reputation']['tld_reputation_tier']}"
    
    log_result("End-to-End API Analysis with Domain Intelligence", True, f"Scan ID: {data.get('scan_id')}, Verdict: {data['threat']['verdict']}, Score: {data['threat']['score']}")
except Exception as e:
    log_result("End-to-End API Analysis with Domain Intelligence", False, str(e))

# SUMMARY REPORT
print("\n" + "=" * 65)
print("             PHASE 5 VERIFICATION SUMMARY REPORT")
print("=" * 65)
all_passed = True
for feat, (status, detail) in results_summary.items():
    print(f" - {feat:50}: {status}")
    if status == "FAIL":
        all_passed = False

print("=" * 65)
if all_passed:
    print(" >>> ALL PHASE 5 TESTS PASSED SUCCESSFULLY (100%) <<<")
else:
    print(" >>> SOME PHASE 5 TESTS FAILED <<<")
print("=" * 65)
