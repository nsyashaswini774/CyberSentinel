import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from app.main import app
from app.services.ai_detector import analyze_email_intent
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
print("  CYBERSENTINEL AI - PHASE 4 VERIFICATION TEST SUITE")
print("=" * 65)

# -------------------------------------------------------------
# 1. Test AI Linguistic & Intent Classification (ai_detector.py)
# -------------------------------------------------------------
try:
    # 1a. Credential harvesting + urgency
    phish_intent = analyze_email_intent(
        subject="URGENT: Verify Enterprise Password Now",
        body_text="Your account has unusual sign-in activity. Click the secure link immediately to update your login credentials within 24 hours or face permanent account suspension."
    )
    assert phish_intent["intent_category"] == "Credential Harvesting"
    assert phish_intent["ai_confidence"] >= 0.85
    assert phish_intent["ai_content_score"] >= 20.0
    assert any("verify" in p.lower() or "credentials" in p.lower() for p in phish_intent["flagged_phrases"])

    # 1b. Business Email Compromise (BEC) wire fraud
    bec_intent = analyze_email_intent(
        subject="Action: Urgent Wire Transfer Required",
        body_text="Please initiate a wire transfer to our new vendor before the settlement deadline. Routing number details attached."
    )
    assert bec_intent["intent_category"] == "Business Email Compromise (BEC)"
    assert bec_intent["ai_confidence"] >= 0.70

    # 1c. Benign corporate email
    benign_intent = analyze_email_intent(
        subject="Team Lunch on Friday",
        body_text="Hi everyone, let's meet at 12:30 PM in the cafeteria for the quarterly team lunch. See you all there!"
    )
    assert benign_intent["intent_category"] == "Benign / Normal Communication"
    assert benign_intent["ai_content_score"] == 0.0

    log_result("AI Phishing Intent Classification", True, f"Identified Credential Harvesting (confidence {phish_intent['ai_confidence']}), BEC Wire Fraud (confidence {bec_intent['ai_confidence']}), and Benign email (score {benign_intent['ai_content_score']}).")
except Exception as e:
    log_result("AI Phishing Intent Classification", False, str(e))

# -------------------------------------------------------------
# 2. Test Multi-Dimensional Threat Scoring & Subscores (threat_scorer.py)
# -------------------------------------------------------------
try:
    assessment = evaluate_email_threat(
        subject="URGENT: Password Reset Required",
        sender="IT Support <support@phish-domain.xyz>",
        recipient="user@target.com",
        reply_to="attacker@external-mailbox.top",
        return_path="bounce@phish-domain.xyz",
        auth_status=AuthenticationStatus(spf="FAIL", dkim="FAIL", dmarc="FAIL"),
        urls=[
            ExtractedUrl(
                url="http://xn--microsft-75a.com/auth",
                domain="xn--microsft-75a.com",
                anchor_text="https://security.microsoft.com",
                is_suspicious=True,
                risk_score=90.0,
                has_homograph=True,
                reasons=["IDN Punycode domain", "Anchor text displays 'https://security.microsoft.com' but link navigates to 'xn--microsft-75a.com'"]
            )
        ],
        hops=[
            HopGeolocation(
                ip="185.220.101.5",
                hop_index=1,
                hostname="node01.tor-relay.net",
                country="Germany",
                isp="Tor Exit Relay / Bulletproof Hosting",
                lat=50.1109,
                lon=8.6821,
                is_private=False
            )
        ],
        attachments=[
            AttachmentMeta(
                filename="security_patch.exe",
                content_type="application/octet-stream",
                size_bytes=1024,
                is_suspicious_extension=True
            )
        ],
        plain_body="Your password has expired. Click immediately to update login credentials within 24 hours.",
        html_body=""
    )

    # Validate subscores
    sub = assessment.subscores
    print(f"Subscores: Auth={sub.authentication}/25, URLs={sub.urls_domains}/25, AI={sub.ai_content}/25, Network={sub.network_origin}/15, Attachments={sub.attachments}/10")
    assert sub.authentication == 25.0, f"Expected max 25 for multiple auth failures, got {sub.authentication}"
    assert sub.urls_domains == 25.0, f"Expected max 25 for homograph + anchor mismatch, got {sub.urls_domains}"
    assert sub.ai_content >= 20.0, f"Expected >= 20 for urgency + credential harvesting, got {sub.ai_content}"
    assert sub.network_origin == 15.0, f"Expected 15 for Tor exit node origin, got {sub.network_origin}"
    assert sub.attachments == 10.0, f"Expected 10 for .exe payload, got {sub.attachments}"

    assert assessment.score >= 90.0, f"Expected >= 90 for combined high-threat attack, got {assessment.score}"
    assert assessment.level == "CRITICAL"
    assert assessment.verdict == "Malicious / Active Attack"

    log_result("Multi-Dimensional Threat Scoring Engine", True, f"Calculated 5 forensic subscores (Total: {assessment.score}/100, Level: {assessment.level}). Subscores strictly capped to respective weights.")
except Exception as e:
    log_result("Multi-Dimensional Threat Scoring Engine", False, str(e))

# -------------------------------------------------------------
# 3. Test Explainable AI & "Why is this suspicious?" Bullets
# -------------------------------------------------------------
try:
    bullets = assessment.explanation_points
    assert len(bullets) >= 4, f"Expected at least 4 explainability bullets, got {len(bullets)}"
    print("Explainable AI Insights:")
    for b in bullets:
        print(f"  • {b}")

    assert any("SPF" in b or "DKIM" in b for b in bullets), "Auth failure missing from explanations"
    assert any("anchor" in b.lower() or "homograph" in b.lower() or "punycode" in b.lower() for b in bullets), "URL deception missing from explanations"
    assert any("AI Language Analysis" in b for b in bullets), "AI NLP analysis missing from explanations"
    assert any("Network Forensics" in b for b in bullets), "Network origin missing from explanations"

    assert len(assessment.flagged_phrases) > 0, "Flagged phrases list should not be empty"

    log_result("Explainable AI (Reasoning Bullets & Phrases)", True, f"Generated {len(bullets)} structured reasoning bullet points explaining exact threat factors, along with {len(assessment.flagged_phrases)} flagged phrases.")
except Exception as e:
    log_result("Explainable AI (Reasoning Bullets & Phrases)", False, str(e))

# -------------------------------------------------------------
# 4. Test Live End-to-End API Integration
# -------------------------------------------------------------
try:
    res = client.get("/api/v1/analyze/sample")
    assert res.status_code == 200
    data = res.json()
    threat = data["threat"]

    assert "subscores" in threat, "subscores missing in API response"
    assert "explanation_points" in threat, "explanation_points missing in API response"
    assert "ai_confidence" in threat, "ai_confidence missing in API response"
    assert "intent_category" in threat, "intent_category missing in API response"
    assert threat["ai_confidence"] > 0.8
    assert len(threat["explanation_points"]) >= 3

    log_result("End-to-End Phase 4 API Integration", True, f"Live /api/v1/analyze/sample returned Threat Score {threat['score']}/100, Intent '{threat['intent_category']}' (confidence {threat['ai_confidence']}), and {len(threat['explanation_points'])} explainability points.")
except Exception as e:
    log_result("End-to-End Phase 4 API Integration", False, str(e))

print("\n" + "=" * 65)
print("              PHASE 4 VERIFICATION SUMMARY")
print("=" * 65)
all_ok = True
for feature, (st, det) in results_summary.items():
    print(f"{feature.ljust(42)}: {st}")
    if st != "PASS":
        all_ok = False

print("=" * 65)
if all_ok:
    print("STATUS: ALL PHASE 4 BACKEND FEATURES 100% OPERATIONAL!")
    sys.exit(0)
else:
    print("STATUS: SOME TESTS FAILED")
    sys.exit(1)
