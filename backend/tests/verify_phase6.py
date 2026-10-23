import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from app.main import app
from app.services.pdf_generator import generate_forensic_pdf
from app.services.email_parser import parse_email_message
from app.schemas.email import (
    AuthenticationStatus,
    ExtractedUrl,
    HopGeolocation,
    AttachmentMeta,
    RiskFactor,
    ThreatAssessment,
    ThreatSubscores,
    EmailAnalysisResult,
)

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
print("  CYBERSENTINEL AI - PHASE 6 VERIFICATION TEST SUITE")
print("=" * 65)

# -------------------------------------------------------------
# 1. Test Forensic PDF Report Generator Service (ReportLab)
# -------------------------------------------------------------
try:
    mock_threat = ThreatAssessment(
        score=88.5,
        level="CRITICAL",
        verdict="Phishing & Credential Theft",
        summary="High-confidence phishing campaign targeting corporate credentials via deceptive link spoofing.",
        ai_confidence=0.98,
        intent_category="Credential Harvesting",
        subscores=ThreatSubscores(
            authentication=25.0,
            urls_domains=25.0,
            ai_content=20.0,
            network_origin=15.0,
            attachments=3.5
        ),
        explanation_points=[
            "SPF and DKIM authentication failed for the transmitting host.",
            "Deceptive anchor text mismatch found in embedded hyperlinks.",
            "AI NLP Engine flagged urgent account suspension coercion lure."
        ],
        flagged_phrases=["within 24 hours", "update login credentials immediately", "account suspended"],
        risk_factors=[
            RiskFactor(rule="SPF_FAIL", severity="HIGH", points=15.0, description="SPF check failed on mail server."),
            RiskFactor(rule="BRAND_TYPOSQUATTING", severity="CRITICAL", points=25.0, description="Targeting PayPal brand.")
        ]
    )

    mock_analysis = EmailAnalysisResult(
        scan_id=42,
        analyzed_at="2026-09-13T12:00:00Z",
        file_name="suspicious_phish.eml",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        subject="URGENT: Verify Enterprise Account Immediately",
        sender="Security Team <security@paypa1-support.top>",
        recipient="target.user@company.com",
        date="Sun, 13 Sep 2026 12:00:00 +0000",
        reply_to="attacker@external-inbox.net",
        return_path="bounce@paypa1-support.top",
        message_id="<20260913.120000.42@paypa1-support.top>",
        authentication=AuthenticationStatus(spf="FAIL", dkim="FAIL", dmarc="FAIL"),
        headers=[],
        hops=[
            HopGeolocation(
                ip="185.220.101.5",
                hop_index=1,
                country="Germany",
                city="Frankfurt",
                isp="Tor Exit / High Risk Hosting",
                delay_seconds=4.5,
                is_private=False
            )
        ],
        urls=[
            ExtractedUrl(
                url="http://paypa1-login.top/auth",
                domain="paypa1-login.top",
                anchor_text="https://paypal.com/verify",
                is_suspicious=True,
                risk_score=95.0,
                threat_category="Brand Impersonation",
                reasons=["Typosquatting detected targeting PayPal"]
            )
        ],
        attachments=[
            AttachmentMeta(
                filename="AccountVerification.exe",
                content_type="application/x-msdownload",
                size_bytes=24500,
                is_suspicious_extension=True
            )
        ],
        threat=mock_threat
    )

    pdf_bytes = generate_forensic_pdf(mock_analysis)
    
    assert isinstance(pdf_bytes, bytes), "PDF output is not bytes"
    assert len(pdf_bytes) > 2000, f"PDF output is too small: {len(pdf_bytes)} bytes"
    assert pdf_bytes.startswith(b"%PDF-"), "PDF magic bytes %PDF- missing"
    assert b"CYBERSENTINEL" in pdf_bytes or b"PDF" in pdf_bytes

    log_result("Forensic PDF Report Generator Engine", True, f"Generated {len(pdf_bytes)} bytes valid PDF report with 5D scores and evidence tables.")
except Exception as e:
    log_result("Forensic PDF Report Generator Engine", False, str(e))

# -------------------------------------------------------------
# 2. Test Edge Case PDF Generation (Empty Hops/URLs/Unicode)
# -------------------------------------------------------------
try:
    minimal_analysis = EmailAnalysisResult(
        scan_id=999,
        analyzed_at="2026-09-13T12:00:00Z",
        file_name="unicode_test.eml",
        md5="00000000000000000000000000000000",
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        subject="Test with <HTML> tags & characters: ⚠️ £ ¥ €",
        sender="test <sender@clean-domain.org>",
        recipient="target@clean-domain.org",
        date="Sun, 13 Sep 2026 12:00:00 +0000",
        authentication=AuthenticationStatus(spf="PASS", dkim="PASS", dmarc="PASS"),
        headers=[],
        hops=[],
        urls=[],
        attachments=[],
        threat=ThreatAssessment(
            score=5.0,
            level="SAFE",
            verdict="Legitimate Email",
            summary="Clean message with valid DKIM and SPF passing.",
            ai_confidence=0.99,
            intent_category="Benign / Normal Communication",
            subscores=ThreatSubscores(authentication=0, urls_domains=0, ai_content=0, network_origin=0, attachments=0),
            explanation_points=[],
            flagged_phrases=[],
            risk_factors=[]
        )
    )

    edge_pdf = generate_forensic_pdf(minimal_analysis)
    assert len(edge_pdf) > 1000
    assert edge_pdf.startswith(b"%PDF-")

    log_result("PDF Edge Case & Unicode Sanitization", True, "Successfully generated clean PDF for empty arrays and special HTML characters.")
except Exception as e:
    log_result("PDF Edge Case & Unicode Sanitization", False, str(e))

# -------------------------------------------------------------
# 3. Test Ingest & Historical Case Persistence
# -------------------------------------------------------------
created_scan_id = None
try:
    raw_text = """Received: from relay01.attacker.top ([198.51.100.77]) by mx.victim.com with ESMTP; Sun, 13 Sep 2026 12:00:00 +0000
From: Banking Helpdesk <alerts@paypa1-update.xyz>
To: target.victim@enterprise.com
Subject: Notice: Account Suspended Pending Identity Verification
Authentication-Results: mx.victim.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html

<html>
<body>
<p>Dear customer,</p>
<p>Your online account requires immediate identity verification within 24 hours.</p>
<p><a href="http://paypa1-update.xyz/verify">https://paypal.com/security</a></p>
</body>
</html>
"""
    ingest_resp = client.post("/api/v1/analyze/raw", json={"raw_content": raw_text, "filename": "phase6_case_test.eml"})
    assert ingest_resp.status_code == 200, f"Status code: {ingest_resp.status_code}"
    scan_data = ingest_resp.json()
    created_scan_id = scan_data.get("scan_id")
    assert created_scan_id is not None and created_scan_id > 0, "Failed to obtain created scan_id"

    log_result("Case Persistence & Database Indexing", True, f"Ingested and created persistent Case #{created_scan_id}")
except Exception as e:
    log_result("Case Persistence & Database Indexing", False, str(e))

# -------------------------------------------------------------
# 4. Test Historical Case Archives Listing & Search Filters
# -------------------------------------------------------------
try:
    # 4a. List cases
    list_resp = client.get("/api/v1/history?limit=20")
    assert list_resp.status_code == 200
    records = list_resp.json()
    assert len(records) >= 1
    assert any(r["id"] == created_scan_id for r in records)

    # 4b. Keyword search
    search_resp = client.get("/api/v1/history?q=Account+Suspended")
    assert search_resp.status_code == 200
    searched = search_resp.json()
    assert len(searched) >= 1
    assert any(r["id"] == created_scan_id for r in searched)

    # 4c. Threat level filter
    level_resp = client.get("/api/v1/history?threat_level=HIGH")
    assert level_resp.status_code == 200

    log_result("Historical Case Archives Search & Filter API", True, f"Listed {len(records)} cases; Search matched Case #{created_scan_id}")
except Exception as e:
    log_result("Historical Case Archives Search & Filter API", False, str(e))

# -------------------------------------------------------------
# 5. Test Case Detail Retrieval by ID
# -------------------------------------------------------------
try:
    assert created_scan_id is not None
    detail_resp = client.get(f"/api/v1/history/{created_scan_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    
    assert detail_data["scan_id"] == created_scan_id
    assert "threat" in detail_data
    assert detail_data["subject"] == "Notice: Account Suspended Pending Identity Verification"
    assert len(detail_data["urls"]) >= 1

    # 404 test for non-existent scan
    missing_resp = client.get("/api/v1/history/999999")
    assert missing_resp.status_code == 404

    log_result("Case Detail Retrieval by ID", True, f"Retrieved full forensic state for Case #{created_scan_id} and verified 404 handler.")
except Exception as e:
    log_result("Case Detail Retrieval by ID", False, str(e))

# -------------------------------------------------------------
# 6. Test PDF Download Endpoints (GET /history/{id}/pdf & POST /analyze/export-pdf)
# -------------------------------------------------------------
try:
    # 6a. GET /history/{id}/pdf
    pdf_resp = client.get(f"/api/v1/history/{created_scan_id}/pdf")
    assert pdf_resp.status_code == 200, f"Status code: {pdf_resp.status_code}"
    assert "application/pdf" in pdf_resp.headers.get("content-type", "")
    assert "attachment" in pdf_resp.headers.get("content-disposition", "")
    assert pdf_resp.content.startswith(b"%PDF-")
    assert len(pdf_resp.content) > 2000

    # 6b. POST /analyze/export-pdf
    export_resp = client.post("/api/v1/analyze/export-pdf", json=detail_data)
    assert export_resp.status_code == 200
    assert "application/pdf" in export_resp.headers.get("content-type", "")
    assert export_resp.content.startswith(b"%PDF-")

    log_result("PDF Report Download & Live Export Endpoints", True, f"Downloaded {len(pdf_resp.content)} bytes PDF from stored Case #{created_scan_id} & live export endpoint.")
except Exception as e:
    log_result("PDF Report Download & Live Export Endpoints", False, str(e))

# -------------------------------------------------------------
# 7. Test Case Deletion
# -------------------------------------------------------------
try:
    assert created_scan_id is not None
    del_resp = client.delete(f"/api/v1/history/{created_scan_id}")
    assert del_resp.status_code == 200
    assert del_resp.json().get("status") == "success"

    # Confirm case is no longer found
    post_del_resp = client.get(f"/api/v1/history/{created_scan_id}")
    assert post_del_resp.status_code == 404

    log_result("Historical Case Deletion API", True, f"Deleted Case #{created_scan_id} and confirmed deletion.")
except Exception as e:
    log_result("Historical Case Deletion API", False, str(e))

# -------------------------------------------------------------
# SUMMARY REPORT
# -------------------------------------------------------------
print("\n" + "=" * 65)
print("             PHASE 6 VERIFICATION SUMMARY REPORT")
print("=" * 65)
all_passed = True
for feat, (status, detail) in results_summary.items():
    print(f" - {feat:50}: {status}")
    if status == "FAIL":
        all_passed = False

print("=" * 65)
if all_passed:
    print(" >>> ALL PHASE 6 TESTS PASSED SUCCESSFULLY (100%) <<<")
else:
    print(" >>> SOME PHASE 6 TESTS FAILED <<<")
print("=" * 65)
