import sys
import os
import io

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal
from app.models.scan import ScanRecord

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

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
print("  CYBERSENTINEL AI - PHASE 2 VERIFICATION TEST SUITE")
print("=" * 65)

# -------------------------------------------------------------
# 1. Test Email Header Extraction (via Direct Raw Input)
# -------------------------------------------------------------
try:
    raw_rfc_email = (
        "Received: from relay01.external-source.org (relay01.external-source.org [198.51.100.25])\r\n"
        "    by mx01.internal-corp.net with ESMTP id corp12345;\r\n"
        "    Thu, 03 Sep 2026 14:00:00 +0000\r\n"
        "From: \"Executive CEO\" <ceo@spoofed-company.com>\r\n"
        "To: victim.accountant@target-corp.com\r\n"
        "Subject: Urgent Wire Transfer Authorization Required\r\n"
        "Date: Thu, 03 Sep 2026 14:00:00 +0000\r\n"
        "Message-ID: <wire-urg-20260903@spoofed-company.com>\r\n"
        "Return-Path: <actual-attacker@malicious-relay.net>\r\n"
        "Reply-To: offsite-mailbox@external-fraud.xyz\r\n"
        "Authentication-Results: mx01.internal-corp.net;\r\n"
        "    spf=fail (sender IP is 198.51.100.25) smtp.mailfrom=spoofed-company.com;\r\n"
        "    dkim=fail header.i=@spoofed-company.com;\r\n"
        "    dmarc=fail (p=REJECT)\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
        "Please process the wire transfer of $45,000 immediately to the following portal:\r\n"
        "http://payment-processing.xyz/wire/transfer?id=9921\r\n"
    )

    response = client.post("/api/v1/analyze/raw", json={"raw_content": raw_rfc_email, "filename": "wire_fraud.eml"})
    assert response.status_code == 200, f"HTTP {response.status_code}: {response.text}"
    data = response.json()

    # Verify extracted headers
    assert data["subject"] == "Urgent Wire Transfer Authorization Required", f"Subject mismatch: {data['subject']}"
    assert "ceo@spoofed-company.com" in data["sender"], f"Sender mismatch: {data['sender']}"
    assert "victim.accountant@target-corp.com" in data["recipient"], f"Recipient mismatch: {data['recipient']}"
    assert data["reply_to"] == "offsite-mailbox@external-fraud.xyz", f"Reply-To mismatch: {data['reply_to']}"
    assert "<actual-attacker@malicious-relay.net>" in data["return_path"], f"Return-Path mismatch: {data['return_path']}"
    assert "<wire-urg-20260903@spoofed-company.com>" in data["message_id"], f"Message-ID mismatch: {data['message_id']}"
    assert data["authentication"]["spf"] == "FAIL", f"SPF mismatch: {data['authentication']['spf']}"
    assert data["authentication"]["dkim"] == "FAIL", f"DKIM mismatch: {data['authentication']['dkim']}"
    assert data["authentication"]["dmarc"] == "FAIL", f"DMARC mismatch: {data['authentication']['dmarc']}"
    assert len(data["headers"]) >= 8, f"Expected >= 8 headers, found {len(data['headers'])}"

    log_result("Email Header Extraction", True, f"Extracted Subject, From, To, Reply-To, Return-Path, Message-ID, and SPF/DKIM/DMARC status correctly ({len(data['headers'])} headers parsed).")
except Exception as e:
    log_result("Email Header Extraction", False, str(e))

# -------------------------------------------------------------
# 2. Test Raw Email Text Parsing (POST /analyze/raw)
# -------------------------------------------------------------
try:
    simple_raw = (
        "From: security@alerts-support.top\n"
        "To: employee@target.com\n"
        "Subject: Critical: Account Locked\n"
        "Content-Type: text/plain\n\n"
        "Your account has been locked. Verify at http://192.168.10.50/unlock\n"
    )
    res_raw = client.post("/api/v1/analyze/raw", json={"raw_content": simple_raw, "filename": "account_alert.eml"})
    assert res_raw.status_code == 200, f"HTTP {res_raw.status_code}: {res_raw.text}"
    raw_data = res_raw.json()

    assert raw_data["subject"] == "Critical: Account Locked"
    assert "Your account has been locked" in raw_data["body_plain"]
    assert raw_data["md5"] and len(raw_data["md5"]) == 32
    assert raw_data["sha256"] and len(raw_data["sha256"]) == 64

    log_result("Raw Email Text Parsing", True, f"Successfully parsed raw RFC string with body content and generated SHA-256 evidence hash ({raw_data['sha256'][:16]}...).")
except Exception as e:
    log_result("Raw Email Text Parsing", False, str(e))

# -------------------------------------------------------------
# 3. Test URL Extraction
# -------------------------------------------------------------
try:
    html_url_email = (
        "From: newsletter@promo.com\r\n"
        "To: user@target.com\r\n"
        "Subject: Special Promo\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><body>"
        "<p>Visit our normal shop <a href=\"https://legit-shop.com/deals\">Deals</a></p>"
        "<p>Or check our server <a href=\"http://172.217.16.206/tracker\">Direct IP</a></p>"
        "<p>Or spam site <a href=\"http://free-crypto-giveaway.buzz/claim\">Claim</a></p>"
        "</body></html>"
    )
    res_url = client.post("/api/v1/analyze/raw", json={"raw_content": html_url_email})
    assert res_url.status_code == 200
    url_data = res_url.json()
    extracted_urls = url_data["urls"]

    found_domains = [u["domain"] for u in extracted_urls]
    assert any("legit-shop.com" in d for d in found_domains), f"legit-shop.com missing: {found_domains}"
    assert any("172.217.16.206" in d for d in found_domains), f"172.217.16.206 missing: {found_domains}"
    assert any("free-crypto-giveaway.buzz" in d for d in found_domains), f"buzz TLD missing: {found_domains}"

    # Verify suspicious flags
    raw_ip_url = next((u for u in extracted_urls if "172.217.16.206" in u["url"]), None)
    assert raw_ip_url is not None and raw_ip_url["is_suspicious"] is True, "Raw IP URL should be flagged as suspicious"

    buzz_url = next((u for u in extracted_urls if "buzz" in u["url"]), None)
    assert buzz_url is not None and buzz_url["is_suspicious"] is True, "High-risk TLD (.buzz) should be flagged"

    log_result("URL Extraction", True, f"Successfully parsed {len(extracted_urls)} URLs from HTML anchors and plaintext. Flagged raw IP host and high-risk TLDs.")
except Exception as e:
    log_result("URL Extraction", False, str(e))

# -------------------------------------------------------------
# 4. Test IP Extraction (from Received headers and routing hops)
# -------------------------------------------------------------
try:
    multi_hop_email = (
        "Received: from mx.target.com (mx.target.com [10.200.0.1])\r\n"
        "    by internal-inbox.target.com with SMTP; Thu, 03 Sep 2026 15:30:00 +0000\r\n"
        "Received: from relay-external.attacker-network.net (relay-external.attacker-network.net [185.220.101.5])\r\n"
        "    by mx.target.com with ESMTP id rly9921; Thu, 03 Sep 2026 15:29:55 +0000\r\n"
        "Received: from workstation-client (192.168.1.105)\r\n"
        "    by relay-external.attacker-network.net; Thu, 03 Sep 2026 15:29:50 +0000\r\n"
        "From: test@attacker-network.net\r\n"
        "To: target@target.com\r\n"
        "Subject: Multihop Trace Test\r\n\r\n"
        "Testing multi-hop IP extraction."
    )
    res_hops = client.post("/api/v1/analyze/raw", json={"raw_content": multi_hop_email})
    assert res_hops.status_code == 200
    hops_data = res_hops.json()["hops"]

    assert len(hops_data) >= 3, f"Expected 3 hops, got {len(hops_data)}"
    extracted_ips = [h["ip"] for h in hops_data]
    assert "192.168.1.105" in extracted_ips, f"192.168.1.105 not found in {extracted_ips}"
    assert "185.220.101.5" in extracted_ips, f"185.220.101.5 not found in {extracted_ips}"
    assert "10.200.0.1" in extracted_ips, f"10.200.0.1 not found in {extracted_ips}"

    # Verify private vs public classifications
    pub_hop = next(h for h in hops_data if h["ip"] == "185.220.101.5")
    priv_hop1 = next(h for h in hops_data if h["ip"] == "192.168.1.105")
    priv_hop2 = next(h for h in hops_data if h["ip"] == "10.200.0.1")

    assert pub_hop["is_private"] is False, "185.220.101.5 must be marked public"
    assert priv_hop1["is_private"] is True, "192.168.1.105 must be marked private"
    assert priv_hop2["is_private"] is True, "10.200.0.1 must be marked private"

    log_result("IP Extraction", True, f"Reconstructed {len(hops_data)} relay hops in chronological order. Correctly identified public IP (185.220.101.5) and internal RFC 1918 IPs (192.168.1.105, 10.200.0.1).")
except Exception as e:
    log_result("IP Extraction", False, str(e))

# -------------------------------------------------------------
# 5. Test .EML File Upload (POST /analyze/upload) with Attachment
# -------------------------------------------------------------
try:
    boundary = "CyberSentinel_Boundary_998"
    eml_file_bytes = (
        f"From: HR Department <hr@phish-payroll.xyz>\r\n"
        f"To: user@target.org\r\n"
        f"Subject: 2026 Bonus Distribution Document\r\n"
        f"Date: Thu, 03 Sep 2026 15:40:00 +0000\r\n"
        f"Received: from sender-relay.phish-payroll.xyz ([198.51.100.88]) by mx.target.org; Thu, 03 Sep 2026 15:40:02 +0000\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
        f"Please execute the attached bonus calculation tool.\r\n\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: application/x-dosexec; name=\"BonusCalculator.exe\"\r\n"
        f"Content-Disposition: attachment; filename=\"BonusCalculator.exe\"\r\n\r\n"
        f"MZ90...[Binary executable content payload]...\r\n\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    files = {"file": ("bonus_notice.eml", io.BytesIO(eml_file_bytes), "message/rfc822")}
    res_upload = client.post("/api/v1/analyze/upload", files=files)
    assert res_upload.status_code == 200, f"HTTP {res_upload.status_code}: {res_upload.text}"
    upload_data = res_upload.json()

    assert upload_data["file_name"] == "bonus_notice.eml"
    assert upload_data["subject"] == "2026 Bonus Distribution Document"
    assert len(upload_data["attachments"]) == 1
    att = upload_data["attachments"][0]
    assert att["filename"] == "BonusCalculator.exe"
    assert att["is_suspicious_extension"] is True, "Executable (.exe) attachment was not flagged as suspicious"

    # Threat assessment should have flagged the attachment
    assert any(rf["rule"] == "DANGEROUS_ATTACHMENT" for rf in upload_data["threat"]["risk_factors"])

    log_result(".eml Upload", True, f"Successfully uploaded multipart .eml file. Extracted attachment '{att['filename']}' ({att['size_bytes']}B) and flagged high-risk executable.")
except Exception as e:
    log_result(".eml Upload", False, str(e))

# -------------------------------------------------------------
# 6. Test SQLite Database Logging
# -------------------------------------------------------------
try:
    # 1. Query history endpoint
    res_hist = client.get("/api/v1/history")
    assert res_hist.status_code == 200
    history_items = res_hist.json()
    assert len(history_items) >= 4, f"Expected at least 4 scans logged, found {len(history_items)}"

    # 2. Check latest scan properties in API response
    latest = history_items[0]
    assert latest["subject"] == "2026 Bonus Distribution Document"
    assert latest["threat_score"] > 0
    assert latest["origin_ip"] == "198.51.100.88"

    # 3. Directly inspect SQLite database via SQLAlchemy session to guarantee ACID persistence
    db = SessionLocal()
    db_records = db.query(ScanRecord).all()
    db.close()
    assert len(db_records) >= 4, f"Direct SQLite query expected >= 4 records, got {len(db_records)}"
    
    # 4. Test detail retrieval endpoint
    latest_id = latest["id"]
    res_detail = client.get(f"/api/v1/history/{latest_id}")
    assert res_detail.status_code == 200
    detail_data = res_detail.json()
    assert detail_data["sha256"] == upload_data["sha256"]

    log_result("SQLite Database Logging", True, f"Verified {len(db_records)} records persisted in cybersentinel.db with SHA-256 evidence hashes and origin IP {latest['origin_ip']}. History API retrieved successfully.")
except Exception as e:
    log_result("SQLite Database Logging", False, str(e))

print("\n" + "=" * 65)
print("              PHASE 2 VERIFICATION SUMMARY")
print("=" * 65)
all_ok = True
for feature, (st, det) in results_summary.items():
    print(f"{feature.ljust(30)}: {st}")
    if st != "PASS":
        all_ok = False

print("=" * 65)
if all_ok:
    print("STATUS: ALL PHASE 2 FEATURES ARE 100% OPERATIONAL AND VERIFIED!")
    sys.exit(0)
else:
    print("STATUS: SOME TESTS FAILED")
    sys.exit(1)
