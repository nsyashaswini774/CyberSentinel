from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.email import EmailAnalysisResult, EmailRawInput
from app.services.email_parser import parse_email_message

router = APIRouter(prefix="/analyze", tags=["Forensic Analysis"])


def save_scan_to_database(db: Session, result: EmailAnalysisResult) -> int:
    """Helper to persist scan results into the SQLite database."""
    try:
        public_hops = [h for h in result.hops if not h.is_private]
        origin_hop = public_hops[0] if public_hops else (result.hops[0] if result.hops else None)
        origin_ip = origin_hop.ip if origin_hop else None
        origin_country = origin_hop.country if origin_hop else None
        origin_city = origin_hop.city if origin_hop else None

        record = ScanRecord(
            file_name=result.file_name,
            subject=result.subject,
            sender=result.sender,
            recipient=result.recipient,
            date_header=result.date,
            message_id=result.message_id,
            sha256_hash=result.sha256,
            md5_hash=result.md5,
            threat_score=result.threat.score,
            threat_level=result.threat.level,
            verdict=result.threat.verdict,
            origin_ip=origin_ip,
            origin_country=origin_country,
            origin_city=origin_city,
            forensic_data=result.model_dump(mode="json")
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record.id
    except Exception as e:
        db.rollback()
        # Non-blocking for the analysis response
        return 0


@router.post("/upload", response_model=EmailAnalysisResult)
async def analyze_eml_file(
    file: UploadFile = File(..., description="The .eml email file to analyze"),
    db: Session = Depends(get_db)
):
    """
    Ingests and parses an uploaded .eml file.
    Extracts headers, authentication status, URLs, attachments, and computes evidence hashes.
    """
    if not file.filename.lower().endswith((".eml", ".msg", ".txt")):
        # Still attempt to parse, but warn
        pass

    try:
        content_bytes = await file.read()
        if not content_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        analysis = parse_email_message(content_bytes, filename=file.filename)
        scan_id = save_scan_to_database(db, analysis)
        analysis.scan_id = scan_id
        return analysis

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse email file: {str(e)}")


@router.post("/raw", response_model=EmailAnalysisResult)
def analyze_raw_text(
    payload: EmailRawInput,
    db: Session = Depends(get_db)
):
    """
    Ingests and parses raw email RFC 822/5322 text or pasted email content.
    """
    if not payload.raw_content.strip():
        raise HTTPException(status_code=400, detail="Raw content cannot be empty.")

    try:
        content_bytes = payload.raw_content.encode("utf-8")
        analysis = parse_email_message(content_bytes, filename=payload.filename or "pasted_email.eml")
        scan_id = save_scan_to_database(db, analysis)
        analysis.scan_id = scan_id
        return analysis

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse email text: {str(e)}")


# Built-in sample email for 1-click testing
SAMPLE_PHISHING_EMAIL = """Received: from mx.enterprise.org (mx.enterprise.org [10.0.0.1])
    by internal-mail.enterprise.org with ESMTP id ent88912;
    Thu, 03 Sep 2026 14:22:15 +0000
Received: from relay02.transit-net.nl (relay02.transit-net.nl [198.51.100.42])
    by mx.enterprise.org with ESMTP id mx99214;
    Thu, 03 Sep 2026 14:22:13 +0000
Received: from node01.sec-alerts-update.xyz (node01.sec-alerts-update.xyz [185.220.101.5])
    by relay02.transit-net.nl with ESMTP id tr88210;
    Thu, 03 Sep 2026 14:22:10 +0000
From: "IT Support Helpdesk" <support@sec-alerts-update.xyz>
To: target.user@enterprise.org
Subject: URGENT: Mandatory Password Reset Required Immediately
Date: Thu, 03 Sep 2026 14:22:10 +0000
Message-ID: <20260903142210.12345@sec-alerts-update.xyz>
Return-Path: <bounce-99@malicious-spoofer.net>
Reply-To: credential-collector@suspicious-external.top
Authentication-Results: mx.enterprise.org;
    spf=fail (sender IP is 185.220.101.5) smtp.mailfrom=sec-alerts-update.xyz;
    dkim=fail header.i=@sec-alerts-update.xyz;
    dmarc=fail (p=REJECT)
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<body>
  <h2>Urgent Security Notice</h2>
  <p>Dear Employee,</p>
  <p>Your enterprise email account has been flagged for unusual sign-in activity. Failure to verify your credentials within 24 hours will result in permanent account suspension.</p>
  <p>Please click the secure link below to update your login credentials immediately:</p>
  <p><a href="http://192.168.1.100/login/verify.php?user=target">https://security.enterprise.org/reset-password</a></p>
  <p>Alternatively visit our shortlink portal: <a href="https://bit.ly/secure-auth-99">https://bit.ly/secure-auth-99</a></p>
  <p>Or backup mirror: <a href="http://xn--microsft-75a.com/auth">http://portal-verification.buzz/auth</a></p>
  <br>
  <p>Corporate IT Security Operations Center</p>
</body>
</html>
"""

@router.get("/sample", response_model=EmailAnalysisResult)
def get_sample_analysis(db: Session = Depends(get_db)):
    """
    Provides an instant analysis of a pre-configured realistic phishing email sample
    for live evaluation and testing.
    """
    content_bytes = SAMPLE_PHISHING_EMAIL.encode("utf-8")
    analysis = parse_email_message(content_bytes, filename="sample_phishing_attack.eml")
    scan_id = save_scan_to_database(db, analysis)
    analysis.scan_id = scan_id
    return analysis


@router.post("/export-pdf")
def export_analysis_pdf(payload: EmailAnalysisResult):
    """
    Exports full forensic scan results into a downloadable PDF report.
    """
    try:
        from app.services.pdf_generator import generate_forensic_pdf
        pdf_bytes = generate_forensic_pdf(payload)
        sha_short = (payload.sha256 or "scan")[:8]
        filename = f"VYUHA_Report_{payload.scan_id or 'active'}_{sha_short}.pdf"

        from fastapi import Response
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate forensic PDF report: {str(e)}")

