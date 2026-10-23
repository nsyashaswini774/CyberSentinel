from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.email import ScanHistorySummary, EmailAnalysisResult
from app.services.pdf_generator import generate_forensic_pdf

router = APIRouter(prefix="/history", tags=["Scan History & Case Archives"])


@router.get("", response_model=List[ScanHistorySummary])
def list_scan_history(
    q: Optional[str] = Query(None, description="Search keyword across subject, sender, recipient, IP, verdict"),
    threat_level: Optional[str] = Query(None, description="Filter by threat level (CRITICAL, HIGH, MEDIUM, LOW, SAFE)"),
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """
    Retrieves and filters historical forensic cases from the SQLite database.
    Supports full-text keyword search and threat level filtering.
    """
    query = db.query(ScanRecord)

    if threat_level and threat_level.upper() != "ALL":
        query = query.filter(ScanRecord.threat_level == threat_level.upper())

    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                ScanRecord.subject.ilike(term),
                ScanRecord.sender.ilike(term),
                ScanRecord.recipient.ilike(term),
                ScanRecord.verdict.ilike(term),
                ScanRecord.origin_ip.ilike(term),
                ScanRecord.origin_country.ilike(term),
                ScanRecord.sha256_hash.ilike(term),
                ScanRecord.file_name.ilike(term)
            )
        )

    records = query.order_by(ScanRecord.created_at.desc()).offset(skip).limit(limit).all()
    return records


@router.get("/{scan_id}", response_model=EmailAnalysisResult)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """
    Retrieves full structured forensic details for a specific case by ID.
    """
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Case record #{scan_id} not found")

    if not record.forensic_data:
        raise HTTPException(status_code=404, detail="Forensic case data is empty or corrupted")

    data = dict(record.forensic_data)
    data["scan_id"] = record.id
    return data


@router.get("/{scan_id}/pdf")
def download_scan_pdf(scan_id: int, db: Session = Depends(get_db)):
    """
    Generates and streams an executive-grade Forensic PDF Investigation Report for a stored case.
    """
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Case record #{scan_id} not found")

    if not record.forensic_data:
        raise HTTPException(status_code=404, detail="Forensic case data is empty or corrupted")

    data = dict(record.forensic_data)
    data["scan_id"] = record.id

    try:
        analysis_obj = EmailAnalysisResult.model_validate(data)
        pdf_bytes = generate_forensic_pdf(analysis_obj)
        sha_short = (record.sha256_hash or "scan")[:8]
        filename = f"VYUHA_Forensic_Report_{record.id}_{sha_short}.pdf"

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


@router.delete("/{scan_id}")
def delete_scan_record(scan_id: int, db: Session = Depends(get_db)):
    """
    Deletes a case record from the historical archives.
    """
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Case record #{scan_id} not found")

    try:
        db.delete(record)
        db.commit()
        return {"status": "success", "message": f"Case #{scan_id} successfully deleted"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete case record: {str(e)}")

