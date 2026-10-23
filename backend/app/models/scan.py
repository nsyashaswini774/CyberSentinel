import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, JSON
from app.core.database import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Email Metadata
    file_name = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=True, default="(No Subject)")
    sender = Column(String(255), nullable=True)
    recipient = Column(String(255), nullable=True)
    date_header = Column(String(100), nullable=True)
    message_id = Column(String(255), nullable=True)
    
    # Forensic Integrity & Hashes
    sha256_hash = Column(String(64), nullable=True, index=True)
    md5_hash = Column(String(32), nullable=True)
    
    # Threat Metrics
    threat_score = Column(Float, default=0.0)
    threat_level = Column(String(50), default="SAFE")
    verdict = Column(String(100), default="Legitimate")
    
    # Network & Geolocation
    origin_ip = Column(String(45), nullable=True)
    origin_country = Column(String(100), nullable=True)
    origin_city = Column(String(100), nullable=True)
    
    # Full Structured Forensic Details
    forensic_data = Column(JSON, nullable=True)
