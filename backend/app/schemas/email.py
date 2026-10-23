from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class HealthResponse(BaseModel):
    status: str = "ok"
    project: str = "VYUHA AI"
    version: str = "0.1.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class EmailRawInput(BaseModel):
    """Schema for direct text/header paste input."""
    raw_content: str = Field(..., description="Raw RFC 822/5322 email string or email headers + body")
    filename: Optional[str] = Field("pasted_email.eml", description="Optional label for the email")


class AuthenticationStatus(BaseModel):
    spf: str = "NONE"          # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE
    dkim: str = "NONE"         # PASS, FAIL, NONE
    dmarc: str = "NONE"        # PASS, FAIL, NONE
    details: Optional[str] = None


class ExtractedHeader(BaseModel):
    name: str
    value: str


class AttachmentMeta(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    is_suspicious_extension: bool = False


class DomainReputationDetails(BaseModel):
    entropy: float = 0.0
    is_high_entropy: bool = False
    impersonated_brand: Optional[str] = None
    typosquatting_detected: bool = False
    tld_reputation_tier: str = "Standard"
    protocol_risk: str = "Secure (HTTPS)"
    reputation_verdict: str = "Neutral"
    reputation_score: float = 0.0
    threat_indicators: List[str] = []


class ExtractedUrl(BaseModel):
    url: str
    domain: str
    anchor_text: Optional[str] = None
    is_suspicious: bool = False
    risk_score: float = 0.0
    threat_category: Optional[str] = None
    is_shortener: bool = False
    has_homograph: bool = False
    reputation: Optional[DomainReputationDetails] = None
    reasons: List[str] = []


class HopGeolocation(BaseModel):
    ip: str
    hop_index: int
    hostname: Optional[str] = None
    by: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None
    delay_seconds: Optional[float] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    is_private: bool = False


class RiskFactor(BaseModel):
    rule: str
    severity: str              # LOW, MEDIUM, HIGH, CRITICAL
    points: float
    description: str


class ThreatSubscores(BaseModel):
    authentication: float = 0.0
    urls_domains: float = 0.0
    ai_content: float = 0.0
    network_origin: float = 0.0
    attachments: float = 0.0


class ThreatAssessment(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0, description="Risk score from 0 (clean) to 100 (critical)")
    level: str = "SAFE"        # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    verdict: str = "Legitimate" # Legitimate, Suspicious, Likely Phishing, Malicious
    summary: str
    ai_confidence: float = 0.0
    intent_category: str = "Benign"
    subscores: ThreatSubscores = Field(default_factory=ThreatSubscores)
    explanation_points: List[str] = []
    flagged_phrases: List[str] = []
    risk_factors: List[RiskFactor] = []


class EmailAnalysisResult(BaseModel):
    scan_id: Optional[int] = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    file_name: Optional[str] = None
    
    # Hashes for Evidence Integrity
    md5: str
    sha256: str
    
    # Core Headers
    subject: str
    sender: str
    recipient: str
    date: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    
    # Security & Forensics
    authentication: AuthenticationStatus
    headers: List[ExtractedHeader] = []
    hops: List[HopGeolocation] = []
    urls: List[ExtractedUrl] = []
    attachments: List[AttachmentMeta] = []
    
    # Content Snippets
    body_plain: Optional[str] = None
    body_html_snippet: Optional[str] = None
    
    # AI Threat Scoring
    threat: ThreatAssessment


class ScanHistorySummary(BaseModel):
    id: int
    created_at: datetime
    file_name: Optional[str]
    subject: str
    sender: str
    recipient: str
    threat_score: float
    threat_level: str
    verdict: str
    origin_ip: Optional[str]
    origin_country: Optional[str]

    class Config:
        from_attributes = True
