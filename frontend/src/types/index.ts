export interface HealthStatus {
  status: string;
  project: string;
  version: string;
  timestamp: string;
}

export interface ExtractedHeader {
  name: string;
  value: string;
}

export interface AuthenticationStatus {
  spf: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE';
  dkim: 'PASS' | 'FAIL' | 'NONE';
  dmarc: 'PASS' | 'FAIL' | 'NONE';
  details?: string;
}

export interface DomainReputationDetails {
  entropy: number;
  is_high_entropy: boolean;
  impersonated_brand?: string;
  typosquatting_detected: boolean;
  tld_reputation_tier: string;
  protocol_risk: string;
  reputation_verdict: string;
  reputation_score: number;
  threat_indicators: string[];
}

export interface ExtractedUrl {
  url: string;
  domain: string;
  anchor_text?: string;
  is_suspicious: boolean;
  risk_score?: number;
  threat_category?: string;
  is_shortener?: boolean;
  has_homograph?: boolean;
  reputation?: DomainReputationDetails;
  reasons: string[];
}

export interface HopGeolocation {
  ip: string;
  hop_index: number;
  hostname?: string;
  by?: string;
  protocol?: string;
  timestamp?: string;
  delay_seconds?: number;
  country?: string;
  country_code?: string;
  city?: string;
  region?: string;
  isp?: string;
  org?: string;
  lat?: number;
  lon?: number;
  is_private: boolean;
}

export interface AttachmentMeta {
  filename: string;
  content_type: string;
  size_bytes: number;
  is_suspicious_extension: boolean;
}

export interface RiskFactor {
  rule: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  points: number;
  description: string;
}

export interface ThreatSubscores {
  authentication: number;
  urls_domains: number;
  ai_content: number;
  network_origin: number;
  attachments: number;
}

export interface ThreatAssessment {
  score: number;
  level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  verdict: string;
  summary: string;
  ai_confidence: number;
  intent_category: string;
  subscores: ThreatSubscores;
  explanation_points: string[];
  flagged_phrases: string[];
  risk_factors: RiskFactor[];
}

export interface EmailAnalysisResult {
  scan_id?: number;
  analyzed_at: string;
  file_name?: string;
  md5: string;
  sha256: string;
  subject: string;
  sender: string;
  recipient: string;
  date?: string;
  reply_to?: string;
  return_path?: string;
  message_id?: string;
  authentication: AuthenticationStatus;
  headers: ExtractedHeader[];
  hops: HopGeolocation[];
  urls: ExtractedUrl[];
  attachments: AttachmentMeta[];
  body_plain?: string;
  body_html_snippet?: string;
  threat: ThreatAssessment;
}

export interface ScanHistorySummary {
  id: number;
  created_at: string;
  file_name?: string;
  subject: string;
  sender: string;
  recipient: string;
  threat_score: number;
  threat_level: string;
  verdict: string;
  origin_ip?: string;
  origin_country?: string;
}
