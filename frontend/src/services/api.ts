import axios from 'axios';
import type { HealthStatus, EmailAnalysisResult, ScanHistorySummary } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

export const apiService = {
  // System Health Check
  async getHealth(): Promise<HealthStatus> {
    const response = await apiClient.get<HealthStatus>('/health');
    return response.data;
  },

  // Upload .eml file for analysis
  async analyzeEmlFile(file: File): Promise<EmailAnalysisResult> {
    const formData = new FormData();
    formData.append('file', file);
    const response = await apiClient.post<EmailAnalysisResult>('/analyze/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  // Analyze raw text/header input
  async analyzeRawText(rawContent: string, filename?: string): Promise<EmailAnalysisResult> {
    const response = await apiClient.post<EmailAnalysisResult>('/analyze/raw', {
      raw_content: rawContent,
      filename: filename || 'pasted_email.eml',
    });
    return response.data;
  },

  // Fetch scan history with search and threat level filtering
  async getScanHistory(
    query?: string,
    threatLevel?: string,
    limit: number = 50,
    skip: number = 0
  ): Promise<ScanHistorySummary[]> {
    const params: Record<string, any> = { limit, skip };
    if (query && query.trim()) params.q = query.trim();
    if (threatLevel && threatLevel !== 'ALL') params.threat_level = threatLevel;

    const response = await apiClient.get<ScanHistorySummary[]>('/history', { params });
    return response.data;
  },

  // Fetch specific historical scan detail
  async getScanDetail(scanId: number): Promise<EmailAnalysisResult> {
    const response = await apiClient.get<EmailAnalysisResult>(`/history/${scanId}`);
    return response.data;
  },

  // Download PDF report for saved scan
  async downloadScanPdf(scanId: number, preferredFilename?: string): Promise<void> {
    const response = await apiClient.get(`/history/${scanId}/pdf`, {
      responseType: 'blob',
    });
    const blob = new Blob([response.data], { type: 'application/pdf' });
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = preferredFilename || `CyberSentinel_Report_Case_${scanId}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  },

  // Export active in-memory scan result to PDF
  async exportCurrentScanPdf(result: EmailAnalysisResult, preferredFilename?: string): Promise<void> {
    const response = await apiClient.post('/analyze/export-pdf', result, {
      responseType: 'blob',
    });
    const blob = new Blob([response.data], { type: 'application/pdf' });
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    const shaShort = (result.sha256 || 'scan').slice(0, 8);
    link.download = preferredFilename || `CyberSentinel_Report_${result.scan_id || 'Active'}_${shaShort}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  },

  // Delete a case from historical archives
  async deleteScan(scanId: number): Promise<void> {
    await apiClient.delete(`/history/${scanId}`);
  },

  // Load built-in sample email analysis for 1-click testing
  async loadSampleAnalysis(): Promise<EmailAnalysisResult> {
    const response = await apiClient.get<EmailAnalysisResult>('/analyze/sample');
    return response.data;
  },
};

export default apiService;

