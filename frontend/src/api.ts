/**
 * frontend/src/api.ts
 * Type-safe API client for ThreatGuard AI (FastAPI backend).
 */

export interface User {
  id: number;
  name: string;
  username: string;
  email: string;
  role: 'admin' | 'user';
  is_active: boolean;
  created_at: string;
  last_login?: string | null;
}

export interface ScanFinding {
  id: number;
  finding_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
  evidence?: string | null;
  source?: string | null;
  confidence?: number | null;
  points?: number | null;
  recommended_action?: string | null;
}

export interface ExtractedURL {
  id: number;
  original_url: string;
  hostname?: string | null;
  protocol?: string | null;
  anchor_text?: string | null;
  uses_https?: boolean | null;
  is_ip_address?: boolean | null;
  is_punycode?: boolean | null;
  uses_shortener?: boolean | null;
  has_anchor_mismatch?: boolean | null;
  url_score?: number | null;
  analysis_status: string;
  flags?: any[] | null;
  checked_at?: string | null;
}

export interface ScanDetail {
  id: number;
  scan_status: string;
  original_filename?: string | null;
  file_hash?: string | null;
  subject?: string | null;
  sender?: string | null;
  reply_to?: string | null;
  received_at?: string | null;
  classification?: string | null;
  model_score?: number | null;
  overall_risk?: 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical Risk' | 'Inconclusive' | null;
  scoring_rule_version?: string | null;
  error_message?: string | null;
  created_at: string;
  completed_at?: string | null;
  findings: ScanFinding[];
  extracted_urls: ExtractedURL[];
  full_result?: any;
}

export interface ScanSummary {
  id: number;
  scan_status: string;
  original_filename?: string | null;
  subject?: string | null;
  sender?: string | null;
  classification?: string | null;
  model_score?: number | null;
  overall_risk?: string | null;
  created_at: string;
  completed_at?: string | null;
}

export interface ScanListResponse {
  total: number;
  page: number;
  page_size: number;
  items: ScanSummary[];
}

export interface DashboardSummary {
  total_scans: number;
  likely_phishing: number;
  suspicious: number;
  likely_legitimate: number;
  insufficient_evidence: number;
  high_risk_findings: number;
  model_version?: string | null;
  model_status: string;
  recent_scans: Array<{
    id: number;
    subject: string;
    sender: string;
    overall_risk: string;
    classification: string;
    created_at: string;
  }>;
}

export interface TrendPoint {
  date: string;
  total: number;
  phishing: number;
  legitimate: number;
  suspicious: number;
}

export interface DashboardTrends {
  period_days: number;
  data: TrendPoint[];
}

export interface AdminUser {
  id: number;
  name: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login?: string | null;
  scan_count: number;
}

export interface ModelStatus {
  version: string;
  status: string;
  algorithm?: string | null;
  training_date?: string | null;
  artifact_path?: string | null;
  message?: string | null;
}

const TOKEN_KEY = 'threatguard_access_token';
const REFRESH_KEY = 'threatguard_refresh_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setTokens(access: string, refresh: string) {
  localStorage.setItem(TOKEN_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
}

export function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(options.headers || {});

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    // Session expired or invalid
    clearTokens();
    window.dispatchEvent(new Event('auth:unauthorized'));
    throw new Error('Session expired. Please log in again.');
  }

  if (!response.ok) {
    let errorDetail = `Request failed (${response.status})`;
    try {
      const errJson = await response.json();
      if (typeof errJson.detail === 'string') {
        errorDetail = errJson.detail;
      } else if (Array.isArray(errJson.detail)) {
        errorDetail = errJson.detail
          .map((item: any) => {
            if (typeof item === 'string') return item;
            const field = item.loc && item.loc.length > 1 ? `${item.loc[item.loc.length - 1]}: ` : '';
            const msg = (item.msg || item.message || '').replace(/^Value error,\s*/i, '');
            return `${field}${msg}`;
          })
          .filter(Boolean)
          .join('. ');
      } else if (errJson.message) {
        errorDetail = typeof errJson.message === 'string' ? errJson.message : JSON.stringify(errJson.message);
      } else if (errJson.detail) {
        errorDetail = JSON.stringify(errJson.detail);
      }
    } catch {
      // fallback
    }
    throw new Error(errorDetail);
  }

  if (response.status === 204) {
    return null as any;
  }

  return response.json();
}

export const api = {
  // Auth
  async login(username_or_email: string, password: string) {
    const data = await request<{ access_token: string; refresh_token: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username_or_email, password }),
    });
    setTokens(data.access_token, data.refresh_token);
    return this.getMe();
  },

  async register(name: string, username: string, email: string, password: string, confirm_password: string) {
    const data = await request<{ access_token: string; refresh_token: string }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, username, email, password, confirm_password }),
    });
    setTokens(data.access_token, data.refresh_token);
    return this.getMe();
  },

  async getMe(): Promise<User> {
    return request<User>('/api/auth/me');
  },

  logout() {
    clearTokens();
  },

  // Dashboard
  async getDashboardSummary(): Promise<DashboardSummary> {
    return request<DashboardSummary>('/api/dashboard/summary');
  },

  async getDashboardTrends(days = 30): Promise<DashboardTrends> {
    return request<DashboardTrends>(`/api/dashboard/trends?days=${days}`);
  },

  // Scans
  async uploadScan(file: File): Promise<ScanDetail> {
    const formData = new FormData();
    formData.append('file', file);
    return request<ScanDetail>('/api/scans/upload', {
      method: 'POST',
      body: formData,
    });
  },

  async analyzeSource(raw_email: string): Promise<ScanDetail> {
    return request<ScanDetail>('/api/scans/analyze-source', {
      method: 'POST',
      body: JSON.stringify({ raw_email }),
    });
  },

  async listScans(page = 1, pageSize = 15, search?: string, risk?: string): Promise<ScanListResponse> {
    let url = `/api/scans?page=${page}&page_size=${pageSize}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (risk) url += `&risk=${encodeURIComponent(risk)}`;
    return request<ScanListResponse>(url);
  },

  async getScan(id: number): Promise<ScanDetail> {
    return request<ScanDetail>(`/api/scans/${id}`);
  },

  async deleteScan(id: number): Promise<void> {
    return request<void>(`/api/scans/${id}`, { method: 'DELETE' });
  },

  async downloadReport(id: number): Promise<Blob> {
    const token = getToken();
    const res = await fetch(`/api/scans/${id}/report`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error('Report download failed');
    return res.blob();
  },

  // Admin
  async listAdminUsers(): Promise<{ total: number; items: AdminUser[] }> {
    return request<{ total: number; items: AdminUser[] }>('/api/admin/users');
  },

  async toggleUserRole(userId: number): Promise<{ id: number; role: string }> {
    return request(`/api/admin/users/${userId}/toggle-role`, { method: 'POST' });
  },

  async suspendUser(userId: number): Promise<void> {
    return request(`/api/admin/users/${userId}/suspend`, { method: 'POST' });
  },

  async activateUser(userId: number): Promise<void> {
    return request(`/api/admin/users/${userId}/activate`, { method: 'POST' });
  },

  async deleteUser(userId: number): Promise<void> {
    return request(`/api/admin/users/${userId}`, { method: 'DELETE' });
  },

  async getModelStatus(): Promise<ModelStatus> {
    return request<ModelStatus>('/api/model/status');
  },

  async getModelMetrics(): Promise<any> {
    return request<any>('/api/model/metrics');
  },

  // Live Monitor
  async getMonitorStatus(): Promise<MonitorStatus> {
    return request<MonitorStatus>('/api/monitor/status');
  },

  async startMonitor(): Promise<{ success: boolean; message: string; running: boolean }> {
    return request('/api/monitor/start', { method: 'POST' });
  },

  async stopMonitor(): Promise<{ success: boolean; message: string; running: boolean }> {
    return request('/api/monitor/stop', { method: 'POST' });
  },

  async restartMonitor(): Promise<{ success: boolean; message: string; running: boolean }> {
    return request('/api/monitor/restart', { method: 'POST' });
  },

  async pollNow(): Promise<{ success: boolean; message: string }> {
    return request('/api/monitor/poll-now', { method: 'POST' });
  },

  async testImapConnection(data: { imap_host: string; imap_port: number; imap_email: string; app_password: string }): Promise<{ success: boolean; message: string }> {
    return request('/api/monitor/test-connection', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async saveImapCredentials(data: ImapCredentialsInput): Promise<{ success: boolean; message: string; is_active: boolean }> {
    return request('/api/monitor/credentials', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
};

export interface LiveScanEvent {
  time: string;
  subject: string;
  from: string;
  verdict: string;
  scan_id: number;
  user_id: number;
}

export interface MonitorStatus {
  running: boolean;
  active_accounts: number;
  emails_scanned: number;
  last_check?: string | null;
  last_error?: string | null;
  recent: LiveScanEvent[];
  has_credentials: boolean;
  imap_email?: string | null;
  imap_host?: string | null;
  imap_port?: number;
  credentials_active?: boolean;
  poll_interval: number;
}

export interface ImapCredentialsInput {
  imap_host: string;
  imap_port: number;
  imap_email: string;
  app_password: string;
  is_active: boolean;
}
