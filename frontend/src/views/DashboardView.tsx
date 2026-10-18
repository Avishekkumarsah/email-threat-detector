import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, AlertTriangle, CheckCircle, ShieldCheck, 
  Search, ArrowRight, Activity, Cpu, Database, RefreshCw
} from 'lucide-react';
import { api } from '../api';
import type { DashboardSummary } from '../api';

interface DashboardViewProps {
  onGoToScanner: () => void;
  onSelectScan: (scanId: number) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  onGoToScanner,
  onSelectScan,
}) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard statistics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Hero Welcome Banner */}
      <div
        className="glass-panel"
        style={{
          padding: '32px',
          background: 'radial-gradient(ellipse at 80% 20%, rgba(6, 182, 212, 0.15) 0%, rgba(15, 23, 42, 0.8) 70%)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '20px',
        }}
      >
        <div>
          <div className="badge badge-low" style={{ marginBottom: '10px' }}>
            ● Production Threat Defense Active
          </div>
          <h1 style={{ fontSize: '28px', margin: '0 0 8px', color: '#f8fafc' }}>
            Email Threat & Geolocation Intelligence
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '15px', maxWidth: '640px' }}>
            Continuous multi-factor analysis protecting your communications against zero-day phishing,
            lookalike spoofing, macro payloads, and malicious relays.
          </p>
        </div>

        <button
          onClick={onGoToScanner}
          className="btn btn-primary"
          style={{ padding: '12px 24px', fontSize: '15px' }}
        >
          <Search size={18} />
          Launch New Scan
        </button>
      </div>

      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.35)',
          borderRadius: '12px',
          padding: '12px 16px',
          color: '#fca5a5',
          fontSize: '14px',
        }}>
          {error}
        </div>
      )}

      {/* Top 4 Metrics Grid */}
      <div className="grid-cols-4">
        {/* Total Scans */}
        <div className="glass-panel glass-panel-hover" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#94a3b8' }}>Total Scans</span>
            <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'rgba(6, 182, 212, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Activity size={18} color="var(--accent-cyan)" />
            </div>
          </div>
          <div style={{ fontSize: '30px', fontWeight: 800, color: '#f8fafc', fontFamily: 'JetBrains Mono' }}>
            {loading ? '...' : summary?.total_scans ?? 0}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            Indexed forensic evaluations
          </div>
        </div>

        {/* Likely Phishing */}
        <div className="glass-panel glass-panel-hover" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#f87171' }}>Likely Phishing</span>
            <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldAlert size={18} color="#ef4444" />
            </div>
          </div>
          <div style={{ fontSize: '30px', fontWeight: 800, color: '#ef4444', fontFamily: 'JetBrains Mono' }}>
            {loading ? '...' : summary?.likely_phishing ?? 0}
          </div>
          <div style={{ fontSize: '12px', color: '#fca5a5', marginTop: '4px' }}>
            High & Critical threats neutralized
          </div>
        </div>

        {/* Suspicious */}
        <div className="glass-panel glass-panel-hover" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#fbbf24' }}>Suspicious</span>
            <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <AlertTriangle size={18} color="#f59e0b" />
            </div>
          </div>
          <div style={{ fontSize: '30px', fontWeight: 800, color: '#f59e0b', fontFamily: 'JetBrains Mono' }}>
            {loading ? '...' : summary?.suspicious ?? 0}
          </div>
          <div style={{ fontSize: '12px', color: '#fde68a', marginTop: '4px' }}>
            Requires manual scrutiny
          </div>
        </div>

        {/* Likely Legitimate */}
        <div className="glass-panel glass-panel-hover" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#34d399' }}>Legitimate</span>
            <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <CheckCircle size={18} color="#10b981" />
            </div>
          </div>
          <div style={{ fontSize: '30px', fontWeight: 800, color: '#10b981', fontFamily: 'JetBrains Mono' }}>
            {loading ? '...' : summary?.likely_legitimate ?? 0}
          </div>
          <div style={{ fontSize: '12px', color: '#a7f3d0', marginTop: '4px' }}>
            Clean cryptographic authentication
          </div>
        </div>
      </div>

      {/* Middle Grid: Threat Distribution + System Telemetry */}
      <div className="grid-cols-2">
        {/* Threat Distribution Chart Card */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px' }}>
            <ShieldCheck size={18} color="var(--accent-cyan)" />
            Threat Level Classification Distribution
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Phishing Bar */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
                <span style={{ color: '#f87171', fontWeight: 600 }}>Likely Phishing (Critical / High)</span>
                <span style={{ fontFamily: 'JetBrains Mono', color: '#f87171' }}>{summary?.likely_phishing ?? 0}</span>
              </div>
              <div style={{ height: '8px', background: 'rgba(255,255,255,0.06)', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${summary?.total_scans ? ((summary.likely_phishing / summary.total_scans) * 100).toFixed(1) : 0}%`,
                  background: '#ef4444',
                  borderRadius: '4px',
                }} />
              </div>
            </div>

            {/* Suspicious Bar */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
                <span style={{ color: '#fbbf24', fontWeight: 600 }}>Suspicious (Medium Risk)</span>
                <span style={{ fontFamily: 'JetBrains Mono', color: '#fbbf24' }}>{summary?.suspicious ?? 0}</span>
              </div>
              <div style={{ height: '8px', background: 'rgba(255,255,255,0.06)', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${summary?.total_scans ? ((summary.suspicious / summary.total_scans) * 100).toFixed(1) : 0}%`,
                  background: '#f59e0b',
                  borderRadius: '4px',
                }} />
              </div>
            </div>

            {/* Legitimate Bar */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
                <span style={{ color: '#34d399', fontWeight: 600 }}>Likely Legitimate (Low Risk)</span>
                <span style={{ fontFamily: 'JetBrains Mono', color: '#34d399' }}>{summary?.likely_legitimate ?? 0}</span>
              </div>
              <div style={{ height: '8px', background: 'rgba(255,255,255,0.06)', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${summary?.total_scans ? ((summary.likely_legitimate / summary.total_scans) * 100).toFixed(1) : 0}%`,
                  background: '#10b981',
                  borderRadius: '4px',
                }} />
              </div>
            </div>

            {/* High Risk Findings Count */}
            <div style={{
              marginTop: '12px',
              padding: '14px',
              borderRadius: '10px',
              background: 'rgba(239, 68, 68, 0.08)',
              border: '1px solid rgba(239, 68, 68, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <span style={{ fontSize: '13px', color: '#fca5a5' }}>
                High & Critical Forensic Indicators Detected:
              </span>
              <span style={{ fontSize: '16px', fontWeight: 800, color: '#ef4444', fontFamily: 'JetBrains Mono' }}>
                {summary?.high_risk_findings ?? 0}
              </span>
            </div>
          </div>
        </div>

        {/* Architecture & Telemetry Card */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px' }}>
            <Cpu size={18} color="var(--accent-cyan)" />
            Engine Telemetry & ML Runtime Status
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '10px' }}>
              <span style={{ color: '#94a3b8' }}>Backend Architecture:</span>
              <span className="badge badge-low">FastAPI 0.115 + Uvicorn</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '10px' }}>
              <span style={{ color: '#94a3b8' }}>Database Engine:</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
                <Database size={14} color="#06b6d4" />
                Neon Cloud PostgreSQL
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '10px' }}>
              <span style={{ color: '#94a3b8' }}>ML Classifier Status:</span>
              <span className="badge badge-low">
                {summary?.model_status === 'loaded' ? 'Active (Loaded)' : summary?.model_status}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '10px' }}>
              <span style={{ color: '#94a3b8' }}>Model Version:</span>
              <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                v{summary?.model_version || '1.0.0'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#94a3b8' }}>Session Security:</span>
              <span style={{ color: '#cbd5e1' }}>Argon2id + HS256 JWT</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Activity Feed */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={18} color="var(--accent-cyan)" />
            Recent Forensic Evaluations
          </h3>
          <button onClick={fetchSummary} className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '12px' }}>
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>

        {summary?.recent_scans && summary.recent_scans.length > 0 ? (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Subject Line</th>
                  <th>Sender Address</th>
                  <th>Risk Level</th>
                  <th>Classification</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {summary.recent_scans.map((s) => (
                  <tr key={s.id}>
                    <td style={{ fontWeight: 600, color: '#f8fafc', maxWidth: '320px' }}>
                      {s.subject || '(no subject)'}
                    </td>
                    <td style={{ color: '#94a3b8', maxWidth: '240px' }}>{s.sender}</td>
                    <td>
                      <span className={`badge ${
                        s.overall_risk === 'Critical Risk' || s.overall_risk === 'High Risk'
                          ? 'badge-critical'
                          : s.overall_risk === 'Medium Risk'
                          ? 'badge-medium'
                          : 'badge-low'
                      }`}>
                        {s.overall_risk}
                      </span>
                    </td>
                    <td style={{ fontSize: '12px', color: '#cbd5e1' }}>{s.classification}</td>
                    <td style={{ fontSize: '12px', color: '#64748b' }}>
                      {s.created_at ? new Date(s.created_at).toLocaleString() : '-'}
                    </td>
                    <td>
                      <button
                        onClick={() => onSelectScan(s.id)}
                        className="btn btn-outline-cyan"
                        style={{ padding: '4px 10px', fontSize: '12px' }}
                      >
                        Inspect
                        <ArrowRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '36px', textAlign: 'center', color: '#94a3b8' }}>
            No recent scans recorded. Click "Launch New Scan" above to analyze your first email!
          </div>
        )}
      </div>
    </div>
  );
};
