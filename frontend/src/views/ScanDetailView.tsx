import React, { useState } from 'react';
import { 
  ArrowLeft, Download, Trash2, ShieldAlert, AlertTriangle, CheckCircle, 
  Globe, Link, FileCode, Mail, Shield
} from 'lucide-react';
import { api } from '../api';
import type { ScanDetail } from '../api';
import { ScoreGauge } from '../components/ScoreGauge';
import { HopMap } from '../components/HopMap';

interface ScanDetailViewProps {
  scan: ScanDetail;
  onBack: () => void;
  onDeleted?: (id: number) => void;
}

export const ScanDetailView: React.FC<ScanDetailViewProps> = ({
  scan,
  onBack,
  onDeleted,
}) => {
  const [downloading, setDownloading] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  const fullResult = scan.full_result || {};
  const scoreData = fullResult.score || {};
  const geoData = fullResult.geo || {};
  const contentData = fullResult.content || {};

  const handleDownloadPDF = async () => {
    try {
      setDownloading(true);
      const blob = await api.downloadReport(scan.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threat_report_${scan.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Report download error: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this scan and its forensic records?')) return;
    try {
      setDeleting(true);
      await api.deleteScan(scan.id);
      if (onDeleted) onDeleted(scan.id);
      onBack();
    } catch (err: any) {
      alert(`Failed to delete scan: ${err.message}`);
      setDeleting(false);
    }
  };

  const filteredFindings = selectedSeverity === 'all'
    ? scan.findings
    : scan.findings.filter((f) => f.severity.toLowerCase() === selectedSeverity.toLowerCase());

  const getVerdictStyle = () => {
    const risk = scan.overall_risk;
    if (risk === 'Critical Risk' || risk === 'High Risk' || scan.classification === 'Likely Phishing') {
      return {
        bg: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(185, 28, 28, 0.1) 100%)',
        border: 'rgba(239, 68, 68, 0.4)',
        color: '#f87171',
        icon: <ShieldAlert size={28} color="#ef4444" />,
      };
    }
    if (risk === 'Medium Risk' || scan.classification === 'Suspicious') {
      return {
        bg: 'linear-gradient(135deg, rgba(245, 158, 11, 0.2) 0%, rgba(180, 83, 9, 0.1) 100%)',
        border: 'rgba(245, 158, 11, 0.4)',
        color: '#fbbf24',
        icon: <AlertTriangle size={28} color="#f59e0b" />,
      };
    }
    return {
      bg: 'linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(4, 120, 87, 0.1) 100%)',
      border: 'rgba(16, 185, 129, 0.4)',
      color: '#34d399',
      icon: <CheckCircle size={28} color="#10b981" />,
    };
  };

  const verdictStyle = getVerdictStyle();

  return (
    <div style={{ maxWidth: '1240px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Action Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <button onClick={onBack} className="btn btn-secondary" style={{ padding: '8px 16px' }}>
          <ArrowLeft size={16} />
          Back to List
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={handleDownloadPDF}
            disabled={downloading}
            className="btn btn-primary"
            style={{ padding: '8px 20px' }}
          >
            <Download size={16} />
            {downloading ? 'Generating PDF...' : 'Download Forensic PDF Report'}
          </button>

          <button
            onClick={handleDelete}
            disabled={deleting}
            className="btn btn-danger"
            style={{ padding: '8px 14px' }}
            title="Delete this scan"
          >
            <Trash2 size={16} />
          </button>
        </div>
      </div>

      {/* Main Verdict Banner */}
      <div
        className="glass-panel"
        style={{
          background: verdictStyle.bg,
          borderColor: verdictStyle.border,
          padding: '24px 32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '16px',
            background: 'rgba(15, 23, 42, 0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${verdictStyle.border}`,
          }}>
            {verdictStyle.icon}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
              <span className={`badge ${
                scan.overall_risk === 'Critical Risk' || scan.overall_risk === 'High Risk'
                  ? 'badge-critical'
                  : scan.overall_risk === 'Medium Risk'
                  ? 'badge-medium'
                  : 'badge-low'
              }`} style={{ fontSize: '13px', padding: '4px 12px' }}>
                {scan.overall_risk || 'Analyzed'}
              </span>
              <span style={{ fontSize: '14px', color: '#cbd5e1' }}>
                Classification: <b>{scan.classification || 'Completed'}</b>
              </span>
            </div>
            <h2 style={{ fontSize: '22px', margin: 0, color: '#f8fafc' }}>
              {scan.subject || '(No Subject Line)'}
            </h2>
            <div style={{ fontSize: '13px', color: '#94a3b8', marginTop: '4px' }}>
              Sender: <code style={{ color: '#38bdf8' }}>{scan.sender || 'Unknown'}</code>
            </div>
          </div>
        </div>

        <div>
          <ScoreGauge score={scoreData.final_score ?? scan.model_score ?? 0} size={130} strokeWidth={11} risk={scan.overall_risk} />
        </div>
      </div>

      {/* Grid: Metadata + Score Breakdown */}
      <div className="grid-cols-2">
        {/* Metadata Card */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
            <Mail size={18} color="var(--accent-cyan)" />
            Email Header & Identification Metadata
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '8px' }}>
              <span style={{ color: '#94a3b8' }}>Original File:</span>
              <span style={{ fontWeight: 600 }}>{scan.original_filename || 'source.eml'}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '8px' }}>
              <span style={{ color: '#94a3b8' }}>Reply-To:</span>
              <span style={{ fontWeight: 600 }}>{scan.reply_to || 'None (Matches From)'}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '8px' }}>
              <span style={{ color: '#94a3b8' }}>Scan Timestamp:</span>
              <span style={{ color: '#cbd5e1' }}>
                {scan.created_at ? new Date(scan.created_at).toLocaleString() : '-'}
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '8px' }}>
              <span style={{ color: '#94a3b8' }}>Cryptographic Hash (SHA-256):</span>
              <span className="font-mono" style={{ fontSize: '11px', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                {scan.file_hash || 'N/A'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#94a3b8' }}>Rule Specification Version:</span>
              <span className="badge badge-neutral">{scan.scoring_rule_version || '2.0'}</span>
            </div>
          </div>
        </div>

        {/* AI & Multi-Layer Threat Breakdown */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
            <Shield size={18} color="var(--accent-cyan)" />
            AI Content & Category Score Contributions
          </h3>

          <div style={{ marginBottom: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
              <span>AI Content Model Phishing Probability:</span>
              <span style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>
                {contentData.phishing_probability ?? scan.model_score ?? 0}%
              </span>
            </div>
            <div style={{ height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}>
              <div style={{
                height: '100%',
                width: `${contentData.phishing_probability ?? scan.model_score ?? 0}%`,
                background: 'linear-gradient(90deg, #06b6d4, #ef4444)',
                borderRadius: '4px',
              }} />
            </div>
          </div>

          {/* Breakdown table */}
          {scoreData.breakdown && scoreData.breakdown.length > 0 && (
            <div className="table-wrapper">
              <table className="data-table" style={{ fontSize: '12px' }}>
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Raw Score</th>
                    <th>Weight</th>
                    <th>Points</th>
                  </tr>
                </thead>
                <tbody>
                  {scoreData.breakdown.map((b: any, idx: number) => (
                    <tr key={idx}>
                      <td style={{ fontWeight: 600 }}>{b.category}</td>
                      <td>{b.raw_score}</td>
                      <td>{(b.weight * 100).toFixed(0)}%</td>
                      <td style={{ color: b.contribution > 0 ? '#f87171' : '#34d399', fontWeight: 700 }}>
                        +{b.contribution}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Hop Map Section */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <Globe size={18} color="var(--accent-cyan)" />
          Network Hop Routing & Sender Geolocation
        </h3>
        <HopMap hops={geoData.hops || []} />
      </div>

      {/* Forensic Findings Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '18px' }}>
          <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCode size={18} color="var(--accent-cyan)" />
            Detected Forensic Findings ({scan.findings.length})
          </h3>

          <div style={{ display: 'flex', gap: '6px' }}>
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`btn ${selectedSeverity === sev ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '4px 12px', fontSize: '11px', textTransform: 'capitalize' }}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {filteredFindings.length > 0 ? (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Severity</th>
                  <th>Points</th>
                  <th>Forensic Evidence & Explanation</th>
                  <th>Recommended Mitigation Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((f) => (
                  <tr key={f.id}>
                    <td style={{ fontWeight: 600 }}>
                      <code>{f.finding_type}</code>
                    </td>
                    <td>
                      <span className={`badge ${
                        f.severity === 'critical' ? 'badge-critical' :
                        f.severity === 'high' ? 'badge-high' :
                        f.severity === 'medium' ? 'badge-medium' : 'badge-low'
                      }`}>
                        {f.severity}
                      </span>
                    </td>
                    <td style={{ fontWeight: 700, color: '#f87171' }}>+{f.points || 0}</td>
                    <td style={{ maxWidth: '380px' }}>{f.explanation}</td>
                    <td style={{ maxWidth: '320px', color: '#38bdf8' }}>
                      {f.recommended_action || 'Inspect before taking action.'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>
            No security findings matching the selected filter.
          </div>
        )}
      </div>

      {/* Extracted URLs Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
          <Link size={18} color="var(--accent-cyan)" />
          Extracted Links & Hyperlink Reputation ({scan.extracted_urls.length})
        </h3>

        {scan.extracted_urls.length > 0 ? (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hostname / Target URL</th>
                  <th>HTTPS</th>
                  <th>IP Address</th>
                  <th>Shortener</th>
                  <th>Punycode</th>
                  <th>Risk Score</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {scan.extracted_urls.map((u) => (
                  <tr key={u.id}>
                    <td style={{ maxWidth: '350px', wordBreak: 'break-all' }}>
                      <span style={{ fontWeight: 600, color: '#f8fafc' }}>{u.hostname || u.original_url}</span>
                    </td>
                    <td>
                      <span className={`badge ${u.uses_https ? 'badge-low' : 'badge-medium'}`}>
                        {u.uses_https ? 'HTTPS' : 'HTTP (Insecure)'}
                      </span>
                    </td>
                    <td>
                      {u.is_ip_address ? (
                        <span className="badge badge-critical">RAW IP</span>
                      ) : (
                        <span style={{ color: '#64748b' }}>No</span>
                      )}
                    </td>
                    <td>
                      {u.uses_shortener ? (
                        <span className="badge badge-medium">SHORTENER</span>
                      ) : (
                        <span style={{ color: '#64748b' }}>No</span>
                      )}
                    </td>
                    <td>
                      {u.is_punycode ? (
                        <span className="badge badge-critical">PUNYCODE</span>
                      ) : (
                        <span style={{ color: '#64748b' }}>No</span>
                      )}
                    </td>
                    <td style={{ fontWeight: 700, color: (u.url_score || 0) > 30 ? '#ef4444' : '#10b981' }}>
                      {u.url_score || 0}
                    </td>
                    <td style={{ fontSize: '11px', color: '#94a3b8' }}>
                      {(u.flags || []).map((fl: any) => fl.check).join(', ') || 'Clean'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>
            No hyperlinks detected in this email.
          </div>
        )}
      </div>
    </div>
  );
};
