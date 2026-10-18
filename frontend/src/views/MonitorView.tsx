import React, { useState, useEffect } from 'react';
import {
  Radio, Play, Square, RotateCw, Zap, Settings, CheckCircle,
  AlertTriangle, Mail, ShieldAlert, ArrowRight, Server, Key,
  RefreshCw
} from 'lucide-react';
import { api } from '../api';
import type { MonitorStatus } from '../api';

interface MonitorViewProps {
  onSelectScan: (scanId: number) => void;
}

export const MonitorView: React.FC<MonitorViewProps> = ({ onSelectScan }) => {
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [showSettings, setShowSettings] = useState(false);

  // Settings form fields
  const [host, setHost] = useState('imap.gmail.com');
  const [port, setPort] = useState(993);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [testingConnection, setTestingConnection] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);

  const fetchStatus = async (silent = false) => {
    try {
      const data = await api.getMonitorStatus();
      setStatus(data);
      if (data.imap_email && !email) {
        setEmail(data.imap_email);
      }
      if (data.imap_host) {
        setHost(data.imap_host);
      }
      if (data.imap_port) {
        setPort(data.imap_port);
      }
    } catch (err: any) {
      if (!silent) {
        setMessage({ type: 'error', text: err.message || 'Failed to fetch monitor status.' });
      }
    }
  };

  useEffect(() => {
    fetchStatus();
    // Poll monitor status every 5 seconds like legacy monitor.html
    const interval = setInterval(() => {
      fetchStatus(true);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    setActionLoading(true);
    setMessage(null);
    try {
      const res = await api.startMonitor();
      setMessage({ type: 'success', text: res.message });
      await fetchStatus(true);
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Could not start live monitor.' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    setMessage(null);
    try {
      const res = await api.stopMonitor();
      setMessage({ type: 'success', text: res.message });
      await fetchStatus(true);
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Could not stop live monitor.' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleRestart = async () => {
    setActionLoading(true);
    setMessage(null);
    try {
      const res = await api.restartMonitor();
      setMessage({ type: 'success', text: res.message });
      await fetchStatus(true);
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Could not restart live monitor.' });
    } finally {
      setActionLoading(false);
    }
  };

  const handlePollNow = async () => {
    setActionLoading(true);
    setMessage(null);
    try {
      const res = await api.pollNow();
      setMessage({ type: 'success', text: res.message + ' Checking mailbox now...' });
      await fetchStatus(true);
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Poll Now trigger failed.' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleTestConnection = async () => {
    if (!email || !password) {
      setMessage({ type: 'error', text: 'Please fill in both email and 16-character App Password to test.' });
      return;
    }
    setTestingConnection(true);
    setMessage(null);
    try {
      const res = await api.testImapConnection({
        imap_host: host,
        imap_port: Number(port),
        imap_email: email,
        app_password: password,
      });
      setMessage({ type: 'success', text: res.message || 'Connection verified successfully!' });
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'IMAP connection failed.' });
    } finally {
      setTestingConnection(false);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setMessage({ type: 'error', text: 'Email and 16-character App Password are required.' });
      return;
    }
    setSavingSettings(true);
    setMessage(null);
    try {
      const res = await api.saveImapCredentials({
        imap_host: host,
        imap_port: Number(port),
        imap_email: email,
        app_password: password,
        is_active: true,
      });
      setMessage({ type: 'success', text: res.message });
      setShowSettings(false);
      setPassword('');
      await fetchStatus(true);
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Failed to save IMAP credentials.' });
    } finally {
      setSavingSettings(false);
    }
  };

  const isRunning = status?.running ?? false;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Top Banner */}
      <div
        className="glass-panel"
        style={{
          padding: '32px',
          background: 'radial-gradient(ellipse at 85% 20%, rgba(34, 197, 94, 0.12) 0%, rgba(15, 23, 42, 0.85) 70%)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '20px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <span
              className={isRunning ? 'badge badge-low' : 'badge'}
              style={{
                background: isRunning ? 'rgba(34, 197, 94, 0.15)' : 'rgba(100, 116, 139, 0.2)',
                color: isRunning ? '#4ade80' : '#94a3b8',
                border: isRunning ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid rgba(100, 116, 139, 0.3)',
                fontFamily: 'JetBrains Mono',
                fontWeight: 700,
              }}
            >
              {isRunning ? '● Live Monitoring Active' : '◉ Monitoring Idle'}
            </span>
            <span style={{ fontSize: '12px', color: '#64748b' }}>
              Auto-refreshes every 5s
            </span>
          </div>

          <h1 style={{ fontSize: '28px', margin: '0 0 8px', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Radio size={28} color={isRunning ? '#22c55e' : 'var(--accent-cyan)'} />
            Real-Time Inbox Threat Monitor
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '15px', maxWidth: '680px', margin: 0 }}>
            Continuous background polling over encrypted IMAP SSL. Every incoming email is scored
            identically to manual uploads across content ML, spoofed headers, malicious URLs, and routing hops.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {isRunning ? (
            <button
              onClick={handleStop}
              disabled={actionLoading}
              className="btn btn-secondary"
              style={{ borderColor: 'rgba(239, 68, 68, 0.4)', color: '#fca5a5' }}
            >
              <Square size={16} color="#ef4444" />
              Stop Monitoring
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={actionLoading}
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)' }}
            >
              <Play size={16} />
              Start Monitoring
            </button>
          )}

          <button
            onClick={handlePollNow}
            disabled={actionLoading}
            className="btn btn-secondary"
            title="Immediately fetch unseen emails right now"
          >
            <Zap size={16} color="#06b6d4" />
            Poll Now
          </button>

          <button
            onClick={handleRestart}
            disabled={actionLoading}
            className="btn btn-secondary"
            title="Force-restart the background worker thread"
          >
            <RotateCw size={16} />
            Restart
          </button>

          <button
            onClick={() => setShowSettings(!showSettings)}
            className="btn btn-secondary"
          >
            <Settings size={16} />
            {showSettings ? 'Hide IMAP Settings' : 'IMAP Settings'}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {message && (
        <div style={{
          padding: '14px 18px',
          borderRadius: '12px',
          background: message.type === 'success' ? 'rgba(34, 197, 94, 0.12)' : 'rgba(239, 68, 68, 0.15)',
          border: message.type === 'success' ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
          color: message.type === 'success' ? '#86efac' : '#fca5a5',
          fontSize: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}>
          {message.type === 'success' ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
          {message.text}
        </div>
      )}

      {/* Last Error banner if thread encountered an IMAP error */}
      {status?.last_error && (
        <div style={{
          padding: '14px 18px',
          borderRadius: '12px',
          background: 'rgba(245, 158, 11, 0.12)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          color: '#fde68a',
          fontSize: '13px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}>
          <AlertTriangle size={18} color="#f59e0b" />
          <div>
            <strong>Monitor Alert:</strong> {status.last_error}
          </div>
        </div>
      )}

      {/* Top 4 Status Metrics Cards */}
      <div className="grid-cols-4">
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 600 }}>Thread Status</span>
            <Radio size={18} color={isRunning ? '#22c55e' : '#64748b'} />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 700, color: isRunning ? '#4ade80' : '#94a3b8', fontFamily: 'JetBrains Mono' }}>
            {isRunning ? 'RUNNING' : 'STOPPED'}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            Background daemon worker
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 600 }}>Monitored Mailbox</span>
            <Mail size={18} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {status?.imap_email || 'Not Configured'}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            {status?.imap_host}:{status?.imap_port || 993}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 600 }}>Emails Auto-Scanned</span>
            <ShieldAlert size={18} color="#06b6d4" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#f8fafc', fontFamily: 'JetBrains Mono' }}>
            {status?.emails_scanned ?? 0}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            From this monitoring session
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 600 }}>Last Poll Check</span>
            <RefreshCw size={18} color="#94a3b8" />
          </div>
          <div style={{ fontSize: '14px', fontWeight: 700, color: '#cbd5e1', fontFamily: 'JetBrains Mono' }}>
            {status?.last_check || 'Awaiting first poll'}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            Interval: {status?.poll_interval || 30}s
          </div>
        </div>
      </div>

      {/* IMAP Configuration Panel (collapsible or open when toggled) */}
      {showSettings && (
        <div className="glass-panel" style={{ padding: '28px', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Server size={22} color="var(--accent-cyan)" />
            <div>
              <h3 style={{ margin: 0, fontSize: '18px', color: '#f8fafc' }}>IMAP Mailbox Connection Settings</h3>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#94a3b8' }}>
                Connect your Gmail or work mailbox. Incoming unread messages are parsed in memory and scanned automatically.
              </p>
            </div>
          </div>

          <form onSubmit={handleSaveSettings} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
              <div>
                <label className="form-label">IMAP Host</label>
                <input
                  type="text"
                  className="form-input"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="imap.gmail.com"
                  autoComplete="off"
                  spellCheck={false}
                  required
                />
              </div>

              <div>
                <label className="form-label">IMAP Port (SSL)</label>
                <input
                  type="number"
                  className="form-input"
                  value={port}
                  onChange={(e) => setPort(Number(e.target.value))}
                  placeholder="993"
                  autoComplete="off"
                  required
                />
              </div>

              <div>
                <label className="form-label">Email Address</label>
                <input
                  type="email"
                  className="form-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="youraddress@gmail.com"
                  autoComplete="off"
                  spellCheck={false}
                  required
                />
              </div>

              <div>
                <label className="form-label">
                  Google App Password (16-char)
                </label>
                <input
                  type="password"
                  className="form-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••••••"
                  autoComplete="new-password"
                  required
                />
              </div>
            </div>

            <div style={{
              background: 'rgba(6, 182, 212, 0.08)',
              border: '1px solid rgba(6, 182, 212, 0.2)',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '13px',
              color: '#94a3b8',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}>
              <Key size={18} color="var(--accent-cyan)" />
              <span>
                <strong>Security Notice:</strong> For Gmail, generate an <strong>App Password</strong> at Google Account → Security → 2-Step Verification → App Passwords. Passwords are encrypted with AES in the database.
              </span>
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '10px' }}>
              <button
                type="button"
                onClick={handleTestConnection}
                disabled={testingConnection || savingSettings}
                className="btn btn-secondary"
              >
                {testingConnection ? 'Testing Connection...' : 'Test Connection'}
              </button>

              <button
                type="submit"
                disabled={savingSettings || testingConnection}
                className="btn btn-primary"
              >
                {savingSettings ? 'Verifying & Saving...' : 'Save & Enable Monitoring'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Live Ingestion Feed Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Radio size={18} color={isRunning ? '#22c55e' : '#94a3b8'} />
              Live Inbox Feed
            </h3>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#94a3b8' }}>
              Emails fetched automatically from your inbox in real time appear here immediately.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '12px', color: '#64748b' }}>
              {status?.recent?.length ?? 0} captured events
            </span>
          </div>
        </div>

        {status?.recent && status.recent.length > 0 ? (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Sender</th>
                  <th>Subject</th>
                  <th>Threat Verdict</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {status.recent.map((item, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: '12px', color: '#94a3b8' }}>
                      {item.time}
                    </td>
                    <td style={{ color: '#cbd5e1', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {item.from}
                    </td>
                    <td style={{ color: '#f8fafc', fontWeight: 600, maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {item.subject}
                    </td>
                    <td>
                      <span className={`badge ${
                        item.verdict === 'Dangerous' || item.verdict === 'Critical Risk' || item.verdict === 'Likely Phishing'
                          ? 'badge-critical'
                          : item.verdict === 'Suspicious'
                          ? 'badge-medium'
                          : 'badge-low'
                      }`}>
                        {item.verdict}
                      </span>
                    </td>
                    <td>
                      {item.scan_id ? (
                        <button
                          onClick={() => onSelectScan(item.scan_id)}
                          className="btn btn-outline-cyan"
                          style={{ padding: '4px 10px', fontSize: '12px' }}
                        >
                          Inspect
                          <ArrowRight size={12} />
                        </button>
                      ) : (
                        <span style={{ fontSize: '12px', color: '#64748b' }}>Processing</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{
            padding: '48px 24px',
            textAlign: 'center',
            color: '#94a3b8',
            background: 'rgba(255, 255, 255, 0.02)',
            borderRadius: '12px',
            border: '1px dashed rgba(255, 255, 255, 0.1)',
          }}>
            <Mail size={36} color="#64748b" style={{ margin: '0 auto 12px' }} />
            <h4 style={{ margin: '0 0 6px', color: '#e2e8f0', fontSize: '16px' }}>
              No incoming emails detected yet
            </h4>
            <p style={{ margin: '0 auto', maxWidth: '480px', fontSize: '14px', color: '#64748b' }}>
              {isRunning
                ? `Active and listening to ${status?.imap_email || 'your mailbox'}. Send an email to that inbox, and it will appear here within ${status?.poll_interval || 30} seconds.`
                : 'Configure your IMAP credentials above and click "Start Monitoring" to begin receiving real-time scans.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
