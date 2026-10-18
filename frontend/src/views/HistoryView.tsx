import React, { useState, useEffect } from 'react';
import { Search, Download, Trash2, RefreshCw } from 'lucide-react';
import { api } from '../api';
import type { ScanSummary } from '../api';

interface HistoryViewProps {
  onSelectScan: (scanId: number) => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({ onSelectScan }) => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.listScans(page, pageSize, search || undefined, riskFilter || undefined);
      setScans(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [page, riskFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchScans();
  };

  const handleDownloadPDF = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    try {
      const blob = await api.downloadReport(id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threat_report_${id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Download failed: ${err.message}`);
    }
  };

  const handleDelete = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this scan record?')) return;
    try {
      await api.deleteScan(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
      setTotal((prev) => Math.max(0, prev - 1));
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div style={{ maxWidth: '1240px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '26px', margin: '0 0 6px', color: '#f8fafc' }}>
            Forensic Scan History
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '14px' }}>
            Browse and inspect all historical email evaluations ({total} records found)
          </p>
        </div>

        <button onClick={fetchScans} className="btn btn-secondary" style={{ padding: '8px 14px' }}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel" style={{ padding: '16px 20px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Search Input */}
          <div style={{ flex: 1, minWidth: '240px', position: 'relative' }}>
            <input
              type="text"
              className="form-input"
              placeholder="Search by subject, sender, or filename..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: '36px' }}
            />
            <Search size={16} color="#64748b" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
          </div>

          {/* Risk Level Filter */}
          <div style={{ minWidth: '180px' }}>
            <select
              className="form-select"
              value={riskFilter}
              onChange={(e) => { setRiskFilter(e.target.value); setPage(1); }}
            >
              <option value="">All Risk Levels</option>
              <option value="Critical Risk">Critical Risk</option>
              <option value="High Risk">High Risk</option>
              <option value="Medium Risk">Medium Risk</option>
              <option value="Low Risk">Low Risk</option>
            </select>
          </div>

          <button type="submit" className="btn btn-primary" style={{ padding: '9px 18px' }}>
            Search
          </button>
        </form>
      </div>

      {/* Table Card */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
            Loading records from PostgreSQL database...
          </div>
        ) : error ? (
          <div style={{ padding: '30px', textAlign: 'center', color: '#f87171' }}>
            {error}
          </div>
        ) : scans.length > 0 ? (
          <>
            <div className="table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Subject</th>
                    <th>Sender</th>
                    <th>Original Filename</th>
                    <th>Overall Risk</th>
                    <th>Score</th>
                    <th>Date Evaluated</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr
                      key={s.id}
                      onClick={() => onSelectScan(s.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>#{s.id}</td>
                      <td style={{ fontWeight: 600, color: '#f8fafc', maxWidth: '280px' }}>
                        {s.subject || '(no subject)'}
                      </td>
                      <td style={{ color: '#94a3b8', maxWidth: '200px' }}>
                        {s.sender || 'Unknown'}
                      </td>
                      <td style={{ color: '#64748b', fontSize: '12px' }}>
                        {s.original_filename || 'source.eml'}
                      </td>
                      <td>
                        <span className={`badge ${
                          s.overall_risk === 'Critical Risk' || s.overall_risk === 'High Risk'
                            ? 'badge-critical'
                            : s.overall_risk === 'Medium Risk'
                            ? 'badge-medium'
                            : 'badge-low'
                        }`}>
                          {s.overall_risk || 'Analyzed'}
                        </span>
                      </td>
                      <td className="font-mono" style={{ fontWeight: 700 }}>
                        {s.model_score ?? '-'}
                      </td>
                      <td style={{ fontSize: '12px', color: '#64748b' }}>
                        {s.created_at ? new Date(s.created_at).toLocaleDateString() : '-'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <button
                            onClick={(e) => handleDownloadPDF(e, s.id)}
                            className="btn btn-secondary"
                            style={{ padding: '6px 10px' }}
                            title="Download PDF Forensic Report"
                          >
                            <Download size={14} color="#06b6d4" />
                          </button>
                          <button
                            onClick={(e) => handleDelete(e, s.id)}
                            className="btn btn-danger"
                            style={{ padding: '6px 10px' }}
                            title="Delete record"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '18px', paddingTop: '14px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: '13px', color: '#94a3b8' }}>
                Page {page} of {totalPages} ({total} total scans)
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="btn btn-secondary"
                  style={{ padding: '6px 14px', fontSize: '12px' }}
                >
                  Previous
                </button>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  className="btn btn-secondary"
                  style={{ padding: '6px 14px', fontSize: '12px' }}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        ) : (
          <div style={{ padding: '48px', textAlign: 'center', color: '#94a3b8' }}>
            No scans matched your search query. Try clearing your search or filters.
          </div>
        )}
      </div>
    </div>
  );
};
