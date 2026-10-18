import React, { useState, useEffect } from 'react';
import { Users, Cpu, RefreshCw, Trash2, UserCheck } from 'lucide-react';
import { api } from '../api';
import type { AdminUser, ModelStatus } from '../api';

export const AdminView: React.FC = () => {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [uRes, mRes] = await Promise.all([
        api.listAdminUsers(),
        api.getModelStatus(),
      ]);
      setUsers(uRes.items);
      setModelStatus(mRes);
    } catch (err: any) {
      setError(err.message || 'Failed to load administrative data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleToggleRole = async (userId: number) => {
    try {
      await api.toggleUserRole(userId);
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, role: u.role === 'admin' ? 'user' : 'admin' } : u))
      );
    } catch (err: any) {
      alert(`Role change failed: ${err.message}`);
    }
  };

  const handleToggleActive = async (userId: number, currentActive: boolean) => {
    try {
      if (currentActive) {
        await api.suspendUser(userId);
      } else {
        await api.activateUser(userId);
      }
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, is_active: !currentActive } : u))
      );
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    }
  };

  const handleDeleteUser = async (userId: number) => {
    if (!window.confirm('Are you sure you want to permanently delete this user account?')) return;
    try {
      await api.deleteUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch (err: any) {
      alert(`Delete user failed: ${err.message}`);
    }
  };

  return (
    <div style={{ maxWidth: '1240px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Title */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div className="badge badge-critical" style={{ marginBottom: '8px' }}>
            Administrator Console
          </div>
          <h1 style={{ fontSize: '26px', margin: '0 0 6px', color: '#f8fafc' }}>
            System Governance & User Management
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '14px' }}>
            Manage platform users, roles, account suspensions, and inspect active ML models.
          </p>
        </div>

        <button onClick={fetchData} className="btn btn-secondary" style={{ padding: '8px 14px' }}>
          <RefreshCw size={14} />
          Refresh
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

      {/* Model Telemetry Card */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <Cpu size={18} color="var(--accent-cyan)" />
          Active ML Model Runtime Architecture
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
          <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '10px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8' }}>Algorithm</div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', marginTop: '4px' }}>
              {modelStatus?.algorithm || 'Logistic Regression (TF-IDF)'}
            </div>
          </div>

          <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '10px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8' }}>Deployment Version</div>
            <div className="font-mono" style={{ fontSize: '15px', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '4px' }}>
              v{modelStatus?.version || '1.0.0'}
            </div>
          </div>

          <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '10px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8' }}>Artifact Location</div>
            <div className="font-mono" style={{ fontSize: '12px', color: '#cbd5e1', marginTop: '4px', wordBreak: 'break-all' }}>
              {modelStatus?.artifact_path || 'model/phishing_model.pkl'}
            </div>
          </div>

          <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '10px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8' }}>Execution Status</div>
            <div style={{ marginTop: '4px' }}>
              <span className={`badge ${modelStatus?.status === 'loaded' ? 'badge-low' : 'badge-critical'}`}>
                {modelStatus?.status === 'loaded' ? 'Active & Ready' : modelStatus?.status || 'Unknown'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Users Management Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
          <Users size={18} color="var(--accent-cyan)" />
          Registered Users ({users.length})
        </h3>

        {loading ? (
          <div style={{ padding: '36px', textAlign: 'center', color: '#94a3b8' }}>
            Loading users from PostgreSQL database...
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Account Status</th>
                  <th>Scans Conducted</th>
                  <th>Created At</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div style={{ fontWeight: 600, color: '#f8fafc' }}>{u.name || u.username}</div>
                      <div style={{ fontSize: '11px', color: '#64748b' }}>@{u.username}</div>
                    </td>
                    <td style={{ color: '#cbd5e1' }}>{u.email}</td>
                    <td>
                      <span className={`badge ${u.role === 'admin' ? 'badge-critical' : 'badge-neutral'}`}>
                        {u.role}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${u.is_active ? 'badge-low' : 'badge-critical'}`}>
                        {u.is_active ? 'Active' : 'Suspended'}
                      </span>
                    </td>
                    <td className="font-mono" style={{ fontWeight: 700 }}>
                      {u.scan_count}
                    </td>
                    <td style={{ fontSize: '12px', color: '#64748b' }}>
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : '-'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '6px' }}>
                        <button
                          onClick={() => handleToggleRole(u.id)}
                          className="btn btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '11px' }}
                          title="Toggle Role"
                        >
                          <UserCheck size={13} />
                          {u.role === 'admin' ? 'Demote' : 'Make Admin'}
                        </button>

                        <button
                          onClick={() => handleToggleActive(u.id, u.is_active)}
                          className="btn btn-secondary"
                          style={{
                            padding: '4px 10px',
                            fontSize: '11px',
                            color: u.is_active ? '#fca5a5' : '#34d399',
                          }}
                          title={u.is_active ? 'Suspend User' : 'Activate User'}
                        >
                          {u.is_active ? 'Suspend' : 'Activate'}
                        </button>

                        <button
                          onClick={() => handleDeleteUser(u.id)}
                          className="btn btn-danger"
                          style={{ padding: '4px 8px' }}
                          title="Delete User"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
