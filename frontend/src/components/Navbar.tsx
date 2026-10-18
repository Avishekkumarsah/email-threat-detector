import React from 'react';
import { Shield, LayoutDashboard, Search, History, ShieldAlert, LogOut, User as UserIcon, Radio } from 'lucide-react';
import type { User } from '../api';

type Tab = 'dashboard' | 'scanner' | 'history' | 'monitor' | 'admin';

interface NavbarProps {
  currentTab: Tab;
  setCurrentTab: (tab: Tab) => void;
  user: User | null;
  onLogout: () => void;
  onOpenAuth: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  user,
  onLogout,
  onOpenAuth,
}) => {
  return (
    <header style={{
      background: 'rgba(7, 11, 20, 0.85)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border-subtle)',
      position: 'sticky',
      top: 0,
      zIndex: 1000,
    }}>
      <div style={{
        maxWidth: '1320px',
        margin: '0 auto',
        padding: '0 20px',
        height: '68px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        {/* Brand */}
        <div
          onClick={() => setCurrentTab('dashboard')}
          style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
        >
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #0284c7 0%, #06b6d4 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)',
          }}>
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontSize: '17px', fontWeight: 800, letterSpacing: '-0.02em', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '6px' }}>
              ThreatGuard <span style={{ color: 'var(--accent-cyan)', fontWeight: 600, fontSize: '13px' }}>AI 2.0</span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '5px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }}></span>
              FastAPI + ML Intelligence
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => setCurrentTab('dashboard')}
            className={`btn ${currentTab === 'dashboard' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '8px 16px', fontSize: '13px' }}
          >
            <LayoutDashboard size={16} />
            Dashboard
          </button>

          <button
            onClick={() => setCurrentTab('scanner')}
            className={`btn ${currentTab === 'scanner' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '8px 16px', fontSize: '13px' }}
          >
            <Search size={16} />
            Scanner
          </button>

          <button
            onClick={() => setCurrentTab('history')}
            className={`btn ${currentTab === 'history' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '8px 16px', fontSize: '13px' }}
          >
            <History size={16} />
            Scan History
          </button>

          {/* Live Monitor tab - visible to all logged-in users */}
          {user && (
            <button
              onClick={() => setCurrentTab('monitor')}
              className={`btn ${currentTab === 'monitor' ? 'btn-primary' : 'btn-secondary'}`}
              style={{
                padding: '8px 16px',
                fontSize: '13px',
                borderColor: currentTab === 'monitor' ? 'transparent' : 'rgba(34, 197, 94, 0.35)',
                color: currentTab === 'monitor' ? '#fff' : '#86efac',
                position: 'relative',
              }}
            >
              <Radio size={16} />
              Live Monitor
              {/* Green live pulse dot */}
              <span style={{
                position: 'absolute',
                top: '6px',
                right: '6px',
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: '#22c55e',
                boxShadow: '0 0 6px #22c55e',
              }} />
            </button>
          )}

          {user?.role === 'admin' && (
            <button
              onClick={() => setCurrentTab('admin')}
              className={`btn ${currentTab === 'admin' ? 'btn-primary' : 'btn-secondary'}`}
              style={{
                padding: '8px 16px',
                fontSize: '13px',
                borderColor: currentTab === 'admin' ? 'transparent' : 'rgba(239, 68, 68, 0.4)',
                color: currentTab === 'admin' ? '#fff' : '#fca5a5',
              }}
            >
              <ShieldAlert size={16} />
              Admin
            </button>
          )}
        </nav>

        {/* User Account / Auth */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {user ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div className="glass-pill" style={{ padding: '6px 14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <UserIcon size={14} color="#94a3b8" />
                <span style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>
                  {user.name || user.username}
                </span>
                <span className={`badge ${user.role === 'admin' ? 'badge-critical' : 'badge-neutral'}`} style={{ fontSize: '10px', padding: '2px 6px' }}>
                  {user.role}
                </span>
              </div>
              <button
                onClick={onLogout}
                className="btn btn-secondary"
                style={{ padding: '8px', borderRadius: '8px' }}
                title="Log out"
              >
                <LogOut size={16} color="#94a3b8" />
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenAuth}
              className="btn btn-primary"
              style={{ padding: '8px 18px', fontSize: '13px' }}
            >
              Sign In
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
