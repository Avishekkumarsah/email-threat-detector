import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { AuthModal } from './components/AuthModal';
import { DashboardView } from './views/DashboardView';
import { ScannerView } from './views/ScannerView';
import { HistoryView } from './views/HistoryView';
import { ScanDetailView } from './views/ScanDetailView';
import { AdminView } from './views/AdminView';
import { MonitorView } from './views/MonitorView';
import { api, getToken } from './api';
import type { User, ScanDetail } from './api';

type Tab = 'dashboard' | 'scanner' | 'history' | 'monitor' | 'admin';

export function App() {
  const [currentTab, setCurrentTab] = useState<Tab>('dashboard');
  const [user, setUser] = useState<User | null>(null);
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanDetail | null>(null);

  // Restore session
  useEffect(() => {
    const token = getToken();
    if (token) {
      api.getMe()
        .then((u) => setUser(u))
        .catch(() => setUser(null));
    }

    const handleUnauthorized = () => {
      setUser(null);
      setIsAuthOpen(true);
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  const handleLogout = () => {
    api.logout();
    setUser(null);
    setCurrentTab('dashboard');
  };

  const loadScanById = async (scanId: number) => {
    try {
      const scan = await api.getScan(scanId);
      setSelectedScan(scan);
    } catch (err: any) {
      alert(`Failed to load scan #${scanId}: ${err.message}`);
    }
  };

  const handleTabChange = (tab: Tab) => {
    setSelectedScan(null);
    setCurrentTab(tab);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Navbar */}
      <Navbar
        currentTab={currentTab}
        setCurrentTab={handleTabChange}
        user={user}
        onLogout={handleLogout}
        onOpenAuth={() => setIsAuthOpen(true)}
      />

      {/* Main Content Area */}
      <main className="app-container" style={{ flex: 1 }}>
        {selectedScan ? (
          <ScanDetailView
            scan={selectedScan}
            onBack={() => setSelectedScan(null)}
          />
        ) : (
          <>
            {currentTab === 'dashboard' && (
              <DashboardView
                onGoToScanner={() => setCurrentTab('scanner')}
                onSelectScan={loadScanById}
              />
            )}

            {currentTab === 'scanner' && (
              <ScannerView
                onScanComplete={(scan) => setSelectedScan(scan)}
                onOpenAuth={() => setIsAuthOpen(true)}
                isAuthenticated={!!user}
              />
            )}

            {currentTab === 'history' && (
              <HistoryView onSelectScan={loadScanById} />
            )}

            {currentTab === 'monitor' && (
              <MonitorView onSelectScan={loadScanById} />
            )}

            {currentTab === 'admin' && <AdminView />}
          </>
        )}
      </main>

      {/* Footer */}
      <footer style={{
        background: 'rgba(7, 11, 20, 0.95)',
        borderTop: '1px solid var(--border-subtle)',
        padding: '24px 20px',
        textAlign: 'center',
        fontSize: '13px',
        color: '#64748b',
      }}>
        <div style={{ maxWidth: '1320px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            ThreatGuard AI 2.0 — Enterprise Email Threat Detection & Forensic Intelligence Platform
          </div>
          <div style={{ display: 'flex', gap: '16px' }}>
            <span>FastAPI 0.115</span>
            <span>•</span>
            <span>React 18 + Vite</span>
            <span>•</span>
            <span>Neon Cloud PostgreSQL</span>
            <span>•</span>
            <span>Scikit-Learn TF-IDF</span>
          </div>
        </div>
      </footer>

      {/* Auth Modal */}
      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onSuccess={(u) => {
          setUser(u);
          setIsAuthOpen(false);
        }}
      />
    </div>
  );
}

export default App;
