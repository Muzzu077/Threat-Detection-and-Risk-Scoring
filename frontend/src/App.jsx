import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './index.css';

import Sidebar from './components/Sidebar';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import IncidentsPage from './pages/IncidentsPage';
import InvestigationPage from './pages/InvestigationPage';
import AttackGraphPage from './pages/AttackGraphPage';
import MLMetricsPage from './pages/MLMetricsPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import ResponsePage from './pages/ResponsePage';

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const stored = localStorage.getItem('tp_auth');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        const age = Date.now() - parsed.ts;
        if (age < 8 * 60 * 60 * 1000) { // 8-hour session
          setAuthenticated(true);
          setUser(parsed.user);
        } else {
          localStorage.removeItem('tp_auth');
        }
      } catch {}
    }
  }, []);

  const handleLogin = (username) => {
    setAuthenticated(true);
    setUser(username);
  };

  const handleLogout = () => {
    localStorage.removeItem('tp_auth');
    setAuthenticated(false);
    setUser(null);
  };

  return (
    <BrowserRouter>
      {!authenticated ? (
        <LoginPage onLogin={handleLogin} />
      ) : (
        <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          {/* Top Bar */}
          <div style={{
            display: 'flex', justifyContent: 'flex-end', alignItems: 'center',
            marginBottom: 20, paddingBottom: 16,
            borderBottom: '1px solid var(--border-dim)'
          }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginRight: 12 }}>
              OPERATOR: <span style={{ color: 'var(--accent-cyan)' }}>{user?.toUpperCase()}</span>
            </span>
            <button className="btn btn-ghost" style={{ fontSize: 10 }} onClick={handleLogout}>
              DISCONNECT
            </button>
          </div>

          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/incidents/:id" element={<InvestigationPage />} />
            <Route path="/attack-graph" element={<AttackGraphPage />} />
            <Route path="/ml-metrics" element={<MLMetricsPage />} />
            <Route path="/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/response" element={<ResponsePage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
      )}
    </BrowserRouter>
  );
}

export default App;
