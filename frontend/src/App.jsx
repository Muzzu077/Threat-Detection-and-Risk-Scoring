import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './index.css';

import Sidebar from './components/Sidebar';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import IncidentsPage from './pages/IncidentsPage';
import InvestigationPage from './pages/InvestigationPage';
import AttackGraphPage from './pages/AttackGraphPage';
import MLMetricsPage from './pages/MLMetricsPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import ResponsePage from './pages/ResponsePage';
import PlaybooksPage from './pages/PlaybooksPage';
import ApiKeysPage from './pages/ApiKeysPage';
import IntegrationGuidePage from './pages/IntegrationGuidePage';
import LandingPage from './pages/LandingPage';
import { authMe, authLogout } from './api/client';

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const tokens = localStorage.getItem('tp_tokens');
    if (tokens) {
      authMe()
        .then((data) => {
          setUser(data.user);
          setAuthenticated(true);
        })
        .catch(() => {
          localStorage.removeItem('tp_tokens');
          localStorage.removeItem('tp_user');
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const handleLogin = (userData) => {
    setAuthenticated(true);
    setUser(userData);
  };

  const handleLogout = () => {
    const tokens = JSON.parse(localStorage.getItem('tp_tokens') || '{}');
    if (tokens.refresh_token) {
      authLogout(tokens.refresh_token).catch(() => {});
    }
    localStorage.removeItem('tp_tokens');
    localStorage.removeItem('tp_user');
    setAuthenticated(false);
    setUser(null);
  };

  if (loading) {
    return (
      <div style={{
        height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--bg-dark)', color: '#00e5b0',
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
      }}>
        INITIALIZING THREATPULSE...
      </div>
    );
  }

  return (
    <BrowserRouter>
      {!authenticated ? (
        <Routes>
          <Route path="/login" element={<LoginPage onLogin={handleLogin} />} />
          <Route path="/register" element={<RegisterPage onRegister={handleLogin} />} />
          <Route path="/" element={<LandingPage />} />
          <Route path="*" element={<LandingPage />} />
        </Routes>
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
              OPERATOR: <span style={{ color: 'var(--accent-cyan)' }}>{(user?.display_name || user?.email || '').toUpperCase()}</span>
              {user?.role === 'admin' && (
                <span style={{ marginLeft: 8, padding: '2px 6px', background: 'rgba(240,50,80,0.15)', border: '1px solid rgba(240,50,80,0.3)', borderRadius: 3, fontSize: 8, color: '#f03250' }}>
                  ADMIN
                </span>
              )}
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
            <Route path="/playbooks" element={<PlaybooksPage />} />
            <Route path="/api-keys" element={<ApiKeysPage />} />
            <Route path="/integration" element={<IntegrationGuidePage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
      )}
    </BrowserRouter>
  );
}

export default App;
