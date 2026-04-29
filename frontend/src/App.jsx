import { useState, useEffect, useRef } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
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
import ApplicationsPage from './pages/ApplicationsPage';
import ApplicationDetailPage from './pages/ApplicationDetailPage';
import AdminUsersPage from './pages/AdminUsersPage';
import NotificationsPage from './pages/NotificationsPage';
import MLLabPage from './pages/MLLabPage';
import CompliancePage from './pages/CompliancePage';
import PlaybookBuilderPage from './pages/PlaybookBuilderPage';
import { authMe, authLogout } from './api/client';

function AdminOnly({ user, children }) {
  if (user?.role !== 'admin') {
    return (
      <div style={{
        padding: 60, textAlign: 'center', fontFamily: 'IBM Plex Mono, monospace',
        color: '#a0a0a0', fontSize: 13,
      }}>
        <div style={{ fontSize: 32, marginBottom: 16, opacity: 0.4 }}>&#128274;</div>
        <div style={{ color: '#e53e3e', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>
          Access Denied
        </div>
        <div style={{ fontSize: 11, color: '#555555' }}>
          This section requires administrator privileges. If you were just promoted,
          your session needs to refresh — try navigating away and back, or log out and back in.
        </div>
      </div>
    );
  }
  return children;
}

// Re-fetch the current user from the backend on every navigation. This
// ensures a freshly promoted/demoted user picks up their new role without
// having to log out and back in.
function UserRefresher({ onUser }) {
  const location = useLocation();
  const lastPathRef = useRef(null);
  useEffect(() => {
    if (!localStorage.getItem('tp_tokens')) return;
    if (lastPathRef.current === location.pathname) return;
    lastPathRef.current = location.pathname;
    authMe()
      .then((data) => { if (data?.user) onUser(data.user); })
      .catch(() => {});
  }, [location.pathname, onUser]);
  return null;
}

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

  // When any API call hints that the role changed, re-sync from backend.
  useEffect(() => {
    const handler = () => {
      if (!localStorage.getItem('tp_tokens')) return;
      authMe().then((data) => { if (data?.user) setUser(data.user); }).catch(() => {});
    };
    window.addEventListener('tp:role-may-have-changed', handler);
    return () => window.removeEventListener('tp:role-may-have-changed', handler);
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
        background: 'var(--bg-dark)', color: '#ffffff',
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
      }}>
        INITIALIZING TRUSTFLOW...
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
        <UserRefresher onUser={setUser} />
        <Sidebar role={user?.role} />
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
                <span style={{ marginLeft: 8, padding: '2px 6px', background: 'rgba(229,62,62,0.15)', border: '1px solid rgba(229,62,62,0.3)', borderRadius: 3, fontSize: 8, color: '#e53e3e' }}>
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
            <Route path="/applications" element={<ApplicationsPage />} />
            <Route path="/applications/:id" element={<ApplicationDetailPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/incidents/:id" element={<InvestigationPage />} />
            <Route path="/attack-graph" element={<AttackGraphPage />} />
            <Route path="/api-keys" element={<ApiKeysPage />} />
            <Route path="/integration" element={<IntegrationGuidePage />} />
            <Route path="/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/notifications" element={<NotificationsPage />} />
            <Route path="/playbook-builder" element={<PlaybookBuilderPage />} />

            {/* Tenant-scoped SOAR pages — every authenticated user sees their own */}
            <Route path="/response"     element={<ResponsePage user={user} />} />
            <Route path="/playbooks"    element={<PlaybooksPage user={user} />} />

            {/* Admin-only routes — render Access Denied for non-admins */}
            <Route path="/ml-metrics"   element={<AdminOnly user={user}><MLMetricsPage /></AdminOnly>} />
            <Route path="/ml-lab"       element={<AdminOnly user={user}><MLLabPage /></AdminOnly>} />
            <Route path="/compliance"   element={<AdminOnly user={user}><CompliancePage /></AdminOnly>} />
            <Route path="/admin/users"  element={<AdminOnly user={user}><AdminUsersPage /></AdminOnly>} />

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
      )}
    </BrowserRouter>
  );
}

export default App;
