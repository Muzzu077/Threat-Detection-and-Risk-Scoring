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
      <div className="access-denied">
        <div className="access-denied-icon">🔒</div>
        <div className="access-denied-title">Access Denied</div>
        <div className="access-denied-text">
          This section requires administrator privileges. If you were just promoted,
          your session needs to refresh — try navigating away and back, or log out and back in.
        </div>
      </div>
    );
  }
  return children;
}

function UserRefresher({ onUser }) {
  const location = useLocation();
  const lastPathRef = useRef(null);
  useEffect(() => {
    if (!localStorage.getItem('tp_tokens')) return;
    if (lastPathRef.current === location.pathname) return;
    lastPathRef.current = location.pathname;
    authMe()
      .then((data) => { if (data?.user) onUser(data.user); })
      .catch(() => { /* ignore */ });
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

  useEffect(() => {
    const handler = () => {
      if (!localStorage.getItem('tp_tokens')) return;
      authMe().then((data) => { if (data?.user) setUser(data.user); }).catch(() => { /* ignore */ });
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
      authLogout(tokens.refresh_token).catch(() => { /* ignore */ });
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
        flexDirection: 'column', gap: 16,
        background: 'var(--bg-base)', color: 'var(--text-primary)',
      }}>
        <div className="spinner" />
        <div className="loading-text">Initializing TrustFlow...</div>
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
          <div className="top-bar">
            <span className="top-bar-user">
              OPERATOR: <span className="top-bar-user-name">{(user?.display_name || user?.email || '').toUpperCase()}</span>
              {user?.role === 'admin' && (
                <span className="top-bar-admin-badge">ADMIN</span>
              )}
            </span>
            <button className="btn btn-ghost top-bar-logout" onClick={handleLogout}>
              Disconnect
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

            <Route path="/response"     element={<ResponsePage user={user} />} />
            <Route path="/playbooks"    element={<PlaybooksPage user={user} />} />

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
