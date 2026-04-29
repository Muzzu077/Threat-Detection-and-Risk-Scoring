import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

// nav schema:
//   path, label, sub, icon, group ('operations' | 'developer' | 'admin'),
//   adminOnly (true → admins only)
const NAV = [
  // ── Operations: visible to every authenticated user ─────────────────────────
  { path: '/',             label: 'Operations',  sub: 'Dashboard',      icon: '◈', group: 'operations' },
  { path: '/applications', label: 'Applications', sub: 'Your Integrations', icon: '▢', group: 'operations' },
  { path: '/incidents',    label: 'Incidents',   sub: 'Active Threats', icon: '⚠', group: 'operations' },
  { path: '/attack-graph', label: 'Kill Chain',  sub: 'Attack Graph',   icon: '⬡', group: 'operations' },
  { path: '/threat-intel', label: 'Threat Intel', sub: 'IP Reputation', icon: '◉', group: 'operations' },

  // ── Developer: visible to every authenticated user ──────────────────────────
  { path: '/api-keys',      label: 'API Keys',     sub: 'Key Management',   icon: '⚿', group: 'developer' },
  { path: '/integration',   label: 'Integration',  sub: 'SDK Setup Guide',  icon: '◇', group: 'developer' },
  { path: '/notifications', label: 'Notifications', sub: 'Alert Channels',  icon: '⌬', group: 'developer' },
  { path: '/playbook-builder', label: 'Playbooks',  sub: 'SOAR Builder',     icon: '▶', group: 'developer' },

  // ── SOAR: scoped to the current tenant for non-admins; admins see global ────
  { path: '/response',     label: 'SOAR',          sub: 'Auto Response',  icon: '⚡', group: 'developer' },
  { path: '/playbooks',    label: 'Playbooks',     sub: 'SOAR Flows',     icon: '▶', group: 'developer' },

  // ── Admin: only role=admin ─────────────────────────────────────────────────
  { path: '/ml-metrics',   label: 'ML Engine',     sub: 'Model Metrics',  icon: '◎', group: 'admin', adminOnly: true },
  { path: '/ml-lab',       label: 'ML Lab',        sub: 'Phase 2 Models', icon: '⌬', group: 'admin', adminOnly: true },
  { path: '/compliance',   label: 'Compliance',    sub: 'SOC 2 / ISO',    icon: '⛓', group: 'admin', adminOnly: true },
  { path: '/admin/users',  label: 'Users',         sub: 'Tenant Admin',   icon: '○', group: 'admin', adminOnly: true },
];

function NavGroup({ items, location, navigate, label }) {
  if (items.length === 0) return null;
  return (
    <>
      <div className="nav-section-label">{label}</div>
      {items.map(item => {
        const isActive = location.pathname === item.path ||
          (item.path !== '/' && location.pathname.startsWith(item.path));
        return (
          <div
            key={item.path}
            className={`nav-item ${isActive ? 'active' : ''}`}
            onClick={() => navigate(item.path)}
            style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 1, padding: '10px 16px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%' }}>
              <span className="nav-icon" style={{ fontSize: 14 }}>{item.icon}</span>
              <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12 }}>{item.label}</span>
              {isActive && (
                <span style={{ marginLeft: 'auto', width: 4, height: 4, borderRadius: '50%', background: '#ffffff', boxShadow: '0 0 6px #ffffff' }} />
              )}
            </div>
            <div style={{ paddingLeft: 28, fontSize: 9, color: isActive ? 'rgba(255,255,255,0.5)' : 'rgba(61,96,117,0.7)', letterSpacing: 2, textTransform: 'uppercase' }}>
              {item.sub}
            </div>
          </div>
        );
      })}
    </>
  );
}

export default function Sidebar({ role = 'user' }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const timeStr = time.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const visible = NAV.filter(n => !n.adminOnly || role === 'admin');
  const ops      = visible.filter(n => n.group === 'operations');
  const dev      = visible.filter(n => n.group === 'developer');
  const admin    = visible.filter(n => n.group === 'admin');

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="logo-icon" style={{ fontSize: 18 }}>&#128737;</div>
        <div>
          <div className="logo-text">TRUSTFLOW</div>
          <div className="logo-sub">SOC Platform v3.0</div>
        </div>
      </div>

      {/* Live Clock */}
      <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div className="live-badge" style={{ padding: 0, border: 'none' }}>
          <div className="live-dot" />
          SYSTEM ONLINE
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#ffffff', letterSpacing: 1 }}>
          {timeStr}
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <NavGroup items={ops}   location={location} navigate={navigate} label="Operations" />
        <NavGroup items={dev}   location={location} navigate={navigate} label="Developer" />
        <NavGroup items={admin} location={location} navigate={navigate} label="Admin" />
      </nav>

      {/* Footer */}
      <div style={{ padding: '14px 16px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#555555', letterSpacing: '0.12em', lineHeight: 1.8 }}>
          AUTONOMOUS AI DEFENSE<br />
          <span style={{ color: 'rgba(255,255,255,0.35)' }}>// THREAT DETECTION ACTIVE</span><br />
          <span style={{ color: '#1a3a50' }}>// v3.0.0-enterprise</span>
        </div>
      </div>
    </aside>
  );
}
