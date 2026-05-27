import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, AppWindow, AlertTriangle, Network, Globe,
  Key, Code, Bell, Workflow, Zap, Play,
  BarChart3, FlaskConical, ShieldCheck, Users, Shield
} from 'lucide-react';

const NAV = [
  { path: '/',             label: 'Operations',    sub: 'Dashboard',        icon: LayoutDashboard, group: 'operations' },
  { path: '/applications', label: 'Applications',  sub: 'Your Integrations', icon: AppWindow,       group: 'operations' },
  { path: '/incidents',    label: 'Incidents',     sub: 'Active Threats',    icon: AlertTriangle,   group: 'operations' },
  { path: '/attack-graph', label: 'Kill Chain',    sub: 'Attack Graph',      icon: Network,         group: 'operations' },
  { path: '/threat-intel', label: 'Threat Intel',  sub: 'IP Reputation',     icon: Globe,           group: 'operations' },

  { path: '/api-keys',        label: 'API Keys',      sub: 'Key Management',  icon: Key,       group: 'developer' },
  { path: '/integration',     label: 'Integration',   sub: 'SDK Setup Guide', icon: Code,      group: 'developer' },
  { path: '/notifications',   label: 'Notifications', sub: 'Alert Channels',  icon: Bell,      group: 'developer' },
  { path: '/playbook-builder', label: 'Builder',      sub: 'SOAR Builder',    icon: Workflow,  group: 'developer' },
  { path: '/response',        label: 'SOAR',          sub: 'Auto Response',   icon: Zap,       group: 'developer' },
  { path: '/playbooks',       label: 'Playbooks',     sub: 'SOAR Flows',      icon: Play,      group: 'developer' },

  { path: '/ml-metrics',  label: 'ML Engine',   sub: 'Model Metrics',  icon: BarChart3,    group: 'admin', adminOnly: true },
  { path: '/ml-lab',      label: 'ML Lab',      sub: 'Phase 2 Models', icon: FlaskConical, group: 'admin', adminOnly: true },
  { path: '/compliance',  label: 'Compliance',  sub: 'SOC 2 / ISO',   icon: ShieldCheck,  group: 'admin', adminOnly: true },
  { path: '/admin/users', label: 'Users',       sub: 'Tenant Admin',   icon: Users,        group: 'admin', adminOnly: true },
];

function NavGroup({ items, location, navigate, label }) {
  if (items.length === 0) return null;
  return (
    <>
      <div className="nav-section-label">{label}</div>
      {items.map(item => {
        const isActive = location.pathname === item.path ||
          (item.path !== '/' && location.pathname.startsWith(item.path));
        const Icon = item.icon;
        return (
          <div
            key={item.path}
            className={`nav-item ${isActive ? 'active' : ''}`}
            onClick={() => navigate(item.path)}
            style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 2, padding: '10px 22px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%' }}>
              <Icon size={16} style={{ opacity: isActive ? 1 : 0.6, flexShrink: 0 }} />
              <span style={{ fontFamily: 'var(--font-body)', fontSize: '0.85rem', fontWeight: isActive ? 600 : 500 }}>{item.label}</span>
              {isActive && (
                <span style={{
                  marginLeft: 'auto', width: 6, height: 6, borderRadius: '50%',
                  background: 'var(--accent)',
                  boxShadow: '0 0 8px rgba(74, 93, 79, 0.5)'
                }} />
              )}
            </div>
            <div style={{
              paddingLeft: 26, fontSize: '0.62rem', fontWeight: 500,
              color: isActive ? 'var(--accent)' : 'var(--text-faint)',
              letterSpacing: '0.1em', textTransform: 'uppercase',
              fontFamily: 'var(--font-mono)'
            }}>
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
        <div className="logo-icon">
          <Shield size={18} color="#fff" />
        </div>
        <div>
          <div className="logo-text">TrustFlow</div>
          <div className="logo-sub">SOC Platform v4.0</div>
        </div>
      </div>

      {/* Live Clock */}
      <div style={{
        padding: '12px 22px',
        borderBottom: '1px solid var(--border-dim)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between'
      }}>
        <div className="live-badge" style={{ padding: 0, border: 'none' }}>
          <div className="live-dot" />
          ONLINE
        </div>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: '0.72rem', fontWeight: 500,
          color: 'var(--text-secondary)', letterSpacing: '0.05em'
        }}>
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
      <div style={{ padding: '16px 22px', borderTop: '1px solid var(--border-dim)' }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: '0.6rem', fontWeight: 500,
          color: 'var(--text-faint)', letterSpacing: '0.08em', lineHeight: 1.8
        }}>
          AUTONOMOUS AI DEFENSE<br />
          <span style={{ color: 'var(--text-muted)' }}>// Threat Detection Active</span><br />
          <span style={{ color: 'var(--accent)' }}>// v4.0.0-enterprise</span>
        </div>
      </div>
    </aside>
  );
}
