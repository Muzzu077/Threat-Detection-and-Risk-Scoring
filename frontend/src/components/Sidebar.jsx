import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const NAV = [
  { path: '/', label: 'Operations', sub: 'Dashboard', icon: '◈' },
  { path: '/incidents', label: 'Incidents', sub: 'Active Threats', icon: '⚠' },
  { path: '/attack-graph', label: 'Kill Chain', sub: 'Attack Graph', icon: '⬡' },
  { path: '/ml-metrics', label: 'ML Engine', sub: 'Model Metrics', icon: '◎' },
  { path: '/threat-intel', label: 'Threat Intel', sub: 'IP Reputation', icon: '◉' },
  { path: '/response', label: 'SOAR', sub: 'Auto Response', icon: '⚡' },
  { path: '/playbooks', label: 'Playbooks', sub: 'SOAR Flows', icon: '▶' },
];

export default function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const timeStr = time.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="logo-icon" style={{ fontSize: 18 }}>🛡</div>
        <div>
          <div className="logo-text">THREATPULSE</div>
          <div className="logo-sub">SOC Platform v3.0</div>
        </div>
      </div>

      {/* Live Clock */}
      <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(0,255,200,0.07)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div className="live-badge" style={{ padding: 0, border: 'none' }}>
          <div className="live-dot" />
          SYSTEM ONLINE
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#00e5b0', letterSpacing: 1 }}>
          {timeStr}
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Operations</div>
        {NAV.map(item => {
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
                  <span style={{ marginLeft: 'auto', width: 4, height: 4, borderRadius: '50%', background: '#00e5b0', boxShadow: '0 0 6px #00e5b0' }} />
                )}
              </div>
              <div style={{ paddingLeft: 28, fontSize: 9, color: isActive ? 'rgba(0,255,200,0.5)' : 'rgba(61,96,117,0.7)', letterSpacing: 2, textTransform: 'uppercase' }}>
                {item.sub}
              </div>
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{ padding: '14px 16px', borderTop: '1px solid rgba(0,255,200,0.06)' }}>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: '0.12em', lineHeight: 1.8 }}>
          AUTONOMOUS AI DEFENSE<br />
          <span style={{ color: 'rgba(0,255,200,0.35)' }}>// THREAT DETECTION ACTIVE</span><br />
          <span style={{ color: '#1a3a50' }}>// v3.0.0-enterprise</span>
        </div>
      </div>
    </aside>
  );
}
