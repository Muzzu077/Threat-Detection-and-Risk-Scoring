import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const NAV = [
  { path: '/', label: 'Operations', sub: 'Dashboard', icon: '\u25C8' },
  { path: '/incidents', label: 'Incidents', sub: 'Active Threats', icon: '\u26A0' },
  { path: '/attack-graph', label: 'Kill Chain', sub: 'Attack Graph', icon: '\u2B21' },
  { path: '/ml-metrics', label: 'ML Engine', sub: 'Model Metrics', icon: '\u25CE' },
  { path: '/threat-intel', label: 'Threat Intel', sub: 'IP Reputation', icon: '\u25C9' },
  { path: '/response', label: 'SOAR', sub: 'Auto Response', icon: '\u26A1' },
  { path: '/playbooks', label: 'Playbooks', sub: 'SOAR Flows', icon: '\u25B6' },
  { path: '/api-keys', label: 'API Keys', sub: 'Key Management', icon: '\u26BF' },
  { path: '/integration', label: 'Integration', sub: 'SDK Setup Guide', icon: '\u25C7' },
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
        <div className="logo-icon" style={{ fontSize: 18 }}>&#128737;</div>
        <div>
          <div className="logo-text">THREATPULSE</div>
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
        <div className="nav-section-label">Operations</div>
        {NAV.slice(0, 7).map(item => {
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

        <div className="nav-section-label" style={{ marginTop: 12 }}>Developer</div>
        {NAV.slice(7).map(item => {
          const isActive = location.pathname === item.path;
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
