import { useEffect, useState } from 'react';
import { fetchResponseLog, fetchBlockedIps, fetchDisabledAccounts } from '../api/client';
import { formatDateTime } from '../utils/helpers';

const ACTION_CONFIG = {
  block_ip: { icon: '🚫', label: 'IP BLOCKED', color: '#f03250', bg: 'rgba(255,45,45,0.1)' },
  disable_account: { icon: '🔒', label: 'ACCT DISABLED', color: '#ffb800', bg: 'rgba(255,184,0,0.1)' },
  rate_limit: { icon: '⏱', label: 'RATE LIMITED', color: '#4a9eff', bg: 'rgba(74,158,255,0.1)' },
  firewall_rule: { icon: '🛡', label: 'FW RULE SET', color: '#00e5b0', bg: 'rgba(0,255,200,0.08)' },
};

function ActionTag({ action }) {
  const name = typeof action === 'string' ? action : action.action;
  const status = typeof action === 'object' ? action.status : 'done';
  const cfg = ACTION_CONFIG[name] || { icon: '⚙', label: name?.replace('_', ' ').toUpperCase(), color: '#6e9ab5', bg: 'rgba(125,165,190,0.1)' };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 10px', borderRadius: 4, background: cfg.bg, border: `1px solid ${cfg.color}25`, fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: cfg.color, letterSpacing: 1 }}>
      {cfg.icon} {cfg.label}
    </span>
  );
}

export default function ResponsePage() {
  const [log, setLog] = useState([]);
  const [blocked, setBlocked] = useState([]);
  const [disabled, setDisabled] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const [l, b, d] = await Promise.all([fetchResponseLog(50), fetchBlockedIps(), fetchDisabledAccounts()]);
      setLog(l.data || []);
      setBlocked(b.data || []);
      setDisabled(d.data || []);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  if (loading) return <div className="loading"><div className="spinner" /><div className="loading-text">Loading SOAR data...</div></div>;

  return (
    <div className="fade-in">

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28 }}>
        <div>
          <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#00e5b0', textShadow: '0 0 24px rgba(0,255,200,0.35)', letterSpacing: 2 }}>
            ⚡ SOAR RESPONSE
          </div>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
            Security Orchestration, Automation & Response
          </div>
        </div>
        <button className="btn btn-ghost" onClick={load} style={{ fontSize: 11 }}>↺ REFRESH</button>
      </div>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, marginBottom: 24 }}>
        {[
          { label: 'Total Actions Taken', value: log.length, color: '#00e5b0', glow: 'rgba(0,255,200,0.2)', icon: '⚡' },
          { label: 'IPs Blocked', value: blocked.length, color: '#f03250', glow: 'rgba(255,45,45,0.2)', icon: '🚫' },
          { label: 'Accounts Disabled', value: disabled.length, color: '#ffb800', glow: 'rgba(255,184,0,0.2)', icon: '🔒' },
        ].map(({ label, value, color, glow, icon }) => (
          <div key={label} style={{ background: '#0c1520', border: `1px solid ${glow.replace('0.2', '0.3')}`, borderRadius: 10, padding: '20px 24px', position: 'relative', overflow: 'hidden', transition: 'transform 0.2s, box-shadow 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.boxShadow = `0 8px 24px ${glow}`; }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
          >
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 10 }}>{label}</div>
            <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 32, color, textShadow: `0 0 20px ${glow}` }}>{value}</div>
            <div style={{ position: 'absolute', bottom: 12, right: 16, fontSize: 28, opacity: 0.07 }}>{icon}</div>
          </div>
        ))}
      </div>

      {/* Blocked IPs & Disabled Accounts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* Blocked IPs */}
        <div style={{ background: '#0c1520', border: '1px solid rgba(255,45,45,0.2)', borderRadius: 10, padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#ff6b6b', letterSpacing: 3, textTransform: 'uppercase' }}>🚫 Blocked IPs</div>
            <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>{blocked.length} total</span>
          </div>
          {blocked.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '24px 0', fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#2e5570' }}>No IPs currently blocked</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto' }}>
              {blocked.map(ip => (
                <div key={ip} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,45,45,0.06)', border: '1px solid rgba(255,45,45,0.18)', borderRadius: 7, fontFamily: 'IBM Plex Mono, monospace', fontSize: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f03250', display: 'inline-block', boxShadow: '0 0 6px #f03250', flexShrink: 0 }} />
                    <span style={{ color: '#e8f4f8', letterSpacing: 1 }}>{ip}</span>
                  </div>
                  <span style={{ fontSize: 9, color: '#ff6b6b', letterSpacing: 2, textTransform: 'uppercase', background: 'rgba(255,45,45,0.1)', padding: '2px 8px', borderRadius: 3 }}>BLOCKED</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Disabled Accounts */}
        <div style={{ background: '#0c1520', border: '1px solid rgba(255,184,0,0.2)', borderRadius: 10, padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#ffb800', letterSpacing: 3, textTransform: 'uppercase' }}>🔒 Disabled Accounts</div>
            <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>{disabled.length} total</span>
          </div>
          {disabled.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '24px 0', fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#2e5570' }}>No accounts currently disabled</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto' }}>
              {disabled.map(user => (
                <div key={user} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,184,0,0.06)', border: '1px solid rgba(255,184,0,0.18)', borderRadius: 7, fontFamily: 'IBM Plex Mono, monospace', fontSize: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ffb800', display: 'inline-block', flexShrink: 0 }} />
                    <span style={{ color: '#e8f4f8' }}>{user}</span>
                  </div>
                  <span style={{ fontSize: 9, color: '#ffb800', letterSpacing: 2, textTransform: 'uppercase', background: 'rgba(255,184,0,0.1)', padding: '2px 8px', borderRadius: 3 }}>LOCKED</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Response Action Log */}
      <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.1)', borderRadius: 10, padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase' }}>
            📋 Automated Response Action Log
          </div>
          <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>Last {log.length} entries</span>
        </div>

        {log.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.3 }}>⚡</div>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#2e5570' }}>NO AUTOMATED RESPONSES YET</div>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#1a3a50', marginTop: 8 }}>
              Triggers automatically when risk_score &gt; 90, or manually from an incident investigation.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 600, overflowY: 'auto' }}>
            {log.map((entry, idx) => (
              <div key={idx} style={{ background: '#101d2a', borderRadius: 8, padding: '14px 16px', borderLeft: '3px solid rgba(0,255,200,0.4)', transition: 'border-color 0.2s' }}
                onMouseEnter={e => e.currentTarget.style.borderLeftColor = '#00e5b0'}
                onMouseLeave={e => e.currentTarget.style.borderLeftColor = 'rgba(0,255,200,0.4)'}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    {entry.incident_id && (
                      <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#00e5b0' }}>
                        INC-{String(entry.incident_id).padStart(4, '0')}
                      </span>
                    )}
                    <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>
                      {formatDateTime(entry.timestamp)}
                    </span>
                  </div>
                  <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11 }}>
                    <span style={{ color: '#2e5570' }}>RISK </span>
                    <span style={{ color: (entry.risk_score || 0) >= 85 ? '#f03250' : '#ffb800' }}>{Math.round(entry.risk_score || 0)}</span>
                  </div>
                </div>

                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, marginBottom: 10 }}>
                  <span style={{ color: '#00e5b0' }}>{entry.user || 'unknown'}</span>
                  {entry.ip && <span style={{ color: '#2e5570' }}> @ {entry.ip}</span>}
                </div>

                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {(entry.actions_taken || []).map((action, i) => (
                    <ActionTag key={i} action={action} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
