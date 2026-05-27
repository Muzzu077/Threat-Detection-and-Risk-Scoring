import { useEffect, useState } from 'react';
import { fetchResponseLog, fetchBlockedIps, fetchDisabledAccounts } from '../api/client';
import { formatDateTime } from '../utils/helpers';

const ACTION_CONFIG = {
  block_ip: { icon: '🚫', label: 'IP BLOCKED', color: 'var(--accent-red)', bg: 'rgba(185,28,28,0.1)' },
  disable_account: { icon: '🔒', label: 'ACCT DISABLED', color: 'var(--accent-orange)', bg: 'rgba(230,168,23,0.1)' },
  rate_limit: { icon: '⏱', label: 'RATE LIMITED', color: 'var(--accent-blue)', bg: 'rgba(37,99,235,0.1)' },
  firewall_rule: { icon: '🛡', label: 'FW RULE SET', color: 'var(--text-primary)', bg: 'rgba(200,200,205,0.08)' },
};

function ActionTag({ action }) {
  const name = typeof action === 'string' ? action : action.action;
  const cfg = ACTION_CONFIG[name] || { icon: '⚙', label: name?.replace('_', ' ').toUpperCase(), color: 'var(--text-muted)', bg: 'var(--bg-glass)' };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 10px', borderRadius: 'var(--radius-sm)', background: cfg.bg, border: `1px solid ${cfg.color}35`, fontFamily: 'var(--font-mono)', fontSize: 10, color: cfg.color, letterSpacing: 1 }}>
      {cfg.icon} {cfg.label}
    </span>
  );
}

export default function ResponsePage({ user }) {
  const [log, setLog] = useState([]);
  const [blocked, setBlocked] = useState([]);
  const [disabled, setDisabled] = useState([]);
  const [scope, setScope] = useState('tenant');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const [l, b, d] = await Promise.all([fetchResponseLog(50), fetchBlockedIps(), fetchDisabledAccounts()]);
      setLog(l.data || []);
      setBlocked(b.data || []);
      setDisabled(d.data || []);
      setScope(l.scope || b.scope || d.scope || (user?.role === 'admin' ? 'all' : 'tenant'));
    } catch {
      // ignore
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  if (loading) return <div className="loading"><div className="spinner" /><div className="loading-text">Loading SOAR data...</div></div>;

  return (
    <div className="page-enter">

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
            ⚡ SOAR RESPONSE
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
            Security Orchestration, Automation & Response
          </div>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 9,
            padding: '4px 10px', borderRadius: 'var(--radius-sm)', letterSpacing: 1.5,
            color: scope === 'all' ? 'var(--accent-red)' : 'var(--accent)',
            background: scope === 'all' ? 'rgba(185,28,28,0.1)' : 'rgba(74,93,79,0.1)',
            border: `1px solid ${scope === 'all' ? 'rgba(185,28,28,0.3)' : 'rgba(74,93,79,0.3)'}`,
          }}>
            {scope === 'all' ? 'GLOBAL VIEW (ADMIN)' : 'YOUR TENANT'}
          </span>
          <button className="btn btn-ghost" onClick={load} style={{ fontSize: 11 }}>↺ REFRESH</button>
        </div>
      </div>

      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)',
        padding: '10px 14px', marginBottom: 20, lineHeight: 1.6,
        background: 'var(--bg-glass)', borderLeft: '2px solid var(--accent)',
        borderRadius: 'var(--radius-sm)',
      }}>
        {scope === 'all'
          ? 'Showing automated SOAR actions across every tenant. Switch to a tenant role to see only one tenant.'
          : 'Showing only the SOAR actions taken in response to events ingested through your own API keys. Each tenant sees a separate action log.'}
      </div>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, marginBottom: 24 }}>
        {[
          { label: 'Total Actions Taken', value: log.length, color: 'var(--text-primary)', glow: 'rgba(200,200,205,0.3)', icon: '⚡' },
          { label: 'IPs Blocked', value: blocked.length, color: 'var(--accent-red)', glow: 'rgba(185,28,28,0.3)', icon: '🚫' },
          { label: 'Accounts Disabled', value: disabled.length, color: 'var(--accent-orange)', glow: 'rgba(230,168,23,0.3)', icon: '🔒' },
        ].map(({ label, value, color, glow, icon }) => (
          <div key={label} style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: `1px solid var(--border-light)`, borderRadius: 'var(--radius-lg)', padding: '20px 24px', position: 'relative', overflow: 'hidden', transition: 'transform 0.2s, box-shadow 0.2s', boxShadow: 'var(--shadow-sm)' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.boxShadow = `0 8px 24px ${glow}`; }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'var(--shadow-sm)'; }}
          >
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 10 }}>{label}</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 32, color, textShadow: `0 0 20px ${glow}` }}>{value}</div>
            <div style={{ position: 'absolute', bottom: 12, right: 16, fontSize: 28, opacity: 0.1 }}>{icon}</div>
          </div>
        ))}
      </div>

      {/* Blocked IPs & Disabled Accounts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* Blocked IPs */}
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-lg)', padding: 20, boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent-red)', letterSpacing: 3, textTransform: 'uppercase' }}>🚫 Blocked IPs</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{blocked.length} total</span>
          </div>
          {blocked.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '24px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>No IPs currently blocked</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto' }}>
              {blocked.map(ip => (
                <div key={ip} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(185,28,28,0.06)', border: '1px solid rgba(185,28,28,0.18)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-red)', display: 'inline-block', boxShadow: '0 0 6px var(--accent-red)', flexShrink: 0 }} />
                    <span style={{ color: 'var(--text-primary)', letterSpacing: 1 }}>{ip}</span>
                  </div>
                  <span style={{ fontSize: 9, color: 'var(--accent-red)', letterSpacing: 2, textTransform: 'uppercase', background: 'rgba(185,28,28,0.1)', padding: '2px 8px', borderRadius: 'var(--radius-sm)' }}>BLOCKED</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Disabled Accounts */}
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid rgba(230,168,23,0.22)', borderRadius: 'var(--radius-lg)', padding: 20, boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent-orange)', letterSpacing: 3, textTransform: 'uppercase' }}>🔒 Disabled Accounts</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{disabled.length} total</span>
          </div>
          {disabled.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '24px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>No accounts currently disabled</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto' }}>
              {disabled.map(user => (
                <div key={user} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(230,168,23,0.06)', border: '1px solid rgba(230,168,23,0.18)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-orange)', display: 'inline-block', flexShrink: 0 }} />
                    <span style={{ color: 'var(--text-primary)' }}>{user}</span>
                  </div>
                  <span style={{ fontSize: 9, color: 'var(--accent-orange)', letterSpacing: 2, textTransform: 'uppercase', background: 'rgba(230,168,23,0.1)', padding: '2px 8px', borderRadius: 'var(--radius-sm)' }}>LOCKED</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Response Action Log */}
      <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: 20, boxShadow: 'var(--shadow-sm)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase' }}>
            📋 Automated Response Action Log
          </div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>Last {log.length} entries</span>
        </div>

        {log.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.3 }}>⚡</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>NO AUTOMATED RESPONSES YET</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-faint)', marginTop: 8 }}>
              Triggers automatically when risk_score &gt; 90, or manually from an incident investigation.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 600, overflowY: 'auto' }}>
            {log.map((entry, idx) => (
              <div key={idx} style={{ background: 'var(--bg-glass-heavy)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-md)', padding: '14px 16px', borderLeft: '3px solid var(--border-dim)', transition: 'border-color 0.2s' }}
                onMouseEnter={e => e.currentTarget.style.borderLeftColor = 'var(--text-primary)'}
                onMouseLeave={e => e.currentTarget.style.borderLeftColor = 'var(--border-dim)'}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    {entry.incident_id && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)' }}>
                        INC-{String(entry.incident_id).padStart(4, '0')}
                      </span>
                    )}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                      {formatDateTime(entry.timestamp)}
                    </span>
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    <span style={{ color: 'var(--text-muted)' }}>RISK </span>
                    <span style={{ color: (entry.risk_score || 0) >= 85 ? 'var(--accent-red)' : 'var(--accent-orange)' }}>{Math.round(entry.risk_score || 0)}</span>
                  </div>
                </div>

                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, marginBottom: 10 }}>
                  <span style={{ color: 'var(--text-primary)' }}>{entry.user || 'unknown'}</span>
                  {entry.ip && <span style={{ color: 'var(--text-muted)' }}> @ {entry.ip}</span>}
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
