import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchApplications, createApplication, deleteApplication } from '../api/client';

const ENV_COLORS = {
  production: '#48bb78',
  staging:    '#e6a817',
  development:'#3182ce',
};

const STATUS_COLORS = {
  active:   '#48bb78',
  paused:   '#e6a817',
  archived: '#555555',
};

function formatRelative(iso) {
  if (!iso) return 'Never';
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60)    return `${Math.floor(diff)}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function CreateModal({ onClose, onCreated }) {
  const [name, setName]         = useState('');
  const [description, setDesc]  = useState('');
  const [environment, setEnv]   = useState('production');
  const [submitting, setSub]    = useState(false);
  const [err, setErr]           = useState('');

  const handleSubmit = async () => {
    if (!name.trim()) { setErr('NAME REQUIRED'); return; }
    setSub(true); setErr('');
    try {
      const app = await createApplication({ name: name.trim(), description, environment });
      onCreated(app);
    } catch (e) {
      setErr(e.response?.data?.detail || 'CREATE FAILED');
    }
    setSub(false);
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(2,7,12,0.85)', backdropFilter: 'blur(6px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.18)',
        borderRadius: 12, padding: '32px 36px', width: 540, maxWidth: '90%',
      }}>
        <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 18, color: '#ffffff', marginBottom: 6, letterSpacing: 1.5 }}>
          NEW APPLICATION
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 24 }}>
          Register an application to monitor with TrustFlow
        </div>

        <Field label="NAME" required>
          <input className="input" autoFocus value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Checkout Service" />
        </Field>

        <Field label="DESCRIPTION">
          <textarea className="input" rows={3} value={description} onChange={e => setDesc(e.target.value)}
            placeholder="What does this application do?" style={{ resize: 'vertical', minHeight: 60 }} />
        </Field>

        <Field label="ENVIRONMENT">
          <div style={{ display: 'flex', gap: 8 }}>
            {['production', 'staging', 'development'].map(e => (
              <button key={e} type="button" onClick={() => setEnv(e)} style={{
                flex: 1, fontFamily: 'IBM Plex Mono, monospace', fontSize: 11,
                padding: '10px 0', borderRadius: 5, cursor: 'pointer',
                border: `1px solid ${environment === e ? ENV_COLORS[e] : 'rgba(255,255,255,0.1)'}`,
                background: environment === e ? `${ENV_COLORS[e]}18` : 'transparent',
                color: environment === e ? ENV_COLORS[e] : '#a0a0a0',
                letterSpacing: '0.08em', textTransform: 'uppercase',
              }}>{e}</button>
            ))}
          </div>
        </Field>

        {err && (
          <div style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#e53e3e',
            padding: '8px 12px', marginBottom: 16,
            background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)',
            borderRadius: 5,
          }}>{err}</div>
        )}

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 8 }}>
          <button onClick={onClose} style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
            padding: '10px 20px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)',
            cursor: 'pointer', background: 'transparent', color: '#a0a0a0',
            letterSpacing: '0.08em', textTransform: 'uppercase',
          }}>CANCEL</button>
          <button onClick={handleSubmit} disabled={submitting} style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
            padding: '10px 22px', borderRadius: 6, border: 'none', cursor: 'pointer',
            background: submitting ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.15)',
            color: '#ffffff', letterSpacing: '0.08em', textTransform: 'uppercase',
            outline: '1px solid rgba(255,255,255,0.3)',
          }}>{submitting ? 'CREATING...' : 'CREATE'}</button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, required, children }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, letterSpacing: '0.18em',
        color: '#555555', marginBottom: 6, textTransform: 'uppercase',
      }}>{label}{required && <span style={{ color: '#e53e3e' }}> *</span>}</div>
      {children}
    </div>
  );
}

function AppCard({ app, onClick, onArchive }) {
  const stats = app.stats || {};
  const envColor    = ENV_COLORS[app.environment] || '#a0a0a0';
  const statusColor = STATUS_COLORS[app.status] || '#a0a0a0';

  return (
    <div onClick={onClick} style={{
      background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 10, padding: 22, cursor: 'pointer', transition: 'all 0.2s',
      position: 'relative', overflow: 'hidden',
    }}
    onMouseEnter={e => {
      e.currentTarget.style.border = '1px solid rgba(255,255,255,0.25)';
      e.currentTarget.style.transform = 'translateY(-2px)';
    }}
    onMouseLeave={e => {
      e.currentTarget.style.border = '1px solid rgba(255,255,255,0.08)';
      e.currentTarget.style.transform = 'translateY(0)';
    }}>
      {/* corner accent */}
      <div style={{ position: 'absolute', top: 0, left: 0, width: 3, height: '100%', background: envColor, opacity: 0.4 }} />

      {/* header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 16, color: '#ffffff', marginBottom: 4, letterSpacing: 0.5 }}>
            {app.name}
          </div>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555' }}>
            slug: <span style={{ color: '#7a9bb0' }}>{app.slug}</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-end' }}>
          <span style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
            padding: '2px 8px', borderRadius: 3,
            background: `${envColor}18`, border: `1px solid ${envColor}40`,
            color: envColor, letterSpacing: '0.08em', textTransform: 'uppercase',
          }}>{app.environment}</span>
          <span style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
            padding: '2px 8px', borderRadius: 3,
            background: `${statusColor}18`, border: `1px solid ${statusColor}40`,
            color: statusColor, letterSpacing: '0.08em', textTransform: 'uppercase',
          }}>{app.status}</span>
        </div>
      </div>

      {/* description */}
      {app.description && (
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#a0a0a0', marginBottom: 16, lineHeight: 1.5 }}>
          {app.description}
        </div>
      )}

      {/* stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 12 }}>
        <Stat label="EVENTS"   value={stats.total_events ?? 0} />
        <Stat label="AVG RISK" value={stats.avg_risk ?? 0} color={(stats.avg_risk ?? 0) >= 60 ? '#e53e3e' : (stats.avg_risk ?? 0) >= 30 ? '#e6a817' : '#48bb78'} />
        <Stat label="CRITICAL" value={stats.critical_events ?? 0} color={stats.critical_events ? '#e53e3e' : '#a0a0a0'} />
        <Stat label="OPEN"     value={stats.open_incidents ?? 0} color={stats.open_incidents ? '#ed8936' : '#a0a0a0'} />
      </div>

      {/* footer */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.05)',
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555',
      }}>
        <span>last seen: <span style={{ color: '#7a9bb0' }}>{formatRelative(stats.last_event_at)}</span></span>
        {app.status !== 'archived' && (
          <button onClick={(e) => { e.stopPropagation(); onArchive(app); }} style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
            padding: '3px 10px', borderRadius: 3, cursor: 'pointer',
            background: 'rgba(229,62,62,0.06)', border: '1px solid rgba(229,62,62,0.2)',
            color: '#e53e3e', letterSpacing: '0.06em', textTransform: 'uppercase',
          }}>ARCHIVE</button>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, color = '#ffffff' }) {
  return (
    <div>
      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#555555', letterSpacing: '0.12em', marginBottom: 2 }}>
        {label}
      </div>
      <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 18, color, letterSpacing: 0.5 }}>
        {value}
      </div>
    </div>
  );
}

export default function ApplicationsPage() {
  const [apps, setApps]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setMod]   = useState(false);
  const [error, setError]     = useState('');
  const navigate              = useNavigate();

  const load = async () => {
    try {
      const data = await fetchApplications();
      setApps(data.data || []);
    } catch {
      setError('FAILED TO LOAD APPLICATIONS');
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleCreated = (newApp) => {
    setMod(false);
    setApps(prev => [{ ...newApp, stats: {} }, ...prev]);
    navigate(`/applications/${newApp.id}`);
  };

  const handleArchive = async (app) => {
    if (!confirm(`Archive "${app.name}"? Existing event history is kept; you'll just stop seeing it on the active list.`)) return;
    try {
      await deleteApplication(app.id);
      load();
    } catch {
      setError('FAILED TO ARCHIVE');
    }
  };

  const active   = apps.filter(a => a.status !== 'archived');
  const archived = apps.filter(a => a.status === 'archived');

  return (
    <div className="page-enter">
      {/* Header */}
      <div style={{ marginBottom: 28, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#ffffff', textShadow: '0 0 24px rgba(255,255,255,0.35)', letterSpacing: 2 }}>
            APPLICATIONS
          </div>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
            Your TrustFlow integrations &mdash; {active.length} active
          </div>
        </div>
        <button onClick={() => setMod(true)} style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
          padding: '10px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
          background: 'rgba(255,255,255,0.12)', color: '#ffffff',
          letterSpacing: '0.08em', textTransform: 'uppercase',
          outline: '1px solid rgba(255,255,255,0.3)',
        }}>+ NEW APPLICATION</button>
      </div>

      {error && (
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#e53e3e',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)', borderRadius: 6,
        }}>&#9888; {error}</div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading applications...</div></div>
      ) : apps.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '80px 0', fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#555555' }}>
          <div style={{ fontSize: 36, marginBottom: 14, opacity: 0.4 }}>&#128218;</div>
          <div style={{ marginBottom: 8 }}>NO APPLICATIONS YET</div>
          <div style={{ fontSize: 10, color: '#3a3a3a', marginBottom: 24, letterSpacing: '0.06em' }}>
            Register your first app to start sending events to TrustFlow
          </div>
          <button onClick={() => setMod(true)} style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
            padding: '10px 24px', borderRadius: 6, border: 'none', cursor: 'pointer',
            background: 'rgba(255,255,255,0.12)', color: '#ffffff',
            letterSpacing: '0.08em', textTransform: 'uppercase',
            outline: '1px solid rgba(255,255,255,0.3)',
          }}>+ CREATE APPLICATION</button>
        </div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: 16 }}>
            {active.map(app => (
              <AppCard key={app.id} app={app}
                onClick={() => navigate(`/applications/${app.id}`)}
                onArchive={handleArchive} />
            ))}
          </div>
          {archived.length > 0 && (
            <>
              <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555', letterSpacing: 3, textTransform: 'uppercase', marginTop: 36, marginBottom: 16 }}>
                Archived &mdash; {archived.length}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: 16, opacity: 0.55 }}>
                {archived.map(app => (
                  <AppCard key={app.id} app={app}
                    onClick={() => navigate(`/applications/${app.id}`)}
                    onArchive={() => {}} />
                ))}
              </div>
            </>
          )}
        </>
      )}

      {showModal && <CreateModal onClose={() => setMod(false)} onCreated={handleCreated} />}
    </div>
  );
}
