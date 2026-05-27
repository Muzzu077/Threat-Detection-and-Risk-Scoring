import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchApplications, createApplication, deleteApplication } from '../api/client';

const ENV_COLORS = {
  production: '#059669',
  staging:    '#D97706',
  development:'#2563EB',
};

const STATUS_COLORS = {
  active:   '#059669',
  paused:   '#D97706',
  archived: '#78716C',
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
      background: 'rgba(200,200,205,0.7)', backdropFilter: 'blur(12px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg-glass-heavy)', backdropFilter: 'blur(24px)',
        border: '1px solid var(--border-light)',
        borderRadius: 'var(--radius-xl)', padding: '32px 36px', width: 540, maxWidth: '90%',
        boxShadow: 'var(--shadow-xl)',
      }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, color: 'var(--text-primary)', marginBottom: 6, letterSpacing: -0.5 }}>
          New Application
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 24 }}>
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
                flex: 1, fontFamily: 'var(--font-body)', fontSize: 11, fontWeight: 500,
                padding: '10px 0', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                border: `1px solid ${environment === e ? ENV_COLORS[e] : 'var(--border-dim)'}`,
                background: environment === e ? `${ENV_COLORS[e]}18` : 'transparent',
                color: environment === e ? ENV_COLORS[e] : 'var(--text-muted)',
                letterSpacing: '0.08em', textTransform: 'uppercase',
              }}>{e}</button>
            ))}
          </div>
        </Field>

        {err && (
          <div style={{
            fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--accent-red)', fontWeight: 500,
            padding: '8px 12px', marginBottom: 16,
            background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)',
            borderRadius: 'var(--radius-sm)',
          }}>{err}</div>
        )}

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 8 }}>
          <button onClick={onClose} className="btn btn-ghost">CANCEL</button>
          <button onClick={handleSubmit} disabled={submitting} className="btn btn-primary">
            {submitting ? 'CREATING...' : 'CREATE'}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, required, children }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.18em',
        color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase',
      }}>{label}{required && <span style={{ color: 'var(--accent-red)' }}> *</span>}</div>
      {children}
    </div>
  );
}

function AppCard({ app, onClick, onArchive }) {
  const stats = app.stats || {};
  const envColor    = ENV_COLORS[app.environment] || '#78716C';
  const statusColor = STATUS_COLORS[app.status] || '#78716C';

  return (
    <div onClick={onClick} style={{
      background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
      borderRadius: 'var(--radius-lg)', padding: 22, cursor: 'pointer', transition: 'all 0.2s var(--ease-out)',
      position: 'relative', overflow: 'hidden', boxShadow: 'var(--shadow-sm)',
    }}
    onMouseEnter={e => {
      e.currentTarget.style.borderColor = 'var(--border-bright)';
      e.currentTarget.style.transform = 'translateY(-2px)';
      e.currentTarget.style.boxShadow = 'var(--shadow-lg)';
    }}
    onMouseLeave={e => {
      e.currentTarget.style.borderColor = '';
      e.currentTarget.style.transform = 'translateY(0)';
      e.currentTarget.style.boxShadow = 'var(--shadow-sm)';
    }}>
      {/* corner accent */}
      <div style={{ position: 'absolute', top: 0, left: 0, width: 3, height: '100%', background: envColor, opacity: 0.6 }} />

      {/* header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 17, color: 'var(--text-primary)', marginBottom: 4, letterSpacing: -0.3 }}>
            {app.name}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
            slug: <span style={{ color: 'var(--accent)' }}>{app.slug}</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-end' }}>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 9,
            padding: '2px 8px', borderRadius: 'var(--radius-sm)',
            background: `${envColor}18`, border: `1px solid ${envColor}40`,
            color: envColor, letterSpacing: '0.08em', textTransform: 'uppercase',
          }}>{app.environment}</span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 9,
            padding: '2px 8px', borderRadius: 'var(--radius-sm)',
            background: `${statusColor}18`, border: `1px solid ${statusColor}40`,
            color: statusColor, letterSpacing: '0.08em', textTransform: 'uppercase',
          }}>{app.status}</span>
        </div>
      </div>

      {/* description */}
      {app.description && (
        <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.5 }}>
          {app.description}
        </div>
      )}

      {/* stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 12 }}>
        <Stat label="EVENTS"   value={stats.total_events ?? 0} />
        <Stat label="AVG RISK" value={stats.avg_risk ?? 0} color={(stats.avg_risk ?? 0) >= 60 ? 'var(--accent-red)' : (stats.avg_risk ?? 0) >= 30 ? 'var(--accent-amber)' : 'var(--accent-green)'} />
        <Stat label="CRITICAL" value={stats.critical_events ?? 0} color={stats.critical_events ? 'var(--accent-red)' : 'var(--text-muted)'} />
        <Stat label="OPEN"     value={stats.open_incidents ?? 0} color={stats.open_incidents ? 'var(--accent-amber)' : 'var(--text-muted)'} />
      </div>

      {/* footer */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        paddingTop: 12, borderTop: '1px solid var(--border-dim)',
        fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)',
      }}>
        <span>last seen: <span style={{ color: 'var(--accent)' }}>{formatRelative(stats.last_event_at)}</span></span>
        {app.status !== 'archived' && (
          <button onClick={(e) => { e.stopPropagation(); onArchive(app); }} style={{
            fontFamily: 'var(--font-mono)', fontSize: 9,
            padding: '3px 10px', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
            background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)',
            color: 'var(--accent-red)', letterSpacing: '0.06em', textTransform: 'uppercase',
          }}>ARCHIVE</button>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, color = 'var(--text-primary)' }) {
  return (
    <div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 2 }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color, letterSpacing: 0.5 }}>
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
          <div className="page-title">
            Applications
          </div>
          <div className="page-subtitle">
            Your TrustFlow integrations &mdash; {active.length} active
          </div>
        </div>
        <button onClick={() => setMod(true)} className="btn btn-primary">+ New Application</button>
      </div>

      {error && (
        <div style={{
          fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--accent-red)', fontWeight: 500,
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-sm)',
        }}>&#9888; {error}</div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading applications...</div></div>
      ) : apps.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '80px 0', fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text-muted)' }}>
          <div style={{ fontSize: 36, marginBottom: 14, opacity: 0.4 }}>&#128218;</div>
          <div style={{ marginBottom: 8, fontWeight: 500 }}>NO APPLICATIONS YET</div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 24, letterSpacing: '0.06em' }}>
            Register your first app to start sending events to TrustFlow
          </div>
          <button onClick={() => setMod(true)} className="btn btn-primary">+ Create Application</button>
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
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginTop: 36, marginBottom: 16 }}>
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
