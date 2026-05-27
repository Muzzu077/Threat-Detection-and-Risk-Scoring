import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  fetchApplication, fetchApplicationKeys, createApiKey, revokeApiKey,
  deleteApplication, updateApplication,
} from '../api/client';

function formatDate(s) {
  if (!s) return '—';
  return new Date(s).toLocaleString('en-US', { hour12: false });
}

function KeyRevealModal({ fullKey, onClose }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try { await navigator.clipboard.writeText(fullKey); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch {}
  };
  return (
    <div onClick={onClose} style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(200,200,205,0.7)', backdropFilter: 'blur(12px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg-glass-heavy)', backdropFilter: 'blur(24px)',
        border: '1px solid var(--border-light)',
        borderRadius: 'var(--radius-xl)', padding: '32px 36px', width: 580, maxWidth: '90%',
        boxShadow: 'var(--shadow-xl)',
      }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-primary)', marginBottom: 8 }}>API Key Generated</div>
        <div style={{
          fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--accent-red)', marginBottom: 18, fontWeight: 500,
          padding: '8px 12px', background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-sm)',
        }}>WARNING: This key will only be shown once. Copy it now.</div>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)',
          background: 'var(--bg-glass)', backdropFilter: 'blur(12px)', border: '1px solid var(--border-dim)',
          borderRadius: 'var(--radius-sm)', padding: '14px 16px', wordBreak: 'break-all', marginBottom: 18,
        }}>{fullKey}</div>
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={handleCopy} className="btn btn-primary">{copied ? 'COPIED' : 'COPY KEY'}</button>
          <button onClick={onClose} className="btn btn-ghost">CLOSE</button>
        </div>
      </div>
    </div>
  );
}

const btnPrimary = {
  fontFamily: 'var(--font-body)', fontSize: 12, fontWeight: 600,
  padding: '10px 24px', borderRadius: 'var(--radius-full)', border: 'none', cursor: 'pointer',
  background: 'var(--accent)', color: '#fff',
  letterSpacing: '0.02em', textTransform: 'uppercase',
  boxShadow: 'var(--shadow-glow)',
};

const btnGhost = {
  fontFamily: 'var(--font-body)', fontSize: 12, fontWeight: 500,
  padding: '10px 20px', borderRadius: 'var(--radius-full)', border: '1px solid var(--border-dim)',
  cursor: 'pointer', background: 'var(--bg-glass)', backdropFilter: 'blur(8px)',
  color: 'var(--text-secondary)',
  letterSpacing: '0.02em', textTransform: 'uppercase',
};

function CodeBlock({ children, label }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try { await navigator.clipboard.writeText(children); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch {}
  };
  return (
    <div style={{ position: 'relative', marginTop: 8 }}>
      {label && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
          {label}
        </div>
      )}
      <pre style={{
        background: 'var(--bg-glass)', backdropFilter: 'blur(12px)', border: '1px solid var(--border-dim)',
        borderRadius: 'var(--radius-sm)', padding: '14px 16px', margin: 0, overflowX: 'auto',
        fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)',
        lineHeight: 1.6,
      }}>{children}</pre>
      <button onClick={handleCopy} style={{
        position: 'absolute', top: label ? 24 : 8, right: 8,
        fontFamily: 'var(--font-mono)', fontSize: 9,
        padding: '4px 10px', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
        background: 'var(--bg-glass)', border: '1px solid var(--border-dim)',
        color: copied ? 'var(--accent-green)' : 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase',
      }}>{copied ? 'COPIED' : 'COPY'}</button>
    </div>
  );
}

export default function ApplicationDetailPage() {
  const { id }     = useParams();
  const navigate   = useNavigate();
  const [app, setApp]       = useState(null);
  const [keys, setKeys]     = useState([]);
  const [loading, setLoad]  = useState(true);
  const [reveal, setReveal] = useState(null);
  const [keyName, setKn]    = useState('');
  const [generating, setG]  = useState(false);
  const [err, setErr]       = useState('');
  const [editing, setEd]    = useState(false);
  const [name, setName]     = useState('');
  const [desc, setDesc]     = useState('');

  const load = async () => {
    try {
      const [a, k] = await Promise.all([fetchApplication(id), fetchApplicationKeys(id)]);
      setApp(a); setName(a.name); setDesc(a.description || '');
      setKeys(k.data || []);
    } catch {
      setErr('FAILED TO LOAD APPLICATION');
    }
    setLoad(false);
  };

  useEffect(() => { load(); }, [id]);

  const handleCreate = async () => {
    setG(true); setErr('');
    try {
      const r = await createApiKey(keyName || 'Untitled Key', Number(id));
      setReveal(r.key);
      setKn('');
      load();
    } catch (e) {
      setErr(e.response?.data?.detail || 'FAILED TO GENERATE KEY');
    }
    setG(false);
  };

  const handleRevoke = async (kid) => {
    if (!confirm('Revoke this API key?')) return;
    try { await revokeApiKey(kid); load(); } catch {}
  };

  const handleArchive = async () => {
    if (!confirm(`Archive "${app.name}"?`)) return;
    await deleteApplication(id);
    navigate('/applications');
  };

  const handleSaveEdit = async () => {
    try {
      await updateApplication(id, { name, description: desc });
      setEd(false);
      load();
    } catch {
      setErr('FAILED TO UPDATE');
    }
  };

  if (loading) return <div className="loading"><div className="spinner" /><div className="loading-text">Loading...</div></div>;
  if (!app) return <div style={{ padding: 40, color: 'var(--text-muted)' }}>Application not found.</div>;

  const stats        = app.stats || {};
  const apiBase      = window.location.origin;
  const exampleKey   = keys[0]?.prefix ? `${keys[0].prefix}...` : 'tf_live_<your_key>';

  const curlSnippet = `curl -X POST ${apiBase}/api/v1/ingest \\
  -H "X-API-Key: ${exampleKey}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "events": [{
      "timestamp": "${new Date().toISOString()}",
      "user": "alice",
      "ip": "203.0.113.42",
      "action": "POST",
      "status": "success",
      "resource": "/api/checkout"
    }]
  }'`;

  const pythonSnippet = `from trustflow import TrustFlow

tf = TrustFlow(api_key="${exampleKey}", base_url="${apiBase}")

tf.send_event(
    user="alice",
    ip="203.0.113.42",
    action="POST",
    status="success",
    resource="/api/checkout",
)`;

  const nodeSnippet = `import { TrustFlow } from "@trustflow/sdk";

const tf = new TrustFlow({ apiKey: "${exampleKey}", baseUrl: "${apiBase}" });

await tf.sendEvent({
  user: "alice",
  ip: "203.0.113.42",
  action: "POST",
  status: "success",
  resource: "/api/checkout",
});`;

  return (
    <div className="page-enter">
      {/* Breadcrumb */}
      <button onClick={() => navigate('/applications')} style={{
        background: 'transparent', border: 'none', cursor: 'pointer',
        fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--accent)', fontWeight: 500,
        letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 18, padding: 0,
      }}>← Applications</button>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28 }}>
        <div style={{ flex: 1 }}>
          {editing ? (
            <>
              <input className="input" value={name} onChange={e => setName(e.target.value)}
                style={{ fontSize: 18, marginBottom: 8, width: '60%' }} />
              <textarea className="input" rows={2} value={desc} onChange={e => setDesc(e.target.value)}
                style={{ width: '60%', marginBottom: 8 }} />
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={handleSaveEdit} style={btnPrimary}>SAVE</button>
                <button onClick={() => setEd(false)} style={btnGhost}>CANCEL</button>
              </div>
            </>
          ) : (
            <>
              <div className="page-title" style={{ marginBottom: 6 }}>
                {app.name}
              </div>
              <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
                {app.description || <em style={{ color: 'var(--text-faint)' }}>No description</em>}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
                slug: <span style={{ color: 'var(--accent)' }}>{app.slug}</span> · env: <span style={{ color: 'var(--accent)' }}>{app.environment}</span> · status: <span style={{ color: 'var(--accent)' }}>{app.status}</span>
              </div>
            </>
          )}
        </div>
        {!editing && (
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => setEd(true)} style={btnGhost}>EDIT</button>
            {app.status !== 'archived' && (
              <button onClick={handleArchive} style={{ ...btnGhost, color: 'var(--accent-red)', border: '1px solid rgba(185,28,28,0.25)' }}>ARCHIVE</button>
            )}
          </div>
        )}
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 }}>
        <StatCard label="TOTAL EVENTS"     value={stats.total_events ?? 0} />
        <StatCard label="AVG RISK"         value={stats.avg_risk ?? 0}
          color={(stats.avg_risk ?? 0) >= 60 ? 'var(--accent-red)' : (stats.avg_risk ?? 0) >= 30 ? 'var(--accent-amber)' : 'var(--accent-green)'} />
        <StatCard label="CRITICAL EVENTS"  value={stats.critical_events ?? 0}
          color={stats.critical_events ? 'var(--accent-red)' : 'var(--text-muted)'} />
        <StatCard label="OPEN INCIDENTS"   value={stats.open_incidents ?? 0}
          color={stats.open_incidents ? 'var(--accent-amber)' : 'var(--text-muted)'} />
      </div>

      {err && (
        <div style={{
          fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--accent-red)', fontWeight: 500,
          padding: '8px 12px', marginBottom: 16,
          background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-sm)',
        }}>&#9888; {err}</div>
      )}

      {/* API Keys */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 14, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            API Keys ({keys.filter(k => k.is_active).length} active)
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input className="input" placeholder="Key name..." value={keyName} onChange={e => setKn(e.target.value)} style={{ width: 200, fontSize: 12 }} />
            <button onClick={handleCreate} disabled={generating} style={btnPrimary}>
              {generating ? 'GENERATING...' : '+ NEW KEY'}
            </button>
          </div>
        </div>

        {keys.length === 0 ? (
          <div style={{ padding: 30, textAlign: 'center', fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-muted)', background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', boxShadow: 'var(--shadow-sm)' }}>
            No keys yet — generate one to start sending events from this application.
          </div>
        ) : (
          <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
            <table className="data-table">
              <thead><tr>{['PREFIX','NAME','CREATED','LAST USED','STATUS',''].map(h => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {keys.map(k => (
                  <tr key={k.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)' }}>{k.prefix}</td>
                    <td style={{ fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--text-primary)', fontWeight: 500 }}>{k.name}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)' }}>{formatDate(k.created_at)}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-faint)' }}>{k.last_used_at ? formatDate(k.last_used_at) : 'Never'}</td>
                    <td>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 9,
                        padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                        background: k.is_active ? 'rgba(5,150,105,0.10)' : 'rgba(185,28,28,0.10)',
                        border: `1px solid ${k.is_active ? 'rgba(5,150,105,0.22)' : 'rgba(185,28,28,0.22)'}`,
                        color: k.is_active ? 'var(--accent-green)' : 'var(--accent-red)', letterSpacing: '0.08em',
                      }}>{k.is_active ? 'ACTIVE' : 'REVOKED'}</span>
                    </td>
                    <td>
                      {k.is_active && (
                        <button onClick={() => handleRevoke(k.id)} style={{
                          fontFamily: 'var(--font-mono)', fontSize: 9, padding: '3px 10px',
                          borderRadius: 'var(--radius-sm)', border: '1px solid rgba(185,28,28,0.22)',
                          background: 'rgba(185,28,28,0.08)', color: 'var(--accent-red)', cursor: 'pointer',
                          letterSpacing: '0.06em', textTransform: 'uppercase',
                        }}>REVOKE</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* SDK Snippets */}
      <div>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 14, color: 'var(--text-primary)', letterSpacing: '-0.01em', marginBottom: 14 }}>
          Integration Snippets
        </div>
        <CodeBlock label="cURL">{curlSnippet}</CodeBlock>
        <CodeBlock label="Python SDK">{pythonSnippet}</CodeBlock>
        <CodeBlock label="Node.js SDK">{nodeSnippet}</CodeBlock>
      </div>

      {reveal && <KeyRevealModal fullKey={reveal} onClose={() => setReveal(null)} />}
    </div>
  );
}

function StatCard({ label, value, color = 'var(--text-primary)' }) {
  return (
    <div style={{
      background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
      borderRadius: 'var(--radius-lg)', padding: '18px 20px', boxShadow: 'var(--shadow-sm)',
    }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: 6, textTransform: 'uppercase' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, color, letterSpacing: 1 }}>
        {value}
      </div>
    </div>
  );
}
