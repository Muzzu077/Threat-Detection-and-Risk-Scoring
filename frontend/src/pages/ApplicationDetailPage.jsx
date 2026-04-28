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
      background: 'rgba(2,7,12,0.85)', backdropFilter: 'blur(6px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.3)',
        borderRadius: 12, padding: '32px 36px', width: 580, maxWidth: '90%',
      }}>
        <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 16, color: '#ffffff', marginBottom: 8 }}>API KEY GENERATED</div>
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#e53e3e', marginBottom: 18,
          padding: '8px 12px', background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)', borderRadius: 5,
        }}>WARNING: This key will only be shown once. Copy it now.</div>
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 13, color: '#e8f4f8',
          background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.15)',
          borderRadius: 6, padding: '14px 16px', wordBreak: 'break-all', marginBottom: 18,
        }}>{fullKey}</div>
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={handleCopy} style={btnPrimary}>{copied ? 'COPIED' : 'COPY KEY'}</button>
          <button onClick={onClose} style={btnGhost}>CLOSE</button>
        </div>
      </div>
    </div>
  );
}

const btnPrimary = {
  fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
  padding: '10px 24px', borderRadius: 6, border: 'none', cursor: 'pointer',
  background: 'rgba(255,255,255,0.15)', color: '#ffffff',
  letterSpacing: '0.08em', textTransform: 'uppercase',
  outline: '1px solid rgba(255,255,255,0.3)',
};

const btnGhost = {
  fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
  padding: '10px 20px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)',
  cursor: 'pointer', background: 'transparent', color: '#a0a0a0',
  letterSpacing: '0.08em', textTransform: 'uppercase',
};

function CodeBlock({ children, label }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try { await navigator.clipboard.writeText(children); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch {}
  };
  return (
    <div style={{ position: 'relative', marginTop: 8 }}>
      {label && (
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, letterSpacing: '0.18em', color: '#555555', marginBottom: 6, textTransform: 'uppercase' }}>
          {label}
        </div>
      )}
      <pre style={{
        background: '#050505', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 8, padding: '14px 16px', margin: 0, overflowX: 'auto',
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#cfd8dc',
        lineHeight: 1.6,
      }}>{children}</pre>
      <button onClick={handleCopy} style={{
        position: 'absolute', top: label ? 24 : 8, right: 8,
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
        padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
        background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)',
        color: copied ? '#48bb78' : '#a0a0a0', letterSpacing: '0.06em', textTransform: 'uppercase',
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
  if (!app) return <div style={{ padding: 40, color: '#555' }}>Application not found.</div>;

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
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#7a9bb0',
        letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 18, padding: 0,
      }}>← APPLICATIONS</button>

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
              <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 26, color: '#ffffff', textShadow: '0 0 24px rgba(255,255,255,0.35)', letterSpacing: 1.5, marginBottom: 6 }}>
                {app.name}
              </div>
              <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#a0a0a0', marginBottom: 6 }}>
                {app.description || <em style={{ color: '#555' }}>No description</em>}
              </div>
              <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555', letterSpacing: '0.1em' }}>
                slug: <span style={{ color: '#7a9bb0' }}>{app.slug}</span> · env: <span style={{ color: '#7a9bb0' }}>{app.environment}</span> · status: <span style={{ color: '#7a9bb0' }}>{app.status}</span>
              </div>
            </>
          )}
        </div>
        {!editing && (
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => setEd(true)} style={btnGhost}>EDIT</button>
            {app.status !== 'archived' && (
              <button onClick={handleArchive} style={{ ...btnGhost, color: '#e53e3e', border: '1px solid rgba(229,62,62,0.3)' }}>ARCHIVE</button>
            )}
          </div>
        )}
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 }}>
        <StatCard label="TOTAL EVENTS"     value={stats.total_events ?? 0} />
        <StatCard label="AVG RISK"         value={stats.avg_risk ?? 0}
          color={(stats.avg_risk ?? 0) >= 60 ? '#e53e3e' : (stats.avg_risk ?? 0) >= 30 ? '#e6a817' : '#48bb78'} />
        <StatCard label="CRITICAL EVENTS"  value={stats.critical_events ?? 0}
          color={stats.critical_events ? '#e53e3e' : '#a0a0a0'} />
        <StatCard label="OPEN INCIDENTS"   value={stats.open_incidents ?? 0}
          color={stats.open_incidents ? '#ed8936' : '#a0a0a0'} />
      </div>

      {err && (
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#e53e3e',
          padding: '8px 12px', marginBottom: 16,
          background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)', borderRadius: 5,
        }}>&#9888; {err}</div>
      )}

      {/* API Keys */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#ffffff', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
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
          <div style={{ padding: 30, textAlign: 'center', fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#555555', background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8 }}>
            No keys yet — generate one to start sending events from this application.
          </div>
        ) : (
          <div style={{ background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, overflow: 'hidden' }}>
            <table className="data-table">
              <thead><tr>{['PREFIX','NAME','CREATED','LAST USED','STATUS',''].map(h => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {keys.map(k => (
                  <tr key={k.id}>
                    <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#ffffff' }}>{k.prefix}</td>
                    <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#e8f4f8' }}>{k.name}</td>
                    <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#a0a0a0' }}>{formatDate(k.created_at)}</td>
                    <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555' }}>{k.last_used_at ? formatDate(k.last_used_at) : 'Never'}</td>
                    <td>
                      <span style={{
                        fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
                        padding: '2px 8px', borderRadius: 3,
                        background: k.is_active ? 'rgba(72,187,120,0.1)' : 'rgba(229,62,62,0.1)',
                        border: `1px solid ${k.is_active ? 'rgba(72,187,120,0.3)' : 'rgba(229,62,62,0.3)'}`,
                        color: k.is_active ? '#48bb78' : '#e53e3e', letterSpacing: '0.08em',
                      }}>{k.is_active ? 'ACTIVE' : 'REVOKED'}</span>
                    </td>
                    <td>
                      {k.is_active && (
                        <button onClick={() => handleRevoke(k.id)} style={{
                          fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, padding: '3px 10px',
                          borderRadius: 3, border: '1px solid rgba(229,62,62,0.3)',
                          background: 'rgba(229,62,62,0.08)', color: '#e53e3e', cursor: 'pointer',
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
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#ffffff', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 14 }}>
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

function StatCard({ label, value, color = '#ffffff' }) {
  return (
    <div style={{
      background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 8, padding: '18px 20px',
    }}>
      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#555555', letterSpacing: '0.18em', marginBottom: 6, textTransform: 'uppercase' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 28, color, letterSpacing: 1 }}>
        {value}
      </div>
    </div>
  );
}
