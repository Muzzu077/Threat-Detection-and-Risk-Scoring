import { useEffect, useState } from 'react';
import { fetchApiKeys, createApiKey, revokeApiKey, apiBase } from '../api/client';

const INGEST_ORIGIN =
  apiBase ||
  (typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.host}` : 'http://localhost:8000');

function formatDate(dateStr) {
  if (!dateStr) return '\u2014';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) +
    ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
}

function KeyRevealModal({ fullKey, onClose }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(fullKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = fullKey;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(200,200,205,0.7)', backdropFilter: 'blur(12px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg-glass-heavy)', backdropFilter: 'blur(24px)', border: '1px solid var(--border-light)',
        borderRadius: 'var(--radius-xl)', padding: '32px 36px', maxWidth: 560, width: '90%',
        position: 'relative', boxShadow: 'var(--shadow-xl)'
      }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, color: 'var(--text-primary)', marginBottom: 8, letterSpacing: -0.5 }}>
          API KEY GENERATED
        </div>

        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-red)',
          marginBottom: 20, padding: '8px 12px',
          background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)',
          borderRadius: 'var(--radius-sm)', letterSpacing: '0.04em',
        }}>
          WARNING: This key will only be shown once. Copy it now.
        </div>

        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)',
          background: 'var(--bg-card)', border: '1px solid var(--border-light)',
          borderRadius: 'var(--radius-sm)', padding: '14px 16px', wordBreak: 'break-all',
          marginBottom: 20, letterSpacing: '0.02em',
        }}>
          {fullKey}
        </div>

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={handleCopy} className="btn btn-primary">
            {copied ? 'COPIED' : 'COPY KEY'}
          </button>
          <button onClick={onClose} className="btn btn-ghost">
            CLOSE
          </button>
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ active }) {
  const color = active ? 'var(--accent-green)' : 'var(--text-muted)';
  const bg = active ? 'rgba(5,150,105,0.08)' : 'rgba(161,161,170,0.08)';
  const border = active ? 'rgba(5,150,105,0.22)' : 'rgba(161,161,170,0.22)';
  const label = active ? 'ACTIVE' : 'REVOKED';
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 10, padding: '3px 10px',
      borderRadius: 'var(--radius-sm)', background: bg, border: `1px solid ${border}`,
      color, letterSpacing: '0.08em', textTransform: 'uppercase',
    }}>
      {label}
    </span>
  );
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [revealKey, setRevealKey] = useState(null);
  const [newKeyName, setNewKeyName] = useState('');
  const [showNameInput, setShowNameInput] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    try {
      const data = await fetchApiKeys();
      setKeys(data.data || data.keys || data || []);
    } catch {
      setError('FAILED TO LOAD API KEYS');
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    setError('');
    try {
      const data = await createApiKey(newKeyName || 'Untitled Key');
      setRevealKey(data.key || data.api_key || data.full_key);
      setShowNameInput(false);
      setNewKeyName('');
      load();
    } catch (err) {
      setError(err.response?.data?.detail || 'FAILED TO GENERATE KEY');
    }
    setGenerating(false);
  };

  const handleRevoke = async (keyId) => {
    try {
      await revokeApiKey(keyId);
      load();
    } catch {
      setError('FAILED TO REVOKE KEY');
    }
  };

  return (
    <div className="page-enter">
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
              API KEY MANAGEMENT
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
              Generate and manage API access credentials
            </div>
            <div style={{
              marginTop: 12, padding: '8px 12px', display: 'inline-flex', alignItems: 'center', gap: 10,
              background: 'rgba(74,93,79,0.08)', border: '1px solid rgba(74,93,79,0.22)', borderRadius: 'var(--radius-sm)',
            }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                Endpoint
              </span>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', letterSpacing: '0.02em' }}>
                {INGEST_ORIGIN}
              </code>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {showNameInput && (
              <input
                className="input"
                placeholder="Key name..."
                value={newKeyName}
                onChange={e => setNewKeyName(e.target.value)}
                style={{ width: 200, fontSize: 12 }}
                autoFocus
                onKeyDown={e => { if (e.key === 'Enter') handleGenerate(); }}
              />
            )}
            <button
              onClick={() => showNameInput ? handleGenerate() : setShowNameInput(true)}
              disabled={generating}
              className="btn btn-primary"
            >
              {generating ? 'GENERATING...' : showNameInput ? 'CONFIRM' : '+ GENERATE NEW KEY'}
            </button>
            {showNameInput && (
              <button
                onClick={() => { setShowNameInput(false); setNewKeyName(''); }}
                className="btn btn-ghost"
              >
                CANCEL
              </button>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent-red)',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)',
          borderRadius: 'var(--radius-sm)', display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span style={{ fontSize: 14 }}>&#9888;</span> {error}
        </div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading API keys...</div></div>
      ) : keys.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>
          <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.4 }}>&#128273;</div>
          NO API KEYS FOUND \u2014 GENERATE ONE TO GET STARTED
        </div>
      ) : (
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
          <table className="data-table">
            <thead>
              <tr>
                {['KEY PREFIX', 'NAME', 'CREATED', 'LAST USED', 'STATUS', 'ACTIONS'].map(h => <th key={h}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id || k.prefix}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', letterSpacing: '0.03em' }}>
                    {k.prefix || k.key_prefix || '\u2014'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                    {k.name || '\u2014'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
                    {formatDate(k.created_at)}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
                    {k.last_used_at ? formatDate(k.last_used_at) : 'Never'}
                  </td>
                  <td>
                    <StatusBadge active={k.is_active !== false} />
                  </td>
                  <td>
                    {k.is_active !== false && (
                      <button
                        onClick={() => handleRevoke(k.id)}
                        style={{
                          fontFamily: 'var(--font-mono)', fontSize: 10,
                          padding: '5px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(185,28,28,0.22)',
                          cursor: 'pointer', background: 'rgba(185,28,28,0.08)', color: 'var(--accent-red)',
                          letterSpacing: '0.06em', textTransform: 'uppercase', transition: 'all 0.2s',
                        }}
                      >
                        REVOKE
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Key count footer */}
      <div style={{
        marginTop: 16, fontFamily: 'var(--font-mono)', fontSize: 10,
        color: 'var(--text-muted)', letterSpacing: '0.06em',
      }}>
        {keys.filter(k => k.is_active !== false).length} active key{keys.filter(k => k.is_active !== false).length !== 1 ? 's' : ''} / {keys.length} total
      </div>

      {/* Key reveal modal */}
      {revealKey && <KeyRevealModal fullKey={revealKey} onClose={() => setRevealKey(null)} />}
    </div>
  );
}
