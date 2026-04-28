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
      background: 'rgba(2,7,12,0.85)', backdropFilter: 'blur(6px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.3)',
        borderRadius: 12, padding: '32px 36px', maxWidth: 560, width: '90%',
        position: 'relative',
      }}>
        {/* Corner marks */}
        <div style={{ position: 'absolute', top: -1, left: -1, width: 16, height: 16, borderTop: '2px solid rgba(255,255,255,0.5)', borderLeft: '2px solid rgba(255,255,255,0.5)', borderRadius: '2px 0 0 0' }} />
        <div style={{ position: 'absolute', top: -1, right: -1, width: 16, height: 16, borderTop: '2px solid rgba(255,255,255,0.5)', borderRight: '2px solid rgba(255,255,255,0.5)', borderRadius: '0 2px 0 0' }} />
        <div style={{ position: 'absolute', bottom: -1, left: -1, width: 16, height: 16, borderBottom: '2px solid rgba(255,255,255,0.5)', borderLeft: '2px solid rgba(255,255,255,0.5)', borderRadius: '0 0 0 2px' }} />
        <div style={{ position: 'absolute', bottom: -1, right: -1, width: 16, height: 16, borderBottom: '2px solid rgba(255,255,255,0.5)', borderRight: '2px solid rgba(255,255,255,0.5)', borderRadius: '0 0 2px 0' }} />

        <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 16, color: '#ffffff', marginBottom: 8 }}>
          API KEY GENERATED
        </div>

        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#e53e3e',
          marginBottom: 20, padding: '8px 12px',
          background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)',
          borderRadius: 6, letterSpacing: '0.04em',
        }}>
          WARNING: This key will only be shown once. Copy it now.
        </div>

        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 13, color: '#e8f4f8',
          background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.15)',
          borderRadius: 6, padding: '14px 16px', wordBreak: 'break-all',
          marginBottom: 20, letterSpacing: '0.02em',
        }}>
          {fullKey}
        </div>

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={handleCopy} style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
            padding: '10px 24px', borderRadius: 6, border: 'none', cursor: 'pointer',
            background: copied ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.12)',
            color: '#ffffff', letterSpacing: '0.08em', textTransform: 'uppercase',
            transition: 'all 0.2s',
          }}>
            {copied ? 'COPIED' : 'COPY KEY'}
          </button>
          <button onClick={onClose} style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
            padding: '10px 24px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)',
            cursor: 'pointer', background: 'transparent', color: '#a0a0a0',
            letterSpacing: '0.08em', textTransform: 'uppercase', transition: 'all 0.2s',
          }}>
            CLOSE
          </button>
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ active }) {
  const color = active ? '#ffffff' : '#e53e3e';
  const label = active ? 'ACTIVE' : 'REVOKED';
  return (
    <span style={{
      fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, padding: '3px 10px',
      borderRadius: 4, background: `${color}15`, border: `1px solid ${color}35`,
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
            <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#ffffff', textShadow: '0 0 24px rgba(255,255,255,0.35)', letterSpacing: 2 }}>
              API KEY MANAGEMENT
            </div>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
              Generate and manage API access credentials
            </div>
            <div style={{
              marginTop: 12, padding: '8px 12px', display: 'inline-flex', alignItems: 'center', gap: 10,
              background: 'rgba(72,187,120,0.06)', border: '1px solid rgba(72,187,120,0.25)', borderRadius: 6,
            }}>
              <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#48bb78', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                Endpoint
              </span>
              <code style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#ffffff', letterSpacing: '0.02em' }}>
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
              style={{
                fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
                padding: '10px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
                background: 'rgba(255,255,255,0.12)', color: '#ffffff',
                letterSpacing: '0.08em', textTransform: 'uppercase', transition: 'all 0.2s',
                outline: '1px solid rgba(255,255,255,0.3)',
              }}
            >
              {generating ? 'GENERATING...' : showNameInput ? 'CONFIRM' : '+ GENERATE NEW KEY'}
            </button>
            {showNameInput && (
              <button
                onClick={() => { setShowNameInput(false); setNewKeyName(''); }}
                style={{
                  fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
                  padding: '10px 16px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)',
                  cursor: 'pointer', background: 'transparent', color: '#a0a0a0',
                  letterSpacing: '0.08em', textTransform: 'uppercase',
                }}
              >
                CANCEL
              </button>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#e53e3e',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)',
          borderRadius: 6, display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span style={{ fontSize: 14 }}>&#9888;</span> {error}
        </div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading API keys...</div></div>
      ) : keys.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#555555' }}>
          <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.4 }}>&#128273;</div>
          NO API KEYS FOUND \u2014 GENERATE ONE TO GET STARTED
        </div>
      ) : (
        <div style={{ background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                {['KEY PREFIX', 'NAME', 'CREATED', 'LAST USED', 'STATUS', 'ACTIONS'].map(h => <th key={h}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id || k.prefix}>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#ffffff', letterSpacing: '0.03em' }}>
                    {k.prefix || k.key_prefix || '\u2014'}
                  </td>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#e8f4f8' }}>
                    {k.name || '\u2014'}
                  </td>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#a0a0a0' }}>
                    {formatDate(k.created_at)}
                  </td>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#555555' }}>
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
                          fontFamily: 'IBM Plex Mono, monospace', fontSize: 10,
                          padding: '5px 14px', borderRadius: 4, border: '1px solid rgba(229,62,62,0.3)',
                          cursor: 'pointer', background: 'rgba(229,62,62,0.08)', color: '#e53e3e',
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
        marginTop: 16, fontFamily: 'IBM Plex Mono, monospace', fontSize: 10,
        color: '#555555', letterSpacing: '0.06em',
      }}>
        {keys.filter(k => k.is_active !== false).length} active key{keys.filter(k => k.is_active !== false).length !== 1 ? 's' : ''} / {keys.length} total
      </div>

      {/* Key reveal modal */}
      {revealKey && <KeyRevealModal fullKey={revealKey} onClose={() => setRevealKey(null)} />}
    </div>
  );
}
