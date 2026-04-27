import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authLogin } from '../api/client';

export default function LoginPage({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [shake, setShake] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const data = await authLogin(email, password);
      localStorage.setItem('tp_tokens', JSON.stringify({
        access_token: data.access_token,
        refresh_token: data.refresh_token,
      }));
      localStorage.setItem('tp_user', JSON.stringify(data.user));
      onLogin(data.user);
    } catch (err) {
      const msg = err.response?.data?.detail || 'Authentication failed';
      setError(`ACCESS DENIED \u2014 ${msg.toUpperCase()}`);
      setShake(true);
      setTimeout(() => setShake(false), 600);
    }
    setLoading(false);
  };

  return (
    <div className="login-page" style={{ overflow: 'hidden' }}>
      <div className="login-bg-grid" />

      <div className="login-box" style={{
        position: 'relative', zIndex: 10,
        animation: shake ? 'shake 0.5s ease' : undefined,
      }}>
        <div style={{ position: 'absolute', top: -1, left: -1, width: 20, height: 20, borderTop: '2px solid rgba(255,255,255,0.5)', borderLeft: '2px solid rgba(255,255,255,0.5)', borderRadius: '2px 0 0 0' }} />
        <div style={{ position: 'absolute', top: -1, right: -1, width: 20, height: 20, borderTop: '2px solid rgba(255,255,255,0.5)', borderRight: '2px solid rgba(255,255,255,0.5)', borderRadius: '0 2px 0 0' }} />
        <div style={{ position: 'absolute', bottom: -1, left: -1, width: 20, height: 20, borderBottom: '2px solid rgba(255,255,255,0.5)', borderLeft: '2px solid rgba(255,255,255,0.5)', borderRadius: '0 0 0 2px' }} />
        <div style={{ position: 'absolute', bottom: -1, right: -1, width: 20, height: 20, borderBottom: '2px solid rgba(255,255,255,0.5)', borderRight: '2px solid rgba(255,255,255,0.5)', borderRadius: '0 0 2px 0' }} />

        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: 24, lineHeight: 1.4, textAlign: 'center' }}>
          {'// AUTONOMOUS CYBER DEFENSE SYSTEM'}
        </div>

        <div className="login-header">
          <div style={{ fontSize: 40, marginBottom: 12, filter: 'drop-shadow(0 0 12px rgba(255,255,255,0.3))' }}>&#128737;</div>
          <div className="login-title" style={{ fontSize: 28 }}>TRUSTFLOW</div>
          <div className="login-subtitle">
            <span>Security Operations Center</span>
          </div>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input className="input" type="email" placeholder="operator@example.com" value={email}
              onChange={e => setEmail(e.target.value)} autoComplete="email" required />
          </div>

          <div className="form-group">
            <label className="form-label">Access Key</label>
            <input className="input" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
              value={password} onChange={e => setPassword(e.target.value)}
              autoComplete="current-password" required />
          </div>

          {error && (
            <div className="login-error" style={{
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <span style={{ fontSize: 14 }}>&#9888;</span> {error}
            </div>
          )}

          <button className="login-btn" type="submit" disabled={loading} style={{
            position: 'relative', overflow: 'hidden',
          }}>
            {loading ? (
              <span style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
                <span className="spinner" style={{ width: 14, height: 14, borderWidth: 1.5 }} />
                AUTHENTICATING...
              </span>
            ) : 'AUTHENTICATE \u2192'}
          </button>
        </form>

        <div style={{ marginTop: 24, textAlign: 'center' }}>
          <button
            onClick={() => navigate('/register')}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10, color: '#ffffff',
              letterSpacing: '0.08em', textDecoration: 'underline',
              textUnderlineOffset: 3,
            }}
          >
            CREATE NEW ACCOUNT
          </button>
          <div style={{ marginTop: 8, fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--border-bright)', letterSpacing: 2 }}>
            ALL ACTIVITIES ARE MONITORED AND LOGGED
          </div>
        </div>
      </div>
    </div>
  );
}
