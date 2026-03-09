import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const CREDENTIALS = { admin: 'threatpulse', analyst: 'soc2024' };

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    await new Promise(r => setTimeout(r, 600));

    if (CREDENTIALS[username.toLowerCase()] === password) {
      localStorage.setItem('tp_auth', JSON.stringify({ user: username, ts: Date.now() }));
      onLogin(username);
    } else {
      setError('ACCESS DENIED — INVALID CREDENTIALS');
    }
    setLoading(false);
  };

  return (
    <div className="login-page">
      <div className="login-bg-grid" />

      {/* Ambient glow effects */}
      <div style={{
        position: 'absolute', top: '20%', left: '15%',
        width: 300, height: 300,
        background: 'radial-gradient(circle, rgba(0,255,200,0.06) 0%, transparent 70%)',
        borderRadius: '50%', pointerEvents: 'none'
      }} />
      <div style={{
        position: 'absolute', bottom: '20%', right: '15%',
        width: 400, height: 400,
        background: 'radial-gradient(circle, rgba(255,45,45,0.04) 0%, transparent 70%)',
        borderRadius: '50%', pointerEvents: 'none'
      }} />

      <div className="login-box fade-in">
        {/* ASCII-style header */}
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)',
          letterSpacing: '0.1em', marginBottom: 24, lineHeight: 1.4, textAlign: 'center'
        }}>
          {'// AUTONOMOUS CYBER DEFENSE SYSTEM'}
        </div>

        <div className="login-header">
          <div style={{ fontSize: 36, marginBottom: 8 }}>🛡</div>
          <div className="login-title">THREATPULSE</div>
          <div className="login-subtitle">Security Operations Center</div>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Operator ID</label>
            <input
              className="input"
              type="text"
              placeholder="admin"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Access Key</label>
            <input
              className="input"
              type="password"
              placeholder="••••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          {error && <div className="login-error">{error}</div>}

          <button className="login-btn" type="submit" disabled={loading}>
            {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE →'}
          </button>
        </form>

        <div style={{
          marginTop: 24, fontFamily: 'var(--font-mono)', fontSize: 9,
          color: 'var(--text-muted)', textAlign: 'center', letterSpacing: '0.08em'
        }}>
          <div>DEFAULT: admin / threatpulse</div>
          <div style={{ marginTop: 4, color: 'var(--border-bright)' }}>
            ALL ACTIVITIES ARE MONITORED AND LOGGED
          </div>
        </div>
      </div>
    </div>
  );
}
