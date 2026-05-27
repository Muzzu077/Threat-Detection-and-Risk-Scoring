import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { authLogin } from '../api/client';
import DecryptedText from '../components/ReactBits/DecryptedText';

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
      setError(msg);
      setShake(true);
      setTimeout(() => setShake(false), 600);
    }
    setLoading(false);
  };

  return (
    <div className="login-page">
      <div className="login-bg-grid" />

      <div className="login-box" style={{
        position: 'relative', zIndex: 10,
        animation: shake ? 'shake 0.5s ease' : undefined,
      }}>
        <div className="login-header">
          <div style={{
            width: 56, height: 56, borderRadius: 14,
            background: 'var(--accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 20px',
            boxShadow: 'var(--shadow-glow)'
          }}>
            <Shield size={26} color="#fff" />
          </div>
          <div className="login-title">
            <DecryptedText text="TrustFlow" animateOn="view" speed={50} maxIterations={6} />
          </div>
          <div className="login-subtitle">
            Security Operations Center
          </div>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email" className="form-label">Email</label>
            <input id="email" className="input" type="email" placeholder="operator@company.com" value={email}
              onChange={e => setEmail(e.target.value)} autoComplete="email" required />
          </div>

          <div className="form-group">
            <label htmlFor="access-key" className="form-label">Access Key</label>
            <input id="access-key" className="input" type="password" placeholder="••••••••••"
              value={password} onChange={e => setPassword(e.target.value)}
              autoComplete="current-password" required />
          </div>

          {error && (
            <div className="login-error">
              ⚠ {error}
            </div>
          )}

          <button className="login-btn" type="submit" disabled={loading}>
            {loading ? (
              <span style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
                <span className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
                Authenticating...
              </span>
            ) : 'Sign In →'}
          </button>
        </form>

        <div style={{ marginTop: 28, textAlign: 'center' }}>
          <button
            onClick={() => navigate('/register')}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              fontFamily: 'var(--font-body)', fontSize: '0.82rem', fontWeight: 500,
              color: 'var(--accent)',
              textDecoration: 'underline', textUnderlineOffset: 3,
            }}
          >
            Create New Account
          </button>
          <div style={{
            marginTop: 10, fontFamily: 'var(--font-mono)', fontSize: '0.58rem',
            color: 'var(--text-faint)', letterSpacing: '0.1em', fontWeight: 500,
          }}>
            ALL ACTIVITIES ARE MONITORED AND LOGGED
          </div>
        </div>
      </div>
    </div>
  );
}
