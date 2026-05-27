import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { api } from '../api/client';
import DecryptedText from '../components/ReactBits/DecryptedText';

export default function RegisterPage({ onRegister }) {
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [shake, setShake] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      setShake(true);
      setTimeout(() => setShake(false), 600);
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      setShake(true);
      setTimeout(() => setShake(false), 600);
      return;
    }

    setLoading(true);
    try {
      const res = await api.post('/auth/register', {
        email,
        password,
        display_name: displayName,
      });

      const { access_token, refresh_token, user } = res.data;

      localStorage.setItem('tp_tokens', JSON.stringify({ access_token, refresh_token }));
      localStorage.setItem('tp_user', JSON.stringify(user));

      if (onRegister) onRegister(user);
    } catch (err) {
      const msg = err.response?.data?.detail || err.response?.data?.message || 'Registration failed — try again';
      setError(typeof msg === 'string' ? msg : 'Registration failed');
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
            New Operator Registration
          </div>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email" className="form-label">Email</label>
            <input id="email" className="input" type="email" placeholder="operator@company.com"
              value={email} onChange={e => setEmail(e.target.value)}
              autoComplete="email" required />
          </div>

          <div className="form-group">
            <label htmlFor="display-name" className="form-label">Display Name</label>
            <input id="display-name" className="input" type="text" placeholder="Your display name"
              value={displayName} onChange={e => setDisplayName(e.target.value)}
              autoComplete="name" required />
          </div>

          <div className="form-group">
            <label htmlFor="password" className="form-label">Password</label>
            <input id="password" className="input" type="password" placeholder="••••••••••"
              value={password} onChange={e => setPassword(e.target.value)}
              autoComplete="new-password" required />
          </div>

          <div className="form-group">
            <label htmlFor="confirm-password" className="form-label">Confirm Password</label>
            <input id="confirm-password" className="input" type="password" placeholder="••••••••••"
              value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
              autoComplete="new-password" required />
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
                Creating Account...
              </span>
            ) : 'Create Account →'}
          </button>
        </form>

        <div style={{ marginTop: 28, textAlign: 'center' }}>
          <button
            onClick={() => navigate('/login')}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              fontFamily: 'var(--font-body)', fontSize: '0.82rem', fontWeight: 500,
              color: 'var(--accent)',
              textDecoration: 'underline', textUnderlineOffset: 3,
            }}
          >
            Already have an account? Sign In
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
