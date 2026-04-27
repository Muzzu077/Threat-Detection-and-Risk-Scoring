import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';

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
      setError('ACCESS DENIED \u2014 PASSWORDS DO NOT MATCH');
      setShake(true);
      setTimeout(() => setShake(false), 600);
      return;
    }

    if (password.length < 6) {
      setError('ACCESS DENIED \u2014 PASSWORD MUST BE AT LEAST 6 CHARACTERS');
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
      const msg = err.response?.data?.detail || err.response?.data?.message || 'REGISTRATION FAILED \u2014 TRY AGAIN';
      setError(typeof msg === 'string' ? msg.toUpperCase() : 'REGISTRATION FAILED');
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
          {'// OPERATOR ENROLLMENT SYSTEM'}
        </div>

        <div className="login-header">
          <div style={{ fontSize: 40, marginBottom: 12, filter: 'drop-shadow(0 0 12px rgba(255,255,255,0.3))' }}>&#128737;</div>
          <div className="login-title" style={{ fontSize: 28 }}>THREATPULSE</div>
          <div className="login-subtitle">
            <span>New Operator Registration</span>
          </div>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">EMAIL</label>
            <input className="input" type="email" placeholder="operator@threatpulse.io"
              value={email} onChange={e => setEmail(e.target.value)}
              autoComplete="email" required />
          </div>

          <div className="form-group">
            <label className="form-label">DISPLAY NAME</label>
            <input className="input" type="text" placeholder="Agent Callsign"
              value={displayName} onChange={e => setDisplayName(e.target.value)}
              autoComplete="name" required />
          </div>

          <div className="form-group">
            <label className="form-label">PASSWORD</label>
            <input className="input" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
              value={password} onChange={e => setPassword(e.target.value)}
              autoComplete="new-password" required />
          </div>

          <div className="form-group">
            <label className="form-label">CONFIRM PASSWORD</label>
            <input className="input" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
              value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
              autoComplete="new-password" required />
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
                CREATING ACCOUNT...
              </span>
            ) : 'CREATE ACCOUNT \u2192'}
          </button>
        </form>

        <div style={{ marginTop: 24, textAlign: 'center' }}>
          <span
            onClick={() => navigate('/login')}
            style={{
              fontFamily: 'var(--font-mono)', fontSize: 11, color: '#ffffff',
              cursor: 'pointer', letterSpacing: '0.05em',
              borderBottom: '1px solid rgba(255,255,255,0.3)', paddingBottom: 2,
            }}
          >
            Already have an account? Login
          </span>
        </div>

        <div style={{ marginTop: 16, fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--border-bright)', letterSpacing: 2, textAlign: 'center' }}>
          ALL ACTIVITIES ARE MONITORED AND LOGGED
        </div>
      </div>
    </div>
  );
}
