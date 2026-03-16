import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';

const BOOT_SEQUENCE = [
  '[SYS] Initializing ThreatPulse Core...',
  '[NET] Establishing secure channel... OK',
  '[REG] Preparing operator enrollment module...',
  '[DB]  Validating identity store... OK',
  '[AUTH] Ready for new operator registration...',
];

// Matrix rain canvas component
function MatrixRain() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = 'THREATPULSE01\u30A2\u30A4\u30A6\u30A8\u30AA\u30AB\u30AD\u30AF\u30B1\u30B3\u30B5\u30B7\u30B9\u30BB\u30BD\u2588\u2593\u2591\u2592'.split('');
    const fontSize = 12;
    const cols = Math.floor(canvas.width / fontSize);
    const drops = Array(cols).fill(1);

    const draw = () => {
      ctx.fillStyle = 'rgba(2, 7, 12, 0.06)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = 'rgba(0, 229, 176, 0.15)';
      ctx.font = `${fontSize}px monospace`;

      for (let i = 0; i < drops.length; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillText(char, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    };

    const interval = setInterval(draw, 45);
    const handleResize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    window.addEventListener('resize', handleResize);
    return () => { clearInterval(interval); window.removeEventListener('resize', handleResize); };
  }, []);

  return <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, zIndex: 0, opacity: 0.7 }} />;
}

export default function RegisterPage({ onRegister }) {
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [booting, setBooting] = useState(true);
  const [bootLines, setBootLines] = useState([]);
  const [shake, setShake] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    let i = 0;
    const timer = setInterval(() => {
      if (i < BOOT_SEQUENCE.length) {
        const line = BOOT_SEQUENCE[i];
        i++;
        setBootLines(prev => [...prev, line]);
      } else {
        clearInterval(timer);
        setTimeout(() => setBooting(false), 400);
      }
    }, 250);
    return () => clearInterval(timer);
  }, []);

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
      <MatrixRain />
      <div className="login-bg-grid" />

      {/* Ambient glows */}
      <div style={{ position: 'absolute', top: '15%', left: '10%', width: 350, height: 350, background: 'radial-gradient(circle, rgba(0,229,176,0.08) 0%, transparent 70%)', borderRadius: '50%', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', bottom: '15%', right: '10%', width: 400, height: 400, background: 'radial-gradient(circle, rgba(240,50,80,0.05) 0%, transparent 70%)', borderRadius: '50%', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: 600, height: 600, background: 'radial-gradient(circle, rgba(74,158,255,0.04) 0%, transparent 70%)', borderRadius: '50%', pointerEvents: 'none' }} />

      {/* Boot Sequence */}
      {booting ? (
        <div style={{
          position: 'relative', zIndex: 10, width: '100%', maxWidth: 500,
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#00e5b0',
          padding: 40, lineHeight: 2.2,
        }}>
          {bootLines.map((line, i) => (
            <div key={i} style={{ animation: `fadeIn 0.2s ease ${i * 0.05}s both`, opacity: 0 }}>
              <span style={{ color: (line || '').includes('OK') ? '#00e5b0' : (line || '').includes('AUTH') ? '#ffb800' : '#2e5570' }}>
                {line}
              </span>
            </div>
          ))}
          <div className="typing-cursor" style={{ display: 'inline-block', marginTop: 8, color: '#2e5570' }}>_</div>
        </div>
      ) : (
        <div className="login-box page-enter" style={{
          position: 'relative', zIndex: 10,
          animation: shake ? 'shake 0.5s ease' : undefined,
        }}>
          {/* Decorative corner marks */}
          <div style={{ position: 'absolute', top: -1, left: -1, width: 20, height: 20, borderTop: '2px solid rgba(0,229,176,0.5)', borderLeft: '2px solid rgba(0,229,176,0.5)', borderRadius: '2px 0 0 0' }} />
          <div style={{ position: 'absolute', top: -1, right: -1, width: 20, height: 20, borderTop: '2px solid rgba(0,229,176,0.5)', borderRight: '2px solid rgba(0,229,176,0.5)', borderRadius: '0 2px 0 0' }} />
          <div style={{ position: 'absolute', bottom: -1, left: -1, width: 20, height: 20, borderBottom: '2px solid rgba(0,229,176,0.5)', borderLeft: '2px solid rgba(0,229,176,0.5)', borderRadius: '0 0 0 2px' }} />
          <div style={{ position: 'absolute', bottom: -1, right: -1, width: 20, height: 20, borderBottom: '2px solid rgba(0,229,176,0.5)', borderRight: '2px solid rgba(0,229,176,0.5)', borderRadius: '0 0 2px 0' }} />

          {/* Header */}
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: 24, lineHeight: 1.4, textAlign: 'center' }}>
            {'// OPERATOR ENROLLMENT SYSTEM'}
          </div>

          <div className="login-header">
            <div style={{ fontSize: 40, marginBottom: 12, filter: 'drop-shadow(0 0 12px rgba(0,229,176,0.3))' }}>&#128737;</div>
            <div className="login-title glitch-text" style={{ fontSize: 28 }}>THREATPULSE</div>
            <div className="login-subtitle">
              <span className="typing-cursor">New Operator Registration</span>
            </div>
          </div>

          <form className="login-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">EMAIL</label>
              <input
                className="input"
                type="email"
                placeholder="operator@threatpulse.io"
                value={email}
                onChange={e => setEmail(e.target.value)}
                autoComplete="email"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">DISPLAY NAME</label>
              <input
                className="input"
                type="text"
                placeholder="Agent Callsign"
                value={displayName}
                onChange={e => setDisplayName(e.target.value)}
                autoComplete="name"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">PASSWORD</label>
              <input
                className="input"
                type="password"
                placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">CONFIRM PASSWORD</label>
              <input
                className="input"
                type="password"
                placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
            </div>

            {error && (
              <div className="login-error" style={{
                animation: 'fadeIn 0.3s ease',
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
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                color: '#00e5b0',
                cursor: 'pointer',
                letterSpacing: '0.05em',
                borderBottom: '1px solid rgba(0,229,176,0.3)',
                paddingBottom: 2,
                transition: 'color 0.2s',
              }}
            >
              Already have an account? Login
            </span>
          </div>

          <div style={{ marginTop: 16, fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--border-bright)', letterSpacing: 2, textAlign: 'center' }}>
            ALL ACTIVITIES ARE MONITORED AND LOGGED
          </div>
        </div>
      )}
    </div>
  );
}
