import { useState, useEffect, useRef } from 'react';

const CREDENTIALS = { admin: 'threatpulse', analyst: 'soc2024' };

// Matrix rain canvas component
function MatrixRain() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = 'THREATPULSE01アイウエオカキクケコサシスセソ█▓░▒'.split('');
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

// Floating threat card
function FloatingThreat({ label, value, color, delay, position }) {
  return (
    <div style={{
      position: 'absolute', ...position,
      background: 'rgba(8,18,24,0.6)', backdropFilter: 'blur(8px)',
      border: `1px solid ${color}25`, borderRadius: 8,
      padding: '10px 14px', fontFamily: 'IBM Plex Mono, monospace',
      animation: `fadeIn 0.6s ease ${delay}s both`,
      pointerEvents: 'none',
    }}>
      <div style={{ fontSize: 8, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 16, color, fontFamily: 'Syne Mono, monospace' }}>{value}</div>
    </div>
  );
}

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [booting, setBooting] = useState(true);
  const [bootLines, setBootLines] = useState([]);
  const [shake, setShake] = useState(false);

  const BOOT_SEQUENCE = [
    '[SYS] Initializing ThreatPulse Core...',
    '[NET] Establishing secure channel... OK',
    '[ML]  Loading threat detection model... OK',
    '[DB]  Connecting to event database... OK',
    '[SOC] Security Operations Center online',
    '[AUTH] Awaiting operator authentication...',
  ];

  useEffect(() => {
    let i = 0;
    const timer = setInterval(() => {
      if (i < BOOT_SEQUENCE.length) {
        setBootLines(prev => [...prev, BOOT_SEQUENCE[i]]);
        i++;
      } else {
        clearInterval(timer);
        setTimeout(() => setBooting(false), 400);
      }
    }, 250);
    return () => clearInterval(timer);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    await new Promise(r => setTimeout(r, 600));

    if (CREDENTIALS[username.toLowerCase()] === password) {
      localStorage.setItem('tp_auth', JSON.stringify({ user: username, ts: Date.now() }));
      onLogin(username);
    } else {
      setError('ACCESS DENIED \u2014 INVALID CREDENTIALS');
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

      {/* Floating threat indicators */}
      <FloatingThreat label="Active Threats" value="0" color="#f03250" delay={1.5} position={{ top: '18%', left: '12%' }} />
      <FloatingThreat label="ML Model" value="READY" color="#00e5b0" delay={1.8} position={{ top: '25%', right: '14%' }} />
      <FloatingThreat label="Events/24h" value="--" color="#4a9eff" delay={2.1} position={{ bottom: '28%', left: '10%' }} />
      <FloatingThreat label="OSINT Feeds" value="3" color="#a855f7" delay={2.4} position={{ bottom: '22%', right: '12%' }} />

      {/* Boot Sequence */}
      {booting ? (
        <div style={{
          position: 'relative', zIndex: 10, width: '100%', maxWidth: 500,
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#00e5b0',
          padding: 40, lineHeight: 2.2,
        }}>
          {bootLines.map((line, i) => (
            <div key={i} style={{ animation: `fadeIn 0.2s ease ${i * 0.05}s both`, opacity: 0 }}>
              <span style={{ color: line.includes('OK') ? '#00e5b0' : line.includes('AUTH') ? '#ffb800' : '#2e5570' }}>
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
            {'// AUTONOMOUS CYBER DEFENSE SYSTEM'}
          </div>

          <div className="login-header">
            <div style={{ fontSize: 40, marginBottom: 12, filter: 'drop-shadow(0 0 12px rgba(0,229,176,0.3))' }}>&#128737;</div>
            <div className="login-title glitch-text" style={{ fontSize: 28 }}>THREATPULSE</div>
            <div className="login-subtitle">
              <span className="typing-cursor">Security Operations Center</span>
            </div>
          </div>

          <form className="login-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Operator ID</label>
              <input className="input" type="text" placeholder="admin" value={username}
                onChange={e => setUsername(e.target.value)} autoComplete="username" required />
            </div>

            <div className="form-group">
              <label className="form-label">Access Key</label>
              <input className="input" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
                value={password} onChange={e => setPassword(e.target.value)}
                autoComplete="current-password" required />
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
                  AUTHENTICATING...
                </span>
              ) : 'AUTHENTICATE \u2192'}
            </button>
          </form>

          <div style={{ marginTop: 24, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', textAlign: 'center', letterSpacing: '0.08em' }}>
            <div style={{ padding: '8px 0', background: 'rgba(0,229,176,0.03)', borderRadius: 4, border: '1px solid rgba(0,229,176,0.08)' }}>
              DEFAULT: admin / threatpulse
            </div>
            <div style={{ marginTop: 8, color: 'var(--border-bright)', fontSize: 8, letterSpacing: 2 }}>
              ALL ACTIVITIES ARE MONITORED AND LOGGED
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
