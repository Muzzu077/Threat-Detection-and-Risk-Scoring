import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

/* ─── Animated Grid Background ──────────────────────────────────────────── */
function HexGrid() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const c = canvasRef.current, ctx = c.getContext('2d');
    let w, h, cols, rows, frame = 0, pulses = [];
    const HEX = 28, GAP = 4;
    const resize = () => { w = c.width = window.innerWidth; h = c.height = window.innerHeight; cols = Math.ceil(w / (HEX * 1.75)) + 2; rows = Math.ceil(h / (HEX * 1.55)) + 2; };
    resize();
    window.addEventListener('resize', resize);
    const drawHex = (x, y, r, alpha) => {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) { const a = (Math.PI / 3) * i - Math.PI / 6; ctx.lineTo(x + r * Math.cos(a), y + r * Math.sin(a)); }
      ctx.closePath(); ctx.strokeStyle = `rgba(255,255,255,${alpha})`; ctx.lineWidth = 0.5; ctx.stroke();
    };
    const animate = () => {
      frame++;
      ctx.fillStyle = 'rgba(2,7,12,0.15)';
      ctx.fillRect(0, 0, w, h);
      if (frame % 90 === 0) pulses.push({ cx: Math.random() * w, cy: Math.random() * h, r: 0, maxR: 200 + Math.random() * 300 });
      pulses = pulses.filter(p => p.r < p.maxR);
      pulses.forEach(p => p.r += 2.5);
      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          const x = col * HEX * 1.75 + (row % 2) * HEX * 0.875;
          const y = row * HEX * 1.55;
          let alpha = 0.03;
          for (const p of pulses) { const d = Math.hypot(x - p.cx, y - p.cy); if (Math.abs(d - p.r) < 40) alpha = Math.max(alpha, 0.18 * (1 - Math.abs(d - p.r) / 40)); }
          drawHex(x, y, HEX / 2 - GAP / 2, alpha);
        }
      }
      requestAnimationFrame(animate);
    };
    const id = requestAnimationFrame(animate);
    return () => { cancelAnimationFrame(id); window.removeEventListener('resize', resize); };
  }, []);
  return <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, zIndex: 0 }} />;
}

/* ─── Floating Orbs ─────────────────────────────────────────────────────── */
function Orbs() {
  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', top: '-10%', left: '-5%', width: 700, height: 700, borderRadius: '50%', background: 'radial-gradient(circle, rgba(255,255,255,0.07) 0%, transparent 70%)', animation: 'orbFloat1 25s ease-in-out infinite' }} />
      <div style={{ position: 'absolute', bottom: '-15%', right: '-10%', width: 900, height: 900, borderRadius: '50%', background: 'radial-gradient(circle, rgba(61,142,240,0.05) 0%, transparent 70%)', animation: 'orbFloat2 30s ease-in-out infinite' }} />
      <div style={{ position: 'absolute', top: '40%', left: '60%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, rgba(229,62,62,0.04) 0%, transparent 70%)', animation: 'orbFloat3 20s ease-in-out infinite' }} />
    </div>
  );
}

/* ─── Stat Counter ──────────────────────────────────────────────────────── */
function StatCounter({ value, suffix = '', label, delay = 0 }) {
  const [count, setCount] = useState(0);
  const [visible, setVisible] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setVisible(true); }, { threshold: 0.3 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  useEffect(() => {
    if (!visible) return;
    const timer = setTimeout(() => {
      let start = 0;
      const step = Math.max(1, Math.ceil(value / 60));
      const interval = setInterval(() => { start += step; if (start >= value) { setCount(value); clearInterval(interval); } else setCount(start); }, 16);
      return () => clearInterval(interval);
    }, delay);
    return () => clearTimeout(timer);
  }, [visible, value, delay]);
  return (
    <div ref={ref} style={{ textAlign: 'center' }}>
      <div style={{ fontFamily: '"Syne Mono", monospace', fontSize: 48, fontWeight: 400, color: '#ffffff', lineHeight: 1, textShadow: '0 0 30px rgba(255,255,255,0.3)', letterSpacing: -2 }}>
        {count}{suffix}
      </div>
      <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: '#555555', letterSpacing: 3, textTransform: 'uppercase', marginTop: 8 }}>{label}</div>
    </div>
  );
}

/* ─── Feature Card ──────────────────────────────────────────────────────── */
function FeatureCard({ icon, title, desc, accent = '#ffffff', delay = 0 }) {
  const [visible, setVisible] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setVisible(true); }, { threshold: 0.15 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  return (
    <div ref={ref} style={{
      background: 'rgba(8,18,24,0.7)', backdropFilter: 'blur(12px)', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 12, padding: '32px 28px', position: 'relative', overflow: 'hidden',
      opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(30px)',
      transition: `opacity 0.6s ease ${delay}s, transform 0.6s ease ${delay}s`,
    }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${accent}40, transparent)` }} />
      <div style={{ fontSize: 28, marginBottom: 16, filter: `drop-shadow(0 0 8px ${accent}40)` }}>{icon}</div>
      <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 14, fontWeight: 600, color: '#f0f0f0', marginBottom: 10, letterSpacing: 0.5 }}>{title}</div>
      <div style={{ fontFamily: '"IBM Plex Sans", sans-serif', fontSize: 13, color: '#a0a0a0', lineHeight: 1.7 }}>{desc}</div>
    </div>
  );
}

/* ─── Attack Type Ticker ────────────────────────────────────────────────── */
function AttackTicker() {
  const attacks = [
    'SQL Injection', 'XSS', 'Brute Force', 'Credential Stuffing', 'Privilege Escalation',
    'DDoS Attack', 'Data Exfiltration', 'Session Hijacking', 'Command Injection', 'Port Scan',
    'SSRF', 'Directory Traversal', 'Malware Upload', 'Insider Threat', 'Ransomware',
  ];
  return (
    <div style={{ overflow: 'hidden', position: 'relative', padding: '16px 0' }}>
      <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 80, background: 'linear-gradient(90deg, #02070c, transparent)', zIndex: 2 }} />
      <div style={{ position: 'absolute', right: 0, top: 0, bottom: 0, width: 80, background: 'linear-gradient(270deg, #02070c, transparent)', zIndex: 2 }} />
      <div style={{ display: 'flex', gap: 24, animation: 'tickerScroll 40s linear infinite', width: 'max-content' }}>
        {[...attacks, ...attacks, ...attacks].map((a, i) => (
          <div key={i} style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, letterSpacing: 2,
            color: '#555555', textTransform: 'uppercase', whiteSpace: 'nowrap',
            padding: '6px 16px', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4,
            background: 'rgba(255,255,255,0.02)',
          }}>
            {a}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Architecture Diagram ──────────────────────────────────────────────── */
function ArchDiagram() {
  const [visible, setVisible] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setVisible(true); }, { threshold: 0.2 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  const steps = [
    { label: 'SDK / Log Ingestion', sub: 'Node.js & Python SDK', color: '#3d8ef0' },
    { label: 'ML Detection Engine', sub: 'LightGBM + TF Autoencoder', color: '#9b59f0' },
    { label: 'Threat Intelligence', sub: 'AbuseIPDB + OSINT Feeds', color: '#f0a500' },
    { label: 'SOAR Automation', sub: 'Auto-block, Rate Limit', color: '#e53e3e' },
    { label: 'SOC Dashboard', sub: 'Real-time Visualization', color: '#ffffff' },
  ];
  return (
    <div ref={ref} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0, flexWrap: 'wrap', padding: '20px 0' }}>
      {steps.map((s, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', opacity: visible ? 1 : 0, transform: visible ? 'translateX(0)' : 'translateX(-20px)', transition: `all 0.5s ease ${i * 0.15}s` }}>
          <div style={{ textAlign: 'center', padding: '20px 24px', background: `${s.color}08`, border: `1px solid ${s.color}20`, borderRadius: 10, minWidth: 160 }}>
            <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, fontWeight: 600, color: s.color, marginBottom: 4 }}>{s.label}</div>
            <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: '#555555', letterSpacing: 1 }}>{s.sub}</div>
          </div>
          {i < steps.length - 1 && (
            <div style={{ fontFamily: '"Syne Mono", monospace', fontSize: 16, color: '#555555', padding: '0 8px' }}>&rarr;</div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ─── Pricing Card ──────────────────────────────────────────────────────── */
function PricingCard({ name, price, period, features, accent, highlighted, onCta }) {
  const [hovered, setHovered] = useState(false);
  return (
    <div
      onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}
      style={{
        background: highlighted ? 'rgba(255,255,255,0.03)' : 'rgba(8,18,24,0.7)',
        backdropFilter: 'blur(12px)',
        border: `1px solid ${highlighted ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.06)'}`,
        borderRadius: 14, padding: '40px 32px', position: 'relative', overflow: 'hidden',
        transform: hovered ? 'translateY(-4px)' : 'translateY(0)',
        transition: 'all 0.3s ease', flex: '1 1 300px', maxWidth: 380,
        boxShadow: highlighted ? '0 0 40px rgba(255,255,255,0.06)' : 'none',
      }}
    >
      {highlighted && <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, transparent, #ffffff, transparent)' }} />}
      {highlighted && (
        <div style={{ position: 'absolute', top: 16, right: 20, fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, letterSpacing: 2, color: '#ffffff', background: 'rgba(255,255,255,0.08)', padding: '3px 10px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.15)' }}>
          POPULAR
        </div>
      )}
      <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, letterSpacing: 3, color: '#555555', textTransform: 'uppercase', marginBottom: 12 }}>{name}</div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 24 }}>
        <span style={{ fontFamily: '"Syne Mono", monospace', fontSize: 42, color: accent, lineHeight: 1 }}>{price}</span>
        {period && <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: '#555555' }}>/{period}</span>}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 32 }}>
        {features.map((f, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, fontFamily: '"IBM Plex Sans", sans-serif', fontSize: 13, color: '#a0a0a0' }}>
            <span style={{ color: '#ffffff', fontSize: 10 }}>&#9670;</span> {f}
          </div>
        ))}
      </div>
      <button onClick={onCta} style={{
        width: '100%', padding: '14px 0', border: highlighted ? 'none' : '1px solid rgba(255,255,255,0.2)',
        borderRadius: 8, fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, letterSpacing: 2, cursor: 'pointer',
        background: highlighted ? 'linear-gradient(135deg, #ffffff, #cccccc)' : 'transparent',
        color: highlighted ? '#050505' : '#ffffff', fontWeight: 600,
        transition: 'all 0.2s ease',
      }}>
        GET STARTED
      </button>
    </div>
  );
}

/* ─── Testimonial ───────────────────────────────────────────────────────── */
function Testimonial({ quote, name, role, company }) {
  return (
    <div style={{
      background: 'rgba(8,18,24,0.5)', backdropFilter: 'blur(8px)', border: '1px solid rgba(255,255,255,0.06)',
      borderRadius: 12, padding: '32px 28px', position: 'relative',
    }}>
      <div style={{ fontFamily: '"Syne Mono", monospace', fontSize: 32, color: 'rgba(255,255,255,0.15)', position: 'absolute', top: 16, left: 20 }}>"</div>
      <div style={{ fontFamily: '"IBM Plex Sans", sans-serif', fontSize: 14, color: '#a0a0a0', lineHeight: 1.8, fontStyle: 'italic', marginBottom: 20, paddingTop: 8 }}>
        {quote}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg, #ffffff, #3d8ef0)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: '"IBM Plex Mono", monospace', fontSize: 13, fontWeight: 600, color: '#050505' }}>
          {name[0]}
        </div>
        <div>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: '#f0f0f0' }}>{name}</div>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: '#555555' }}>{role}, {company}</div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   LANDING PAGE
   ═══════════════════════════════════════════════════════════════════════════ */
export default function LandingPage() {
  const navigate = useNavigate();
  const [scrollY, setScrollY] = useState(0);

  useEffect(() => {
    const handler = () => setScrollY(window.scrollY);
    window.addEventListener('scroll', handler, { passive: true });
    return () => window.removeEventListener('scroll', handler);
  }, []);

  return (
    <div style={{ background: '#02070c', minHeight: '100vh', overflow: 'hidden', position: 'relative' }}>
      <HexGrid />
      <Orbs />

      {/* inject keyframes */}
      <style>{`
        @import url("https://fonts.googleapis.com/css2?family=Syne+Mono&family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap");
        @keyframes orbFloat1 { 0%,100% { transform: translate(0,0); } 50% { transform: translate(40px, 30px); } }
        @keyframes orbFloat2 { 0%,100% { transform: translate(0,0); } 50% { transform: translate(-50px, -40px); } }
        @keyframes orbFloat3 { 0%,100% { transform: translate(0,0); } 50% { transform: translate(30px, -20px); } }
        @keyframes tickerScroll { 0% { transform: translateX(0); } 100% { transform: translateX(-33.333%); } }
        @keyframes pulseGlow { 0%,100% { box-shadow: 0 0 20px rgba(255,255,255,0.15); } 50% { box-shadow: 0 0 40px rgba(255,255,255,0.3); } }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes scanline { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
        .landing-cta:hover { transform: translateY(-2px) !important; box-shadow: 0 8px 32px rgba(255,255,255,0.25) !important; }
        .landing-cta-ghost:hover { background: rgba(255,255,255,0.08) !important; }
        .nav-link { transition: color 0.2s; }
        .nav-link:hover { color: #ffffff !important; }
      `}</style>

      {/* ─── Navbar ─────────────────────────────────────────────── */}
      <nav style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 48px', height: 64,
        background: scrollY > 40 ? 'rgba(2,7,12,0.85)' : 'transparent',
        backdropFilter: scrollY > 40 ? 'blur(16px)' : 'none',
        borderBottom: scrollY > 40 ? '1px solid rgba(255,255,255,0.06)' : '1px solid transparent',
        transition: 'all 0.3s ease',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }} onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
          <span style={{ fontSize: 22, filter: 'drop-shadow(0 0 8px rgba(255,255,255,0.4))' }}>&#128737;</span>
          <span style={{ fontFamily: '"Syne Mono", monospace', fontSize: 16, fontWeight: 400, color: '#f0f0f0', letterSpacing: 2 }}>TRUSTFLOW</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
          {['Features', 'Architecture', 'Pricing'].map(s => (
            <a key={s} href={`#${s.toLowerCase()}`} className="nav-link" style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: '#a0a0a0', textDecoration: 'none', letterSpacing: 1.5, textTransform: 'uppercase' }}>{s}</a>
          ))}
          <button onClick={() => navigate('/login')} style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, letterSpacing: 2, color: '#ffffff', background: 'transparent', border: '1px solid rgba(255,255,255,0.25)', borderRadius: 6, padding: '8px 20px', cursor: 'pointer', transition: 'all 0.2s' }} className="landing-cta-ghost">
            LOG IN
          </button>
          <button onClick={() => navigate('/register')} className="landing-cta" style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, letterSpacing: 2, color: '#050505', fontWeight: 600, background: 'linear-gradient(135deg, #ffffff, #cccccc)', border: 'none', borderRadius: 6, padding: '8px 24px', cursor: 'pointer', transition: 'all 0.2s' }}>
            START FREE
          </button>
        </div>
      </nav>

      {/* ─── Hero Section ───────────────────────────────────────── */}
      <section style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: '120px 24px 80px' }}>
        {/* Live badge */}
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 18px', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 20, marginBottom: 32, animation: 'fadeUp 0.6s ease both', background: 'rgba(255,255,255,0.03)' }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ffffff', boxShadow: '0 0 8px #ffffff', animation: 'blink 2s ease infinite' }} />
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: '#ffffff', letterSpacing: 2 }}>NOW IN PUBLIC BETA</span>
        </div>

        {/* Title */}
        <h1 style={{ fontFamily: '"Syne Mono", monospace', fontSize: 'clamp(36px, 6vw, 72px)', fontWeight: 400, color: '#f0f0f0', lineHeight: 1.1, maxWidth: 900, marginBottom: 24, animation: 'fadeUp 0.8s ease 0.1s both', letterSpacing: -1 }}>
          AI-Powered Threat<br />
          <span style={{ color: '#ffffff', textShadow: '0 0 40px rgba(255,255,255,0.25)' }}>Detection</span> & <span style={{ color: '#3d8ef0' }}>Response</span>
        </h1>

        {/* Subtitle */}
        <p style={{ fontFamily: '"IBM Plex Sans", sans-serif', fontSize: 'clamp(14px, 1.8vw, 18px)', color: '#a0a0a0', maxWidth: 640, lineHeight: 1.8, marginBottom: 40, animation: 'fadeUp 0.8s ease 0.2s both' }}>
          Deploy TrustFlow on your infrastructure in minutes. Our ML engine detects 15 attack types in real-time, maps to MITRE ATT&CK, and auto-remediates with SOAR playbooks.
        </p>

        {/* CTA buttons */}
        <div style={{ display: 'flex', gap: 16, marginBottom: 64, animation: 'fadeUp 0.8s ease 0.3s both' }}>
          <button onClick={() => navigate('/register')} className="landing-cta" style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 13, letterSpacing: 2, fontWeight: 600,
            color: '#050505', background: 'linear-gradient(135deg, #ffffff, #cccccc)',
            border: 'none', borderRadius: 8, padding: '16px 40px', cursor: 'pointer', transition: 'all 0.25s ease',
          }}>
            START FOR FREE &rarr;
          </button>
          <button onClick={() => { const el = document.getElementById('features'); el?.scrollIntoView({ behavior: 'smooth' }); }} className="landing-cta-ghost" style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 13, letterSpacing: 2,
            color: '#a0a0a0', background: 'transparent',
            border: '1px solid rgba(255,255,255,0.15)', borderRadius: 8, padding: '16px 32px', cursor: 'pointer', transition: 'all 0.2s',
          }}>
            SEE HOW IT WORKS
          </button>
        </div>

        {/* Trusted by */}
        <div style={{ animation: 'fadeUp 0.8s ease 0.4s both' }}>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: '#555555', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16 }}>Trusted by security teams worldwide</div>
          <div style={{ display: 'flex', gap: 40, alignItems: 'center', justifyContent: 'center', opacity: 0.3 }}>
            {['FINTECH CO', 'HEALTHSEC', 'GOV-CERT', 'CLOUDSHIELD', 'DATAFORT'].map(name => (
              <span key={name} style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: '#555555', letterSpacing: 3 }}>{name}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ─── Attack Ticker ──────────────────────────────────────── */}
      <div style={{ position: 'relative', zIndex: 1, borderTop: '1px solid rgba(255,255,255,0.06)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <AttackTicker />
      </div>

      {/* ─── Stats Bar ──────────────────────────────────────────── */}
      <section style={{ position: 'relative', zIndex: 1, padding: '80px 48px', display: 'flex', justifyContent: 'center', gap: 80, flexWrap: 'wrap' }}>
        <StatCounter value={15} label="Attack Types Detected" delay={0} />
        <StatCounter value={98} suffix="%" label="ML Precision" delay={100} />
        <StatCounter value={45} suffix="+" label="API Endpoints" delay={200} />
        <StatCounter value={200} suffix="ms" label="Avg Response Time" delay={300} />
      </section>

      {/* ─── Features Grid ──────────────────────────────────────── */}
      <section id="features" style={{ position: 'relative', zIndex: 1, padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 56 }}>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, letterSpacing: 4, color: '#ffffff', textTransform: 'uppercase', marginBottom: 12 }}>Capabilities</div>
          <h2 style={{ fontFamily: '"Syne Mono", monospace', fontSize: 'clamp(24px, 3.5vw, 40px)', color: '#f0f0f0', fontWeight: 400 }}>
            Full-Stack Cyber Defense
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20 }}>
          <FeatureCard delay={0} icon="&#9881;" title="ML Detection Engine" desc="Multi-layer pipeline: TensorFlow autoencoder for anomaly detection + LightGBM classifier identifying 15 attack types with 98% precision. Real-time risk scoring on every event." accent="#9b59f0" />
          <FeatureCard delay={0.1} icon="&#9889;" title="SOAR Automation" desc="15 automated playbooks execute in under 200ms. IP blocking, account lockdown, rate limiting, and firewall rule injection — all triggered without human intervention." accent="#e53e3e" />
          <FeatureCard delay={0.2} icon="&#128269;" title="Threat Intelligence" desc="Live enrichment from AbuseIPDB, AlienVault OTX, and VirusTotal. Every IP gets a reputation score, country mapping, and historical abuse data before risk scoring." accent="#f0a500" />
          <FeatureCard delay={0.3} icon="&#9878;" title="MITRE ATT&CK Mapping" desc="Every detected attack maps to MITRE technique IDs and tactics. See exactly where adversaries are in the kill chain — from initial access to data exfiltration." accent="#3d8ef0" />
          <FeatureCard delay={0.4} icon="&#128200;" title="Attack Graph Visualization" desc="D3.js force-directed graphs reveal kill chains and lateral movement. See attacker IP clusters, compromised accounts, and pivot points in real time." accent="#48bb78" />
          <FeatureCard delay={0.5} icon="&#128274;" title="Multi-Tenant Isolation" desc="Full data isolation per tenant. Generate API keys, install our Node.js or Python SDK, and your events flow into your own scoped dashboard. Zero cross-tenant leakage." accent="#ffffff" />
        </div>
      </section>

      {/* ─── Architecture ───────────────────────────────────────── */}
      <section id="architecture" style={{ position: 'relative', zIndex: 1, padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, letterSpacing: 4, color: '#3d8ef0', textTransform: 'uppercase', marginBottom: 12 }}>Architecture</div>
          <h2 style={{ fontFamily: '"Syne Mono", monospace', fontSize: 'clamp(24px, 3.5vw, 40px)', color: '#f0f0f0', fontWeight: 400 }}>
            How TrustFlow Works
          </h2>
        </div>
        <ArchDiagram />
        {/* SDK snippet */}
        <div style={{ maxWidth: 600, margin: '48px auto 0', background: 'rgba(8,18,24,0.8)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 12, overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ display: 'flex', gap: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#e53e3e' }} />
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#f0a500' }} />
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#48bb78' }} />
            </div>
            <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: '#555555' }}>integration.js</span>
          </div>
          <pre style={{ padding: '20px 24px', margin: 0, fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, lineHeight: 1.8, color: '#a0a0a0', overflow: 'auto' }}>
{`const { trustFlowMiddleware } = require(`}<span style={{ color: '#f0a500' }}>'trustflow-sdk/express'</span>{`);

app.use(trustFlowMiddleware({
  apiKey: process.env.`}<span style={{ color: '#ffffff' }}>TRUSTFLOW_API_KEY</span>{`
}));

`}<span style={{ color: '#555555' }}>// That's it. Every request is now monitored.</span>
          </pre>
        </div>
      </section>

      {/* ─── Testimonials ───────────────────────────────────────── */}
      <section style={{ position: 'relative', zIndex: 1, padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, letterSpacing: 4, color: '#f0a500', textTransform: 'uppercase', marginBottom: 12 }}>Testimonials</div>
          <h2 style={{ fontFamily: '"Syne Mono", monospace', fontSize: 'clamp(24px, 3.5vw, 36px)', color: '#f0f0f0', fontWeight: 400 }}>
            What Security Teams Say
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
          <Testimonial quote="TrustFlow cut our incident response time from hours to seconds. The SOAR playbooks caught a brute force campaign at 3AM that would've gone unnoticed until morning." name="Sarah Chen" role="SOC Lead" company="FinGuard Capital" />
          <Testimonial quote="We replaced three separate tools with TrustFlow. The MITRE ATT&CK mapping gives our team a common language, and the ML engine catches things our rule-based SIEM missed entirely." name="Marcus Rivera" role="CISO" company="MedSecure Health" />
          <Testimonial quote="Setting up the SDK took 5 minutes. We were seeing our Express traffic analyzed and threat-scored in real-time before lunch. The kill chain graphs are incredible for investigations." name="Aiko Tanaka" role="Security Engineer" company="CloudForge" />
        </div>
      </section>

      {/* ─── Pricing ────────────────────────────────────────────── */}
      <section id="pricing" style={{ position: 'relative', zIndex: 1, padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 56 }}>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, letterSpacing: 4, color: '#9b59f0', textTransform: 'uppercase', marginBottom: 12 }}>Pricing</div>
          <h2 style={{ fontFamily: '"Syne Mono", monospace', fontSize: 'clamp(24px, 3.5vw, 40px)', color: '#f0f0f0', fontWeight: 400 }}>
            Start Free, Scale Securely
          </h2>
        </div>
        <div style={{ display: 'flex', gap: 24, justifyContent: 'center', flexWrap: 'wrap', alignItems: 'stretch' }}>
          <PricingCard
            name="Starter" price="$0" period="forever" accent="#a0a0a0"
            features={['10,000 events/month', '1 API key', '5 SOAR playbooks', 'Community support', '7-day data retention']}
            onCta={() => navigate('/register')}
          />
          <PricingCard highlighted
            name="Pro" price="$49" period="month" accent="#ffffff"
            features={['500,000 events/month', 'Unlimited API keys', 'All 15 SOAR playbooks', 'Priority support', '90-day data retention', 'MITRE ATT&CK mapping', 'Custom alert channels']}
            onCta={() => navigate('/register')}
          />
          <PricingCard
            name="Enterprise" price="Custom" accent="#3d8ef0"
            features={['Unlimited events', 'Dedicated infrastructure', 'SSO & RBAC', 'On-premise deployment', '1-year data retention', 'Custom ML model training', 'SLA guarantee']}
            onCta={() => navigate('/register')}
          />
        </div>
      </section>

      {/* ─── Final CTA ──────────────────────────────────────────── */}
      <section style={{ position: 'relative', zIndex: 1, padding: '100px 48px', textAlign: 'center' }}>
        <div style={{
          maxWidth: 700, margin: '0 auto', padding: '64px 48px', borderRadius: 20,
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.1)',
          position: 'relative', overflow: 'hidden',
        }}>
          <div style={{ position: 'absolute', top: 0, left: '20%', right: '20%', height: 1, background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)' }} />
          <h2 style={{ fontFamily: '"Syne Mono", monospace', fontSize: 'clamp(22px, 3vw, 36px)', color: '#f0f0f0', fontWeight: 400, marginBottom: 16 }}>
            Your network is being scanned<br /><span style={{ color: '#e53e3e' }}>right now</span>.
          </h2>
          <p style={{ fontFamily: '"IBM Plex Sans", sans-serif', fontSize: 15, color: '#a0a0a0', marginBottom: 32, lineHeight: 1.7 }}>
            Deploy TrustFlow in 5 minutes. No credit card required.
          </p>
          <button onClick={() => navigate('/register')} className="landing-cta" style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 14, letterSpacing: 2, fontWeight: 600,
            color: '#050505', background: 'linear-gradient(135deg, #ffffff, #cccccc)',
            border: 'none', borderRadius: 8, padding: '18px 48px', cursor: 'pointer', transition: 'all 0.25s ease',
            animation: 'pulseGlow 3s ease infinite',
          }}>
            START FOR FREE &rarr;
          </button>
        </div>
      </section>

      {/* ─── Footer ─────────────────────────────────────────────── */}
      <footer style={{ position: 'relative', zIndex: 1, borderTop: '1px solid rgba(255,255,255,0.06)', padding: '48px 48px 32px' }}>
        <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 40 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
              <span style={{ fontSize: 18 }}>&#128737;</span>
              <span style={{ fontFamily: '"Syne Mono", monospace', fontSize: 14, color: '#f0f0f0', letterSpacing: 2 }}>TRUSTFLOW</span>
            </div>
            <div style={{ fontFamily: '"IBM Plex Sans", sans-serif', fontSize: 12, color: '#555555', maxWidth: 280, lineHeight: 1.7 }}>
              AI-powered threat detection and autonomous response platform for modern security teams.
            </div>
          </div>
          {[
            { title: 'Product', links: ['Features', 'Pricing', 'SDK Docs', 'API Reference', 'Changelog'] },
            { title: 'Security', links: ['MITRE ATT&CK', 'SOAR Playbooks', 'Threat Intel', 'ML Engine'] },
            { title: 'Company', links: ['About', 'Blog', 'Careers', 'Contact'] },
          ].map(col => (
            <div key={col.title}>
              <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, letterSpacing: 3, color: '#a0a0a0', textTransform: 'uppercase', marginBottom: 16 }}>{col.title}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {col.links.map(l => (
                  <a key={l} href="#" style={{ fontFamily: '"IBM Plex Sans", sans-serif', fontSize: 13, color: '#555555', textDecoration: 'none', transition: 'color 0.2s' }}
                    onMouseEnter={e => e.target.style.color = '#ffffff'} onMouseLeave={e => e.target.style.color = '#555555'}>
                    {l}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div style={{ maxWidth: 1200, margin: '40px auto 0', paddingTop: 24, borderTop: '1px solid rgba(255,255,255,0.04)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: '#1a3a50', letterSpacing: 1 }}>
            &copy; 2025 TrustFlow. All rights reserved.
          </span>
          <div style={{ display: 'flex', gap: 24 }}>
            {['Privacy', 'Terms', 'Security'].map(l => (
              <a key={l} href="#" style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: '#1a3a50', textDecoration: 'none', letterSpacing: 1 }}>{l}</a>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
}
