import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
// eslint-disable-next-line no-unused-vars
import { motion, useScroll, useTransform, useMotionValue, useSpring, useMotionTemplate } from 'framer-motion';
import { 
  Shield, Activity, Zap, Server, Lock, Cpu, Command, 
  ArrowRight, Github, Twitter, Fingerprint, 
  TerminalSquare, BarChart, FileJson, Play, RefreshCw, AlertTriangle, CheckCircle2
} from 'lucide-react';
import Particles from '../components/ReactBits/Particles';
import StarBorder from '../components/ReactBits/StarBorder';
import DecryptedText from '../components/ReactBits/DecryptedText';
import SpotlightCard from '../components/ReactBits/SpotlightCard';

/* ─── Aesthetics & Theme ────────────────────────────────────────────────── */
const THEME = {
  bg: '#000000',
  bgCard: '#050505',
  bgCardHover: '#0A0A0A',
  border: 'rgba(255, 255, 255, 0.08)',
  borderHover: 'rgba(255, 255, 255, 0.2)',
  textMain: '#EDEDED',
  textMuted: '#888888',
  accent: '#FFFFFF',
};

/* ─── Utility Components ────────────────────────────────────────────────── */
const FadeIn = ({ children, delay = 0, y = 30, className = '', style = {} }) => (
  <motion.div
    initial={{ opacity: 0, y }}
    whileInView={{ opacity: 1, y: 0 }}
    viewport={{ once: true, margin: "-50px" }}
    transition={{ duration: 0.8, delay, ease: [0.16, 1, 0.3, 1] }}
    className={className}
    style={style}
  >
    {children}
  </motion.div>
);

const Button = ({ children, variant = 'primary', icon: Icon, onClick, className = '' }) => {
  const isPrimary = variant === 'primary';
  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className={`btn-${variant} ${className}`}
      style={{
        padding: '0.8rem 1.5rem',
        background: isPrimary ? '#FFFFFF' : 'transparent',
        color: isPrimary ? '#000000' : THEME.textMain,
        border: isPrimary ? '1px solid #FFFFFF' : `1px solid ${THEME.border}`,
        borderRadius: '6px',
        fontFamily: '"Inter", sans-serif',
        fontSize: '0.875rem',
        fontWeight: 500,
        cursor: 'pointer',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.5rem',
        transition: 'all 0.3s ease',
        boxShadow: isPrimary ? '0 0 20px rgba(255,255,255,0.2)' : 'none',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      <span style={{ position: 'relative', zIndex: 2, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        {children}
        {Icon && <Icon size={16} />}
      </span>
      {isPrimary && (
        <div className="btn-glow" style={{ position: 'absolute', top: 0, left: '-100%', width: '100%', height: '100%', background: 'linear-gradient(90deg, transparent, rgba(0,0,0,0.1), transparent)', transition: '0.5s' }} />
      )}
    </motion.button>
  );
};

/* ─── 3D Spatial Components ─────────────────────────────────────────────── */

const TiltCard = ({ children, className = '', delay = 0 }) => {
  const ref = useRef(null);
  
  // Motion values for tilt
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const xSpring = useSpring(x, { stiffness: 400, damping: 40 });
  const ySpring = useSpring(y, { stiffness: 400, damping: 40 });
  const rotateX = useTransform(ySpring, [-0.5, 0.5], ["5deg", "-5deg"]);
  const rotateY = useTransform(xSpring, [-0.5, 0.5], ["-5deg", "5deg"]);

  // Motion values for radial glow
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  const handleMouseMove = (e) => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const localX = e.clientX - rect.left;
    const localY = e.clientY - rect.top;
    
    x.set(localX / width - 0.5);
    y.set(localY / height - 0.5);
    mouseX.set(localX);
    mouseY.set(localY);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
    // Move glow off-screen smoothly
    mouseX.set(-1000);
    mouseY.set(-1000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{ duration: 0.8, delay, ease: [0.16, 1, 0.3, 1] }}
      style={{ perspective: 1200 }}
      className={`bento-card-wrapper ${className}`}
    >
      <motion.div
        ref={ref}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        style={{ rotateX, rotateY, transformStyle: "preserve-3d" }}
        className="bento-card"
      >
        {/* Animated Radial Glow */}
        <motion.div
          className="bento-glow"
          style={{
            background: useMotionTemplate`radial-gradient(350px circle at ${mouseX}px ${mouseY}px, rgba(255,255,255,0.06), transparent 80%)`,
          }}
        />
        
        {/* Border Gradient overlay that follows mouse */}
        <motion.div
          className="bento-border-glow"
          style={{
            background: useMotionTemplate`radial-gradient(200px circle at ${mouseX}px ${mouseY}px, rgba(255,255,255,0.4), transparent 70%)`,
          }}
        />
        
        <div className="bento-inner" style={{ transform: "translateZ(40px)" }}>
          {children}
        </div>
      </motion.div>
    </motion.div>
  );
};

/* ─── Page Sections ─────────────────────────────────────────────────────── */

function Header() {
  const navigate = useNavigate();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 1000,
      padding: '1rem 5vw', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      background: scrolled ? 'rgba(0,0,0,0.7)' : 'transparent',
      backdropFilter: scrolled ? 'blur(16px)' : 'none',
      borderBottom: scrolled ? `1px solid ${THEME.border}` : '1px solid transparent',
      transition: 'all 0.4s ease'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }} onClick={() => window.scrollTo(0,0)}>
        <Shield size={22} color="#FFFFFF" strokeWidth={2.5} />
        <span style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.1rem', fontWeight: 600, letterSpacing: '-0.02em', color: THEME.textMain }}>
          TrustFlow
        </span>
      </div>

      <nav style={{ gap: '2.5rem' }} className="desktop-nav">
        {['Platform', 'Integrations', 'Process', 'Contact'].map((item) => (
          <a key={item} href={`#${item.toLowerCase()}`} style={{
            fontFamily: '"Inter", sans-serif', fontSize: '0.85rem', fontWeight: 500, color: THEME.textMuted, textDecoration: 'none',
            transition: 'color 0.2s'
          }} className="nav-link">
            {item}
          </a>
        ))}
      </nav>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <Button variant="outline" onClick={() => navigate('/login')} className="hidden-mobile">Log In</Button>
      </div>
    </header>
  );
}

function CyberConsole() {
  const [logs, setLogs] = useState([
    { id: 1, type: 'info', text: 'SYS // Stream ingestion engine initialized successfully.' },
    { id: 2, type: 'info', text: 'ML  // Neural classifier baseline active across 15 vectors.' },
    { id: 3, type: 'success', text: 'SLA // SOC telemetry latency stabilized at 114ms.' },
    { id: 4, type: 'info', text: 'SOAR// Hot-standby playbooks synchronized with gateway.' },
  ]);
  const [attackState, setAttackState] = useState('idle'); // idle, triggered, detecting, mitigating, secured
  const [riskLevel, setRiskLevel] = useState(0.12);
  const terminalEndRef = useRef(null);

  // Auto scroll terminal logs
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Periodic random background telemetry log additions
  useEffect(() => {
    const defaultMessages = [
      'SYS // Ingesting 25,482 EPS from cloudwatch-us-east-1.',
      'SYS // Kafka consumer groups healthy. Zero log lag.',
      'ML  // Processing classification tensor array (batch size 128).',
      'SLA // Telemetry round-trip latency verified: 121ms.',
      'AUDIT// Continuous compliance scan generated for SOC 2 Trust Criteria.',
    ];

    const interval = setInterval(() => {
      if (attackState !== 'idle') return;
      const randomMsg = defaultMessages[Math.floor(Math.random() * defaultMessages.length)];
      setLogs(prev => [
        ...prev,
        { id: Date.now(), type: 'info', text: randomMsg }
      ]);
    }, 4500);

    return () => clearInterval(interval);
  }, [attackState]);

  const triggerAttack = () => {
    if (attackState !== 'idle') return;
    setAttackState('triggered');
    setRiskLevel(98.4);
    
    // Add logs step-by-step
    setLogs(prev => [
      ...prev,
      { id: Date.now(), type: 'danger', text: 'CRITICAL // Threat incident detected: lateral movement on subnet 10.0.4.0/24.' }
    ]);

    setTimeout(() => {
      setAttackState('detecting');
      setLogs(prev => [
        ...prev,
        { id: Date.now() + 1, type: 'warning', text: 'ML // Classification complete: classified CVE-2026-9812 Zero-Day RCE.' }
      ]);
    }, 1500);

    setTimeout(() => {
      setAttackState('mitigating');
      setLogs(prev => [
        ...prev,
        { id: Date.now() + 2, type: 'info', text: 'SOAR // Executing Autonomous Playbook [GATEWAY_ISOLATE_SUBNET].' }
      ]);
    }, 3000);

    setTimeout(() => {
      setAttackState('secured');
      setRiskLevel(0.08);
      setLogs(prev => [
        ...prev,
        { id: Date.now() + 3, type: 'success', text: 'SUCCESS // Subnet 10.0.4.0 isolated, risk mitigated in 142ms.' }
      ]);
    }, 4800);
  };

  const resetAttack = () => {
    setAttackState('idle');
    setRiskLevel(0.12);
    setLogs([
      { id: Date.now(), type: 'info', text: 'SYS // Operations console telemetry reset.' },
      { id: Date.now() + 1, type: 'info', text: 'SYS // Stream ingestion engine active.' },
      { id: Date.now() + 2, type: 'success', text: 'SLA // Telemetry stabilized at 112ms.' }
    ]);
  };

  // Node Map Colors based on state
  const getNodeColor = (nodeId) => {
    if (attackState === 'secured') return '#00E676';
    if (attackState === 'mitigating') {
      if (nodeId === 'soar') return '#29B6F6';
      return '#EDEDED';
    }
    if (attackState === 'triggered' || attackState === 'detecting') {
      if (nodeId === 'subnet') return '#FF5252';
      return '#333';
    }
    return '#EDEDED';
  };

  const getLineColor = (from, to) => {
    if (attackState === 'secured') return '#00E676';
    if (attackState === 'mitigating') return '#29B6F6';
    if (attackState === 'triggered' || attackState === 'detecting') {
      if (from === 'subnet' || to === 'subnet') return '#FF5252';
      return '#222';
    }
    return 'rgba(255,255,255,0.08)';
  };

  return (
    <SpotlightCard 
      spotlightColor="rgba(255, 255, 255, 0.03)" 
      borderColor="rgba(255, 255, 255, 0.12)"
      style={{
        width: '100%',
        background: 'rgba(5, 5, 5, 0.85)',
        backdropFilter: 'blur(20px)',
        boxShadow: '0 30px 60px rgba(0,0,0,0.8)',
        borderRadius: '16px',
        overflow: 'hidden'
      }}
    >
      {/* Console Top Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '1rem 1.5rem', borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        background: 'rgba(0,0,0,0.3)'
      }}>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#FF5252' }} />
          <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#FFD740' }} />
          <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#00E676' }} />
          <span style={{ 
            marginLeft: '1rem', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem', 
            color: '#888888', letterSpacing: '0.1em' 
          }}>
            TRUSTFLOW // THREAT_OPS_CENTER v2.0
          </span>
        </div>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <div style={{
            fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', 
            background: 'rgba(255,255,255,0.05)', padding: '0.25rem 0.6rem', 
            borderRadius: '4px', border: '1px solid rgba(255,255,255,0.08)',
            color: attackState === 'triggered' || attackState === 'detecting' ? '#FF5252' : '#00E676',
            display: 'flex', alignItems: 'center', gap: '6px'
          }}>
            <div style={{ 
              width: '6px', height: '6px', borderRadius: '50%', 
              background: attackState === 'triggered' || attackState === 'detecting' ? '#FF5252' : '#00E676',
              animation: 'pulse 1.5s infinite' 
            }} />
            {attackState === 'triggered' ? 'CRITICAL INCIDENT' : attackState === 'detecting' ? 'CLASSIFYING THREAT' : attackState === 'mitigating' ? 'SOAR MITIGATION ACTIVE' : 'SYSTEM HEALTHY'}
          </div>
        </div>
      </div>

      {/* Main Console Content */}
      <div style={{ display: 'flex', height: '420px', flexWrap: 'wrap' }} className="console-layout">
        
        {/* Left Side: Scrolling Security Terminal Logs */}
        <div style={{
          flex: '1 1 500px', borderRight: '1px solid rgba(255, 255, 255, 0.08)',
          padding: '1.5rem', background: 'rgba(0,0,0,0.2)', overflowY: 'auto',
          display: 'flex', flexDirection: 'column', gap: '0.8rem', height: '100%'
        }} className="terminal-logs">
          <div style={{
            fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', 
            color: '#666', borderBottom: '1px solid rgba(255,255,255,0.04)',
            paddingBottom: '0.5rem', display: 'flex', justifyContent: 'space-between'
          }}>
            <span>SYSTEM CONSOLE FEED</span>
            <span>SECURE LINK_CONNECTED</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', flexGrow: 1 }}>
            {logs.map((log) => (
              <div key={log.id} style={{
                fontFamily: '"JetBrains Mono", monospace', fontSize: '0.85rem',
                lineHeight: 1.4, display: 'flex', gap: '10px',
                color: log.type === 'danger' ? '#FF5252' : log.type === 'warning' ? '#FFD740' : log.type === 'success' ? '#00E676' : '#EDEDED'
              }}>
                <span style={{ color: '#555', userSelect: 'none' }}>&gt;</span>
                <span style={{ wordBreak: 'break-all' }}>
                  {log.text.startsWith('CRITICAL') || log.text.startsWith('ML') || log.text.startsWith('SOAR') || log.text.startsWith('SUCCESS') ? (
                    <DecryptedText text={log.text} animateOn="mount" speed={30} maxIterations={8} />
                  ) : (
                    log.text
                  )}
                </span>
              </div>
            ))}
            <div ref={terminalEndRef} />
          </div>
        </div>

        {/* Right Side: Visual SVG Node Network Graph */}
        <div style={{
          flex: '1 1 400px', display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', padding: '2rem',
          position: 'relative', height: '100%', background: 'rgba(5, 5, 5, 0.2)'
        }} className="network-map">
          
          <div style={{
            position: 'absolute', top: '1.5rem', left: '1.5rem',
            fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', color: '#666'
          }}>
            THREAT TOPOGRAPHY VISUALIZER
          </div>

          {/* Radar sweeping backdrop */}
          <div className="radar-sweep" style={{
            position: 'absolute', width: '280px', height: '280px',
            borderRadius: '50%', border: '1px solid rgba(255,255,255,0.03)',
            pointerEvents: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <div style={{ width: '200px', height: '200px', borderRadius: '50%', border: '1px solid rgba(255,255,255,0.02)' }} />
            <div style={{ width: '100px', height: '100px', borderRadius: '50%', border: '1px solid rgba(255,255,255,0.01)' }} />
          </div>

          {/* SVG Topology Nodes and Connections */}
          <svg width="340" height="280" style={{ position: 'relative', zIndex: 5 }}>
            <defs>
              <linearGradient id="glow-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#00E676" />
                <stop offset="100%" stopColor="#29B6F6" />
              </linearGradient>
            </defs>

            {/* Connecting Lines */}
            <line x1="60" y1="140" x2="170" y2="140" stroke={getLineColor('kafka', 'gateway')} strokeWidth={1.5} />
            <line x1="170" y1="140" x2="170" y2="50" stroke={getLineColor('gateway', 'auth')} strokeWidth={1.5} />
            <line x1="170" y1="140" x2="280" y2="100" stroke={getLineColor('gateway', 'subnet')} strokeWidth={1.5} />
            <line x1="170" y1="140" x2="170" y2="230" stroke={getLineColor('gateway', 'soar')} strokeWidth={1.5} />
            <line x1="280" y1="100" x2="170" y2="230" stroke={getLineColor('subnet', 'soar')} strokeWidth={1.5} />

            {/* Animated Data Packets Flowing */}
            {attackState === 'idle' && (
              <>
                <circle r="3" fill="#FFF">
                  <animateMotion dur="4s" repeatCount="indefinite" path="M60,140 L170,140" />
                </circle>
                <circle r="3" fill="#FFF">
                  <animateMotion dur="3s" repeatCount="indefinite" path="M170,140 L170,50" />
                </circle>
                <circle r="3" fill="#FFF">
                  <animateMotion dur="5s" repeatCount="indefinite" path="M170,140 L280,100" />
                </circle>
              </>
            )}

            {attackState === 'triggered' && (
              <circle r="4" fill="#FF5252">
                <animateMotion dur="1s" repeatCount="indefinite" path="M280,100 L170,140" />
              </circle>
            )}

            {attackState === 'mitigating' && (
              <>
                <circle r="5" fill="#29B6F6">
                  <animateMotion dur="0.8s" repeatCount="indefinite" path="M170,230 L280,100" />
                </circle>
                <circle r="5" fill="#29B6F6">
                  <animateMotion dur="0.8s" repeatCount="indefinite" path="M170,230 L170,140" />
                </circle>
              </>
            )}

            {/* Nodes */}
            {/* Kafka Ingestion Node */}
            <circle cx="60" cy="140" r="16" fill="#0A0A0A" stroke={getNodeColor('kafka')} strokeWidth="2" style={{ transition: 'all 0.5s' }} />
            <text x="60" y="145" textAnchor="middle" fill="#888" fontSize="9" fontFamily="monospace">KFK</text>
            
            {/* Auth Server Node */}
            <circle cx="170" cy="50" r="16" fill="#0A0A0A" stroke={getNodeColor('auth')} strokeWidth="2" style={{ transition: 'all 0.5s' }} />
            <text x="170" y="55" textAnchor="middle" fill="#888" fontSize="9" fontFamily="monospace">ATH</text>

            {/* Gateway Central Node */}
            <circle cx="170" cy="140" r="22" fill="#0A0A0A" stroke={getNodeColor('gateway')} strokeWidth="2.5" style={{ transition: 'all 0.5s' }} />
            <text x="170" y="144" textAnchor="middle" fill="#EDEDED" fontSize="10" fontFamily="monospace">GTW</text>

            {/* Vulnerable subnet/DB Cluster Node */}
            <circle cx="280" cy="100" r="20" fill="#0A0A0A" stroke={getNodeColor('subnet')} strokeWidth="2" className={attackState === 'triggered' || attackState === 'detecting' ? 'node-alert-flash' : ''} style={{ transition: 'all 0.5s' }} />
            <text x="280" y="104" textAnchor="middle" fill={attackState === 'triggered' || attackState === 'detecting' ? '#FF5252' : '#888'} fontSize="10" fontFamily="monospace">SUB</text>

            {/* SOAR Playbook Mitigator Node */}
            <circle cx="170" cy="230" r="18" fill="#0A0A0A" stroke={getNodeColor('soar')} strokeWidth="2" style={{ transition: 'all 0.5s' }} />
            <text x="170" y="234" textAnchor="middle" fill="#888" fontSize="10" fontFamily="monospace">SAR</text>
          </svg>

          {/* Attack Alert Banner */}
          {(attackState === 'triggered' || attackState === 'detecting') && (
            <div style={{
              position: 'absolute', bottom: '2rem', background: 'rgba(255,82,82,0.15)',
              border: '1px solid #FF5252', color: '#FF5252', padding: '0.5rem 1rem',
              borderRadius: '8px', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem',
              display: 'flex', alignItems: 'center', gap: '8px', zIndex: 10,
              boxShadow: '0 10px 20px rgba(255,82,82,0.2)'
            }}>
              <AlertTriangle size={16} className="pulse-alert" />
              <span>ALERT // INTRUSION DETECTED IN SUB_4</span>
            </div>
          )}

          {attackState === 'secured' && (
            <div style={{
              position: 'absolute', bottom: '2rem', background: 'rgba(0,230,118,0.15)',
              border: '1px solid #00E676', color: '#00E676', padding: '0.5rem 1rem',
              borderRadius: '8px', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem',
              display: 'flex', alignItems: 'center', gap: '8px', zIndex: 10
            }}>
              <CheckCircle2 size={16} />
              <span>THREAT NEUTRALIZED IN 142MS</span>
            </div>
          )}
        </div>
      </div>

      {/* Control Deck / Telemetry Summary */}
      <div style={{
        display: 'flex', borderTop: '1px solid rgba(255, 255, 255, 0.08)',
        background: 'rgba(0,0,0,0.4)', padding: '1.25rem 1.5rem',
        justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1.5rem'
      }}>
        <div style={{ display: 'flex', gap: '2.5rem', flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', color: '#666', textTransform: 'uppercase', marginBottom: '0.25rem' }}>ACTIVE RISK INDEX</div>
            <div style={{ 
              fontFamily: '"JetBrains Mono", monospace', fontSize: '1.2rem', fontWeight: 500,
              color: riskLevel > 50 ? '#FF5252' : '#00E676', transition: 'color 0.5s'
            }}>
              {riskLevel}%
            </div>
          </div>
          <div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', color: '#666', textTransform: 'uppercase', marginBottom: '0.25rem' }}>INGESTION RATE</div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '1.2rem', fontWeight: 500, color: '#EDEDED' }}>
              142,504 <span style={{ fontSize: '0.8rem', color: '#666' }}>EPS</span>
            </div>
          </div>
          <div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', color: '#666', textTransform: 'uppercase', marginBottom: '0.25rem' }}>LATENCY SLA</div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '1.2rem', fontWeight: 500, color: '#00E676' }}>
              &lt; 150ms
            </div>
          </div>
        </div>

        {/* Action Button Deck */}
        <div style={{ display: 'flex', gap: '10px' }}>
          {attackState === 'idle' ? (
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={triggerAttack}
              style={{
                background: '#FF5252', color: '#000', border: 'none',
                borderRadius: '6px', padding: '0.6rem 1.2rem', cursor: 'pointer',
                fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem', fontWeight: 600,
                display: 'inline-flex', alignItems: 'center', gap: '8px',
                boxShadow: '0 0 15px rgba(255,82,82,0.4)'
              }}
            >
              <Play size={14} fill="#000" />
              Simulate Cyber Attack
            </motion.button>
          ) : (
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={resetAttack}
              disabled={attackState !== 'secured'}
              style={{
                background: 'transparent', color: attackState === 'secured' ? '#EDEDED' : '#666',
                border: `1px solid ${attackState === 'secured' ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.05)'}`,
                borderRadius: '6px', padding: '0.6rem 1.2rem', cursor: attackState === 'secured' ? 'pointer' : 'not-allowed',
                fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem', fontWeight: 500,
                display: 'inline-flex', alignItems: 'center', gap: '8px'
              }}
            >
              <RefreshCw size={14} className={attackState !== 'secured' && attackState !== 'idle' ? 'spin-animation' : ''} />
              Reset Environment
            </motion.button>
          )}
        </div>
      </div>
    </SpotlightCard>
  );
}

function Hero() {
  const navigate = useNavigate();
  
  return (
    <section style={{ 
      position: 'relative', minHeight: '100vh', display: 'flex', flexDirection: 'column', 
      alignItems: 'center', justifyContent: 'center', padding: '0 5vw', overflow: 'hidden',
      perspective: '1000px'
    }}>
      {/* 3D Perspective Grid Background */}
      <Particles
        particleColors={['#ffffff', '#00E676', '#333333']}
        particleCount={250}
        particleSpread={12}
        speed={0.15}
        particleBaseSize={120}
        moveParticlesOnHover={true}
        alphaParticles={true}
        disableRotation={false}
      />
      <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(circle at center, transparent 0%, #000 80%)', pointerEvents: 'none' }} />

      <div style={{ position: 'relative', zIndex: 10, width: '100%', maxWidth: '800px', textAlign: 'center', marginTop: '5vh' }}>
        <FadeIn>
          <StarBorder as="div" color="rgba(255,255,255,0.3)" speed="4s" thickness={1} style={{ borderRadius: '100px', marginBottom: '2.5rem', display: 'inline-block' }}>
            <motion.div 
              whileHover={{ scale: 1.05 }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '0.5rem', padding: '0.25rem 0.75rem',
                background: 'rgba(0,0,0,0.5)', borderRadius: '100px',
                fontFamily: '"Inter", sans-serif', fontSize: '0.75rem', color: THEME.textMuted,
                cursor: 'pointer', backdropFilter: 'blur(10px)'
              }}
            >
              <div className="pulse-dot" style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00E676', boxShadow: '0 0 10px #00E676' }} />
              TrustFlow v2.0 is now live
            </motion.div>
          </StarBorder>
        </FadeIn>

        <FadeIn delay={0.1}>
          <h1 style={{ 
            fontFamily: '"Inter", sans-serif', fontSize: 'clamp(3.5rem, 8vw, 6.5rem)', 
            fontWeight: 500, color: THEME.textMain, lineHeight: 1.05, 
            letterSpacing: '-0.04em', marginBottom: '1.5rem',
            textShadow: '0 10px 40px rgba(255,255,255,0.15)'
          }}>
            Secure infra at the <span style={{ color: THEME.textMuted }}>speed of thought.</span>
          </h1>
        </FadeIn>

        <FadeIn delay={0.2}>
          <p style={{ 
            fontFamily: '"Inter", sans-serif', fontSize: 'clamp(1rem, 1.2vw, 1.25rem)', 
            color: THEME.textMuted, maxWidth: '600px', margin: '0 auto 3rem', lineHeight: 1.6 
          }}>
            An autonomous SOC platform that ingests logs, detects zero-days with an ML ensemble, and triggers SOAR playbooks in under 200ms.
          </p>
        </FadeIn>

        <FadeIn delay={0.3} style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
          <Button onClick={() => navigate('/register')} icon={ArrowRight}>Start Deploying</Button>
          <Button variant="outline" onClick={() => document.getElementById('platform').scrollIntoView()} icon={TerminalSquare}>View Documentation</Button>
        </FadeIn>
      </div>

      {/* Interactive Operations Console */}
      <FadeIn delay={0.4} style={{ width: '100%', maxWidth: '1100px', marginTop: '4rem', zIndex: 20 }}>
        <CyberConsole />
      </FadeIn>
    </section>
  );
}

function BentoGrid() {
  const Brain = Cpu;
  return (
    <section id="platform" style={{ padding: '8rem 5vw', position: 'relative', zIndex: 20 }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <FadeIn>
          <h2 style={{ fontFamily: '"Inter", sans-serif', fontSize: 'clamp(2.5rem, 5vw, 3.5rem)', fontWeight: 500, letterSpacing: '-0.03em', marginBottom: '4rem', lineHeight: 1.1 }}>
            Architecture that <br/><span style={{ color: THEME.textMuted }}>thinks in 3D.</span>
          </h2>
        </FadeIn>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gridAutoRows: '320px', gap: '1.5rem' }} className="bento-grid">
          
          {/* Big Card - ML Ensemble */}
          <FadeIn delay={0.1} className="col-span-2">
            <SpotlightCard spotlightColor="rgba(255, 255, 255, 0.03)" borderColor="rgba(255, 255, 255, 0.12)">
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <Brain size={28} color="#FFF" style={{ marginBottom: '2rem' }} />
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.5rem', fontWeight: 500, marginBottom: '0.75rem', color: THEME.textMain }}>ML Ensemble Engine</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6, maxWidth: '400px' }}>
                  Dual-pipeline analysis leveraging LightGBM and XGBoost for unrivaled threat classification across 15 distinct vectors.
                </p>
                <div style={{ position: 'absolute', bottom: '-10%', right: '-5%', opacity: 0.05, pointerEvents: 'none', transform: 'rotate(-10deg) translateZ(-50px)' }}>
                  <BarChart size={240} />
                </div>
              </div>
            </SpotlightCard>
          </FadeIn>

          {/* Small Card - SOAR */}
          <FadeIn delay={0.2}>
            <SpotlightCard spotlightColor="rgba(255, 255, 255, 0.03)" borderColor="rgba(255, 255, 255, 0.12)">
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <Zap size={28} color="#FFF" style={{ marginBottom: '2rem' }} />
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.5rem', fontWeight: 500, marginBottom: '0.75rem', color: THEME.textMain }}>SOAR Execution</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6 }}>
                  Millisecond playbook automation. IP blocking and rate limiting executed autonomously.
                </p>
              </div>
            </SpotlightCard>
          </FadeIn>

          {/* Small Card - Compliance */}
          <FadeIn delay={0.3}>
            <SpotlightCard spotlightColor="rgba(255, 255, 255, 0.03)" borderColor="rgba(255, 255, 255, 0.12)">
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <FileJson size={28} color="#FFF" style={{ marginBottom: '2rem' }} />
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.5rem', fontWeight: 500, marginBottom: '0.75rem', color: THEME.textMain }}>SOC 2 / ISO 27001</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6 }}>
                  Continuous tracking and audit-ready reports generated dynamically in seconds.
                </p>
              </div>
            </SpotlightCard>
          </FadeIn>

          {/* Big Card - Threat Graph */}
          <FadeIn delay={0.4} className="col-span-2">
            <SpotlightCard spotlightColor="rgba(255, 255, 255, 0.03)" borderColor="rgba(255, 255, 255, 0.12)">
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <Activity size={28} color="#FFF" style={{ marginBottom: '2rem' }} />
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.5rem', fontWeight: 500, marginBottom: '0.75rem', color: THEME.textMain }}>Live Threat Topography</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6, maxWidth: '450px' }}>
                  Real-time spatial visualization mapping adversary lateral movement to MITRE ATT&CK techniques with node-based telemetry tracking.
                </p>
                <div style={{ position: 'absolute', bottom: '-20%', right: '5%', opacity: 0.05, pointerEvents: 'none', transform: 'rotate(15deg) translateZ(-80px)' }}>
                  <Server size={220} />
                </div>
              </div>
            </SpotlightCard>
          </FadeIn>

        </div>
      </div>
    </section>
  );
}

function Metrics() {
  return (
    <section style={{ padding: '6rem 5vw', borderTop: `1px solid ${THEME.border}`, borderBottom: `1px solid ${THEME.border}`, background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.01), transparent)' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexWrap: 'wrap', gap: '4rem', justifyContent: 'space-between' }}>
        {[
          { label: 'Latency', value: '< 150ms' },
          { label: 'Accuracy', value: '97.2%' },
          { label: 'Threats Neutralized', value: '1.2B+' },
          { label: 'Uptime SLA', value: '99.99%' },
        ].map((metric, i) => (
          <FadeIn key={i} delay={i * 0.1} style={{ flex: '1 1 200px' }}>
            <div style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.85rem', color: THEME.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{ width: '4px', height: '4px', background: THEME.accent, borderRadius: '50%' }} />
              {metric.label}
            </div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '3rem', fontWeight: 400, color: THEME.textMain, letterSpacing: '-0.03em' }}>
              {metric.value}
            </div>
          </FadeIn>
        ))}
      </div>
    </section>
  );
}

function Process() {
  return (
    <section id="process" style={{ padding: '10rem 5vw', position: 'relative' }}>
      <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '1px', background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent)' }} />
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6rem' }} className="responsive-split">
          <FadeIn>
            <h2 style={{ fontFamily: '"Inter", sans-serif', fontSize: 'clamp(2.5rem, 4vw, 3.5rem)', fontWeight: 500, letterSpacing: '-0.03em', marginBottom: '1.5rem', lineHeight: 1.1 }}>
              Drop-in <br/><span style={{ color: THEME.textMuted }}>integration.</span>
            </h2>
            <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.05rem', color: THEME.textMuted, lineHeight: 1.7, marginBottom: '3rem' }}>
              TrustFlow was conceived when our offensive security team recognized the latency inherent in traditional SIEM platforms. We engineered an intelligent, autonomous layer capable of executing remediations before human analysts even receive the alert.
            </p>
            
            {/* Terminal Window */}
            <div style={{ background: '#050505', border: `1px solid ${THEME.border}`, borderRadius: '12px', overflow: 'hidden', boxShadow: '0 20px 40px rgba(0,0,0,0.4)' }}>
              <div style={{ padding: '1rem', borderBottom: `1px solid ${THEME.border}`, display: 'flex', gap: '0.5rem' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#333' }} />
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#333' }} />
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#333' }} />
              </div>
              <div style={{ padding: '2rem', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.9rem', color: THEME.textMuted, lineHeight: 1.6 }}>
                <span style={{ color: '#E53E3E' }}>import</span> &#123; trustFlow &#125; <span style={{ color: '#E53E3E' }}>from</span> <span style={{ color: '#A0AEC0' }}>'@trustflow/node'</span>;<br/><br/>
                app.<span style={{ color: '#63B3ED' }}>use</span>(trustFlow(&#123;<br/>
                &nbsp;&nbsp;apiKey: process.env.<span style={{ color: '#FFF' }}>TRUSTFLOW_KEY</span>,<br/>
                &nbsp;&nbsp;mode: <span style={{ color: '#A0AEC0' }}>'autonomous'</span><br/>
                &#125;));
              </div>
            </div>
          </FadeIn>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '3rem', justifyContent: 'center' }}>
            {[
              { icon: Cpu, title: 'Stream Ingestion', desc: 'Logs are heavily encrypted and shipped via Kafka.' },
              { icon: Fingerprint, title: 'UEBA Profiling', desc: 'Dynamic baselines built on User & Entity Behavior Analytics.' },
              { icon: Command, title: 'Autonomous Action', desc: 'SOAR playbooks execute instantly if risk exceeds threshold.' }
            ].map((step, i) => (
              <FadeIn key={i} delay={i * 0.15} style={{ display: 'flex', gap: '1.5rem', alignItems: 'flex-start' }}>
                <div style={{ width: '56px', height: '56px', borderRadius: '12px', background: THEME.bgCard, border: `1px solid ${THEME.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, boxShadow: 'inset 0 1px 1px rgba(255,255,255,0.05)' }}>
                  <step.icon size={24} color="#FFF" />
                </div>
                <div>
                  <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', color: THEME.textMuted, marginBottom: '0.5rem', letterSpacing: '0.05em' }}>0{i + 1}</div>
                  <h4 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.15rem', fontWeight: 500, color: THEME.textMain, marginBottom: '0.5rem' }}>{step.title}</h4>
                  <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6 }}>{step.desc}</p>
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function Contact() {
  const [form, setForm] = useState({ email: '' });
  const [status, setStatus] = useState('idle');

  const handleSubmit = (e) => {
    e.preventDefault();
    setStatus('sending');
    setTimeout(() => setStatus('success'), 1500);
  };

  return (
    <section id="contact" style={{ padding: '10rem 5vw', position: 'relative', overflow: 'hidden' }}>
      {/* Animated Glowing Orb Background */}
      <div style={{ position: 'absolute', bottom: '-50%', left: '50%', transform: 'translateX(-50%)', width: '1000px', height: '1000px', background: 'radial-gradient(circle, rgba(255,255,255,0.05) 0%, transparent 60%)', filter: 'blur(50px)', pointerEvents: 'none' }} />
      
      <div style={{ maxWidth: '600px', margin: '0 auto', textAlign: 'center', position: 'relative', zIndex: 10 }}>
        <FadeIn>
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '64px', height: '64px', borderRadius: '50%', border: `1px solid ${THEME.border}`, background: THEME.bgCard, marginBottom: '2rem' }}>
            <Lock size={28} color="#FFF" />
          </div>
          <h2 style={{ fontFamily: '"Inter", sans-serif', fontSize: 'clamp(2.5rem, 4vw, 3.5rem)', fontWeight: 500, letterSpacing: '-0.03em', marginBottom: '1.5rem' }}>
            Ready to secure your stack?
          </h2>
          <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.1rem', color: THEME.textMuted, marginBottom: '3rem', lineHeight: 1.6 }}>
            Deploy TrustFlow on your infrastructure today or contact sales for enterprise licensing.
          </p>
          
          <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.5rem', maxWidth: '450px', margin: '0 auto', position: 'relative' }}>
            <input 
              type="email" required value={form.email} onChange={e => setForm({email: e.target.value})}
              placeholder="name@company.com"
              style={{ 
                flex: 1, background: THEME.bgCard, border: `1px solid ${THEME.border}`, 
                borderRadius: '8px', padding: '1rem 1.25rem', color: THEME.textMain, 
                fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', outline: 'none',
                transition: 'border-color 0.3s ease'
              }}
            />
            <Button style={{ padding: '0 2rem' }}>{status === 'idle' ? 'Request Access' : status === 'sending' ? 'Sending...' : 'Received'}</Button>
          </form>
        </FadeIn>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer style={{ padding: '5rem 5vw 3rem', borderTop: `1px solid ${THEME.border}`, background: '#020202' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '4rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '3rem' }}>
          <div style={{ maxWidth: '300px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <Shield size={22} color="#FFFFFF" strokeWidth={2.5} />
              <span style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.1rem', fontWeight: 600, letterSpacing: '-0.02em', color: THEME.textMain }}>
                TrustFlow
              </span>
            </div>
            <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.9rem', color: THEME.textMuted, lineHeight: 1.6 }}>
              Enterprise AI defense platform. Engineered for zero trust architectures and high-velocity hostile environments.
            </p>
          </div>
          
          <div style={{ display: 'flex', gap: '5rem', flexWrap: 'wrap' }}>
            {[
              { title: 'Platform', links: ['ML Ensemble', 'Threat Graph', 'SOAR Engine', 'Compliance'] },
              { title: 'Resources', links: ['Documentation', 'API Reference', 'SDK Downloads', 'System Status'] },
              { title: 'Company', links: ['About', 'Blog', 'Privacy Policy', 'Terms of Service'] }
            ].map((col) => (
              <div key={col.title}>
                <div style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.9rem', fontWeight: 500, color: THEME.textMain, marginBottom: '1.25rem' }}>{col.title}</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {col.links.map(l => (
                    <a key={l} href="#" style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.9rem', color: THEME.textMuted, textDecoration: 'none', transition: 'color 0.2s' }} className="nav-link">{l}</a>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', paddingTop: '2.5rem', borderTop: `1px solid ${THEME.border}` }}>
          <div style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.85rem', color: THEME.textMuted }}>
            © 2026 TrustFlow. All rights reserved.
          </div>
          <div style={{ display: 'flex', gap: '1.25rem' }}>
            <a href="#" className="nav-link"><Github size={20} /></a>
            <a href="#" className="nav-link"><Twitter size={20} /></a>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default function LandingPage() {
  return (
    <div style={{ background: THEME.bg, minHeight: '100vh', color: THEME.textMain, overflowX: 'hidden' }}>
      <Header />
      <main>
        <Hero />
        <BentoGrid />
        <Metrics />
        <Process />
        <Contact />
      </main>
      <Footer />

      <style>{`
        /* Global Reset & Base */
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; font-size: 16px; }
        body { background: ${THEME.bg}; overflow-x: hidden; }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: ${THEME.bg}; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #555; }

        /* Component Hover States */
        .btn-outline:hover { background: rgba(255,255,255,0.05); }
        .btn-primary:hover .btn-glow { left: 100%; transition: 0.5s; }
        .nav-link:hover { color: #FFFFFF !important; }

        /* Perspective Grid Background */
        .spatial-grid-bg {
          position: absolute;
          inset: -100%;
          background-image: 
            linear-gradient(to right, rgba(255,255,255,0.03) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255,255,255,0.03) 1px, transparent 1px);
          background-size: 50px 50px;
          transform: perspective(1000px) rotateX(60deg) translateY(-100px) translateZ(-200px);
          animation: gridMove 20s linear infinite;
          pointer-events: none;
          z-index: 0;
        }
        @keyframes gridMove {
          0% { transform: perspective(1000px) rotateX(60deg) translateY(0) translateZ(-200px); }
          100% { transform: perspective(1000px) rotateX(60deg) translateY(50px) translateZ(-200px); }
        }

        /* 3D Bento Grid Elements */
        .bento-card-wrapper {
          position: relative;
        }
        .bento-card {
          background: ${THEME.bgCard};
          border-radius: 16px;
          position: relative;
          height: 100%;
          border: 1px solid transparent;
          transition: border-color 0.3s ease;
          overflow: hidden;
        }
        .bento-card-wrapper:hover .bento-card {
          border-color: rgba(255,255,255,0.02);
        }
        
        /* The border glow effect using an inset mask */
        .bento-border-glow {
          position: absolute;
          inset: 0;
          border-radius: 16px;
          padding: 1px;
          -webkit-mask: 
            linear-gradient(#fff 0 0) content-box, 
            linear-gradient(#fff 0 0);
          -webkit-mask-composite: xor;
          mask-composite: exclude;
          pointer-events: none;
          opacity: 0;
          transition: opacity 0.3s ease;
        }

        input:focus {
          border-color: rgba(255,255,255,0.3) !important;
        }

        .desktop-nav {
          display: none;
        }

        /* Threat Operations Console Animations */
        @keyframes pulse {
          0% { opacity: 0.4; }
          50% { opacity: 1; }
          100% { opacity: 0.4; }
        }
        
        .node-alert-flash {
          animation: flashRed 1s infinite alternate;
        }
        @keyframes flashRed {
          0% { stroke: #333; fill: #0A0A0A; }
          100% { stroke: #FF5252; fill: rgba(255,82,82,0.15); }
        }
        
        .pulse-alert {
          animation: alertPulse 1.2s infinite;
        }
        @keyframes alertPulse {
          0% { transform: scale(1); opacity: 0.8; }
          50% { transform: scale(1.1); opacity: 1; }
          100% { transform: scale(1); opacity: 0.8; }
        }
        
        .spin-animation {
          animation: rotateSpin 1.5s linear infinite;
        }
        @keyframes rotateSpin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        .radar-sweep {
          position: absolute;
          background: conic-gradient(from 0deg, rgba(255,255,255,0.015) 0deg, rgba(0,230,118,0.04) 180deg, transparent 360deg);
          animation: radarRot 8s linear infinite;
        }
        @keyframes radarRot {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        @media (max-width: 900px) {
          .console-layout {
            flex-direction: column !important;
            height: auto !important;
          }
          .terminal-logs {
            border-right: none !important;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            height: 250px !important;
          }
          .network-map {
            height: 300px !important;
            padding: 1.5rem !important;
          }
        }

        /* Responsive Utilities */
        @media (min-width: 768px) {
          .desktop-nav { display: flex !important; }
          .col-span-2 { grid-column: span 2; }
          .col-span-3 { grid-column: span 3; }
        }
        @media (max-width: 768px) {
          .hidden-mobile { display: none !important; }
          .bento-grid { grid-template-columns: 1fr !important; }
          .responsive-split { grid-template-columns: 1fr !important; gap: 3rem !important; }
          .spatial-grid-bg { display: none; }
        }
      `}</style>
    </div>
  );
}
