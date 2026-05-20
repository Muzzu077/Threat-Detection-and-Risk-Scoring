import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
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
import Aurora from '../components/ReactBits/Aurora';
import ShinyText from '../components/ReactBits/ShinyText';
import SplitText from '../components/ReactBits/SplitText';

/* ─── Aesthetics & Theme ────────────────────────────────────────────────── */
const THEME = {
  bg: '#F8FAFC',               // Clean Slate 50
  bgCard: 'rgba(255, 255, 255, 0.75)', // Glassmorphic Frosted White
  bgCardHover: 'rgba(255, 255, 255, 0.95)',
  border: 'rgba(15, 23, 42, 0.06)',     // Slate-900 border at low opacity
  borderHover: 'rgba(79, 70, 229, 0.15)', // Indigo glow border
  textMain: '#0F172A',          // Slate-900 sharp primary
  textMuted: '#475569',         // Slate-600 readable secondary
  accent: '#4F46E5',            // Cyber Indigo
  accentLight: '#EEF2FF',       // Very light indigo backdrop
  success: '#10B981',           // Emerald
  danger: '#EF4444',            // Crimson
  warning: '#F59E0B',           // Amber
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
        background: isPrimary ? THEME.accent : 'transparent',
        color: isPrimary ? '#FFFFFF' : THEME.textMain,
        border: isPrimary ? `1px solid ${THEME.accent}` : `1px solid ${THEME.border}`,
        borderRadius: '8px',
        fontFamily: '"Inter", sans-serif',
        fontSize: '0.875rem',
        fontWeight: 500,
        cursor: 'pointer',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.5rem',
        transition: 'all 0.3s ease',
        boxShadow: isPrimary ? '0 4px 20px rgba(79, 70, 229, 0.25)' : 'none',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      <span style={{ position: 'relative', zIndex: 2, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        {children}
        {Icon && <Icon size={16} />}
      </span>
      {isPrimary && (
        <div className="btn-glow" style={{ position: 'absolute', top: 0, left: '-100%', width: '100%', height: '100%', background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent)', transition: '0.5s' }} />
      )}
    </motion.button>
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
      background: scrolled ? 'rgba(255, 255, 255, 0.75)' : 'transparent',
      backdropFilter: scrolled ? 'blur(16px)' : 'none',
      borderBottom: scrolled ? `1px solid ${THEME.border}` : '1px solid transparent',
      transition: 'all 0.4s ease'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }} onClick={() => window.scrollTo(0,0)}>
        <div style={{
          width: '32px', height: '32px', borderRadius: '8px', 
          background: `linear-gradient(135deg, ${THEME.accent}, #3B82F6)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 4px 10px rgba(79, 70, 229, 0.2)'
        }}>
          <Shield size={18} color="#FFFFFF" strokeWidth={2.5} />
        </div>
        <span style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.15rem', fontWeight: 600, letterSpacing: '-0.02em', color: THEME.textMain }}>
          TrustFlow
        </span>
      </div>

      <nav style={{ gap: '2.5rem' }} className="desktop-nav">
        {['Platform', 'Integrations', 'Process', 'Contact'].map((item) => (
          <a key={item} href={`#${item.toLowerCase()}`} style={{
            fontFamily: '"Inter", sans-serif', fontSize: '0.875rem', fontWeight: 500, color: THEME.textMuted, textDecoration: 'none',
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
  const [riskLevel, setRiskLevel] = useState(12);
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
    setRiskLevel(98);
    
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
      setRiskLevel(8);
      setLogs(prev => [
        ...prev,
        { id: Date.now() + 3, type: 'success', text: 'SUCCESS // Subnet 10.0.4.0 isolated, risk mitigated in 142ms.' }
      ]);
    }, 4800);
  };

  const resetAttack = () => {
    setAttackState('idle');
    setRiskLevel(12);
    setLogs([
      { id: Date.now(), type: 'info', text: 'SYS // Operations console telemetry reset.' },
      { id: Date.now() + 1, type: 'info', text: 'SYS // Stream ingestion engine active.' },
      { id: Date.now() + 2, type: 'success', text: 'SLA // Telemetry stabilized at 112ms.' }
    ]);
  };

  // Node Map Colors based on state
  const getNodeColor = (nodeId) => {
    if (attackState === 'secured') return THEME.success;
    if (attackState === 'mitigating') {
      if (nodeId === 'soar') return '#3B82F6';
      return THEME.textMuted;
    }
    if (attackState === 'triggered' || attackState === 'detecting') {
      if (nodeId === 'subnet') return THEME.danger;
      return '#CBD5E1';
    }
    return THEME.textMain;
  };

  const getLineColor = (from, to) => {
    if (attackState === 'secured') return THEME.success;
    if (attackState === 'mitigating') return '#3B82F6';
    if (attackState === 'triggered' || attackState === 'detecting') {
      if (from === 'subnet' || to === 'subnet') return THEME.danger;
      return '#E2E8F0';
    }
    return 'rgba(15, 23, 42, 0.06)';
  };

  return (
    <SpotlightCard 
      spotlightColor="rgba(79, 70, 229, 0.04)" 
      borderColor={THEME.border}
      style={{
        width: '100%',
        background: 'rgba(255, 255, 255, 0.75)',
        backdropFilter: 'blur(20px)',
        boxShadow: '0 40px 80px rgba(15, 23, 42, 0.05), 0 0 1px rgba(0, 0, 0, 0.08)',
        borderRadius: '20px',
        overflow: 'hidden'
      }}
    >
      {/* Console Top Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '1rem 1.5rem', borderBottom: `1px solid ${THEME.border}`,
        background: 'rgba(15, 23, 42, 0.02)'
      }}>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: THEME.danger }} />
          <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: THEME.warning }} />
          <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: THEME.success }} />
          <span style={{ 
            marginLeft: '1rem', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem', 
            color: THEME.textMuted, letterSpacing: '0.05em' 
          }}>
            TRUSTFLOW // THREAT_OPS_CENTER v2.0
          </span>
        </div>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <div style={{
            fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', 
            background: 'rgba(15, 23, 42, 0.03)', padding: '0.25rem 0.6rem', 
            borderRadius: '6px', border: `1px solid ${THEME.border}`,
            color: attackState === 'triggered' || attackState === 'detecting' ? THEME.danger : THEME.success,
            display: 'flex', alignItems: 'center', gap: '6px',
            fontWeight: 500
          }}>
            <div style={{ 
              width: '6px', height: '6px', borderRadius: '50%', 
              background: attackState === 'triggered' || attackState === 'detecting' ? THEME.danger : THEME.success,
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
          flex: '1 1 500px', borderRight: `1px solid ${THEME.border}`,
          padding: '1.5rem', background: 'rgba(248, 250, 252, 0.3)', overflowY: 'auto',
          display: 'flex', flexDirection: 'column', gap: '0.8rem', height: '100%'
        }} className="terminal-logs">
          <div style={{
            fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', 
            color: THEME.textMuted, borderBottom: `1px solid ${THEME.border}`,
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
                color: log.type === 'danger' ? THEME.danger : log.type === 'warning' ? THEME.warning : log.type === 'success' ? '#059669' : THEME.textMain
              }}>
                <span style={{ color: '#94A3B8', userSelect: 'none' }}>&gt;</span>
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
          position: 'relative', height: '100%', background: 'rgba(248, 250, 252, 0.1)'
        }} className="network-map">
          
          <div style={{
            position: 'absolute', top: '1.5rem', left: '1.5rem',
            fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', color: THEME.textMuted
          }}>
            THREAT TOPOGRAPHY VISUALIZER
          </div>

          {/* Radar sweeping backdrop */}
          <div className="radar-sweep" style={{
            position: 'absolute', width: '280px', height: '280px',
            borderRadius: '50%', border: '1px solid rgba(15, 23, 42, 0.02)',
            pointerEvents: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <div style={{ width: '200px', height: '200px', borderRadius: '50%', border: '1px solid rgba(15, 23, 42, 0.015)' }} />
            <div style={{ width: '100px', height: '100px', borderRadius: '50%', border: '1px solid rgba(15, 23, 42, 0.008)' }} />
          </div>

          {/* SVG Topology Nodes and Connections */}
          <svg width="340" height="280" style={{ position: 'relative', zIndex: 5 }}>
            <defs>
              <linearGradient id="glow-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor={THEME.accent} />
                <stop offset="100%" stopColor="#3B82F6" />
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
                <circle r="3.5" fill={THEME.accent}>
                  <animateMotion dur="4s" repeatCount="indefinite" path="M60,140 L170,140" />
                </circle>
                <circle r="3.5" fill={THEME.accent}>
                  <animateMotion dur="3s" repeatCount="indefinite" path="M170,140 L170,50" />
                </circle>
                <circle r="3.5" fill={THEME.accent}>
                  <animateMotion dur="5s" repeatCount="indefinite" path="M170,140 L280,100" />
                </circle>
              </>
            )}

            {attackState === 'triggered' && (
              <circle r="4" fill={THEME.danger}>
                <animateMotion dur="1s" repeatCount="indefinite" path="M280,100 L170,140" />
              </circle>
            )}

            {attackState === 'mitigating' && (
              <>
                <circle r="4.5" fill="#3B82F6">
                  <animateMotion dur="0.8s" repeatCount="indefinite" path="M170,230 L280,100" />
                </circle>
                <circle r="4.5" fill="#3B82F6">
                  <animateMotion dur="0.8s" repeatCount="indefinite" path="M170,230 L170,140" />
                </circle>
              </>
            )}

            {/* Nodes */}
            {/* Kafka Ingestion Node */}
            <circle cx="60" cy="140" r="16" fill="#FFFFFF" stroke={getNodeColor('kafka')} strokeWidth="2" style={{ transition: 'all 0.5s', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.04))' }} />
            <text x="60" y="143" textAnchor="middle" fill={THEME.textMuted} fontSize="9" fontWeight="600" fontFamily="monospace">KFK</text>
            
            {/* Auth Server Node */}
            <circle cx="170" cy="50" r="16" fill="#FFFFFF" stroke={getNodeColor('auth')} strokeWidth="2" style={{ transition: 'all 0.5s', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.04))' }} />
            <text x="170" y="53" textAnchor="middle" fill={THEME.textMuted} fontSize="9" fontWeight="600" fontFamily="monospace">ATH</text>

            {/* Gateway Central Node */}
            <circle cx="170" cy="140" r="22" fill={THEME.textMain} stroke={getNodeColor('gateway')} strokeWidth="2.5" style={{ transition: 'all 0.5s', filter: 'drop-shadow(0 4px 8px rgba(15,23,42,0.15))' }} />
            <text x="170" y="144" textAnchor="middle" fill="#FFFFFF" fontSize="10" fontWeight="600" fontFamily="monospace">GTW</text>

            {/* Vulnerable subnet/DB Cluster Node */}
            <circle cx="280" cy="100" r="20" fill="#FFFFFF" stroke={getNodeColor('subnet')} strokeWidth="2" className={attackState === 'triggered' || attackState === 'detecting' ? 'node-alert-flash' : ''} style={{ transition: 'all 0.5s', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.04))' }} />
            <text x="280" y="103" textAnchor="middle" fill={attackState === 'triggered' || attackState === 'detecting' ? THEME.danger : THEME.textMuted} fontSize="10" fontWeight="600" fontFamily="monospace">SUB</text>

            {/* SOAR Playbook Mitigator Node */}
            <circle cx="170" cy="230" r="18" fill="#FFFFFF" stroke={getNodeColor('soar')} strokeWidth="2" style={{ transition: 'all 0.5s', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.04))' }} />
            <text x="170" y="233" textAnchor="middle" fill={THEME.textMuted} fontSize="10" fontWeight="600" fontFamily="monospace">SAR</text>
          </svg>

          {/* Attack Alert Banner */}
          {(attackState === 'triggered' || attackState === 'detecting') && (
            <div style={{
              position: 'absolute', bottom: '2rem', background: 'rgba(239, 68, 68, 0.08)',
              border: `1px solid ${THEME.danger}`, color: THEME.danger, padding: '0.5rem 1rem',
              borderRadius: '8px', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem',
              display: 'flex', alignItems: 'center', gap: '8px', zIndex: 10,
              boxShadow: '0 10px 20px rgba(239, 68, 68, 0.1)',
              fontWeight: 500
            }}>
              <AlertTriangle size={16} className="pulse-alert" />
              <span>ALERT // INTRUSION DETECTED IN SUB_4</span>
            </div>
          )}

          {attackState === 'secured' && (
            <div style={{
              position: 'absolute', bottom: '2rem', background: 'rgba(16, 185, 129, 0.08)',
              border: `1px solid ${THEME.success}`, color: '#059669', padding: '0.5rem 1rem',
              borderRadius: '8px', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem',
              display: 'flex', alignItems: 'center', gap: '8px', zIndex: 10,
              fontWeight: 500
            }}>
              <CheckCircle2 size={16} />
              <span>THREAT NEUTRALIZED IN 142MS</span>
            </div>
          )}
        </div>
      </div>

      {/* Control Deck / Telemetry Summary */}
      <div style={{
        display: 'flex', borderTop: `1px solid ${THEME.border}`,
        background: 'rgba(15, 23, 42, 0.01)', padding: '1.25rem 1.5rem',
        justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1.5rem'
      }}>
        <div style={{ display: 'flex', gap: '2.5rem', flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', color: THEME.textMuted, textTransform: 'uppercase', marginBottom: '0.25rem', fontWeight: 600 }}>ACTIVE RISK INDEX</div>
            <div style={{ 
              fontFamily: '"JetBrains Mono", monospace', fontSize: '1.25rem', fontWeight: 600,
              color: riskLevel > 50 ? THEME.danger : '#059669', transition: 'color 0.5s'
            }}>
              {riskLevel}%
            </div>
          </div>
          <div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', color: THEME.textMuted, textTransform: 'uppercase', marginBottom: '0.25rem', fontWeight: 600 }}>INGESTION RATE</div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '1.25rem', fontWeight: 600, color: THEME.textMain }}>
              142,504 <span style={{ fontSize: '0.8rem', color: THEME.textMuted, fontWeight: 500 }}>EPS</span>
            </div>
          </div>
          <div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', color: THEME.textMuted, textTransform: 'uppercase', marginBottom: '0.25rem', fontWeight: 600 }}>LATENCY SLA</div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '1.25rem', fontWeight: 600, color: '#059669' }}>
              &lt; 150ms
            </div>
          </div>
        </div>

        {/* Action Button Deck */}
        <div style={{ display: 'flex', gap: '10px' }}>
          {attackState === 'idle' ? (
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={triggerAttack}
              style={{
                background: THEME.danger, color: '#FFFFFF', border: 'none',
                borderRadius: '8px', padding: '0.65rem 1.25rem', cursor: 'pointer',
                fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem', fontWeight: 600,
                display: 'inline-flex', alignItems: 'center', gap: '8px',
                boxShadow: '0 4px 15px rgba(239, 68, 68, 0.2)',
                transition: 'all 0.2s ease'
              }}
            >
              <Play size={14} fill="#FFF" />
              Simulate Cyber Attack
            </motion.button>
          ) : (
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={resetAttack}
              disabled={attackState !== 'secured'}
              style={{
                background: 'rgba(15, 23, 42, 0.05)', color: attackState === 'secured' ? THEME.textMain : THEME.textMuted,
                border: `1px solid ${THEME.border}`,
                borderRadius: '8px', padding: '0.65rem 1.25rem', cursor: attackState === 'secured' ? 'pointer' : 'not-allowed',
                fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem', fontWeight: 500,
                display: 'inline-flex', alignItems: 'center', gap: '8px',
                transition: 'all 0.2s ease'
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
      {/* Aurora Ambient Fluid Glows */}
      <div style={{ position: 'absolute', inset: 0, zIndex: 0, opacity: 0.55, pointerEvents: 'none' }}>
        <Aurora colorStops={["#E0E7FF", "#F1F5F9", "#E0F2FE"]} blend={0.6} speed={0.4} />
      </div>

      {/* Modern High-Tech Grid Backplane */}
      <div className="spatial-grid-bg" />
      <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(circle at center, transparent 30%, #F8FAFC 85%)', pointerEvents: 'none', zIndex: 1 }} />

      <div style={{ position: 'relative', zIndex: 10, width: '100%', maxWidth: '850px', textAlign: 'center', marginTop: '10vh' }}>
        <FadeIn>
          <StarBorder as="div" color="rgba(79, 70, 229, 0.3)" speed="5s" thickness={1.5} style={{ borderRadius: '100px', marginBottom: '2.5rem', display: 'inline-block' }}>
            <motion.div 
              whileHover={{ scale: 1.02 }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '0.5rem', padding: '0.35rem 0.9rem',
                background: 'rgba(255, 255, 255, 0.85)', borderRadius: '100px',
                fontFamily: '"Inter", sans-serif', fontSize: '0.75rem', color: THEME.textMuted,
                cursor: 'pointer', backdropFilter: 'blur(8px)', fontWeight: 500,
                boxShadow: '0 4px 12px rgba(15, 23, 42, 0.03)'
              }}
            >
              <div className="pulse-dot" style={{ width: '6px', height: '6px', borderRadius: '50%', background: THEME.success, boxShadow: '0 0 8px #10B981' }} />
              <ShinyText text="TrustFlow v2.0 is now live" disabled={false} speed={3} />
            </motion.div>
          </StarBorder>
        </FadeIn>

        <FadeIn delay={0.1}>
          <div style={{ 
            fontFamily: '"Inter", sans-serif', fontSize: 'clamp(2.75rem, 6.5vw, 5.25rem)', 
            fontWeight: 700, color: THEME.textMain, lineHeight: 1.1, 
            letterSpacing: '-0.04em', marginBottom: '1.5rem'
          }}>
            <SplitText 
              text="Secure infrastructure at the speed of thought."
              delay={40}
              animationFrom={{ opacity: 0, transform: 'translate3d(0,25px,0)' }}
              animationTo={{ opacity: 1, transform: 'translate3d(0,0,0)' }}
              easing="easeOutCubic"
              threshold={0.2}
              rootMargin="-50px"
            />
          </div>
        </FadeIn>

        <FadeIn delay={0.2}>
          <p style={{ 
            fontFamily: '"Inter", sans-serif', fontSize: 'clamp(1rem, 1.25vw, 1.2rem)', 
            color: THEME.textMuted, maxWidth: '650px', margin: '0 auto 3rem', lineHeight: 1.6 
          }}>
            An autonomous SOC platform that ingests logs, detects zero-days with an ML ensemble, and triggers SOAR playbooks in under 200ms.
          </p>
        </FadeIn>

        <FadeIn delay={0.3} style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
          <Button onClick={() => navigate('/register')} icon={ArrowRight}>Start Deploying</Button>
          <Button variant="outline" onClick={() => document.getElementById('platform').scrollIntoView()} icon={TerminalSquare}>View Platform</Button>
        </FadeIn>
      </div>

      {/* Interactive Operations Console */}
      <FadeIn delay={0.4} style={{ width: '100%', maxWidth: '1100px', marginTop: '5rem', zIndex: 20, marginBottom: '5vh' }}>
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
          <div style={{ 
            fontFamily: '"Inter", sans-serif', fontSize: 'clamp(0.75rem, 1vw, 0.85rem)', 
            color: THEME.accent, textTransform: 'uppercase', letterSpacing: '0.1em',
            fontWeight: 600, marginBottom: '0.75rem'
          }}>
            Defense Architecture
          </div>
          <h2 style={{ fontFamily: '"Inter", sans-serif', fontSize: 'clamp(2.25rem, 4vw, 3.25rem)', fontWeight: 700, letterSpacing: '-0.03em', marginBottom: '4rem', lineHeight: 1.1, color: THEME.textMain }}>
            Engineered for <span style={{ color: THEME.textMuted }}>fraction-of-a-second</span> action.
          </h2>
        </FadeIn>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gridAutoRows: '320px', gap: '1.5rem' }} className="bento-grid">
          
          {/* Card 1 - ML Ensemble */}
          <FadeIn delay={0.1} className="col-span-2">
            <SpotlightCard spotlightColor="rgba(79, 70, 229, 0.03)" borderColor={THEME.border}>
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <div style={{
                  width: '48px', height: '48px', borderRadius: '12px', background: THEME.accentLight,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '2rem'
                }}>
                  <Brain size={24} color={THEME.accent} />
                </div>
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.4rem', fontWeight: 600, marginBottom: '0.75rem', color: THEME.textMain }}>ML Ensemble Engine</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6, maxWidth: '450px' }}>
                  Dual-pipeline classification using optimized LightGBM and XGBoost models. Detects stealthy intrusions across 15 attack vectors.
                </p>
                <div style={{ position: 'absolute', bottom: '-15%', right: '-5%', opacity: 0.02, pointerEvents: 'none', transform: 'rotate(-5deg)' }}>
                  <BarChart size={240} color={THEME.textMain} />
                </div>
              </div>
            </SpotlightCard>
          </FadeIn>

          {/* Card 2 - SOAR */}
          <FadeIn delay={0.2}>
            <SpotlightCard spotlightColor="rgba(79, 70, 229, 0.03)" borderColor={THEME.border}>
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <div style={{
                  width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(245, 158, 11, 0.08)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '2rem'
                }}>
                  <Zap size={24} color={THEME.warning} />
                </div>
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.4rem', fontWeight: 600, marginBottom: '0.75rem', color: THEME.textMain }}>SOAR Execution</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6 }}>
                  Millisecond response. Triggers customized IP blocking, environment resets, and messaging alerts autonomously.
                </p>
              </div>
            </SpotlightCard>
          </FadeIn>

          {/* Card 3 - Compliance */}
          <FadeIn delay={0.3}>
            <SpotlightCard spotlightColor="rgba(79, 70, 229, 0.03)" borderColor={THEME.border}>
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <div style={{
                  width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.08)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '2rem'
                }}>
                  <FileJson size={24} color={THEME.success} />
                </div>
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.4rem', fontWeight: 600, marginBottom: '0.75rem', color: THEME.textMain }}>SOC 2 / ISO 27001</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6 }}>
                  Continuous infrastructure tracking. Automatically builds audit-ready SOC compliance reports in seconds.
                </p>
              </div>
            </SpotlightCard>
          </FadeIn>

          {/* Card 4 - Threat Graph */}
          <FadeIn delay={0.4} className="col-span-2">
            <SpotlightCard spotlightColor="rgba(79, 70, 229, 0.03)" borderColor={THEME.border}>
              <div style={{ padding: '2.5rem', height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
                <div style={{
                  width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(59, 130, 246, 0.08)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '2rem'
                }}>
                  <Activity size={24} color="#3B82F6" />
                </div>
                <h3 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.4rem', fontWeight: 600, marginBottom: '0.75rem', color: THEME.textMain }}>Live Threat Topography</h3>
                <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', color: THEME.textMuted, lineHeight: 1.6, maxWidth: '480px' }}>
                  Real-time visual mappings tracing intrusion path coordinates. Feeds back live telemetry vectors to our incident mitigation playbook core.
                </p>
                <div style={{ position: 'absolute', bottom: '-20%', right: '5%', opacity: 0.02, pointerEvents: 'none', transform: 'rotate(10deg)' }}>
                  <Server size={220} color={THEME.textMain} />
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
    <section style={{ padding: '6rem 5vw', borderTop: `1px solid ${THEME.border}`, borderBottom: `1px solid ${THEME.border}`, background: 'rgba(255, 255, 255, 0.4)' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexWrap: 'wrap', gap: '4rem', justifyContent: 'space-between' }}>
        {[
          { label: 'Latency SLA', value: '< 150ms' },
          { label: 'Ingestion Rate', value: '142K+' },
          { label: 'Weekly Threats Blocked', value: '1.2M+' },
          { label: 'Platform Uptime', value: '99.99%' },
        ].map((metric, i) => (
          <FadeIn key={i} delay={i * 0.1} style={{ flex: '1 1 200px' }}>
            <div style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.85rem', color: THEME.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
              <div style={{ width: '6px', height: '6px', background: THEME.accent, borderRadius: '50%' }} />
              {metric.label}
            </div>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '3rem', fontWeight: 600, color: THEME.textMain, letterSpacing: '-0.03em' }}>
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
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6rem' }} className="responsive-split">
          <FadeIn>
            <div style={{ 
              fontFamily: '"Inter", sans-serif', fontSize: 'clamp(0.75rem, 1vw, 0.85rem)', 
              color: THEME.accent, textTransform: 'uppercase', letterSpacing: '0.1em',
              fontWeight: 600, marginBottom: '0.75rem'
            }}>
              Integration
            </div>
            <h2 style={{ fontFamily: '"Inter", sans-serif', fontSize: 'clamp(2.25rem, 4vw, 3.25rem)', fontWeight: 700, letterSpacing: '-0.03em', marginBottom: '1.5rem', lineHeight: 1.1, color: THEME.textMain }}>
              Integrate in <br/><span style={{ color: THEME.textMuted }}>five minutes.</span>
            </h2>
            <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.05rem', color: THEME.textMuted, lineHeight: 1.7, marginBottom: '3rem' }}>
              TrustFlow bridges the gap between raw API ingestion and autonomous security execution. Deploy our drop-in SDK directly into your node gateway layer to start streaming threat vectors to your dashboard in minutes.
            </p>
            
            {/* Terminal Window */}
            <div style={{ background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 25px 50px -12px rgba(15, 23, 42, 0.25)' }}>
              <div style={{ padding: '1rem', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', gap: '0.5rem', background: '#0A0F1D' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#475569' }} />
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#475569' }} />
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#475569' }} />
              </div>
              <div style={{ padding: '2rem', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.9rem', color: '#94A3B8', lineHeight: 1.6 }}>
                <span style={{ color: '#F43F5E' }}>import</span> &#123; trustFlow &#125; <span style={{ color: '#F43F5E' }}>from</span> <span style={{ color: '#38BDF8' }}>'@trustflow/node'</span>;<br/><br/>
                app.<span style={{ color: '#60A5FA' }}>use</span>(trustFlow(&#123;<br/>
                &nbsp;&nbsp;apiKey: process.env.<span style={{ color: '#F472B6' }}>TRUSTFLOW_KEY</span>,<br/>
                &nbsp;&nbsp;mode: <span style={{ color: '#38BDF8' }}>'autonomous'</span><br/>
                &#125;));
              </div>
            </div>
          </FadeIn>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '3rem', justifyContent: 'center' }}>
            {[
              { icon: Cpu, title: 'Stream Ingestion', desc: 'Logs are heavily parsed, structured, and pushed securely via cloud instances.' },
              { icon: Fingerprint, title: 'UEBA Behavior Analytics', desc: 'Models learn baseline operational fingerprints to capture outlier actions.' },
              { icon: Command, title: 'Autonomous Playbooks', desc: 'If active risk passes your designated limit, mitigation policies trigger instantly.' }
            ].map((step, i) => (
              <FadeIn key={i} delay={i * 0.15} style={{ display: 'flex', gap: '1.5rem', alignItems: 'flex-start' }}>
                <div style={{ 
                  width: '56px', height: '56px', borderRadius: '12px', 
                  background: 'rgba(255, 255, 255, 0.8)', border: `1px solid ${THEME.border}`, 
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, 
                  boxShadow: '0 4px 10px rgba(15,23,42,0.03)' 
                }}>
                  <step.icon size={24} color={THEME.accent} />
                </div>
                <div>
                  <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', color: THEME.accent, marginBottom: '0.5rem', letterSpacing: '0.05em', fontWeight: 600 }}>0{i + 1}</div>
                  <h4 style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.15rem', fontWeight: 600, color: THEME.textMain, marginBottom: '0.5rem' }}>{step.title}</h4>
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
      <div style={{ position: 'absolute', bottom: '-50%', left: '50%', transform: 'translateX(-50%)', width: '1000px', height: '1000px', background: 'radial-gradient(circle, rgba(79,70,229,0.04) 0%, transparent 60%)', filter: 'blur(50px)', pointerEvents: 'none' }} />
      
      <div style={{ maxWidth: '600px', margin: '0 auto', textAlign: 'center', position: 'relative', zIndex: 10 }}>
        <FadeIn>
          <div style={{ 
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', 
            width: '64px', height: '64px', borderRadius: '16px', border: `1px solid ${THEME.border}`, 
            background: '#FFFFFF', marginBottom: '2rem', boxShadow: '0 4px 12px rgba(15,23,42,0.03)' 
          }}>
            <Lock size={26} color={THEME.accent} />
          </div>
          <h2 style={{ fontFamily: '"Inter", sans-serif', fontSize: 'clamp(2.25rem, 4vw, 3.25rem)', fontWeight: 700, letterSpacing: '-0.03em', marginBottom: '1.5rem', color: THEME.textMain }}>
            Ready to secure your stack?
          </h2>
          <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.1rem', color: THEME.textMuted, marginBottom: '3rem', lineHeight: 1.6 }}>
            Connect TrustFlow to your enterprise infrastructure today or request access to our developer sandbox.
          </p>
          
          <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.75rem', maxWidth: '480px', margin: '0 auto', position: 'relative' }} className="contact-form">
            <input 
              type="email" required value={form.email} onChange={e => setForm({email: e.target.value})}
              placeholder="name@company.com"
              style={{ 
                flex: 1, background: '#FFFFFF', border: `1px solid ${THEME.border}`, 
                borderRadius: '8px', padding: '1rem 1.25rem', color: THEME.textMain, 
                fontFamily: '"Inter", sans-serif', fontSize: '0.95rem', outline: 'none',
                transition: 'border-color 0.3s ease',
                boxShadow: '0 2px 8px rgba(15,23,42,0.01)'
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
    <footer style={{ padding: '5rem 5vw 3rem', borderTop: `1px solid ${THEME.border}`, background: '#FFFFFF' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '4rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '3rem' }}>
          <div style={{ maxWidth: '320px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <div style={{
                width: '28px', height: '28px', borderRadius: '7px', 
                background: `linear-gradient(135deg, ${THEME.accent}, #3B82F6)`,
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }}>
                <Shield size={16} color="#FFFFFF" strokeWidth={2.5} />
              </div>
              <span style={{ fontFamily: '"Inter", sans-serif', fontSize: '1.1rem', fontWeight: 600, letterSpacing: '-0.02em', color: THEME.textMain }}>
                TrustFlow
              </span>
            </div>
            <p style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.9rem', color: THEME.textMuted, lineHeight: 1.6 }}>
              High-velocity enterprise AI threat defense. Engineered for zero trust compliance and high-velocity hostile environments.
            </p>
          </div>
          
          <div style={{ display: 'flex', gap: '5rem', flexWrap: 'wrap' }}>
            {[
              { title: 'Platform', links: ['ML Ensemble', 'Threat Graph', 'SOAR Engine', 'Compliance'] },
              { title: 'Resources', links: ['Documentation', 'API Reference', 'SDK Downloads', 'System Status'] },
              { title: 'Company', links: ['About', 'Blog', 'Privacy Policy', 'Terms of Service'] }
            ].map((col) => (
              <div key={col.title}>
                <div style={{ fontFamily: '"Inter", sans-serif', fontSize: '0.9rem', fontWeight: 600, color: THEME.textMain, marginBottom: '1.25rem' }}>{col.title}</div>
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
            <a href="#" className="nav-link" style={{ color: THEME.textMuted }}><Github size={20} /></a>
            <a href="#" className="nav-link" style={{ color: THEME.textMuted }}><Twitter size={20} /></a>
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
      <main style={{ position: 'relative', zIndex: 10 }}>
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
        body { background: ${THEME.bg}; overflow-x: hidden; color: ${THEME.textMain}; }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: ${THEME.bg}; }
        ::-webkit-scrollbar-thumb { background: #CBD5E1; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #94A3B8; }

        /* Component Hover States */
        .btn-outline:hover { background: rgba(15,23,42,0.04); }
        .btn-primary:hover .btn-glow { left: 100%; transition: 0.5s; }
        .nav-link:hover { color: ${THEME.accent} !important; }

        /* High-Tech Grid Backplane CSS */
        .spatial-grid-bg {
          position: absolute;
          inset: -100%;
          background-image: 
            linear-gradient(to right, rgba(15,23,42,0.02) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(15,23,42,0.02) 1px, transparent 1px);
          background-size: 60px 60px;
          transform: perspective(1000px) rotateX(60deg) translateY(-100px) translateZ(-200px);
          animation: gridMove 24s linear infinite;
          pointer-events: none;
          z-index: 1;
          opacity: 0.7;
        }
        @keyframes gridMove {
          0% { transform: perspective(1000px) rotateX(60deg) translateY(0) translateZ(-200px); }
          100% { transform: perspective(1000px) rotateX(60deg) translateY(60px) translateZ(-200px); }
        }

        input:focus {
          border-color: ${THEME.accent} !important;
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
          0% { stroke: #CBD5E1; fill: #FFFFFF; }
          100% { stroke: ${THEME.danger}; fill: rgba(239, 68, 68, 0.08); }
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
          background: conic-gradient(from 0deg, rgba(15,23,42,0.005) 0deg, rgba(79,70,229,0.02) 180deg, transparent 360deg);
          animation: radarRot 10s linear infinite;
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
            border-bottom: 1px solid ${THEME.border};
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
          .contact-form { flex-direction: column !important; }
        }
      `}</style>
    </div>
  );
}
