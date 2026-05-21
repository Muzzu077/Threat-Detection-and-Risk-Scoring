import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useScroll, useTransform } from 'framer-motion';
import {
  Shield, Activity, Zap, Cpu, Lock, ArrowRight, Github, Twitter,
  BarChart3, FileSearch, Radar, Workflow, Fingerprint, Terminal
} from 'lucide-react';
import LineWaves from '../components/ReactBits/LineWaves';
import DecryptedText from '../components/ReactBits/DecryptedText';
import SpotlightCard from '../components/ReactBits/SpotlightCard';
import './LandingPage.css';

/* ═══ Fade-In Wrapper ═══════════════════════════════════════════════ */
const FadeIn = ({ children, delay = 0, className = '' }) => (
  <motion.div
    initial={{ opacity: 0, y: 28 }}
    whileInView={{ opacity: 1, y: 0 }}
    viewport={{ once: true, margin: '-60px' }}
    transition={{ duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] }}
    className={className}
  >
    {children}
  </motion.div>
);

/* ═══ Navigation ════════════════════════════════════════════════════ */
function Nav() {
  const navigate = useNavigate();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 30);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <nav className={`lp-nav ${scrolled ? 'scrolled' : ''}`}>
      <div className="lp-nav-logo" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
        <div className="lp-nav-logo-icon"><Shield size={18} /></div>
        <span>TrustFlow</span>
      </div>

      <ul className="lp-nav-links">
        {['Features', 'Process', 'Contact'].map(item => (
          <li key={item}>
            <a href={`#${item.toLowerCase()}`}>{item}</a>
          </li>
        ))}
      </ul>

      <div className="lp-nav-actions">
        <button className="lp-btn lp-btn-ghost" onClick={() => navigate('/login')}>Log In</button>
        <button className="lp-btn lp-btn-primary" onClick={() => navigate('/register')}>
          Get Started <ArrowRight size={15} />
        </button>
      </div>
    </nav>
  );
}

/* ═══ Hero Section ══════════════════════════════════════════════════ */
function Hero() {
  const navigate = useNavigate();

  return (
    <section className="lp-hero">
      <div className="lp-hero-waves">
        <LineWaves
          speed={0.2}
          innerLineCount={28}
          outerLineCount={32}
          warpIntensity={0.8}
          rotation={-30}
          edgeFadeWidth={0.0}
          colorCycleSpeed={0.6}
          brightness={0.15}
          color1="#4A5D4F"
          color2="#78716C"
          color3="#A8A29E"
          enableMouseInteraction={true}
          mouseInfluence={1.5}
        />
      </div>
      <div className="lp-hero-gradient" />

      <div className="lp-hero-content">
        <FadeIn>
          <div className="lp-hero-badge">
            <div className="lp-hero-badge-dot" />
            <span>TrustFlow v2.0 — Now with Autonomous SOAR</span>
          </div>
        </FadeIn>

        <FadeIn delay={0.1}>
          <h1>
            <DecryptedText text="Secure Your Infra" animateOn="view" speed={40} maxIterations={8} />
            <br />
            At the Speed of <em>Thought.</em>
          </h1>
        </FadeIn>

        <FadeIn delay={0.2}>
          <p className="lp-hero-sub">
            An autonomous SOC platform that ingests logs, detects zero-day threats
            with an ML ensemble engine, and executes SOAR playbooks in under 200ms.
          </p>
        </FadeIn>

        <FadeIn delay={0.3}>
          <div className="lp-hero-actions">
            <button className="lp-btn lp-btn-primary" onClick={() => navigate('/register')}>
              Start Deploying <ArrowRight size={15} />
            </button>
            <button
              className="lp-btn lp-btn-outline"
              onClick={() => document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })}
            >
              <Terminal size={15} /> Explore Platform
            </button>
          </div>
        </FadeIn>
      </div>
    </section>
  );
}

/* ═══ Stats Bar ═════════════════════════════════════════════════════ */
function Stats() {
  const stats = [
    { value: '<150ms', label: 'Detection Latency' },
    { value: '97.2%', label: 'ML Accuracy' },
    { value: '1.2B+', label: 'Threats Analyzed' },
    { value: '99.99%', label: 'Uptime SLA' },
  ];

  return (
    <section className="lp-stats">
      <FadeIn>
        <div className="lp-stats-inner">
          {stats.map((s, i) => (
            <div className="lp-stat" key={i}>
              <div className="lp-stat-value">{s.value}</div>
              <div className="lp-stat-label">{s.label}</div>
            </div>
          ))}
        </div>
      </FadeIn>
    </section>
  );
}

/* ═══ Features Grid ═════════════════════════════════════════════════ */
function Features() {
  const features = [
    {
      icon: Cpu,
      title: 'ML Ensemble Engine',
      desc: 'Dual-pipeline threat classification with LightGBM and XGBoost across 15 distinct attack vectors.',
      wide: true,
    },
    {
      icon: Zap,
      title: 'SOAR Automation',
      desc: 'Millisecond playbook execution — IP blocking, rate limiting, and subnet isolation triggered autonomously.',
    },
    {
      icon: BarChart3,
      title: 'SOC 2 & ISO 27001',
      desc: 'Continuous compliance tracking with audit-ready reports generated dynamically.',
    },
    {
      icon: Radar,
      title: 'Live Threat Topography',
      desc: 'Real-time spatial visualization mapping adversary lateral movement to MITRE ATT&CK kill chains.',
      wide: true,
    },
    {
      icon: Fingerprint,
      title: 'UEBA Profiling',
      desc: 'Dynamic behavioral baselines built on user and entity analytics for insider threat detection.',
    },
    {
      icon: FileSearch,
      title: 'Threat Intelligence',
      desc: 'Multi-feed OSINT enrichment from AbuseIPDB, VirusTotal, and OTX with STIX/TAXII integration.',
    },
  ];

  return (
    <section className="lp-features" id="features">
      <FadeIn>
        <div className="lp-section-label">Platform</div>
        <h2 className="lp-section-title">Architecture that thinks in three dimensions</h2>
        <p className="lp-section-desc">
          Six integrated defense layers working in concert to detect, classify, and neutralize
          threats before they reach your assets.
        </p>
      </FadeIn>

      <div className="lp-features-grid">
        {features.map((f, i) => (
          <FadeIn key={i} delay={i * 0.08} className={f.wide ? 'lp-feature-card wide' : ''}>
            <SpotlightCard
              spotlightColor="rgba(74, 93, 79, 0.08)"
              borderColor="rgba(255, 255, 255, 0.5)"
              style={{
                background: 'var(--lp-bg-card)',
                backdropFilter: 'blur(16px)',
                border: '1px solid var(--lp-border-light)',
                borderRadius: 'var(--lp-radius)',
                height: '100%',
              }}
            >
              <div className="lp-feature-card" style={{ border: 'none', background: 'transparent' }}>
                <div className="lp-feature-icon"><f.icon size={22} /></div>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
              </div>
            </SpotlightCard>
          </FadeIn>
        ))}
      </div>
    </section>
  );
}

/* ═══ How It Works ══════════════════════════════════════════════════ */
function HowItWorks() {
  const steps = [
    {
      icon: Workflow,
      title: 'Stream Ingestion',
      desc: 'Encrypted log streams shipped via Kafka at 140K+ events per second with zero lag.',
    },
    {
      icon: Cpu,
      title: 'ML Classification',
      desc: 'Neural ensemble analyzes each event across 15 threat vectors with 97.2% accuracy.',
    },
    {
      icon: Fingerprint,
      title: 'UEBA Profiling',
      desc: 'Dynamic behavioral baselines detect anomalous patterns unique to each user and entity.',
    },
    {
      icon: Zap,
      title: 'Autonomous Response',
      desc: 'SOAR playbooks execute remediation actions in under 200ms — before analysts receive alerts.',
    },
  ];

  return (
    <section className="lp-how" id="process">
      <div className="lp-how-inner">
        <div>
          <FadeIn>
            <div className="lp-section-label">Process</div>
            <h2 className="lp-section-title">Drop-in integration, instant protection</h2>
            <p className="lp-section-desc">
              TrustFlow was built when our offensive security team recognized the latency
              in traditional SIEM platforms. We engineered an autonomous layer that remediates
              threats before human analysts even see the alert.
            </p>
          </FadeIn>

          <FadeIn delay={0.2}>
            <div className="lp-terminal">
              <div className="lp-terminal-bar">
                <div className="lp-terminal-dot" style={{ background: '#EF4444' }} />
                <div className="lp-terminal-dot" style={{ background: '#F59E0B' }} />
                <div className="lp-terminal-dot" style={{ background: '#22C55E' }} />
              </div>
              <div className="lp-terminal-code">
                <span className="kw">import</span> {'{ trustFlow }'} <span className="kw">from</span> <span className="str">'@trustflow/node'</span>;<br /><br />
                app.<span className="fn">use</span>(trustFlow({'{'}<br />
                &nbsp;&nbsp;apiKey: process.env.<span className="val">TRUSTFLOW_KEY</span>,<br />
                &nbsp;&nbsp;mode: <span className="str">'autonomous'</span><br />
                {'}'}));
              </div>
            </div>
          </FadeIn>
        </div>

        <div className="lp-how-steps">
          {steps.map((step, i) => (
            <FadeIn key={i} delay={i * 0.12}>
              <div className="lp-step">
                <div className="lp-step-num">0{i + 1}</div>
                <div>
                  <h4>{step.title}</h4>
                  <p>{step.desc}</p>
                </div>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ═══ CTA Section ═══════════════════════════════════════════════════ */
function CTA() {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('idle');

  const handleSubmit = (e) => {
    e.preventDefault();
    setStatus('sending');
    setTimeout(() => setStatus('done'), 1500);
  };

  return (
    <section className="lp-cta" id="contact">
      <div className="lp-cta-orb" />
      <div className="lp-cta-inner">
        <FadeIn>
          <div style={{ marginBottom: '2rem' }}>
            <div className="lp-nav-logo-icon" style={{ margin: '0 auto 1.5rem', width: 56, height: 56, borderRadius: 16 }}>
              <Lock size={24} />
            </div>
          </div>
          <h2>Ready to secure your infrastructure?</h2>
          <p>
            Deploy TrustFlow today or contact our team for enterprise licensing
            and dedicated support.
          </p>
          <form className="lp-cta-form" onSubmit={handleSubmit}>
            <input
              type="email"
              required
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="name@company.com"
            />
            <button className="lp-btn lp-btn-primary" type="submit">
              {status === 'idle' ? 'Request Access' : status === 'sending' ? 'Sending...' : 'Received ✓'}
            </button>
          </form>
        </FadeIn>
      </div>
    </section>
  );
}

/* ═══ Footer ════════════════════════════════════════════════════════ */
function Footer() {
  return (
    <footer className="lp-footer">
      <div className="lp-footer-inner">
        <div className="lp-footer-top">
          <div className="lp-footer-brand">
            <div className="lp-nav-logo">
              <div className="lp-nav-logo-icon"><Shield size={18} /></div>
              <span>TrustFlow</span>
            </div>
            <p>Enterprise AI defense platform engineered for zero trust architectures and high-velocity hostile environments.</p>
          </div>

          <div className="lp-footer-cols">
            {[
              { title: 'Platform', links: ['ML Ensemble', 'Threat Graph', 'SOAR Engine', 'Compliance'] },
              { title: 'Resources', links: ['Documentation', 'API Reference', 'SDK Downloads', 'Status'] },
              { title: 'Company', links: ['About', 'Blog', 'Privacy', 'Terms'] },
            ].map(col => (
              <div className="lp-footer-col" key={col.title}>
                <h5>{col.title}</h5>
                {col.links.map(l => <a key={l} href="#">{l}</a>)}
              </div>
            ))}
          </div>
        </div>

        <div className="lp-footer-bottom">
          <span>© 2026 TrustFlow. All rights reserved.</span>
          <div className="lp-footer-socials">
            <a href="#"><Github size={18} /></a>
            <a href="#"><Twitter size={18} /></a>
          </div>
        </div>
      </div>
    </footer>
  );
}

/* ═══ Main Landing Page ═════════════════════════════════════════════ */
export default function LandingPage() {
  return (
    <div className="landing-root">
      <Nav />
      <main>
        <Hero />
        <Stats />
        <Features />
        <HowItWorks />
        <CTA />
      </main>
      <Footer />
    </div>
  );
}
