import { useEffect, useState } from 'react';
import { fetchComplianceReport } from '../api/client';

const SECTIONS = {
  incident_response:  { title: 'Incident Response',     icon: '⚠' },
  access_control:     { title: 'Access Control',        icon: '⚿' },
  monitoring:         { title: 'Monitoring & Logging',  icon: '◉' },
  system_operations:  { title: 'System Operations',     icon: '⌬' },
  data_segregation:   { title: 'Data Segregation',      icon: '⛁' },
};

const btnPrimary = {
  fontFamily: 'IBM Plex Mono, monospace', fontSize: 11,
  padding: '8px 16px', borderRadius: 5, border: 'none', cursor: 'pointer',
  background: 'rgba(255,255,255,0.12)', color: '#ffffff',
  letterSpacing: '0.08em', textTransform: 'uppercase',
  outline: '1px solid rgba(255,255,255,0.25)',
};

const btnTab = (active) => ({
  fontFamily: 'IBM Plex Mono, monospace', fontSize: 11,
  padding: '8px 16px', borderRadius: 5, cursor: 'pointer',
  border: `1px solid ${active ? '#7a9bb0' : 'rgba(255,255,255,0.1)'}`,
  background: active ? 'rgba(122,155,176,0.18)' : 'transparent',
  color: active ? '#7a9bb0' : '#a0a0a0',
  letterSpacing: '0.08em', textTransform: 'uppercase',
});

function EvidenceRow({ label, value }) {
  let display = value;
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    display = Object.entries(value).map(([k, v]) => `${k}: ${v}`).join(' · ');
  } else if (Array.isArray(value)) {
    display = value.join(', ');
  }
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '260px 1fr',
      padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)',
      alignItems: 'flex-start', gap: 16,
    }}>
      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
        {label.replace(/_/g, ' ')}
      </div>
      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#e8f4f8', wordBreak: 'break-word' }}>
        {String(display)}
      </div>
    </div>
  );
}

function Section({ id, body }) {
  const meta = SECTIONS[id] || { title: id, icon: '•' };
  return (
    <div style={{
      background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 10, padding: 22, marginBottom: 18,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 18 }}>{meta.icon}</span>
          <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 16, color: '#ffffff', letterSpacing: 1 }}>
            {meta.title}
          </div>
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#7a9bb0', letterSpacing: '0.08em' }}>
          {(body.controls || []).join(' · ')}
        </div>
      </div>
      {body.narrative && (
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#a0a0a0',
          lineHeight: 1.6, marginBottom: 14, padding: '10px 14px',
          background: 'rgba(255,255,255,0.02)', borderLeft: '2px solid rgba(122,155,176,0.4)',
          borderRadius: 4,
        }}>
          {body.narrative}
        </div>
      )}
      <div>
        {Object.entries(body.evidence || {}).map(([k, v]) => (
          <EvidenceRow key={k} label={k} value={v} />
        ))}
      </div>
    </div>
  );
}

export default function CompliancePage() {
  const [framework, setFramework] = useState('soc2');
  const [days, setDays]           = useState(90);
  const [report, setReport]       = useState(null);
  const [loading, setLoading]     = useState(true);
  const [err, setErr]             = useState('');

  const load = async (f, d) => {
    setLoading(true); setErr('');
    try {
      setReport(await fetchComplianceReport(f, d));
    } catch (e) {
      setErr(e.response?.data?.detail || 'FAILED TO LOAD REPORT');
    }
    setLoading(false);
  };

  useEffect(() => { load(framework, days); }, [framework, days]);

  return (
    <div className="page-enter">
      <style>{`@media print {
        body { background: white !important; }
        .no-print { display: none !important; }
        .compliance-page { color: black !important; }
      }`}</style>

      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#ffffff', textShadow: '0 0 24px rgba(255,255,255,0.35)', letterSpacing: 2 }}>
            COMPLIANCE EVIDENCE
          </div>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
            {report?.framework || framework.toUpperCase()} — Trailing {days} days
          </div>
        </div>
        <button className="no-print" onClick={() => window.print()} style={btnPrimary}>PRINT / SAVE PDF</button>
      </div>

      {/* Controls */}
      <div className="no-print" style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        <button onClick={() => setFramework('soc2')}      style={btnTab(framework === 'soc2')}>SOC 2</button>
        <button onClick={() => setFramework('iso27001')}  style={btnTab(framework === 'iso27001')}>ISO 27001</button>
        <div style={{ width: 1, background: 'rgba(255,255,255,0.1)', margin: '0 4px' }} />
        {[30, 90, 180, 365].map(d => (
          <button key={d} onClick={() => setDays(d)} style={btnTab(days === d)}>{d}d</button>
        ))}
      </div>

      {err && (
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#e53e3e',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)', borderRadius: 6,
        }}>&#9888; {err}</div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Building report...</div></div>
      ) : !report ? null : (
        <div className="compliance-page">
          {/* Header strip */}
          <div style={{
            background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 10, padding: 22, marginBottom: 18,
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 18 }}>
              <Stat label="EVENTS" value={report.summary.total_events.toLocaleString()} />
              <Stat label="INCIDENTS" value={report.summary.total_incidents} />
              <Stat label="TENANTS" value={report.summary.tenants} />
              <Stat label="ACTIVE USERS" value={report.summary.active_users} />
            </div>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#555', letterSpacing: '0.12em', marginTop: 16, paddingTop: 14, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
              {report.controls_covered?.length} CONTROLS COVERED · GENERATED {new Date(report.generated_at).toLocaleString('en-US')} ·
              PERIOD {new Date(report.period.start).toLocaleDateString()} → {new Date(report.period.end).toLocaleDateString()}
            </div>
          </div>

          {/* Sections */}
          {Object.entries(report.sections).map(([id, body]) => (
            <Section key={id} id={id} body={body} />
          ))}

          {/* Footer */}
          <div style={{
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#3a3a3a',
            textAlign: 'center', padding: 16, letterSpacing: '0.18em',
          }}>
            TRUSTFLOW SOC PLATFORM v3.0 · {report.framework} EVIDENCE REPORT · NOT A FORMAL ATTESTATION
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div>
      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#555', letterSpacing: '0.18em', marginBottom: 4, textTransform: 'uppercase' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 28, color: '#ffffff', letterSpacing: 1 }}>
        {value}
      </div>
    </div>
  );
}
