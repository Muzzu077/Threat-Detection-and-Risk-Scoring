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
  fontFamily: 'var(--font-mono)', fontSize: 11,
  padding: '8px 16px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
  background: 'var(--bg-glass-heavy)', color: 'var(--text-primary)',
  letterSpacing: '0.08em', textTransform: 'uppercase',
  outline: '1px solid var(--border-mid)',
};

const btnTab = (active) => ({
  fontFamily: 'var(--font-mono)', fontSize: 11,
  padding: '8px 16px', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
  border: `1px solid ${active ? 'var(--border-bright)' : 'var(--border-dim)'}`,
  background: active ? 'var(--bg-glass-heavy)' : 'transparent',
  color: active ? 'var(--text-primary)' : 'var(--text-muted)',
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
      padding: '8px 0', borderBottom: '1px solid var(--border-dim)',
      alignItems: 'flex-start', gap: 16,
    }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
        {label.replace(/_/g, ' ')}
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', wordBreak: 'break-word' }}>
        {String(display)}
      </div>
    </div>
  );
}

function Section({ id, body }) {
  const meta = SECTIONS[id] || { title: id, icon: '•' };
  return (
    <div style={{
      background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
      borderRadius: 'var(--radius-lg)', padding: 22, marginBottom: 18, boxShadow: 'var(--shadow-sm)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 18 }}>{meta.icon}</span>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, color: 'var(--text-primary)', letterSpacing: 1 }}>
            {meta.title}
          </div>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--accent)', letterSpacing: '0.08em' }}>
          {(body.controls || []).join(' · ')}
        </div>
      </div>
      {body.narrative && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)',
          lineHeight: 1.6, marginBottom: 14, padding: '10px 14px',
          background: 'var(--bg-glass)', borderLeft: '2px solid var(--accent)',
          borderRadius: 'var(--radius-sm)',
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
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
            COMPLIANCE EVIDENCE
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
            {report?.framework || framework.toUpperCase()} — Trailing {days} days
          </div>
        </div>
        <button className="no-print btn btn-ghost" onClick={() => window.print()} style={btnPrimary}>PRINT / SAVE PDF</button>
      </div>

      {/* Controls */}
      <div className="no-print" style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        <button onClick={() => setFramework('soc2')}      style={btnTab(framework === 'soc2')}>SOC 2</button>
        <button onClick={() => setFramework('iso27001')}  style={btnTab(framework === 'iso27001')}>ISO 27001</button>
        <div style={{ width: 1, background: 'var(--border-dim)', margin: '0 4px' }} />
        {[30, 90, 180, 365].map(d => (
          <button key={d} onClick={() => setDays(d)} style={btnTab(days === d)}>{d}d</button>
        ))}
      </div>

      {err && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent-red)',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-sm)',
        }}>&#9888; {err}</div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Building report...</div></div>
      ) : !report ? null : (
        <div className="compliance-page">
          {/* Header strip */}
          <div style={{
            background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
            borderRadius: 'var(--radius-lg)', padding: 22, marginBottom: 18, boxShadow: 'var(--shadow-sm)'
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 18 }}>
              <Stat label="EVENTS" value={report.summary.total_events.toLocaleString()} />
              <Stat label="INCIDENTS" value={report.summary.total_incidents} />
              <Stat label="TENANTS" value={report.summary.tenants} />
              <Stat label="ACTIVE USERS" value={report.summary.active_users} />
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--border-dim)' }}>
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
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-faint)',
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
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: 4, textTransform: 'uppercase' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, color: 'var(--text-primary)', letterSpacing: 1 }}>
        {value}
      </div>
    </div>
  );
}
