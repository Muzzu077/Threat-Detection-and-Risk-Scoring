import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchIncidents } from '../api/client';
import { formatDateTime, getSeverity } from '../utils/helpers';
import { RiskBadge, AttackTypeBadge, StatusBadge } from '../components/Badges';

const STATUS_OPTS = ['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];

// MITRE technique lookup (client-side map for instant display)
const MITRE_QUICK = {
  brute_force:       { id: 'T1110', tactic: 'Credential Access', color: 'var(--accent-red)' },
  sql_injection:     { id: 'T1190', tactic: 'Initial Access',    color: 'var(--accent-amber)' },
  data_exfiltration: { id: 'T1041', tactic: 'Exfiltration',      color: 'var(--accent-red)' },
  port_scan:         { id: 'T1046', tactic: 'Discovery',         color: 'var(--accent-amber)' },
  xss:                 { id: 'T1059.007', tactic: 'Execution',         color: 'var(--accent-amber)' },
  privilege_escalation:{ id: 'T1068', tactic: 'Privilege Esc.',       color: 'var(--accent-red)' },
  dos_attack:          { id: 'T1498', tactic: 'Impact',               color: 'var(--accent-red)' },
  command_injection:   { id: 'T1059', tactic: 'Execution',            color: 'var(--accent-red)' },
  directory_traversal: { id: 'T1083', tactic: 'Discovery',            color: 'var(--accent-amber)' },
  session_hijacking:   { id: 'T1550', tactic: 'Lateral Movement',     color: 'var(--accent-amber)' },
  credential_stuffing: { id: 'T1110.004', tactic: 'Credential Access', color: 'var(--accent-red)' },
  ssrf:                { id: 'T1090', tactic: 'Command & Control',     color: 'var(--accent-amber)' },
  malware:             { id: 'T1204', tactic: 'Execution',            color: 'var(--accent-red)' },
  insider_threat:      { id: 'T1078', tactic: 'Defense Evasion',      color: 'var(--accent-amber)' },
  lateral_movement:  { id: 'T1021', tactic: 'Lateral Movement', color: 'var(--accent-amber)' },
  normal:            { id: '—',     tactic: 'Benign',            color: 'var(--accent)' },
};

function getMitre(attackType) {
  if (!attackType) return null;
  const key = attackType.toLowerCase().replace(/ /g, '_');
  return MITRE_QUICK[key] || null;
}

function RiskBar({ score }) {
  const pct = Math.min(100, Math.max(0, score || 0));
  const color = pct >= 80 ? 'var(--accent-red)' : pct >= 60 ? 'var(--accent-amber)' : pct >= 40 ? 'var(--accent-amber)' : 'var(--accent)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: 'var(--border-dim)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color, minWidth: 28 }}>{Math.round(pct)}</span>
    </div>
  );
}

function MitreTag({ attackType }) {
  const m = getMitre(attackType);
  if (!m || m.id === '—') return null;
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 7px',
      borderRadius: 'var(--radius-sm)', background: 'rgba(74,93,79,0.08)', border: '1px solid var(--border-dim)',
      color: 'var(--text-secondary)', letterSpacing: '0.05em', whiteSpace: 'nowrap',
    }}>
      {m.id}
    </span>
  );
}

function IncidentCard({ inc, onClick }) {
  const sev = getSeverity(inc.risk_score);
  const accentColor = sev === 'critical' ? 'var(--accent-red)' : sev === 'high' ? 'var(--accent-amber)' : sev === 'medium' ? 'var(--accent-amber)' : 'var(--accent)';
  const accentRaw = sev === 'critical' ? '#B91C1C' : sev === 'high' ? '#D97706' : sev === 'medium' ? '#D97706' : '#4A5D4F';
  const [hovered, setHovered] = useState(false);

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? 'var(--bg-glass-heavy)' : 'var(--bg-card)',
        backdropFilter: 'blur(16px)',
        border: `1px solid ${hovered ? 'var(--border-bright)' : 'var(--border-light)'}`,
        borderRadius: 'var(--radius-lg)',
        padding: '16px 20px',
        cursor: 'pointer',
        transition: 'all 0.22s var(--ease-out)',
        transform: hovered ? 'translateY(-3px)' : 'none',
        boxShadow: hovered ? 'var(--shadow-lg)' : 'var(--shadow-sm)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Top accent line */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${accentRaw}80, transparent)` }} />

      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontFamily: 'var(--font-display)', fontSize: 13, color: accentColor }}>
            INC-{String(inc.id).padStart(4, '0')}
          </span>
          <StatusBadge status={inc.status} />
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {getMitre(inc.attack_type) && <MitreTag attackType={inc.attack_type} />}
          <RiskBadge score={inc.risk_score} />
        </div>
      </div>

      {/* User + action */}
      <div style={{ fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text-primary)', fontWeight: 500, marginBottom: 4 }}>{inc.user}</div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.action}</div>

      {/* Footer row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <AttackTypeBadge type={inc.attack_type} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-faint)' }}>{formatDateTime(inc.timestamp)}</span>
      </div>

      <RiskBar score={inc.risk_score} />

      {/* Hover arrow indicator */}
      {hovered && (
        <div style={{ position: 'absolute', bottom: 14, right: 16, color: accentColor, fontSize: 12, fontFamily: 'var(--font-mono)', opacity: 0.7 }}>→</div>
      )}
    </div>
  );
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [filter, setFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [view, setView] = useState('grid');
  const [sortBy, setSortBy] = useState('risk'); // risk | time
  const navigate = useNavigate();

  const load = async () => {
    try {
      const status = filter === 'ALL' ? null : filter;
      const data = await fetchIncidents(status);
      setIncidents(data.data || []);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  let filtered = incidents.filter(i =>
    !search ||
    i.user?.toLowerCase().includes(search.toLowerCase()) ||
    i.action?.toLowerCase().includes(search.toLowerCase()) ||
    i.attack_type?.toLowerCase().includes(search.toLowerCase())
  );

  if (sortBy === 'risk') filtered = [...filtered].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  else filtered = [...filtered].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Status counts for pills
  const counts = {};
  STATUS_OPTS.forEach(s => {
    counts[s] = s === 'ALL' ? incidents.length : incidents.filter(i => i.status === s).length;
  });

  const criticalCount = incidents.filter(i => (i.risk_score || 0) >= 80 && i.status === 'OPEN').length;

  return (
    <div className="page-enter">

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div className="page-title" style={{ color: criticalCount > 0 ? 'var(--accent-red)' : 'var(--text-primary)' }}>
              Incident Dashboard
            </div>
            <div className="page-subtitle">
              Security Incident Management — Triage & Response
            </div>
          </div>
          {/* Quick KPI Strip */}
          <div style={{ display: 'flex', gap: 12 }}>
            {[
              { label: 'OPEN', val: counts['OPEN'] || 0, color: 'var(--accent-red)' },
              { label: 'INVESTIGATING', val: counts['INVESTIGATING'] || 0, color: 'var(--accent-amber)' },
              { label: 'RESOLVED', val: counts['RESOLVED'] || 0, color: 'var(--accent-green)' },
            ].map(({ label, val, color }) => (
              <div key={label} style={{ textAlign: 'center', background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', padding: '6px 14px', borderRadius: 'var(--radius-sm)', boxShadow: 'var(--shadow-sm)' }}>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, color }}>{val}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Control Bar */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 20, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: '0 0 260px' }}>
          <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-faint)', fontSize: 13 }}>⌕</span>
          <input className="input" placeholder="Search user, action, attack type…" value={search}
            onChange={e => setSearch(e.target.value)} style={{ paddingLeft: 30 }}
          />
        </div>

        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {STATUS_OPTS.map(s => (
            <button key={s} onClick={() => setFilter(s)} style={{
              padding: '6px 12px', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 11,
              letterSpacing: '0.06em', textTransform: 'uppercase', cursor: 'pointer', transition: 'all 0.2s', border: 'none',
              background: filter === s ? 'var(--bg-glass-heavy)' : 'transparent',
              color: filter === s ? 'var(--text-primary)' : 'var(--text-muted)',
              outline: filter === s ? '1px solid var(--border-bright)' : '1px solid var(--border-dim)',
            }}>
              {s} <span style={{ opacity: 0.6 }}>({counts[s] || 0})</span>
            </button>
          ))}
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
          {/* Sort control */}
          <select onChange={e => setSortBy(e.target.value)} value={sortBy} className="input" style={{ padding: '6px 10px', fontSize: 11, width: 'auto' }}>
            <option value="risk">Sort: Risk ↓</option>
            <option value="time">Sort: Newest ↓</option>
          </select>

          {['grid', 'table'].map(v => (
            <button key={v} onClick={() => setView(v)} style={{
              padding: '6px 12px', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 11, cursor: 'pointer', border: 'none', transition: 'all 0.2s', textTransform: 'uppercase',
              background: view === v ? 'var(--bg-glass-heavy)' : 'transparent', color: view === v ? 'var(--text-primary)' : 'var(--text-muted)', outline: '1px solid var(--border-dim)',
            }}>
              {v === 'grid' ? '⊞' : '☰'}
            </button>
          ))}
        </div>

        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          {filtered.length} result{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading incidents...</div></div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-muted)' }}>
          <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.4 }}>◎</div>
          NO INCIDENTS MATCH YOUR FILTER
        </div>
      ) : view === 'grid' ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 14 }}>
          {filtered.map(inc => (
            <IncidentCard key={inc.id} inc={inc} onClick={() => navigate(`/incidents/${inc.id}`)} />
          ))}
        </div>
      ) : (
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
          <table className="data-table">
            <thead>
              <tr>
                {['ID','Time','User','Action','Attack Type','MITRE','Risk','Status'].map(h => <th key={h}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {filtered.map(inc => {
                const mitre = getMitre(inc.attack_type);
                return (
                  <tr key={inc.id} onClick={() => navigate(`/incidents/${inc.id}`)} style={{ cursor: 'pointer' }}>
                    <td style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>INC-{String(inc.id).padStart(4,'0')}</td>
                    <td style={{ color: 'var(--text-faint)', fontSize: 11 }}>{formatDateTime(inc.timestamp)}</td>
                    <td style={{ color: 'var(--text-primary)' }}>{inc.user}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.action}</td>
                    <td><AttackTypeBadge type={inc.attack_type} /></td>
                    <td>
                      {mitre && mitre.id !== '—' ? (
                        <div>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)' }}>{mitre.id}</span>
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-faint)' }}>{mitre.tactic}</div>
                        </div>
                      ) : <span style={{ color: 'var(--text-faint)' }}>—</span>}
                    </td>
                    <td style={{ minWidth: 120 }}><RiskBar score={inc.risk_score} /></td>
                    <td><StatusBadge status={inc.status} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
