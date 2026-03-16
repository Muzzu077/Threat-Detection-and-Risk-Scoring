import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchIncidents } from '../api/client';
import { formatDateTime, getSeverity } from '../utils/helpers';
import { RiskBadge, AttackTypeBadge, StatusBadge } from '../components/Badges';

const STATUS_OPTS = ['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];

function RiskBar({ score }) {
  const pct = Math.min(100, Math.max(0, score || 0));
  const color = pct >= 80 ? '#f03250' : pct >= 60 ? '#ff8c00' : pct >= 40 ? '#ffb800' : '#00e5b0';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width 0.6s ease', boxShadow: `0 0 6px ${color}` }} />
      </div>
      <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color, minWidth: 28 }}>{Math.round(pct)}</span>
    </div>
  );
}

function IncidentCard({ inc, onClick }) {
  const sev = getSeverity(inc.risk_score);
  const borderColor = sev === 'critical' ? 'rgba(255,45,45,0.25)' : sev === 'high' ? 'rgba(255,140,0,0.2)' : 'rgba(0,255,200,0.1)';
  const [hovered, setHovered] = useState(false);

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? '#101d2a' : '#0c1520',
        border: `1px solid ${hovered ? (sev === 'critical' ? 'rgba(255,45,45,0.45)' : 'rgba(0,255,200,0.25)') : borderColor}`,
        borderRadius: 10,
        padding: '16px 20px',
        cursor: 'pointer',
        transition: 'all 0.2s',
        transform: hovered ? 'translateY(-2px)' : 'none',
        boxShadow: hovered ? `0 6px 24px ${sev === 'critical' ? 'rgba(255,45,45,0.15)' : 'rgba(0,255,200,0.08)'}` : 'none',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {sev === 'critical' && <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, transparent, #f03250, transparent)' }} />}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontFamily: 'Syne Mono, monospace', fontSize: 12, color: sev === 'critical' ? '#ff6b6b' : '#00e5b0' }}>
            INC-{String(inc.id).padStart(4, '0')}
          </span>
          <StatusBadge status={inc.status} />
        </div>
        <RiskBadge score={inc.risk_score} />
      </div>

      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 13, color: '#e8f4f8', marginBottom: 6 }}>{inc.user}</div>
      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#6e9ab5', marginBottom: 10 }}>{inc.action}</div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <AttackTypeBadge type={inc.attack_type} />
        <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>{formatDateTime(inc.timestamp)}</span>
      </div>

      <div style={{ marginTop: 12 }}>
        <RiskBar score={inc.risk_score} />
      </div>
    </div>
  );
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [filter, setFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [view, setView] = useState('grid'); // grid | table
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

  const filtered = incidents.filter(i =>
    !search ||
    i.user?.toLowerCase().includes(search.toLowerCase()) ||
    i.action?.toLowerCase().includes(search.toLowerCase()) ||
    i.attack_type?.toLowerCase().includes(search.toLowerCase())
  );

  // Status counts for pills
  const counts = {};
  STATUS_OPTS.forEach(s => {
    counts[s] = s === 'ALL' ? incidents.length : incidents.filter(i => i.status === s).length;
  });

  return (
    <div className="fade-in">

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#00e5b0', textShadow: '0 0 24px rgba(0,255,200,0.35)', letterSpacing: 2 }}>
          ⚠ INCIDENT DASHBOARD
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
          Security Incident Management — Triage & Response
        </div>
      </div>

      {/* Control Bar */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 20, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: '0 0 280px' }}>
          <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#2e5570', fontSize: 13 }}>⌕</span>
          <input className="input" placeholder="Search incidents..." value={search}
            onChange={e => setSearch(e.target.value)} style={{ paddingLeft: 30 }}
          />
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {STATUS_OPTS.map(s => (
            <button key={s} onClick={() => setFilter(s)} style={{
              padding: '7px 14px', borderRadius: 6, fontFamily: 'IBM Plex Mono, monospace', fontSize: 11,
              letterSpacing: '0.08em', textTransform: 'uppercase', cursor: 'pointer', transition: 'all 0.2s', border: 'none',
              background: filter === s ? 'rgba(0,255,200,0.12)' : 'transparent',
              color: filter === s ? '#00e5b0' : '#2e5570',
              outline: filter === s ? '1px solid rgba(0,255,200,0.3)' : '1px solid rgba(0,255,200,0.08)',
            }}>
              {s} <span style={{ opacity: 0.6 }}>({counts[s] || 0})</span>
            </button>
          ))}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
          {['grid', 'table'].map(v => (
            <button key={v} onClick={() => setView(v)} style={{
              padding: '7px 14px', borderRadius: 6, fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, cursor: 'pointer', border: 'none', transition: 'all 0.2s', textTransform: 'uppercase',
              background: view === v ? 'rgba(0,255,200,0.1)' : 'transparent', color: view === v ? '#00e5b0' : '#2e5570', outline: '1px solid rgba(0,255,200,0.1)',
            }}>
              {v === 'grid' ? '⊞' : '☰'} {v}
            </button>
          ))}
        </div>
        <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#2e5570' }}>
          {filtered.length} result{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading incidents...</div></div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#2e5570' }}>
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
        <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.1)', borderRadius: 10, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                {['ID','Time','User','Action','Attack','Risk','Status'].map(h => <th key={h}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {filtered.map(inc => (
                <tr key={inc.id} onClick={() => navigate(`/incidents/${inc.id}`)} style={{ cursor: 'pointer' }}>
                  <td style={{ color: '#00e5b0' }}>INC-{String(inc.id).padStart(4,'0')}</td>
                  <td style={{ color: '#2e5570', fontSize: 11 }}>{formatDateTime(inc.timestamp)}</td>
                  <td style={{ color: '#e8f4f8' }}>{inc.user}</td>
                  <td style={{ color: '#6e9ab5', fontSize: 11 }}>{inc.action?.slice(0, 30)}</td>
                  <td><AttackTypeBadge type={inc.attack_type} /></td>
                  <td style={{ minWidth: 120 }}><RiskBar score={inc.risk_score} /></td>
                  <td><StatusBadge status={inc.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
