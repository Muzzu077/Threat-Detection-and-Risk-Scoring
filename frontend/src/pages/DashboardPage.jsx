import { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  BarChart, Bar, Cell, RadarChart, PolarGrid, PolarAngleAxis, Radar
} from 'recharts';
import { fetchStats, fetchEvents, fetchIncidents, fetchGeoDistribution, fetchMttdMttr, apiBase } from '../api/client';
import { getSeverity, formatDateTime } from '../utils/helpers';
import { RiskBadge, AttackTypeBadge } from '../components/Badges';
import LiveFeed from '../components/LiveFeed';
import PredictionWidget from '../components/PredictionWidget';

// Country flag emoji helper (ISO-2)
function flagEmoji(code) {
  if (!code || code.length !== 2) return '🌐';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1A5 + c.charCodeAt(0)));
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '\u2014';
  if (seconds <= 0) return '< 1s';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

const SEV_COLORS = { critical: '#B91C1C', high: '#EA580C', medium: '#D97706', low: '#059669' };

// Animated counter hook
function useCounter(target, duration = 1200) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!target) return;
    let start = 0;
    const step = Math.ceil(target / (duration / 16));
    const timer = setInterval(() => {
      start += step;
      if (start >= target) { setVal(target); clearInterval(timer); }
      else setVal(start);
    }, 16);
    return () => clearInterval(timer);
  }, [target]);
  return val;
}

function AnimCounter({ value, color = 'inherit' }) {
  const v = useCounter(Number(value) || 0);
  return <span style={{ color }}>{v}</span>;
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'rgba(255,255,255,0.85)', backdropFilter: 'blur(12px)', border: '1px solid var(--border-mid)', borderRadius: 8, padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: 11, boxShadow: 'var(--shadow-md)' }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>
      {payload.map(p => <div key={p.dataKey} style={{ color: p.color || 'var(--text-primary)' }}>{p.name}: <strong>{typeof p.value === 'number' ? p.value.toFixed(1) : p.value}</strong></div>)}
    </div>
  );
};

export default function DashboardPage() {
  const [stats, setStats] = useState({});
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [geo, setGeo] = useState([]);
  const [mttd, setMttd] = useState({});
  const [loading, setLoading] = useState(true);
  const [pulse, setPulse] = useState(false);
  const navigate = useNavigate();

  const load = async () => {
    try {
      const [s, e, i, g, m] = await Promise.all([
        fetchStats(), fetchEvents(1, 200), fetchIncidents(), fetchGeoDistribution(), fetchMttdMttr()
      ]);
      setStats(s);
      setEvents(e.data || []);
      setIncidents(i.data || []);
      setGeo(g.data || []);
      setMttd(m || {});
      setPulse(p => !p);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, []);

  // Hourly activity for area chart
  const hourly = Array.from({ length: 24 }, (_, h) => {
    const evts = events.filter(e => new Date(e.timestamp).getHours() === h);
    const criticals = evts.filter(e => getSeverity(e.risk_score).toLowerCase() === 'critical').length;
    const avgRisk = evts.length ? Math.round(evts.reduce((a, b) => a + b.risk_score, 0) / evts.length) : 0;
    return { hour: `${String(h).padStart(2,'0')}:00`, events: evts.length, avgRisk, criticals };
  });

  // Severity breakdown
  const sevDist = ['Low', 'Medium', 'High', 'Critical'].map(sev => ({
    name: sev,
    count: events.filter(e => getSeverity(e.risk_score).toLowerCase() === sev.toLowerCase()).length,
    fill: SEV_COLORS[sev.toLowerCase()]
  }));

  // Attack type radar
  const attackMap = {};
  events.forEach(e => { const t = e.attack_type || 'unknown'; attackMap[t] = (attackMap[t] || 0) + 1; });
  const radarData = Object.entries(attackMap).slice(0, 6).map(([type, count]) => ({ type: type.replace('_', ' ').toUpperCase(), count }));

  const criticalCount = stats.critical_events || 0;
  const openIncidents = incidents.filter(i => i.status === 'OPEN').length;
  const isCritical = criticalCount > 0;

  const recentCritical = incidents.filter(i => i.status === 'OPEN').slice(0, 5);

  return (
    <div className="page-enter" style={{ minHeight: '100vh' }}>

      {/* ── Hero Header ── */}
      <div style={{ marginBottom: 28, position: 'relative' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 24, color: isCritical ? 'var(--accent-red)' : 'var(--text-primary)', letterSpacing: 1 }}>
              TRUSTFLOW SOC
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
              Security Operations Center — Live Monitoring
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            <label style={{ cursor: 'pointer', background: 'var(--bg-glass)', border: '1px solid var(--border-mid)', color: 'var(--text-secondary)', padding: '6px 14px', borderRadius: 'var(--radius-sm)', transition: 'all 0.2s', display: 'flex', alignItems: 'center', gap: 8, letterSpacing: 1, backdropFilter: 'blur(8px)' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.45)'; e.currentTarget.style.boxShadow = 'var(--shadow-md)'; e.currentTarget.style.transform = 'translateY(-1px)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-glass)'; e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.transform = 'translateY(0)'; }}>
              <span style={{ fontSize: 13 }}>📤</span> UPLOAD LOGS (CSV)
              <input type="file" accept=".csv" style={{ display: 'none' }} onChange={async (e) => {
                if (!e.target.files?.length) return;
                const formData = new FormData();
                formData.append('file', e.target.files[0]);
                try {
                  const res = await fetch(`${apiBase}/api/ingest/csv`, { method: 'POST', body: formData });
                  if (res.ok) {
                    const data = await res.json();
                    alert(`✅ Real data uploaded! ${data.events_count} events queued for ML ingestion.`);
                  } else alert('❌ Upload failed.');
                } catch (err) { alert('❌ Network error during upload. Is the API running?'); }
              }} />
            </label>
            <div style={{ height: 16, width: 1, background: 'var(--border-mid)' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent)', boxShadow: '0 0 8px rgba(74,93,79,0.5)', animation: 'pulse-live 2s ease-in-out infinite', display: 'inline-block' }}/>
              <span style={{ color: 'var(--accent)', fontWeight: 600 }}>LIVE</span>
            </div>
            <span style={{ color: 'var(--text-muted)' }}>{new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}</span>
          </div>
        </div>

        {/* Alert Banner */}
        <div style={{ marginTop: 16, padding: '12px 20px', borderRadius: 'var(--radius-md)', background: isCritical ? 'rgba(185,28,28,0.08)' : 'rgba(5,150,105,0.08)', border: `1px solid ${isCritical ? 'rgba(185,28,28,0.22)' : 'rgba(5,150,105,0.18)'}`, display: 'flex', alignItems: 'center', gap: 12, fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>
          <span style={{ fontSize: 16 }}>{isCritical ? '🚨' : '✅'}</span>
          <span style={{ color: isCritical ? 'var(--accent-red)' : 'var(--accent-green)' }}>
            {isCritical ? `CRITICAL ALERT — ${criticalCount} active high-severity events detected. Immediate investigation required.` : 'ALL SYSTEMS SECURE — No critical threats detected. Monitoring active.'}
          </span>
        </div>

      {/* Threat Level Gauge */}
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 24 }}>
        <div style={{ position: 'relative', width: 160, height: 160 }}>
          <svg viewBox="0 0 120 120" style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
            <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border-dim)" strokeWidth="6" />
            <circle cx="60" cy="60" r="52" fill="none"
              stroke={isCritical ? '#B91C1C' : (stats.avg_risk || 0) >= 50 ? '#D97706' : 'var(--accent)'}
              strokeWidth="6" strokeLinecap="round"
              strokeDasharray={`${((stats.avg_risk || 0) / 100) * 327} 327`}
              className="gauge-ring"
              style={{ filter: `drop-shadow(0 0 8px ${isCritical ? 'rgba(185,28,28,0.4)' : 'rgba(74,93,79,0.4)'})` }}
            />
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 32, color: isCritical ? 'var(--accent-red)' : 'var(--text-primary)' }}>
              {Math.round(stats.avg_risk || 0)}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase' }}>THREAT LEVEL</div>
          </div>
        </div>
      </div>
      </div>

      {/* ── KPI Grid ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14, marginBottom: 24 }}>
        {[
          { label: 'TOTAL EVENTS', value: stats.total_events, accent: 'var(--accent)', accentRaw: '#4A5D4F', icon: '◉', glow: 'rgba(74,93,79,0.15)' },
          { label: 'OPEN INCIDENTS', value: openIncidents, accent: 'var(--accent-red)', accentRaw: '#B91C1C', icon: '⚠', glow: 'rgba(185,28,28,0.12)' },
          { label: 'CRITICAL ALERTS', value: criticalCount, accent: 'var(--accent-red)', accentRaw: '#B91C1C', icon: '◈', glow: 'rgba(185,28,28,0.12)' },
          { label: 'AVG RISK SCORE', value: stats.avg_risk ? Math.round(stats.avg_risk) : 0, accent: 'var(--accent-amber)', accentRaw: '#D97706', icon: '▲', glow: 'rgba(217,119,6,0.12)' },
          { label: 'HIGH SEVERITY', value: stats.high_events || 0, accent: '#EA580C', accentRaw: '#EA580C', icon: '◆', glow: 'rgba(234,88,12,0.12)' },
        ].map((kpi, i) => (
          <div key={i} className="stagger-item" style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: '18px 20px', position: 'relative', overflow: 'hidden', cursor: 'default', transition: 'all var(--duration-normal) var(--ease-out)', boxShadow: 'var(--shadow-sm)', animationDelay: `${i * 0.07}s` }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.boxShadow = `var(--shadow-lg)`; e.currentTarget.style.borderColor = 'var(--border-mid)'; }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'var(--shadow-sm)'; e.currentTarget.style.borderColor = 'var(--border-light)'; }}
          >
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, transparent, ${kpi.accentRaw}, transparent)`, opacity: 0.6 }} />
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 10, fontWeight: 500 }}>{kpi.label}</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 34, color: kpi.accent, lineHeight: 1 }}>
              <AnimCounter value={kpi.value} color={kpi.accent} />
            </div>
            <div style={{ position: 'absolute', bottom: 14, right: 16, fontSize: 28, opacity: 0.08, color: kpi.accentRaw }}>{kpi.icon}</div>
          </div>
        ))}
      </div>

      {/* MTTD/MTTR Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, marginBottom: 24 }}>
        {[
          { label: 'MTTD (MEAN TIME TO DETECT)', value: formatDuration(mttd.mttd_avg_seconds), accent: 'var(--accent-blue)', accentRaw: '#2563EB', icon: '\u23F1', glow: 'rgba(37,99,235,0.12)' },
          { label: 'MTTR (MEAN TIME TO RESPOND)', value: formatDuration(mttd.mttr_avg_seconds), accent: 'var(--accent-purple)', accentRaw: '#7C3AED', icon: '\u26A1', glow: 'rgba(124,58,237,0.12)' },
          { label: 'AVG RESOLUTION TIME', value: formatDuration(mttd.resolution_avg_seconds), accent: 'var(--accent)', accentRaw: '#4A5D4F', icon: '\u2713', glow: 'rgba(74,93,79,0.12)' },
        ].map((kpi, i) => (
          <div key={i} style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: '18px 20px', position: 'relative', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, transparent, ${kpi.accentRaw}, transparent)`, opacity: 0.6 }} />
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 10, fontWeight: 500 }}>{kpi.label}</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, color: kpi.accent, lineHeight: 1 }}>
              {kpi.value || '\u2014'}
            </div>
            <div style={{ position: 'absolute', bottom: 14, right: 16, fontSize: 28, opacity: 0.08, color: kpi.accentRaw }}>{kpi.icon}</div>
          </div>
        ))}
      </div>

      {/* ── Charts Row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* Hourly Activity Area Chart */}
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: '20px 20px 12px', boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16, fontWeight: 500 }}>24-H Risk Timeline</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={hourly} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#B91C1C" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#B91C1C" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="evtGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4A5D4F" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#4A5D4F" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-dim)" />
              <XAxis dataKey="hour" tick={{ fontSize: 9, fill: '#78716C', fontFamily: 'var(--font-mono)' }} interval={5} />
              <YAxis tick={{ fontSize: 9, fill: '#78716C', fontFamily: 'var(--font-mono)' }} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="avgRisk" name="Avg Risk" stroke="#B91C1C" strokeWidth={1.5} fill="url(#riskGrad)" />
              <Area type="monotone" dataKey="events" name="Events" stroke="#4A5D4F" strokeWidth={1.5} fill="url(#evtGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: '20px 20px 12px', boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16, fontWeight: 500 }}>Severity Breakdown</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={sevDist} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
              <XAxis type="number" tick={{ fontSize: 9, fill: '#78716C' }} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#44403C', fontFamily: 'var(--font-mono)' }} width={60} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Events" radius={[0, 4, 4, 0]}>
                {sevDist.map((d, i) => <Cell key={i} fill={d.fill} fillOpacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Bottom Row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>

        {/* Left: Active Incidents */}
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: 20, boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', fontWeight: 500 }}>Active Incidents</div>
            <button className="btn btn-ghost" style={{ fontSize: 10, padding: '4px 10px' }} onClick={() => navigate('/incidents')}>VIEW ALL →</button>
          </div>
          {recentCritical.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '30px 0', fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-muted)' }}>NO ACTIVE INCIDENTS</div>
          ) : recentCritical.map(inc => (
            <div key={inc.id} onClick={() => navigate(`/incidents/${inc.id}`)}
              style={{ padding: '12px 14px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-md)', marginBottom: 8, border: '1px solid var(--border-dim)', cursor: 'pointer', transition: 'all 0.2s', backdropFilter: 'blur(8px)' }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-mid)'; e.currentTarget.style.background = 'rgba(255,255,255,0.4)'; e.currentTarget.style.boxShadow = 'var(--shadow-sm)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-dim)'; e.currentTarget.style.background = 'var(--bg-glass)'; e.currentTarget.style.boxShadow = 'none'; }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', fontWeight: 500 }}>INC-{String(inc.id).padStart(4, '0')}</span>
                <RiskBadge score={inc.risk_score} />
              </div>
              <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>{inc.user}</div>
              <AttackTypeBadge type={inc.attack_type} />
            </div>
          ))}
        </div>

        {/* Right: Geo-Distribution + Prediction stacked */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Geo Origin Panel */}
          <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: 20, boxShadow: 'var(--shadow-sm)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', fontWeight: 500 }}>🌐 Attack Origins</div>
              <button className="btn btn-ghost" style={{ fontSize: 10, padding: '4px 10px' }} onClick={() => navigate('/threat-intel')}>INTEL MAP →</button>
            </div>
            {geo.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '16px 0', fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-muted)' }}>NO GEO DATA YET</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {geo.slice(0, 6).map(({ country, count }) => {
                  const maxCount = geo[0]?.count || 1;
                  const pct = (count / maxCount) * 100;
                  return (
                    <div key={country} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 14, minWidth: 22 }}>{flagEmoji(country)}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', minWidth: 30 }}>{country}</span>
                      <div style={{ flex: 1, height: 4, background: 'var(--border-dim)', borderRadius: 2, overflow: 'hidden' }}>
                        <div style={{ width: `${pct}%`, height: '100%', background: 'linear-gradient(90deg, #4A5D4F, #6B8A73)', borderRadius: 2, boxShadow: '0 0 6px rgba(74,93,79,0.3)', transition: 'width 0.8s ease' }} />
                      </div>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', minWidth: 22, textAlign: 'right' }}>{count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* AI Prediction Widget */}
          <PredictionWidget />
        </div>

      </div>

      {/* Live Feed (full width at bottom) */}
      <div style={{ marginTop: 16, background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-dim)', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: 8, fontWeight: 500 }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent)', boxShadow: '0 0 8px rgba(74,93,79,0.5)', display: 'inline-block', animation: 'pulse-live 2s ease-in-out infinite' }} />
          Live Event Feed
        </div>
        <LiveFeed />
      </div>
    </div>
  );
}
