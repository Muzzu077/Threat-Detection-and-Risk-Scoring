import { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  BarChart, Bar, Cell, RadarChart, PolarGrid, PolarAngleAxis, Radar
} from 'recharts';
import { fetchStats, fetchEvents, fetchIncidents } from '../api/client';
import { getSeverity, formatDateTime } from '../utils/helpers';
import { RiskBadge, AttackTypeBadge } from '../components/Badges';
import LiveFeed from '../components/LiveFeed';
import PredictionWidget from '../components/PredictionWidget';

const SEV_COLORS = { critical: '#f03250', high: '#ff8c00', medium: '#ffb800', low: '#00e5b0' };

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
    <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.3)', borderRadius: 6, padding: '10px 14px', fontFamily: 'IBM Plex Mono, monospace', fontSize: 11 }}>
      <div style={{ color: '#2e5570', marginBottom: 4 }}>{label}</div>
      {payload.map(p => <div key={p.dataKey} style={{ color: p.color || '#00e5b0' }}>{p.name}: <strong>{typeof p.value === 'number' ? p.value.toFixed(1) : p.value}</strong></div>)}
    </div>
  );
};

export default function DashboardPage() {
  const [stats, setStats] = useState({});
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pulse, setPulse] = useState(false);
  const navigate = useNavigate();

  const load = async () => {
    try {
      const [s, e, i] = await Promise.all([fetchStats(), fetchEvents(1, 200), fetchIncidents()]);
      setStats(s);
      setEvents(e.data || []);
      setIncidents(i.data || []);
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

  const criticalCount = stats.critical_count || 0;
  const openIncidents = incidents.filter(i => i.status === 'OPEN').length;
  const isCritical = criticalCount > 0;

  const recentCritical = incidents.filter(i => i.status === 'OPEN').slice(0, 5);

  return (
    <div className="fade-in" style={{ minHeight: '100vh' }}>

      {/* ── Hero Header ── */}
      <div style={{ marginBottom: 28, position: 'relative' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 24, color: isCritical ? '#f03250' : '#00e5b0', textShadow: isCritical ? '0 0 30px rgba(255,45,45,0.5)' : '0 0 30px rgba(0,255,200,0.4)', letterSpacing: 2 }}>
              THREATPULSE SOC
            </div>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
              Security Operations Center — Live Monitoring
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontFamily: 'IBM Plex Mono, monospace', fontSize: 11 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00e5b0', boxShadow: '0 0 8px #00e5b0', animation: 'pulse-live 1.5s ease-in-out infinite', display: 'inline-block' }}/>
              <span style={{ color: '#00e5b0' }}>LIVE</span>
            </div>
            <span style={{ color: '#2e5570' }}>{new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}</span>
          </div>
        </div>

        {/* Alert Banner */}
        <div style={{ marginTop: 16, padding: '12px 20px', borderRadius: 8, background: isCritical ? 'rgba(255,45,45,0.07)' : 'rgba(0,255,200,0.04)', border: `1px solid ${isCritical ? 'rgba(255,45,45,0.35)' : 'rgba(0,255,200,0.18)'}`, display: 'flex', alignItems: 'center', gap: 12, fontFamily: 'IBM Plex Mono, monospace', fontSize: 12 }}>
          <span style={{ fontSize: 16 }}>{isCritical ? '🚨' : '✅'}</span>
          <span style={{ color: isCritical ? '#ff6b6b' : '#00e5b0' }}>
            {isCritical ? `CRITICAL ALERT — ${criticalCount} active high-severity events detected. Immediate investigation required.` : 'ALL SYSTEMS SECURE — No critical threats detected. Monitoring active.'}
          </span>
        </div>
      </div>

      {/* ── KPI Grid ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14, marginBottom: 24 }}>
        {[
          { label: 'TOTAL EVENTS', value: stats.total_events, accent: '#00e5b0', icon: '◉', glow: 'rgba(0,255,200,0.2)' },
          { label: 'OPEN INCIDENTS', value: openIncidents, accent: '#f03250', icon: '⚠', glow: 'rgba(255,45,45,0.2)' },
          { label: 'CRITICAL ALERTS', value: criticalCount, accent: '#f03250', icon: '◈', glow: 'rgba(255,45,45,0.2)' },
          { label: 'AVG RISK SCORE', value: stats.avg_risk ? Math.round(stats.avg_risk) : 0, accent: '#ffb800', icon: '▲', glow: 'rgba(255,184,0,0.2)' },
          { label: 'HIGH SEVERITY', value: stats.high_count || 0, accent: '#ff8c00', icon: '◆', glow: 'rgba(255,140,0,0.2)' },
        ].map((kpi, i) => (
          <div key={i} style={{ background: '#0c1520', border: `1px solid ${kpi.glow.replace('0.2', '0.3')}`, borderRadius: 10, padding: '18px 20px', position: 'relative', overflow: 'hidden', cursor: 'default', transition: 'transform 0.2s, box-shadow 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.boxShadow = `0 8px 24px ${kpi.glow}`; }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
          >
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${kpi.accent}, transparent)` }} />
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 10 }}>{kpi.label}</div>
            <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 34, color: kpi.accent, textShadow: `0 0 20px ${kpi.glow}`, lineHeight: 1 }}>
              <AnimCounter value={kpi.value} color={kpi.accent} />
            </div>
            <div style={{ position: 'absolute', bottom: 14, right: 16, fontSize: 28, opacity: 0.06, color: kpi.accent }}>{kpi.icon}</div>
          </div>
        ))}
      </div>

      {/* ── Charts Row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* Hourly Activity Area Chart */}
        <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.12)', borderRadius: 10, padding: '20px 20px 12px' }}>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16 }}>24-H Risk Timeline</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={hourly} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f03250" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#f03250" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="evtGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00e5b0" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#00e5b0" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,255,200,0.05)" />
              <XAxis dataKey="hour" tick={{ fontSize: 9, fill: '#2e5570', fontFamily: 'IBM Plex Mono, monospace' }} interval={5} />
              <YAxis tick={{ fontSize: 9, fill: '#2e5570', fontFamily: 'IBM Plex Mono, monospace' }} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="avgRisk" name="Avg Risk" stroke="#f03250" strokeWidth={1.5} fill="url(#riskGrad)" />
              <Area type="monotone" dataKey="events" name="Events" stroke="#00e5b0" strokeWidth={1.5} fill="url(#evtGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.12)', borderRadius: 10, padding: '20px 20px 12px' }}>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16 }}>Severity Breakdown</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={sevDist} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
              <XAxis type="number" tick={{ fontSize: 9, fill: '#2e5570' }} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#6e9ab5', fontFamily: 'IBM Plex Mono,monospace' }} width={60} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Events" radius={[0, 4, 4, 0]}>
                {sevDist.map((d, i) => <Cell key={i} fill={d.fill} fillOpacity={0.8} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Bottom Row: Active Incidents | Prediction | Live Feed ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>

        {/* Active Incidents */}
        <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.12)', borderRadius: 10, padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase' }}>Active Incidents</div>
            <button className="btn btn-ghost" style={{ fontSize: 10, padding: '4px 10px' }} onClick={() => navigate('/incidents')}>VIEW ALL →</button>
          </div>
          {recentCritical.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '30px 0', fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#2e5570' }}>NO ACTIVE INCIDENTS</div>
          ) : recentCritical.map(inc => (
            <div key={inc.id} onClick={() => navigate(`/incidents/${inc.id}`)}
              style={{ padding: '12px 14px', background: '#101d2a', borderRadius: 8, marginBottom: 8, border: '1px solid rgba(0,255,200,0.06)', cursor: 'pointer', transition: 'border-color 0.2s' }}
              onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(0,255,200,0.2)'}
              onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(0,255,200,0.06)'}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#00e5b0' }}>INC-{String(inc.id).padStart(4, '0')}</span>
                <RiskBadge score={inc.risk_score} />
              </div>
              <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#6e9ab5', marginBottom: 4 }}>{inc.user}</div>
              <AttackTypeBadge type={inc.attack_type} />
            </div>
          ))}
        </div>

        {/* AI Prediction Widget */}
        <PredictionWidget />

        {/* Live Feed */}
        <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.12)', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(0,255,200,0.08)', fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00e5b0', boxShadow: '0 0 8px #00e5b0', display: 'inline-block', animation: 'pulse-live 1.5s ease-in-out infinite' }} />
            Live Event Feed
          </div>
          <LiveFeed />
        </div>
      </div>
    </div>
  );
}
