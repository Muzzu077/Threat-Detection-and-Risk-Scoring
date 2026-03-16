import { useEffect, useState } from 'react';
import { fetchTimeline } from '../api/client';
import { getSeverity } from '../utils/helpers';

const ATK_COLORS = {
  brute_force: '#ff8c00',
  sql_injection: '#f03250',
  data_exfiltration: '#ffb800',
  port_scan: '#a855f7',
  normal: '#00e5b0',
  unknown: '#4a9eff',
};

function formatTime(ts) {
  if (!ts) return '--:--:--';
  return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function AttackTimeline({ incidentId }) {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!incidentId) return;
    fetchTimeline(incidentId)
      .then(d => { setTimeline(d.timeline || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [incidentId]);

  if (loading) return (
    <div className="loading" style={{ padding: 30 }}>
      <div className="spinner" style={{ width: 20, height: 20 }} />
      <div className="loading-text">Building timeline...</div>
    </div>
  );

  if (!timeline.length) return (
    <div className="p-empty" style={{ padding: 30 }}>
      No timeline events found for this incident.
    </div>
  );

  return (
    <div style={{ position: 'relative', paddingLeft: 20 }}>
      {/* Vertical line */}
      <div style={{
        position: 'absolute', left: 7, top: 0, bottom: 0,
        width: 2, background: 'linear-gradient(to bottom, transparent, var(--border-mid), transparent)',
      }} />

      {timeline.map((evt, idx) => {
        const color = ATK_COLORS[evt.attack_type] || '#6e9ab5';
        const isFocal = evt.is_focal;
        return (
          <div
            key={evt.id}
            style={{
              display: 'flex', alignItems: 'flex-start', gap: 14,
              marginBottom: 14, position: 'relative',
              animation: `fadeIn 0.3s ease ${idx * 0.05}s both`,
            }}
          >
            {/* Timeline dot */}
            <div style={{
              width: 14, height: 14, borderRadius: '50%',
              background: isFocal ? color : `${color}55`,
              border: `2px solid ${color}`,
              flexShrink: 0,
              boxShadow: isFocal ? `0 0 10px ${color}80` : 'none',
              zIndex: 1,
              marginTop: 3,
            }} />

            {/* Event card */}
            <div style={{
              flex: 1,
              background: isFocal ? `${color}12` : 'var(--bg-elevated)',
              border: `1px solid ${isFocal ? color + '55' : 'var(--border-dim)'}`,
              borderRadius: 6, padding: '10px 14px',
              transform: isFocal ? 'scale(1.01)' : 'scale(1)',
              transition: 'all 0.2s',
            }}>
              {/* Time + risk */}
              <div className="flex-between" style={{ marginBottom: 6 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
                  {formatTime(evt.timestamp)}
                  {isFocal && <span style={{ marginLeft: 8, fontSize: 9, color, letterSpacing: '0.1em' }}>◀ FOCAL EVENT</span>}
                </span>
                <span style={{ fontFamily: 'var(--font-display)', fontSize: 13, color }}>
                  {Math.round(evt.risk_score)}
                </span>
              </div>

              {/* Action */}
              <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-primary)', marginBottom: 6 }}>
                <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{evt.user}</span>
                {' → '}
                <span>{evt.action}</span>
              </div>

              {/* Labels row */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {/* Attack type */}
                <span style={{
                  padding: '1px 7px', borderRadius: 3, fontSize: 9,
                  background: `${color}18`, border: `1px solid ${color}44`,
                  color, fontFamily: 'var(--font-mono)', letterSpacing: '0.06em',
                }}>
                  {evt.attack_type?.replace('_', ' ').toUpperCase()}
                </span>

                {/* MITRE ID */}
                {evt.mitre_id && (
                  <span style={{
                    padding: '1px 7px', borderRadius: 3, fontSize: 9,
                    background: 'rgba(74,158,255,0.1)', border: '1px solid rgba(74,158,255,0.25)',
                    color: '#4a9eff', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em',
                  }}>
                    {evt.mitre_id}
                  </span>
                )}

                {/* Tactic */}
                {evt.mitre_tactic && evt.mitre_tactic !== 'N/A' && (
                  <span style={{
                    padding: '1px 7px', borderRadius: 3, fontSize: 9,
                    background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.25)',
                    color: '#a855f7', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em',
                  }}>
                    {evt.mitre_tactic}
                  </span>
                )}

                {/* Resource */}
                {evt.resource && (
                  <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    {evt.resource}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
