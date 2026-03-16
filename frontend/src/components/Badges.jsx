import { getSeverity } from '../utils/helpers';

export function RiskBadge({ score }) {
  const sev = getSeverity(score || 0);
  return <span className={`badge badge-${sev}`}>{sev.toUpperCase()}</span>;
}

export function SeverityBadge({ severity }) {
  const s = (severity || 'low').toLowerCase();
  return <span className={`badge badge-${s}`}>{s.toUpperCase()}</span>;
}

export function StatusBadge({ status }) {
  const s = (status || 'open').toLowerCase();
  return <span className={`badge badge-${s}`}>{(status || 'OPEN').toUpperCase()}</span>;
}

export function AttackTypeBadge({ type }) {
  const label = (type || 'unknown').replace('_', ' ').toUpperCase();
  const classMap = {
    brute_force:        'badge-high',
    sql_injection:      'badge-critical',
    data_exfiltration:  'badge-amber',
    port_scan:          'badge-medium',
    normal:             'badge-normal',
    unknown:            'badge-low',
  };
  const cls = classMap[type] || 'badge-low';
  return <span className={`badge ${cls}`}>{label}</span>;
}

export function RiskBar({ score }) {
  const sev = getSeverity(score || 0);
  const colorMap = { critical: '#f03250', high: '#ff8c00', medium: '#ffb800', low: '#00e5b0' };
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{
        flex: 1, height: 4, background: 'var(--bg-elevated)', borderRadius: 2, overflow: 'hidden'
      }}>
        <div style={{
          width: `${score}%`,
          height: '100%',
          background: colorMap[sev],
          borderRadius: 2,
          transition: 'width 0.5s ease',
          boxShadow: `0 0 6px ${colorMap[sev]}80`,
        }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: colorMap[sev], minWidth: 28 }}>
        {Math.round(score || 0)}
      </span>
    </div>
  );
}
