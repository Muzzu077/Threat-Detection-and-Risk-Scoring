export function getSeverity(score) {
  if (score >= 85) return 'critical';
  if (score >= 61) return 'high';
  if (score >= 31) return 'medium';
  return 'low';
}

export function getSeverityColor(severity) {
  const map = {
    critical: '#ff2d2d',
    high: '#ff8c00',
    medium: '#ffb800',
    low: '#00ffc8',
    normal: '#4a9eff',
  };
  return map[severity] || '#7da5be';
}

export function formatTime(ts) {
  if (!ts) return '--';
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDate(ts) {
  if (!ts) return '--';
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
}

export function formatDateTime(ts) {
  if (!ts) return '--';
  return `${formatDate(ts)} ${formatTime(ts)}`;
}

export function getRiskClass(score) {
  if (score >= 85) return 'risk-critical';
  if (score >= 61) return 'risk-high';
  if (score >= 31) return 'risk-medium';
  return 'risk-low';
}

export function getBadgeClass(severity) {
  return `badge badge-${(severity || 'low').toLowerCase()}`;
}

export function getStatusBadgeClass(status) {
  return `badge badge-${(status || 'open').toLowerCase()}`;
}

export function truncate(str, n = 30) {
  if (!str) return '';
  return str.length > n ? str.slice(0, n) + '…' : str;
}
