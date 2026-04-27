export function getSeverity(score) {
  if (score >= 85) return 'critical';
  if (score >= 61) return 'high';
  if (score >= 31) return 'medium';
  return 'low';
}

export function getSeverityColor(severity) {
  const map = {
    critical: '#e53e3e',
    high: '#ed8936',
    medium: '#e6a817',
    low: '#48bb78',
    normal: '#63b3ed',
  };
  return map[severity] || '#a0a0a0';
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
