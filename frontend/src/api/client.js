import axios from 'axios';

const BASE = '/api';

export const api = axios.create({ baseURL: BASE });

// ─── JWT Interceptors ────────────────────────────────────────────────────────

api.interceptors.request.use((config) => {
  const tokens = localStorage.getItem('tp_tokens');
  if (tokens) {
    try {
      const { access_token } = JSON.parse(tokens);
      if (access_token) {
        config.headers.Authorization = `Bearer ${access_token}`;
      }
    } catch {}
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const tokens = JSON.parse(localStorage.getItem('tp_tokens') || '{}');
        if (tokens.refresh_token) {
          const res = await axios.post(`${BASE}/auth/refresh`, {
            refresh_token: tokens.refresh_token,
          });
          localStorage.setItem('tp_tokens', JSON.stringify(res.data));
          originalRequest.headers.Authorization = `Bearer ${res.data.access_token}`;
          return api(originalRequest);
        }
      } catch {
        localStorage.removeItem('tp_tokens');
        localStorage.removeItem('tp_user');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ─── Auth ────────────────────────────────────────────────────────────────────

export const authRegister = (email, password, display_name) =>
  api.post('/auth/register', { email, password, display_name }).then(r => r.data);

export const authLogin = (email, password) =>
  api.post('/auth/login', { email, password }).then(r => r.data);

export const authMe = () => api.get('/auth/me').then(r => r.data);

export const authLogout = (refresh_token) =>
  api.post('/auth/logout', { refresh_token }).then(r => r.data);

// ─── API Keys ────────────────────────────────────────────────────────────────

export const fetchApiKeys = () => api.get('/keys').then(r => r.data);
export const createApiKey = (name) => api.post('/keys', { name }).then(r => r.data);
export const revokeApiKey = (id) => api.delete(`/keys/${id}`).then(r => r.data);

// ─── Events ──────────────────────────────────────────────────────────────────

export const fetchEvents = (page = 1, limit = 50, minRisk = 0) =>
  api.get('/events', { params: { page, limit, min_risk: minRisk } }).then(r => r.data);

// Stats
export const fetchStats = () => api.get('/stats').then(r => r.data);

// Incidents
export const fetchIncidents = (status = null) =>
  api.get('/incidents', { params: status ? { status } : {} }).then(r => r.data);

export const fetchIncident = (id) => api.get(`/incidents/${id}`).then(r => r.data);

export const updateIncidentStatus = (id, status, owner = 'Admin') =>
  api.post(`/incidents/${id}/status`, { status, owner }).then(r => r.data);

// SOAR
export const triggerResponse = (incidentId, force = false) =>
  api.post(`/response/${incidentId}`, { force }).then(r => r.data);

export const fetchResponseLog = (limit = 50) =>
  api.get('/response/log', { params: { limit } }).then(r => r.data);

export const fetchBlockedIps = () => api.get('/response/blocked-ips').then(r => r.data);
export const fetchDisabledAccounts = () => api.get('/response/disabled-accounts').then(r => r.data);

// Attack Graph
export const fetchAttackGraph = () => api.get('/attack-graph').then(r => r.data);
export const fetchAttackChains = () => api.get('/attack-chains').then(r => r.data);

// ML
export const fetchMLMetrics = () => api.get('/ml-metrics').then(r => r.data);

// Threat Intel
export const fetchThreatIntel = (ip) => api.get(`/threat-intel/${ip}`).then(r => r.data);
export const fetchGeoDistribution = () => api.get('/geo-distribution').then(r => r.data);

// MITRE ATT&CK
export const fetchMitreMapping = (attackType, action = '') =>
  api.get('/mitre/mapping', { params: { attack_type: attackType, action } }).then(r => r.data);
export const fetchMitreTechniques = () => api.get('/mitre/techniques').then(r => r.data);
export const fetchEventsWithMitre = (limit = 50, minRisk = 50) =>
  api.get('/events/mitre', { params: { limit, min_risk: minRisk } }).then(r => r.data);

// SHAP Explainability
export const fetchExplainability = () => api.get('/explainability').then(r => r.data);

// Threat Prediction
export const fetchPrediction = () => api.get('/prediction').then(r => r.data);

// Attack Timeline
export const fetchTimeline = (incidentId) => api.get(`/timeline/${incidentId}`).then(r => r.data);

// MTTD/MTTR Metrics
export const fetchMttdMttr = () => api.get('/metrics/mttd-mttr').then(r => r.data);

// Feedback Loop
export const submitFeedback = (incidentId, label, analyst = 'Admin') =>
  api.post(`/feedback/${incidentId}`, { label, analyst }).then(r => r.data);

export const fetchFeedbackStats = () => api.get('/feedback/stats').then(r => r.data);
export const fetchModelDrift = () => api.get('/model/drift').then(r => r.data);

// Adversarial Testing
export const fetchAdversarialResults = () => api.get('/adversarial/results').then(r => r.data);
export const runAdversarialTests = () => api.post('/adversarial/run').then(r => r.data);

// SOAR Playbooks
export const fetchPlaybooks = () => api.get('/playbooks').then(r => r.data);
export const previewPlaybook = (attackType, riskScore = 80) =>
  api.get(`/playbooks/${attackType}`, { params: { risk_score: riskScore } }).then(r => r.data);
export const executePlaybook = (incidentId) =>
  api.post(`/playbooks/execute/${incidentId}`).then(r => r.data);

// OSINT Feeds
export const fetchOsintFeeds = () => api.get('/osint/feeds').then(r => r.data);
export const checkIpOsint = (ip) => api.get(`/osint/check/${ip}`).then(r => r.data);
export const fetchUrlhaus = () => api.get('/osint/urlhaus').then(r => r.data);
