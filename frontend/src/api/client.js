import axios from 'axios';

const BASE = '/api';

export const api = axios.create({ baseURL: BASE });

// Events
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
