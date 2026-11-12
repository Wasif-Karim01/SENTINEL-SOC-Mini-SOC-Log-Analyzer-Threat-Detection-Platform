const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api';

export async function apiRequest<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'API request failed');
  }
  return res.json() as Promise<T>;
}

export const socApi = {
  getOverview: () => apiRequest('/dashboard/overview'),
  loadSampleData: () => apiRequest('/sample-data/load', { method: 'POST' }),
  clearSampleData: () => apiRequest('/sample-data/clear', { method: 'DELETE' }),
  queryEvents: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString();
    return apiRequest(`/events?${qs}`);
  },
  runDetection: () => apiRequest('/detection/run', { method: 'POST' }),
  getRules: () => apiRequest('/rules'),
  updateRule: (ruleId: string, body: Record<string, unknown>) =>
    apiRequest(`/rules/${ruleId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  getAlerts: (severity = 'All', status = 'All') =>
    apiRequest(`/alerts?severity=${encodeURIComponent(severity)}&status=${encodeURIComponent(status)}`),
  updateAlert: (alertId: string, body: Record<string, unknown>) =>
    apiRequest(`/alerts/${alertId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  getIncidents: () => apiRequest('/incidents'),
  createIncident: (body: Record<string, unknown>) =>
    apiRequest('/incidents', { method: 'POST', body: JSON.stringify(body) }),
  updateIncident: (incidentId: string, body: Record<string, unknown>) =>
    apiRequest(`/incidents/${incidentId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  lookupIoc: (ioc_value: string, analyst_notes = '') =>
    apiRequest('/threat-intel/lookup', { method: 'POST', body: JSON.stringify({ ioc_value, analyst_notes }) }),
  getIocHistory: () => apiRequest('/threat-intel/history'),
  simulateEvents: (count = 3) =>
    apiRequest('/live/simulate', { method: 'POST', body: JSON.stringify({ count }) }),
  getReportSummary: (report_type = 'executive_soc_summary', severity = 'All', source = 'All') =>
    apiRequest(`/reports/summary?report_type=${report_type}&severity=${severity}&source=${source}`),
  getSettings: () => apiRequest('/settings'),
  updateSettings: (settings: Record<string, string>) =>
    apiRequest('/settings', { method: 'PUT', body: JSON.stringify({ settings }) }),
};
