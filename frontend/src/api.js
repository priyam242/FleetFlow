const API = '/api';

function getHeaders(getToken) {
  const token = getToken?.();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function parseJsonSafe(res) {
  const text = await res.text();
  if (!text) return { status: res.status, ok: res.ok };
  try {
    return JSON.parse(text);
  } catch (e) {
    return { error: 'Invalid JSON response', status: res.status, body: text };
  }
}

export function createApi(getToken) {
  return {
    auth: {
      login: (email, password) =>
        fetch(`${API}/auth/login`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify({ email, password }),
        }).then(parseJsonSafe),
      forgotPassword: (email) =>
        fetch(`${API}/auth/forgot-password`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify({ email }),
        }).then(parseJsonSafe),
    },
    users: {
      create: (data) =>
        fetch(`${API}/users`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
      register: (data) =>
        fetch(`${API}/users/register`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
    },
    dashboard: () => fetch(`${API}/analytics/dashboard`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
    vehicles: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/vehicles${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then(parseJsonSafe);
      },
      get: (id) => fetch(`${API}/vehicles/${id}`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
      create: (data) =>
        fetch(`${API}/vehicles`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
      update: (id, data) =>
        fetch(`${API}/vehicles/${id}`, {
          method: 'PUT',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
      delete: (id) =>
        fetch(`${API}/vehicles/${id}`, { method: 'DELETE', headers: getHeaders(getToken) }).then(parseJsonSafe),
    },
    drivers: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/drivers${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then(parseJsonSafe);
      },
      get: (id) => fetch(`${API}/drivers/${id}`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
      create: (data) =>
        fetch(`${API}/drivers`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
      update: (id, data) =>
        fetch(`${API}/drivers/${id}`, {
          method: 'PUT',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
    },
    trips: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/trips${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then(parseJsonSafe);
      },
      get: (id) => fetch(`${API}/trips/${id}`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
      create: (data) =>
        fetch(`${API}/trips`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
      updateStatus: (id, status, end_odometer) =>
        fetch(`${API}/trips/${id}/status`, {
          method: 'PATCH',
          headers: getHeaders(getToken),
          body: JSON.stringify({ status, end_odometer }),
        }).then(parseJsonSafe),
    },
    maintenance: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/maintenance${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then(parseJsonSafe);
      },
      create: (data) =>
        fetch(`${API}/maintenance`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
    },
    fuel: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/fuel${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then(parseJsonSafe);
      },
      create: (data) =>
        fetch(`${API}/fuel`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
    },
    expenses: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/expenses${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then(parseJsonSafe);
      },
      create: (data) =>
        fetch(`${API}/expenses`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then(parseJsonSafe),
    },
    analytics: {
      dashboard: () => fetch(`${API}/analytics/dashboard`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
      operationalCost: () =>
        fetch(`${API}/analytics/operational-cost`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
      fuelEfficiency: () =>
        fetch(`${API}/analytics/fuel-efficiency`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
      reports: () => fetch(`${API}/analytics/reports`, { headers: getHeaders(getToken) }).then(parseJsonSafe),
    },
  };
}
