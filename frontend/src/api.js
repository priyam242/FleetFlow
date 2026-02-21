const API = '/api';

function getHeaders(getToken) {
  const token = getToken?.();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export function createApi(getToken) {
  return {
    auth: {
      login: (email, password) =>
        fetch(`${API}/auth/login`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify({ email, password }),
        }).then((r) => r.json()),
      forgotPassword: (email) =>
        fetch(`${API}/auth/forgot-password`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify({ email }),
        }).then((r) => r.json()),
    },
    users: {
      create: (data) =>
        fetch(`${API}/users`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
    },
    dashboard: () =>
      fetch(`${API}/analytics/dashboard`, { headers: getHeaders(getToken) }).then((r) => r.json()),
    vehicles: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/vehicles${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then((r) => r.json());
      },
      get: (id) => fetch(`${API}/vehicles/${id}`, { headers: getHeaders(getToken) }).then((r) => r.json()),
      create: (data) =>
        fetch(`${API}/vehicles`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
      update: (id, data) =>
        fetch(`${API}/vehicles/${id}`, {
          method: 'PUT',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
      delete: (id) =>
        fetch(`${API}/vehicles/${id}`, { method: 'DELETE', headers: getHeaders(getToken) }).then((r) => r.json()),
    },
    drivers: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/drivers${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then((r) => r.json());
      },
      get: (id) => fetch(`${API}/drivers/${id}`, { headers: getHeaders(getToken) }).then((r) => r.json()),
      create: (data) =>
        fetch(`${API}/drivers`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
      update: (id, data) =>
        fetch(`${API}/drivers/${id}`, {
          method: 'PUT',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
    },
    trips: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/trips${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then((r) => r.json());
      },
      get: (id) => fetch(`${API}/trips/${id}`, { headers: getHeaders(getToken) }).then((r) => r.json()),
      create: (data) =>
        fetch(`${API}/trips`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
      updateStatus: (id, status, end_odometer) =>
        fetch(`${API}/trips/${id}/status`, {
          method: 'PATCH',
          headers: getHeaders(getToken),
          body: JSON.stringify({ status, end_odometer }),
        }).then((r) => r.json()),
    },
    maintenance: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/maintenance${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then((r) => r.json());
      },
      create: (data) =>
        fetch(`${API}/maintenance`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
    },
    fuel: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/fuel${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then((r) => r.json());
      },
      create: (data) =>
        fetch(`${API}/fuel`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
    },
    expenses: {
      list: (params) => {
        const q = new URLSearchParams(params).toString();
        return fetch(`${API}/expenses${q ? '?' + q : ''}`, { headers: getHeaders(getToken) }).then((r) => r.json());
      },
      create: (data) =>
        fetch(`${API}/expenses`, {
          method: 'POST',
          headers: getHeaders(getToken),
          body: JSON.stringify(data),
        }).then((r) => r.json()),
    },
    analytics: {
      dashboard: () => fetch(`${API}/analytics/dashboard`, { headers: getHeaders(getToken) }).then((r) => r.json()),
      operationalCost: () =>
        fetch(`${API}/analytics/operational-cost`, { headers: getHeaders(getToken) }).then((r) => r.json()),
      fuelEfficiency: () =>
        fetch(`${API}/analytics/fuel-efficiency`, { headers: getHeaders(getToken) }).then((r) => r.json()),
      reports: () => fetch(`${API}/analytics/reports`, { headers: getHeaders(getToken) }).then((r) => r.json()),
    },
  };
}
