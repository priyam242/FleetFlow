import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { createApi } from '../api';

export default function CreateUser() {
  const { getToken } = useAuth();
  const api = createApi(getToken);
  const [form, setForm] = useState({ full_name: '', email: '', password: '', role: 'manager' });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const roles = [
    { value: 'manager', label: 'Manager' },
    { value: 'dispatcher', label: 'Dispatcher' },
    { value: 'safety_officer', label: 'Safety Officer' },
    { value: 'financial_analyst', label: 'Financial Analyst' },
    { value: 'driver', label: 'Driver' },
  ];

  const save = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (!form.email || !form.full_name || !form.role) {
      setError('Full name, email and role are required.');
      return;
    }
    const payload = { full_name: form.full_name, email: form.email, role: form.role };
    if (form.password) payload.password = form.password;
    try {
      const res = await api.users.create(payload);
      if (res.error) setError(res.error);
      else {
        setSuccess('User created successfully');
        setForm({ full_name: '', email: '', password: '', role: 'manager' });
      }
    } catch (err) {
      setError(err.message || 'Failed to create user');
    }
  };

  return (
    <>
      <h1>Create User</h1>
      <p style={{ color: '#94a3b8' }}>Create application users and assign roles.</p>

      <div className="card mt1">
        <form onSubmit={save}>
          <div className="form-grid">
            <div>
              <label>Full Name *</label>
              <input value={form.full_name} onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))} required />
            </div>
            <div>
              <label>Email *</label>
              <input type="email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} required />
            </div>
            <div>
              <label>Role *</label>
              <select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}>
                {roles.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
              </select>
            </div>
            <div>
              <label>Password (optional)</label>
              <input type="password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} />
            </div>
          </div>
          {error && <p style={{ color: '#f87171' }}>{error}</p>}
          {success && <p style={{ color: '#34d399' }}>{success}</p>}
          <div className="flex mt1">
            <button type="submit" className="btn btn-primary">Create</button>
          </div>
        </form>
      </div>
    </>
  );
}
