import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createApi } from '../api';

export default function Register() {
  const api = createApi();
  const [form, setForm] = useState({ full_name: '', email: '', password: '' });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const save = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (!form.email || !form.full_name || !form.password) {
      setError('Full name, email and password are required.');
      return;
    }
    try {
      const res = await api.users.register({ full_name: form.full_name, email: form.email, password: form.password, role: 'driver' });
      if (res.error) setError(res.error);
      else {
        setForm({ full_name: '', email: '', password: '' });
        // go to login after successful registration
        navigate('/login');
      }
    } catch (err) {
      setError(err.message || 'Registration failed');
    }
  };

  return (
    <div className="container" style={{ maxWidth: '480px', marginTop: '3rem' }}>
      <div className="card">
        <h1>Register</h1>
        <p style={{ color: '#94a3b8' }}>Create a driver account.</p>
        <form onSubmit={save}>
          <label>Full Name</label>
          <input value={form.full_name} onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))} required />
          <label>Email</label>
          <input type="email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} required />
          <label>Password</label>
          <input type="password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} required />
          {error && <p style={{ color: '#f87171' }}>{error}</p>}
          {success && <p style={{ color: '#34d399' }}>{success}</p>}
          <div className="flex mt1">
            <button type="submit" className="btn btn-primary">Register</button>
          </div>
        </form>
      </div>
    </div>
  );
}
