import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { createApi } from '../api';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [forgot, setForgot] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const api = createApi();

  // Redirect already-authenticated users to dashboard
  const { user } = useAuth();
  useEffect(() => {
    if (user) navigate('/');
  }, [user, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (forgot) {
      const res = await api.auth.forgotPassword(email);
      if (res.error) setError(res.error);
      else setError(''); alert('If this email exists, reset instructions would be sent.');
      return;
    }
    const res = await api.auth.login(email, password);
    if (res.error) setError(res.error);
    else {
      login(res.token, res.user);
      navigate('/');
    }
  };

  return (
    <div className="container" style={{ maxWidth: '400px', marginTop: '4rem' }}>
      <div className="card">
        <h1 style={{ marginBottom: '1rem' }}>FleetFlow</h1>
        <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>Fleet & Logistics Management</p>
        <form onSubmit={handleSubmit}>
          <label>Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="admin@fleetflow.com" />
          {!forgot && (
            <>
              <label>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </>
          )}
          {error && <p style={{ color: '#f87171', marginBottom: '0.5rem' }}>{error}</p>}
          <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }}>
            {forgot ? 'Send Reset Link' : 'Login'}
          </button>
          <button type="button" className="btn btn-secondary" style={{ width: '100%', marginTop: '0.5rem' }} onClick={() => setForgot(!forgot)}>
            {forgot ? 'Back to Login' : 'Forgot Password?'}
          </button>
        </form>
        <div style={{ marginTop: '1rem', textAlign: 'center' }}>
          <p style={{ marginBottom: '0.5rem', color: '#94a3b8' }}>Don't have an account?</p>
          <Link to="/register" className="btn btn-primary">Register as Driver</Link>
        </div>
      </div>
    </div>
  );
}
