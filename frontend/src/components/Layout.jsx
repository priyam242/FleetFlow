import { Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Link } from 'react-router-dom';

export default function Layout() {
  const { user, logout } = useAuth();

  return (
    <>
      <nav>
        <Link to="/" className="brand">FleetFlow</Link>
        <div className="flex">
          <Link to="/">Dashboard</Link>
          <Link to="/vehicles">Vehicles</Link>
          <Link to="/trips">Trips</Link>
          <Link to="/maintenance">Maintenance</Link>
          <Link to="/fuel-expense">Fuel & Expense</Link>
          <Link to="/drivers">Drivers</Link>
          <Link to="/users/create">Create User</Link>
          <Link to="/analytics">Analytics</Link>
          <span style={{ color: '#94a3b8', marginLeft: '0.5rem' }}>{user?.full_name} ({user?.role})</span>
          <button className="btn btn-secondary" onClick={logout} style={{ marginLeft: '0.5rem' }}>Logout</button>
        </div>
      </nav>
      <main className="container" style={{ paddingTop: '1.5rem' }}>
        <Outlet />
      </main>
    </>
  );
}
