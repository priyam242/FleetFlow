-- FleetFlow PostgreSQL Schema
-- Run this via initDb.js or psql

-- Users with Role-Based Access (Manager, Dispatcher, Safety Officer, Financial Analyst)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL CHECK (role IN ('manager', 'dispatcher', 'safety_officer', 'financial_analyst', 'driver')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vehicles (Asset Registry)
CREATE TABLE IF NOT EXISTS vehicles (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  model VARCHAR(255),
  license_plate VARCHAR(50) UNIQUE NOT NULL,
  vehicle_type VARCHAR(50) NOT NULL CHECK (vehicle_type IN ('truck', 'van', 'bike')),
  max_capacity_kg DECIMAL(12,2) NOT NULL,
  odometer DECIMAL(12,2) DEFAULT 0,
  status VARCHAR(50) DEFAULT 'available' CHECK (status IN ('available', 'on_trip', 'in_shop', 'out_of_service')),
  region VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Drivers (Human Resource & Compliance)
CREATE TABLE IF NOT EXISTS drivers (
  id SERIAL PRIMARY KEY,
  full_name VARCHAR(255) NOT NULL,
  license_number VARCHAR(100),
  license_expiry DATE,
  license_category VARCHAR(50),
  status VARCHAR(50) DEFAULT 'off_duty' CHECK (status IN ('on_duty', 'off_duty', 'suspended')),
  safety_score DECIMAL(4,2) DEFAULT 100,
  trips_completed INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Trips (Dispatch & Lifecycle: draft -> dispatched -> completed -> cancelled)
CREATE TABLE IF NOT EXISTS trips (
  id SERIAL PRIMARY KEY,
  vehicle_id INT REFERENCES vehicles(id),
  driver_id INT REFERENCES drivers(id),
  cargo_weight_kg DECIMAL(12,2) NOT NULL,
  origin VARCHAR(255),
  destination VARCHAR(255),
  status VARCHAR(50) DEFAULT 'draft' CHECK (status IN ('draft', 'dispatched', 'completed', 'cancelled')),
  start_odometer DECIMAL(12,2),
  end_odometer DECIMAL(12,2),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP,
  created_by INT REFERENCES users(id)
);

-- Maintenance & Service Logs (vehicle status -> in_shop when logged)
CREATE TABLE IF NOT EXISTS maintenance_logs (
  id SERIAL PRIMARY KEY,
  vehicle_id INT NOT NULL REFERENCES vehicles(id),
  description TEXT NOT NULL,
  cost DECIMAL(12,2) DEFAULT 0,
  service_date DATE DEFAULT CURRENT_DATE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_by INT REFERENCES users(id)
);

-- Fuel Logs (per vehicle, for cost calculation)
CREATE TABLE IF NOT EXISTS fuel_logs (
  id SERIAL PRIMARY KEY,
  vehicle_id INT NOT NULL REFERENCES vehicles(id),
  trip_id INT REFERENCES trips(id),
  liters DECIMAL(10,2) NOT NULL,
  cost DECIMAL(12,2) NOT NULL,
  fuel_date DATE DEFAULT CURRENT_DATE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Expenses (other operational costs linked to vehicle)
CREATE TABLE IF NOT EXISTS expenses (
  id SERIAL PRIMARY KEY,
  vehicle_id INT NOT NULL REFERENCES vehicles(id),
  trip_id INT REFERENCES trips(id),
  amount DECIMAL(12,2) NOT NULL,
  description VARCHAR(255),
  expense_date DATE DEFAULT CURRENT_DATE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_vehicles_status ON vehicles(status);
CREATE INDEX IF NOT EXISTS idx_vehicles_type ON vehicles(vehicle_type);
CREATE INDEX IF NOT EXISTS idx_trips_status ON trips(status);
CREATE INDEX IF NOT EXISTS idx_trips_vehicle ON trips(vehicle_id);
CREATE INDEX IF NOT EXISTS idx_drivers_status ON drivers(status);
CREATE INDEX IF NOT EXISTS idx_fuel_vehicle ON fuel_logs(vehicle_id);
CREATE INDEX IF NOT EXISTS idx_maintenance_vehicle ON maintenance_logs(vehicle_id);
