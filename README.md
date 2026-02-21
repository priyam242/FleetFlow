# FleetFlow - Modular Fleet & Logistics Management System

A full-stack fleet management system built with **React.js**, **Express.js**, **Node.js**, and **PostgreSQL**.

## Quick Start

### 1. PostgreSQL Setup
- Install PostgreSQL and create a database named `fleetflow`:
  ```bash
  createdb fleetflow
  ```
- Or in psql: `CREATE DATABASE fleetflow;`

### 2. Backend
```bash
cd backend
cp .env.example .env
# Edit .env and set DATABASE_URL and JWT_SECRET
npm install
npm run db:init
npm run db:seed
npm run dev
```
Backend runs at http://localhost:5001

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```
Frontend runs at http://localhost:3000

### 4. Login
- Email: **admin@fleetflow.com**
- Password: **admin123**

---

See **README_HINDI.md** for full code explanation and run instructions in Hindi.
