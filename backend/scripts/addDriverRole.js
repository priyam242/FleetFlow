/**
 * Migration: Add 'driver' to users.role check constraint
 * Run: node scripts/addDriverRole.js
 */
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function run() {
  try {
    console.log('Altering users.role check constraint...');
    await pool.query("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check");
    await pool.query("ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('manager','dispatcher','safety_officer','financial_analyst','driver'))");
    console.log('Constraint updated successfully.');
  } catch (err) {
    console.error('Migration error:', err.message || err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

run();
