const express = require('express');
const bcrypt = require('bcryptjs');
const { pool } = require('../config/db');
const { auth, requireRole } = require('../middleware/auth');

const router = express.Router();

const ALLOWED_ROLES = ['manager', 'dispatcher', 'safety_officer', 'financial_analyst', 'driver'];

// Create user (only manager can create users)
router.post('/', auth, requireRole('manager'), async (req, res) => {
  try {
    const { full_name, email, password, role } = req.body;
    if (!full_name || !email || !role) {
      return res.status(400).json({ error: 'full_name, email and role are required.' });
    }
    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: 'Invalid role.' });
    }

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'User with this email already exists.' });
    }

    const rawPassword = password || Math.random().toString(36).slice(-12);
    const hash = await bcrypt.hash(rawPassword, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, role, created_at`,
      [email, hash, full_name, role]
    );

    const user = result.rows[0];
    // Return created user and temporary password if we generated one
    res.json({ user, tempPassword: password ? undefined : rawPassword });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
