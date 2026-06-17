const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Database Connection Definition
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

// Middleware
app.use(helmet());
app.use(express.json());
app.use(cors({ origin: '*' })); // Allows connection access during layout builds

// Rate Limiter to stop form spamming
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many requests. Try again later.' }
});

// API Routes
app.get('/api/projects', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM projects ORDER BY sort_order ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database read failure.' });
  }
});

app.post('/api/contact', formLimiter, async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: 'All parameters mandatory.' });
  }
  try {
    await pool.query(
      'INSERT INTO contact_submissions (name, email, subject, message) VALUES ($1, $2, $3, $4)',
      [name, email, subject, message]
    );
    res.status(201).json({ success: true, message: 'Saved successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Database write failure.' });
  }
});

app.listen(PORT, () => console.log(`Server executing securely on port ${PORT}`));
