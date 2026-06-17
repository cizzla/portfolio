const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const path = require('path'); // Added for handling folder paths securely

const app = express();
const PORT = process.env.PORT || 5000;

// Database Connection Definition
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disables strict CSP so CDNs for icons/Tailwind load smoothly
}));
app.use(express.json());
app.use(cors({ origin: '*' }));

// Serve static frontend files from the public folder
// This tells Express to serve everything inside the public folder automatically
app.use(express.static(path.join(__dirname, '../public')));

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
  const { name, email, subject, message } = require.body || req.body;
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

// Wildcard Route: If a user hits any other link, send them back to the main index.html page
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => console.log(`Server executing securely on port ${PORT}`));
