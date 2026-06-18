const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Database Connection Definition
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

// Middleware Architecture
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(express.json());
app.use(cors({ origin: '*' }));

// Serve static frontend files from the public folder
app.use(express.static(path.join(__dirname, '../public')));

// Rate Limiter to protect endpoints
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts. Try again later.' }
});

/* ==========================================================================
   USER AUTHENTICATION PIPELINES
   ========================================================================== */

// 1. SIGN UP ROUTE
app.post('/api/auth/signup', formLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are strictly mandatory.' });
  }

  try {
    // Check if the user email signature already exists
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email registry profile already exists.' });
    }

    // Insert user credentials into database
    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING name, email',
      [name, email.toLowerCase(), password] // In standard production environments, pass this through hashing middleware (e.g., bcrypt)
    );

    res.status(201).json({ 
      success: true, 
      message: 'Account registered successfully!',
      name: newUser.rows[0].name,
      email: newUser.rows[0].email
    });
  } catch (err) {
    res.status(500).json({ error: 'Database pipeline registration crash.' });
  }
});

// 2. LOGIN ROUTE
app.post('/api/auth/login', formLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email record or password verification.' });
    }

    const user = result.rows[0];
    
    // Validate password signature
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid email record or password verification.' });
    }

    res.json({
      success: true,
      message: 'Authentication validated!',
      name: user.name,
      email: user.email
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal system validation error.' });
  }
});

// 3. FORGOT PASSWORD ROUTE
app.post('/api/auth/forgot', formLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Target email coordinate required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No account matching that email address found.' });
    }

    // Standard simulation link generation pipeline
    res.json({
      success: true,
      message: 'Password reset link dispatched! Check your workspace folder.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Security structural routing crash.' });
  }
});

/* ==========================================================================
   PORTFOLIO CONTENT ROUTING PIPELINES
   ========================================================================== */

app.get('/api/projects', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM projects ORDER BY sort_order ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database read failure.' });
  }
});

app.post('/api/contact', async (req, res) => {
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

// Wildcard Fallback Route to serve index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => console.log(`Server executing securely on port ${PORT}`));
