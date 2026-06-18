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

// Increase JSON body limits so large picture files pass through cleanly
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.static(path.join(__dirname, '../public')));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many requests. Try again later.' }
});

/* ==========================================================================
   USER AUTHENTICATION PIPELINES & IMAGE STORAGE
   ========================================================================== */

// 1. SIGN UP ROUTE
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Account registry email already exists.' });
    }

    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING name, email, profile_image_url',
      [name, email.toLowerCase(), password]
    );

    res.status(201).json({ 
      success: true, 
      message: 'Account created! Entering workspace...',
      name: newUser.rows[0].name,
      email: newUser.rows[0].email,
      profile_image_url: newUser.rows[0].profile_image_url
    });
  } catch (err) {
    res.status(500).json({ error: 'Database pipeline registration failure.' });
  }
});

// 2. LOGIN ROUTE
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0 || result.rows[0].password !== password) {
      return res.status(401).json({ error: 'Invalid email record or password verification.' });
    }

    const user = result.rows[0];
    res.json({
      success: true,
      message: 'Access Granted! Initializing portfolio datasets...',
      name: user.name,
      email: user.email,
      profile_image_url: user.profile_image_url
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal system validation error.' });
  }
});

// 3. FORGOT PASSWORD SIMULATION
app.post('/api/auth/forgot', authLimiter, async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No account matching that email found.' });
    }
    res.json({ success: true, message: 'Password reset link simulated in active directory logs.' });
  } catch (err) {
    res.status(500).json({ error: 'Routing parameter reset error.' });
  }
});

// 4. PERMANENT PROFILE PICTURE UPDATE ROUTE
app.post('/api/auth/update-picture', async (req, res) => {
  const { email, image_data } = req.body;
  if (!email || !image_data) {
    return res.status(400).json({ error: 'Missing image payload arguments.' });
  }

  try {
    // Save image string completely into users database table row entry securely
    await pool.query(
      'UPDATE users SET profile_image_url = $1 WHERE email = $2',
      [image_data, email.toLowerCase()]
    );

    res.json({ success: true, message: 'Image configuration saved permanently to Neon!' });
  } catch (err) {
    res.status(500).json({ error: 'Failed mapping image string stream to Neon table structural profile.' });
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
  const { name, message } = req.body;
  try {
    await pool.query(
      'INSERT INTO contact_submissions (name, email, subject, message) VALUES ($1, $2, $3, $4)',
      [name || 'Anonymous Portal User', 'portal@system.local', 'Gate Form Submission', message]
    );
    res.status(201).json({ success: true, message: 'Saved successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Database write failure.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => console.log(`Server executing securely on port ${PORT}`));
