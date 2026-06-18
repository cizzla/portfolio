const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

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

// Configure Secure SMTP Mail Transporter Engine
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* ==========================================================================
   USER AUTHENTICATION PIPELINES
   ========================================================================== */

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required.' });
  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (userCheck.rows.length > 0) return res.status(400).json({ error: 'Account registry email already exists.' });

    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING name, email, profile_image_url',
      [name, email.toLowerCase(), password]
    );
    res.status(201).json({ 
      success: true, message: 'Account created!', name: newUser.rows[0].name, email: newUser.rows[0].email, profile_image_url: newUser.rows[0].profile_image_url 
    });
  } catch (err) { res.status(500).json({ error: 'Database error.' }); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0 || result.rows[0].password !== password) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const user = result.rows[0];
    res.json({ success: true, message: 'Access Granted!', name: user.name, email: user.email, profile_image_url: user.profile_image_url });
  } catch (err) { res.status(500).json({ error: 'System validation error.' }); }
});

// 1. TRIGGER ACTUAL REAL PASSWORD RESET EMAIL
app.post('/api/auth/forgot', authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email coordinate required.' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'No account matching that email found.' });

    // Generate secure crypto hex token string
    const token = crypto.randomBytes(20).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 Hour lifespan

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3',
      [token, expires, email.toLowerCase()]
    );

    const resetUrl = `${req.protocol}://${req.get('host')}?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email.toLowerCase(),
      subject: 'Fred Waweru Portal - Password Reset Security Token',
      html: `
        <div style="font-family: sans-serif; padding: 20px; max-width: 500px; border: 1px solid #e2e8f0; rounded: 12px;">
          <h2 style="color: #2563eb;">Password Reset Request</h2>
          <p>You requested a system credential parameter modification. Click the secure routing anchor below to formulate your new password configuration:</p>
          <a href="${resetUrl}" style="display: inline-block; background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 15px 0;">Reset My Password</a>
          <p style="font-size: 11px; color: #64748b;">This link remains valid for exactly 60 minutes. If you did not initiate this command, please disregard this transmission.</p>
        </div>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Secure link dispatched! Check your email inbox.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed executing mail delivery configuration subsystem.' });
  }
});

// 2. CONFIRM RESET TOKEN AND UPDATE CHANNELS
app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Missing security payload attributes.' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: 'Token validation expired or configuration invalid.' });

    const user = result.rows[0];
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [newPassword, user.id]
    );

    res.json({ success: true, message: 'Password updated successfully! Redirecting to login portal...' });
  } catch (err) { res.status(500).json({ error: 'Failed modifying credential row variables.' }); }
});

app.post('/api/auth/update-picture', async (req, res) => {
  const { email, image_data } = req.body;
  try {
    await pool.query('UPDATE users SET profile_image_url = $1 WHERE email = $2', [image_data, email.toLowerCase()]);
    res.json({ success: true, message: 'Image configuration saved permanently to Neon!' });
  } catch (err) { res.status(500).json({ error: 'Failed mapping image layout.' }); }
});

/* ==========================================================================
   PORTFOLIO INFRASTRUCTURE ROUTES
   ========================================================================== */

app.get('/api/projects', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM projects ORDER BY sort_order ASC');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Database failure.' }); }
});

app.post('/api/contact', async (req, res) => {
  const { name, message } = req.body;
  try {
    await pool.query(
      'INSERT INTO contact_submissions (name, email, subject, message) VALUES ($1, $2, $3, $4)',
      [name || 'Portal User', 'portal@system.local', 'Gate Form Submission', message]
    );
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Write failure.' }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => console.log(`Server running safely on port ${PORT}`));
