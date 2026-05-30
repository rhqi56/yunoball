const express = require('express');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ── SUPABASE ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ── ACTIVE SESSIONS (in-memory) ──
const sessions = new Map();

app.use(express.json());
app.use(express.static('.'));

// ── RATE LIMITER — max 10 requests per minute per IP ──
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── STRICTER LIMITER for login — max 5 attempts per 5 minutes ──
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Too many login attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── AUTH MIDDLEWARE — checks session token ──
function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
  }
  // Attach user to request
  req.user = sessions.get(token);
  next();
}

// ── ADMIN MIDDLEWARE ──
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required.' });
  }
  next();
}

// ══════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════

// ── REGISTER ──
app.post('/api/register', limiter, async (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password)
    return res.status(400).json({ success: false, message: 'All fields required.' });
  if (password.length < 6)
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
  if (username.length < 3)
    return res.status(400).json({ success: false, message: 'Username must be at least 3 characters.' });

  try {
    const { data: existing } = await supabase
      .from('users').select('id').eq('username', username).single();
    if (existing)
      return res.status(400).json({ success: false, message: 'Username already taken.' });

    const hash = await bcrypt.hash(password, 12);
    const { error } = await supabase
      .from('users').insert({ username, password_hash: hash, role: 'user' });
    if (error)
      return res.status(500).json({ success: false, message: 'Registration failed.' });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── LOGIN ──
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    const { data: user, error } = await supabase
      .from('users').select('*').eq('username', username).single();

    if (error || !user) {
      await supabase.from('activity_logs').insert({
        username: username || 'unknown',
        action: 'LOGIN_FAILED',
        ip_address: ip,
        status: 'failed'
      });
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      await supabase.from('activity_logs').insert({
        username,
        action: 'LOGIN_FAILED',
        ip_address: ip,
        status: 'failed'
      });
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    // Create session token
    const token = uuidv4();
    sessions.set(token, {
      username: user.username,
      role: user.role,
      loginTime: new Date()
    });

    // Auto-expire session after 8 hours
    setTimeout(() => sessions.delete(token), 8 * 60 * 60 * 1000);

    await supabase.from('activity_logs').insert({
      username,
      action: 'LOGIN_SUCCESS',
      ip_address: ip,
      status: 'success'
    });

    res.json({ success: true, role: user.role, username: user.username, token });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── LOGOUT ──
app.post('/api/logout', requireAuth, async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const token = req.headers['x-session-token'];

  // Destroy session
  sessions.delete(token);

  await supabase.from('activity_logs').insert({
    username: req.user.username,
    action: 'LOGOUT',
    ip_address: ip,
    status: 'success'
  });

  res.json({ success: true });
});

// ── LOGS — admin only ──
app.get('/api/logs', requireAuth, requireAdmin, async (req, res) => {
  const { data } = await supabase
    .from('activity_logs')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(100);
  res.json(data || []);
});

// ── VERIFY SESSION — frontend can check if token is still valid ──
app.get('/api/verify', requireAuth, (req, res) => {
  res.json({ success: true, user: req.user });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Running on port ${PORT}`));
