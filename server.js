const express = require('express');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

app.use(express.json());
app.use(express.static('.'));

// ── REGISTER ──
app.post('/api/register', async (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password) return res.status(400).json({ success: false, message: 'All fields required.' });
  if (password.length < 6) return res.status(400).json({ success: false, message: 'Password too short.' });

  try {
    const { data: existing } = await supabase.from('users').select('id').eq('username', username).single();
    if (existing) return res.status(400).json({ success: false, message: 'Username already taken.' });

    const hash = await bcrypt.hash(password, 10);
    const { error } = await supabase.from('users').insert({ username, password_hash: hash, role: 'user' });
    if (error) return res.status(500).json({ success: false, message: 'Registration failed.' });

    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    const { data: user, error } = await supabase.from('users').select('*').eq('username', username).single();

    if (error || !user) {
      await supabase.from('activity_logs').insert({ username: username || 'unknown', action: 'LOGIN_FAILED', ip_address: ip, status: 'failed' });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      await supabase.from('activity_logs').insert({ username, action: 'LOGIN_FAILED', ip_address: ip, status: 'failed' });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    await supabase.from('activity_logs').insert({ username, action: 'LOGIN_SUCCESS', ip_address: ip, status: 'success' });
    res.json({ success: true, role: user.role, username: user.username });

  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── LOGOUT ──
app.post('/api/logout', async (req, res) => {
  const { username } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  await supabase.from('activity_logs').insert({ username, action: 'LOGOUT', ip_address: ip, status: 'success' });
  res.json({ success: true });
});

// ── LOGS ──
app.get('/api/logs', async (req, res) => {
  const { data } = await supabase.from('activity_logs').select('*').order('timestamp', { ascending: false }).limit(100);
  res.json(data || []);
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
