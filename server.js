const express = require('express');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase connection
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

app.use(express.json());
app.use(express.static('.'));

// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    // Get user from database
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !user) {
      // Log failed attempt
      await supabase.from('activity_logs').insert({
        username: username || 'unknown',
        action: 'LOGIN_FAILED',
        ip_address: ip,
        status: 'failed'
      });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check password
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      await supabase.from('activity_logs').insert({
        username,
        action: 'LOGIN_FAILED',
        ip_address: ip,
        status: 'failed'
      });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Success — log it
    await supabase.from('activity_logs').insert({
      username,
      action: 'LOGIN_SUCCESS',
      ip_address: ip,
      status: 'success'
    });

    res.json({ success: true, role: user.role, username: user.username });

  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Logout route
app.post('/api/logout', async (req, res) => {
  const { username } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  await supabase.from('activity_logs').insert({
    username,
    action: 'LOGOUT',
    ip_address: ip,
    status: 'success'
  });
  res.json({ success: true });
});

// Get logs (admin only)
app.get('/api/logs', async (req, res) => {
  const { data, error } = await supabase
    .from('activity_logs')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(50);
  res.json(data || []);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Running on port ${PORT}`));