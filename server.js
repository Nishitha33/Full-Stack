// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(bodyParser.json());
app.use(cookieParser());

// Allow requests from the demo client origin (adjust for your client)
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true // allow cookies
}));

/*
  For demo only: in-memory "database".
  In production, use a proper DB for users, balances and persisted refresh tokens.
*/
const users = [
  {
    id: 'u1',
    username: 'alice',
    // password: "password123" hashed:
    passwordHash: bcrypt.hashSync('password123', 10),
    balance: 1000.00
  },
  {
    id: 'u2',
    username: 'bob',
    passwordHash: bcrypt.hashSync('hunter2', 10),
    balance: 250.50
  }
];

// In-memory refresh token store (map userId -> refreshToken list). Production: DB.
const refreshTokensStore = {
  // userId: [refreshToken1, refreshToken2, ...]
};

function saveRefreshToken(userId, token) {
  refreshTokensStore[userId] = refreshTokensStore[userId] || [];
  refreshTokensStore[userId].push(token);
}

function revokeRefreshToken(userId, token) {
  if (!refreshTokensStore[userId]) return;
  refreshTokensStore[userId] = refreshTokensStore[userId].filter(t => t !== token);
}

function isRefreshTokenValid(userId, token) {
  if (!refreshTokensStore[userId]) return false;
  return refreshTokensStore[userId].includes(token);
}

/* JWT helpers */
const ACCESS_EXPIRES_IN = '15m';
const REFRESH_EXPIRES_IN = '7d';
const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET || 'access-secret-demo';
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || 'refresh-secret-demo';

function generateAccessToken(user) {
  // minimal payload - include user id & username
  return jwt.sign({ userId: user.id, username: user.username }, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES_IN });
}

function generateRefreshToken(user) {
  return jwt.sign({ userId: user.id }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES_IN });
}

/* Middleware to protect routes */
function authenticateAccessToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Malformed authorization header' });

  jwt.verify(token, ACCESS_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ message: 'Invalid or expired access token' });
    req.user = { id: payload.userId, username: payload.username };
    next();
  });
}

/* Routes */

// Simple login: returns access token and sets refresh token in HttpOnly cookie
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  saveRefreshToken(user.id, refreshToken);

  // Set refresh token in HttpOnly cookie. In production: secure: true, sameSite: 'None' (if cross-site)
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: false, // set true when using HTTPS
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.json({ accessToken });
});

// Token refresh endpoint - swaps refresh token (from cookie) for a new access token
app.post('/token', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token' });

  jwt.verify(token, REFRESH_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ message: 'Invalid refresh token' });

    const userId = payload.userId;
    // verify token is in our store (revocation checking)
    if (!isRefreshTokenValid(userId, token)) return res.status(403).json({ message: 'Refresh token revoked' });

    const user = users.find(u => u.id === userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const accessToken = generateAccessToken(user);
    res.json({ accessToken });
  });
});

// Logout: remove refresh token cookie + revoke refresh token
app.post('/logout', (req, res) => {
  const token = req.cookies.refreshToken;
  if (token) {
    try {
      const payload = jwt.verify(token, REFRESH_SECRET);
      revokeRefreshToken(payload.userId, token);
    } catch (e) {
      // ignore
    }
  }
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out' });
});

/* Protected banking endpoints */

// Get account balance
app.get('/balance', authenticateAccessToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ balance: user.balance, username: user.username });
});

// Transfer money to another user (very simplified)
app.post('/transfer', authenticateAccessToken, (req, res) => {
  const { toUsername, amount } = req.body;
  const fromUser = users.find(u => u.id === req.user.id);
  const toUser = users.find(u => u.username === toUsername);

  if (!toUser) return res.status(404).json({ message: 'Recipient not found' });
  const amt = Number(amount);
  if (!amt || amt <= 0) return res.status(400).json({ message: 'Invalid amount' });
  if (fromUser.balance < amt) return res.status(400).json({ message: 'Insufficient funds' });

  // perform transfer
  fromUser.balance -= amt;
  toUser.balance += amt;

  res.json({ message: 'Transfer successful', fromBalance: fromUser.balance });
});

/* Start */
app.listen(PORT, () => {
  console.log(`Demo banking API running on http://localhost:${PORT}`);
  console.log('Seeded users: alice/password123, bob/hunter2');
});
