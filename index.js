const FAST_SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 }; // Fast mode (<1s)
const SLOW_SCRYPT_PARAMS = { N: 131072, r: 8, p: 15 }; // Slow mode (>3s)

const express = require('express');
const logger = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();
const scryptPbkdf = require('scrypt-pbkdf');

const jwtSecret = crypto.randomBytes(16);
const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');
const port = 443;
const app = express();
const db = new sqlite3.Database('./users.db');

app.use(logger('dev'));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// Initialize the database
const initDB = () => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    salt TEXT
  )`);
};
initDB();

// Hash password using scrypt
async function hashPassword(password, fastMode = false) {
  const salt = scryptPbkdf.salt();
  const params = fastMode ? FAST_SCRYPT_PARAMS : SLOW_SCRYPT_PARAMS;
  const derivedKey = await scryptPbkdf.scrypt(password, salt, 32, params);
  return { 
      hash: Buffer.from(derivedKey).toString('hex'), 
      salt: Buffer.from(salt).toString('hex') 
  };
}

// Verify password
async function verifyPassword(password, storedHash, storedSalt, fastMode = false) {
  const params = fastMode ? FAST_SCRYPT_PARAMS : SLOW_SCRYPT_PARAMS;
  const derivedKey = await scryptPbkdf.scrypt(password, Buffer.from(storedSalt, 'hex'), 32, params);
  return Buffer.from(derivedKey).toString('hex') === storedHash;
}

// Passport local strategy
passport.use('username-password', new LocalStrategy(
  async (username, password, done) => {
    db.get('SELECT password_hash, salt FROM users WHERE username = ?', [username], async (err, row) => {
      if (err) return done(err);
      if (!row) return done(null, false);
      const isValid = await verifyPassword(password, row.password_hash, row.salt, false);
      if (isValid) {
        return done(null, { username });
      }
      return done(null, false);
    });
  }
));

// JWT Strategy
passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: (req) => req.cookies.jwt,
    secretOrKey: jwtSecret
  },
  (jwtPayload, done) => {
    return done(null, { username: jwtPayload.sub });
  }
));

app.get('/', passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }), (req, res) => {
  res.send(`Welcome, ${req.user.username}!`);
});

app.get('/login', (req, res) => {
  res.sendFile('login.html', { root: __dirname });
});

app.post('/login', passport.authenticate('username-password', { session: false, failureRedirect: '/login' }), (req, res) => {
  const jwtClaims = {
    sub: req.user.username,
    exp: Math.floor(Date.now() / 1000) + 604800
  };
  const token = jwt.sign(jwtClaims, jwtSecret);
  res.cookie('jwt', token, { httpOnly: true, secure: true });
  res.redirect('/');
});

app.get('/register', (req, res) => {
  res.sendFile('register.html', { root: __dirname });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const { salt, hash } = await hashPassword(password, false);
  db.run('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', [username, hash, salt], (err) => {
    if (err) return res.status(400).send('User already exists');
    res.redirect('/login');
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('jwt', { httpOnly: true, secure: true });
  res.redirect('/login');
});

const httpsOptions = { key: tlsServerKey, cert: tlsServerCrt };
https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`HTTPS server listening at https://localhost:${port}`);
});
