require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const csv = require('csv-parser');
const { Readable } = require('stream');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Environment ───
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

// ─── Security Middleware ───
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://*", "http://*"],
      connectSrc: ["'self'", SUPABASE_URL]
    }
  }
}));

// ─── FIX 1: CORS — same-origin Render pe sab allow ───
app.use(cors({
  origin: function(origin, callback) {
    // Same-origin requests (Render pe frontend + backend ek hi server pe hai)
    if (!origin) return callback(null, true);
    // localhost development bhi allow karo
    if (origin.includes('localhost') || origin.includes('onrender.com')) {
      return callback(null, true);
    }
    // Custom domain support via env variable
    if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip
});
app.use('/api', limiter);

// Stricter, dedicated limiter just for login — the client-side lockout in index.html
// is only a UX nicety (a script hitting the API directly can ignore it entirely), so
// the real brute-force defense has to live here, server-side, per IP.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { message: 'Too many login attempts from this IP. Try again in 15 minutes.' }
});

// ─── Supabase Clients ───
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ─── JWT Helpers ───
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' } // BUG2&3 FIX: 1h se 8h — client SESSION_TTL se match karo
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    // BUG5 FIX: expired aur invalid ka alag signal — client ko sahi message dikhao
    if (err && err.name === 'TokenExpiredError') return { __expired: true };
    return null;
  }
}

// ─── API Middleware ───
function verifyTokenAPI(req, res, next) {
  // BUG5 FIX: sirf Authorization header nahi — cms_token cookie bhi check karo
  // (protectStatic cookie use karta hai, lekin API calls header use karte hain;
  //  dono support karo taaki session ka koi bhi path kaam kare)
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.cookies && req.cookies.cms_token) {
    token = req.cookies.cms_token;
  }

  if (!token) {
    return res.status(401).json({ message: 'Session not found. Please login again.', code: 'NO_TOKEN' });
  }

  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({ message: 'Invalid session. Please login again.', code: 'INVALID_TOKEN' });
  }

  // BUG2 FIX: expired token pe clear message taaki client "Session expired" dikhaye logout ke bajaye
  if (decoded.__expired) {
    return res.status(401).json({ message: 'Your session has expired. Please login again.', code: 'TOKEN_EXPIRED' });
  }

  req.user = decoded;
  next();
}

function requireRole(roles) {
  const allowed = Array.isArray(roles) ? roles : [roles];
  return (req, res, next) => {
    if (!req.user || !allowed.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

// ─── Static File Protection ───
const PROTECTED_PAGES = ['student.html', 'teacher.html', 'admin.html'];
function protectStatic(req, res, next) {
  if (req.method !== 'GET') return next();
  const requestedPath = req.path.split('/').pop();
  if (!PROTECTED_PAGES.includes(requestedPath)) return next();

  let token = req.cookies?.cms_token || null;
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }
  }
  if (!token) return res.redirect('/');

  const decoded = verifyToken(token);
  if (!decoded) return res.redirect('/');

  const pageRoleMap = {
    'student.html': 'student',
    'teacher.html': 'teacher',
    'admin.html': 'admin'
  };
  const requiredRole = pageRoleMap[requestedPath];
  if (decoded.role !== requiredRole) return res.redirect('/');

  req.user = decoded;
  next();
}

// ─── FIX 2: Static Path — server.js backend/ mein hai, public/ uske bahar hai ───
// Render path: /opt/render/project/src/backend/server.js
// Public path: /opt/render/project/src/public/
const publicPath = process.env.PUBLIC_PATH
  ? path.resolve(process.env.PUBLIC_PATH)
  : path.join(__dirname, '..', 'public'); // backend/ se ek upar jaao, phir public/

// ─── Root route — MUST be BEFORE express.static ───
// BUG1&4 FIX: express.static pehle GET / intercept karta tha, isliye CSRF cookie
// kabhi set nahi hoti thi → generateCSRF() random fallback deta tha → server mismatch
// → "Session expired. Please refresh". /index.html direct access bhi cover karo.
app.get(['/', '/index.html'], (req, res) => {
  const csrfToken = crypto.randomBytes(24).toString('hex');
  res.cookie('csrf_token', csrfToken, {
    httpOnly: false, // JS ko ye read karna hai echo ke liye
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 28800000 // BUG2&3 FIX: 8h — JWT expiry se match karo
  });
  res.sendFile(path.join(publicPath, 'index.html'));
});

app.use(protectStatic);
// BUG1 FIX: index:false — express.static ab GET / ke liye index.html serve nahi karega
// (upar wala route handle karta hai aur CSRF cookie properly set karta hai)
app.use(express.static(publicPath, { index: false }));

// ─── CAPTCHA Store ───
const captchaStore = new Map();

// CAPTCHA cleanup — expire hue entries har 10 min mein delete karo
setInterval(() => {
  const now = Date.now();
  for (const [id, data] of captchaStore.entries()) {
    if (data.expires < now) captchaStore.delete(id);
  }
}, 600000);

// ─── Gmail Email Transporter ───
let emailTransporter = null;
if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
  emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
  });
  emailTransporter.verify((err) => {
    if (err) console.error('[EMAIL] Gmail transporter error:', err.message);
    else console.log('[EMAIL] Gmail transporter ready ✓');
  });
} else {
  console.warn('[EMAIL] GMAIL_USER or GMAIL_APP_PASSWORD not set — OTP emails will be logged only');
}

// ─── OTP Store (in-memory, 5 min TTL) ───
const otpStore = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of otpStore.entries()) {
    if (data.expires < now) otpStore.delete(key);
  }
}, 300000); // clean every 5 min

function generateOTPCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendOTPEmail(toEmail, otp, purpose, userName) {
  const purposeText = purpose === 'password_change' ? 'Password Change' : 'Login Verification';
  const htmlBody = `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:28px;background:#f8fafc;border-radius:12px;border:1px solid #e2e8f0;">
      <div style="text-align:center;margin-bottom:20px;">
        <div style="display:inline-block;background:#4f46e5;color:#fff;width:48px;height:48px;border-radius:50%;font-size:22px;line-height:48px;text-align:center;">🔐</div>
      </div>
      <h2 style="color:#1e293b;margin:0 0 8px;font-size:20px;">Verification Code</h2>
      <p style="color:#475569;margin:0 0 20px;font-size:14px;">Hello <strong>${userName || 'User'}</strong>, your OTP for <strong>${purposeText}</strong> is:</p>
      <div style="background:#4f46e5;color:#fff;font-size:34px;font-weight:700;letter-spacing:10px;text-align:center;padding:22px 16px;border-radius:10px;margin:20px 0;">${otp}</div>
      <p style="color:#64748b;font-size:13px;margin:0 0 8px;">⏱ This code expires in <strong>5 minutes</strong>.</p>
      <p style="color:#94a3b8;font-size:12px;margin:0;">Do not share this code. If you did not request this, contact your administrator immediately.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;">
      <p style="color:#cbd5e1;font-size:11px;text-align:center;margin:0;">College Management System — Automated Security Alert</p>
    </div>
  `;
  if (!emailTransporter) {
    console.log(`[OTP-DEV] Email not configured. OTP for ${toEmail} (${purpose}): ${otp}`);
    return true; // dev mode mein always success
  }
  try {
    await emailTransporter.sendMail({
      from: `"CMS Security" <${process.env.GMAIL_USER}>`,
      to: toEmail,
      subject: `[CMS] Your OTP: ${otp} (${purposeText})`,
      html: htmlBody
    });
    console.log(`[OTP] Sent to ${toEmail} for ${purpose}`);
    return true;
  } catch (err) {
    console.error('[OTP] Email send error:', err.message);
    return false;
  }
}

function sanitise(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'/\\`$&]/g, '')
            .replace(/alert|onerror|onload|script|javascript:/gi, '')
            .trim();
}

// ─── School Structure: Classes, Sections, Streams, Subjects ───
const VALID_CLASSES = ['9', '10', '11', '12'];
const VALID_SECTIONS = ['A', 'B', 'C'];
const VALID_STREAMS = ['Science', 'Commerce', 'Arts'];

const SUBJECTS_BY_CLASS = {
  '9': ['English', 'Hindi', 'Mathematics', 'Science', 'Social Science', 'Computer Science'],
  '10': ['English', 'Hindi', 'Mathematics', 'Science', 'Social Science', 'Computer Science'],
  '11': {
    Science: ['English', 'Physics', 'Chemistry', 'Mathematics', 'Biology', 'Computer Science'],
    Commerce: ['English', 'Accountancy', 'Business Studies', 'Economics', 'Mathematics'],
    Arts: ['English', 'History', 'Political Science', 'Geography', 'Economics']
  },
  '12': {
    Science: ['English', 'Physics', 'Chemistry', 'Mathematics', 'Biology', 'Computer Science'],
    Commerce: ['English', 'Accountancy', 'Business Studies', 'Economics', 'Mathematics'],
    Arts: ['English', 'History', 'Political Science', 'Geography', 'Economics']
  }
};

const SUBJECT_CODE = {
  'English': 'ENG', 'Hindi': 'HIN', 'Mathematics': 'MATH', 'Science': 'SCI',
  'Social Science': 'SST', 'Computer Science': 'CS', 'Physics': 'PHY', 'Chemistry': 'CHE',
  'Biology': 'BIO', 'Accountancy': 'ACC', 'Business Studies': 'BST', 'Economics': 'ECO',
  'History': 'HIS', 'Political Science': 'POL', 'Geography': 'GEO'
};

function getSubjectsForClass(classLevel, stream) {
  const entry = SUBJECTS_BY_CLASS[String(classLevel)];
  if (!entry) return [];
  if (Array.isArray(entry)) return entry;
  return entry[stream] || [];
}

function courseCodeFor(classLevel, stream, subject) {
  const subjCode = SUBJECT_CODE[subject] || subject.slice(0, 3).toUpperCase();
  if (stream) {
    return `${classLevel}-${stream.slice(0, 3).toUpperCase()}-${subjCode}`;
  }
  return `${classLevel}-${subjCode}`;
}

function courseTitleFor(classLevel, stream, subject) {
  return stream ? `${subject} (Class ${classLevel} - ${stream})` : `${subject} (Class ${classLevel})`;
}

async function findOrCreateCourse(classLevel, stream, subject) {
  const code = courseCodeFor(classLevel, stream, subject);
  const { data: existing, error: findErr } = await supabaseAdmin
    .from('courses').select('id').eq('code', code).maybeSingle();
  if (findErr) throw findErr;
  if (existing) return existing.id;
  const { data: created, error: createErr } = await supabaseAdmin
    .from('courses').insert({ code, title: courseTitleFor(classLevel, stream, subject), credits: 0 })
    .select('id').single();
  if (createErr) throw createErr;
  return created.id;
}

// ─── Account Activation Links ───
async function createActivationToken(userId) {
  // Invalidate any previous unused tokens for this user first
  await supabaseAdmin.from('activation_tokens').update({ used: true }).eq('user_id', userId).eq('used', false);
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  const { error } = await supabaseAdmin.from('activation_tokens').insert({
    user_id: userId, token, expires_at: expiresAt.toISOString(), used: false
  });
  if (error) throw error;
  return token;
}
function activationLink(req, token) {
  return `${req.protocol}://${req.get('host')}/activate.html?token=${token}`;
}
function isValidEmail(str) {
  return typeof str === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str.trim());
}

// ─── 1. CAPTCHA ───
// ─── 1b. CSRF Token Refresh (auto-called by frontend on session expiry) ───
app.get('/api/auth/csrf', (req, res) => {
  const csrfToken = crypto.randomBytes(24).toString('hex');
  res.cookie('csrf_token', csrfToken, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 28800000 // BUG4 FIX: 8h — JWT expiry se match karo
  });
  // BUG4 FIX: token response body mein bhi do — client cookie timing pe depend na kare
  res.json({ success: true, token: csrfToken });
});

// OTP rate limiter — 3 requests per 10 min per IP
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 3,
  message: { message: 'Too many OTP requests. Please wait 10 minutes.' }
});

app.get('/api/auth/captcha', (req, res) => {
  const ops = ['+', '-', '*'];
  const op = ops[Math.floor(Math.random() * 3)];
  const a = Math.floor(Math.random() * 15) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  let answer;
  switch (op) {
    case '+': answer = a + b; break;
    case '-': answer = a - b; break;
    case '*': answer = a * b; break;
  }
  const question = `What is ${a} ${op} ${b} ?`;
  const id = crypto.randomBytes(16).toString('hex');
  // answer Number ke roop mein store karo
  captchaStore.set(id, { answer: Number(answer), expires: Date.now() + 300000 });
  res.json({ id, question });
});

// ─── 2. Login ───
app.post('/api/auth/login', loginLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('role').isIn(['student', 'teacher', 'admin']),
  body('captcha_answer').isInt().toInt(),
  body('captcha_id').notEmpty(),
  body('device_fingerprint').optional().isString()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.error('Validation errors:', JSON.stringify(errors.array()));
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }

  const { email, password, role, captcha_answer, captcha_id, device_fingerprint, _csrf } = req.body;

  const cookieCsrf = req.cookies && req.cookies.csrf_token;
  if (!cookieCsrf || !_csrf || cookieCsrf !== _csrf) {
    await supabaseAdmin.from('security_logs').insert({
      ip_address: req.ip, user_agent: req.headers['user-agent'],
      event_type: 'CSRF_MISMATCH', details: { email }, severity: 'BLOCK'
    });
    return res.status(403).json({ message: 'Session expired. Please refresh the page and try again.' });
  }

  if (!captchaStore.has(captcha_id)) {
    return res.status(400).json({ message: 'CAPTCHA expired or invalid. Please refresh.' });
  }
  const captcha = captchaStore.get(captcha_id);

  if (Number(captcha.answer) !== parseInt(captcha_answer, 10)) {
    captchaStore.delete(captcha_id); // ek baar use, phir delete
    return res.status(400).json({ message: 'Incorrect CAPTCHA answer.' });
  }
  captchaStore.delete(captcha_id);

  console.log(`[LOGIN] Attempting login for: ${email}, role: ${role}`);

  try {
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email,
      password
    });
    if (authError) {
      console.error('[LOGIN] Supabase auth error:', authError.message);
      await supabaseAdmin.from('security_logs').insert({
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        event_type: 'FAILED_LOGIN',
        browser_fingerprint: device_fingerprint,
        details: { email, role, error: authError.message },
        severity: 'WARN'
      });
      return res.status(401).json({ message: 'Invalid credentials. Check email and password.' });
    }

    const { data: profile, error: profError } = await supabaseAdmin
      .from('profiles')
      .select('id, full_name, role, activated')
      .eq('id', authData.user.id)
      .single();

    if (profError) {
      console.error('[LOGIN] Profile fetch error:', profError.message);
      return res.status(500).json({ message: 'Could not fetch user profile.' });
    }

    if (!profile) {
      console.error('[LOGIN] Profile not found for user:', authData.user.id);
      return res.status(401).json({ message: 'User profile not found. Contact admin.' });
    }

    if (profile.role !== role) {
      console.error(`[LOGIN] Role mismatch: DB role=${profile.role}, requested role=${role}`);
      return res.status(401).json({ message: `Role mismatch. Your account role is: ${profile.role}` });
    }

    const token = generateToken({ id: profile.id, email, role: profile.role });

    // ─── OTP Step: Generate and send OTP instead of issuing full JWT ───
    const otpCode = generateOTPCode();
    const otpKey = `${profile.id}:login`;
    otpStore.set(otpKey, {
      code: otpCode,
      expires: Date.now() + 5 * 60 * 1000, // 5 min
      attempts: 0,
      email
    });

    // OTP token — short-lived JWT proving step 1 passed (no full access yet)
    const otpToken = jwt.sign(
      { id: profile.id, email, role: profile.role, purpose: 'login_otp' },
      JWT_SECRET,
      { expiresIn: '5m' }
    );

    const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(profile.id);
    const userName = profile.full_name || email;
    const sent = await sendOTPEmail(email, otpCode, 'login', userName);

    await supabaseAdmin.from('security_logs').insert({
      user_id: profile.id,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'OTP_SENT_LOGIN',
      browser_fingerprint: device_fingerprint,
      severity: 'OK'
    });

    console.log(`[LOGIN] OTP sent to ${email} for login`);
    return res.json({
      otp_required: true,
      otp_token: otpToken,
      message: sent
        ? `OTP sent to ${email.replace(/(.{2}).*(@.*)/, '$1****$2')}. Check your inbox.`
        : `OTP generated (email unavailable). Check server logs.`
    });
  } catch (err) {
    console.error('[LOGIN] Unexpected error:', err);
    res.status(500).json({ message: 'Internal server error. Try again.' });
  }
});

// ─── 2b. Verify Login OTP → Issue Full JWT ───
app.post('/api/auth/verify-login-otp', [
  body('otp_token').notEmpty(),
  body('otp_code').isLength({ min: 6, max: 6 }).isNumeric()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Invalid input.' });

  const { otp_token, otp_code } = req.body;

  // Verify the short-lived OTP token
  const decoded = verifyToken(otp_token);
  if (!decoded || decoded.purpose !== 'login_otp') {
    return res.status(401).json({ message: 'OTP session expired. Please login again.' });
  }

  const otpKey = `${decoded.id}:login`;
  const stored = otpStore.get(otpKey);

  if (!stored) {
    return res.status(400).json({ message: 'OTP expired or not found. Please login again.' });
  }
  if (stored.expires < Date.now()) {
    otpStore.delete(otpKey);
    return res.status(400).json({ message: 'OTP has expired (5 min limit). Please login again.' });
  }
  if (stored.attempts >= 3) {
    otpStore.delete(otpKey);
    return res.status(429).json({ message: 'Too many incorrect attempts. Please login again.' });
  }
  if (stored.code !== String(otp_code)) {
    stored.attempts++;
    otpStore.set(otpKey, stored);
    const left = 3 - stored.attempts;
    return res.status(401).json({ message: `Incorrect OTP. ${left} attempt(s) remaining.` });
  }

  // OTP correct — issue full JWT
  otpStore.delete(otpKey);
  const fullToken = generateToken({ id: decoded.id, email: decoded.email, role: decoded.role });

  res.cookie('cms_token', fullToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 28800000 // BUG2 FIX: 8h — JWT expiry se match karo
  });

  await supabaseAdmin.from('security_logs').insert({
    user_id: decoded.id,
    ip_address: req.ip,
    user_agent: req.headers['user-agent'],
    event_type: 'LOGIN_SUCCESS',
    severity: 'OK'
  });

  // Fetch full name for response
  const { data: profile } = await supabaseAdmin
    .from('profiles').select('full_name, role').eq('id', decoded.id).maybeSingle();

  console.log(`[LOGIN] OTP verified, full access granted: ${decoded.email}`);
  res.json({
    token: fullToken,
    role: decoded.role,
    email: decoded.email,
    full_name: profile ? profile.full_name : decoded.email
  });
});

// ─── 2c. Send OTP for Password Change (authenticated) ───
app.post('/api/profile/send-password-otp', verifyTokenAPI, otpLimiter, async (req, res) => {
  try {
    const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(req.user.id);
    if (!authUser || !authUser.user) return res.status(404).json({ message: 'Account not found' });

    const { data: profile } = await supabaseAdmin
      .from('profiles').select('full_name').eq('id', req.user.id).maybeSingle();

    const email = authUser.user.email;
    const userName = profile ? profile.full_name : email;

    const otpCode = generateOTPCode();
    const otpKey = `${req.user.id}:password_change`;
    otpStore.set(otpKey, {
      code: otpCode,
      expires: Date.now() + 5 * 60 * 1000,
      attempts: 0,
      email
    });

    const sent = await sendOTPEmail(email, otpCode, 'password_change', userName);
    await supabaseAdmin.from('security_logs').insert({
      user_id: req.user.id, ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'OTP_SENT_PWCHANGE', severity: 'OK'
    });

    res.json({
      message: sent
        ? `OTP sent to ${email.replace(/(.{2}).*(@.*)/, '$1****$2')}. Check your inbox.`
        : 'OTP generated (email unavailable — check server logs).'
    });
  } catch (err) {
    console.error('Send password OTP error:', err);
    res.status(500).json({ message: 'Could not send OTP. Try again.' });
  }
});

// ─── 3. Student Dashboard ───
app.get('/api/student/dashboard', verifyTokenAPI, requireRole('student'), async (req, res) => {
  try {
    const userId = req.user.id;
    const { data: profile, error: pErr } = await supabaseAdmin
      .from('profiles')
      .select('*, students_data(*)')
      .eq('id', userId)
      .single();
    if (pErr || !profile) {
      return res.status(404).json({ message: 'Profile not found' });
    }
    const { data: enrollments, error: eErr } = await supabaseAdmin
      .from('enrollments')
      .select(`
        id,
        courses(code, title),
        attendance(present, date),
        marks(exam_type, internal_marks, external_marks, total_marks)
      `)
      .eq('student_id', profile.students_data.id);
    if (eErr) {
      return res.status(500).json({ message: 'Failed to fetch enrollments' });
    }
    let total = 0, present = 0;
    enrollments.forEach(enr => {
      if (enr.attendance) {
        total += enr.attendance.length;
        present += enr.attendance.filter(a => a.present).length;
      }
    });
    const attendancePct = total ? Math.round((present / total) * 100) : 0;
    let markedCount = 0, totalMarksSum = 0;
    enrollments.forEach(enr => {
      if (enr.marks && enr.marks.length) {
        const mark = enr.marks[enr.marks.length - 1];
        if (mark && typeof mark.total_marks === 'number') {
          totalMarksSum += mark.total_marks;
          markedCount++;
        }
      }
    });
    const percentage = markedCount ? (totalMarksSum / markedCount).toFixed(2) : '0.00';
    const { data: logs } = await supabaseAdmin
      .from('security_logs')
      .select('created_at, event_type, ip_address')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(5);
    res.json({
      profile,
      email: req.user.email,
      class_level: profile.students_data ? profile.students_data.class : null,
      section: profile.students_data ? profile.students_data.section : null,
      stream: profile.students_data ? profile.students_data.stream : null,
      roll_no: profile.students_data ? profile.students_data.roll_no : null,
      enrollments,
      attendance: { total, present, percentage: attendancePct },
      percentage,
      security_logs: logs || []
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 4. Update Attendance ───
app.post('/api/admin/update-attendance', verifyTokenAPI, requireRole('teacher'), [
  body('course_code').notEmpty(),
  body('date').isISO8601(),
  body('records').isArray(),
  body('records.*.roll').notEmpty(),
  body('records.*.present').isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  const { course_code, date, records } = req.body;
  const teacherId = req.user.id;
  try {
    const { data: course, error: cErr } = await supabaseAdmin
      .from('courses')
      .select('id')
      .eq('code', course_code)
      .single();
    if (cErr || !course) return res.status(400).json({ message: 'Course not found' });
    const { data: assign, error: aErr } = await supabaseAdmin
      .from('course_assignments')
      .select('id')
      .eq('teacher_id', teacherId)
      .eq('course_id', course.id)
      .single();
    if (aErr || !assign) {
      return res.status(403).json({ message: 'Not assigned to this course' });
    }
    for (const rec of records) {
      const { data: student } = await supabaseAdmin
        .from('students_data')
        .select('id')
        .eq('roll_no', rec.roll)
        .single();
      if (!student) continue;
      const { data: enrollment } = await supabaseAdmin
        .from('enrollments')
        .select('id')
        .eq('student_id', student.id)
        .eq('course_id', course.id)
        .single();
      if (!enrollment) continue;
      await supabaseAdmin
        .from('attendance')
        .upsert({
          enrollment_id: enrollment.id,
          date,
          present: rec.present,
          marked_by: teacherId
        }, { onConflict: 'enrollment_id,date' });
    }
    await supabaseAdmin.from('security_logs').insert({
      user_id: teacherId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'ATTENDANCE_UPDATED',
      details: { course: course_code, records: records.length, date },
      severity: 'OK'
    });
    res.json({ message: 'Attendance updated' });
  } catch (err) {
    console.error('Attendance error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 5. Modify Grades ───
app.put('/api/teacher/modify-grades', verifyTokenAPI, requireRole('teacher'), [
  body('course_code').notEmpty(),
  body('exam_type').isIn(['internal', 'midterm', 'final']),
  body('grades').isArray(),
  body('grades.*.roll').notEmpty(),
  body('grades.*.internal').isInt({ min: 0, max: 30 }),
  body('grades.*.external').isInt({ min: 0, max: 70 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  const { course_code, exam_type, grades } = req.body;
  const teacherId = req.user.id;
  try {
    const { data: course } = await supabaseAdmin
      .from('courses')
      .select('id')
      .eq('code', course_code)
      .single();
    if (!course) return res.status(400).json({ message: 'Course not found' });
    for (const g of grades) {
      const { data: student } = await supabaseAdmin
        .from('students_data')
        .select('id')
        .eq('roll_no', g.roll)
        .single();
      if (!student) continue;
      const { data: enrollment } = await supabaseAdmin
        .from('enrollments')
        .select('id')
        .eq('student_id', student.id)
        .eq('course_id', course.id)
        .single();
      if (!enrollment) continue;
      await supabaseAdmin
        .from('marks')
        .upsert({
          enrollment_id: enrollment.id,
          exam_type,
          internal_marks: g.internal,
          external_marks: g.external,
          marked_by: teacherId
        }, { onConflict: 'enrollment_id,exam_type' });
    }
    await supabaseAdmin.from('security_logs').insert({
      user_id: teacherId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'GRADES_UPDATED',
      details: { course: course_code, exam_type, count: grades.length },
      severity: 'OK'
    });
    res.json({ message: 'Grades updated' });
  } catch (err) {
    console.error('Grades error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 6. Bulk CSV Upload ───
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB hard cap — matches frontend, but now actually enforced server-side
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.csv') return cb(new Error('Only CSV files allowed'));
    cb(null, true);
  }
});
app.post('/api/admin/bulk-upload', verifyTokenAPI, requireRole('admin'), upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (ext !== '.csv') {
    return res.status(400).json({ message: 'Only CSV files allowed' });
  }
  const fileBuffer = req.file.buffer;
  const header = fileBuffer.slice(0, 4096).toString('utf-8');
  const suspicious = /[<>"';(){}\[\]\\\/\|&$`!@#%\^=*]/;
  if (suspicious.test(header)) {
    return res.status(400).json({ message: 'Suspicious characters in CSV header' });
  }
  const results = [];
  const stream = Readable.from(fileBuffer.toString('utf-8'));
  let rowCount = 0;
  stream
    .pipe(csv())
    .on('data', (data) => {
      rowCount++;
      const clean = {};
      for (const [key, val] of Object.entries(data)) {
        clean[sanitise(key)] = sanitise(val);
      }
      results.push(clean);
    })
    .on('end', async () => {
      const chunkSize = 500;
      let inserted = 0;
      for (let i = 0; i < results.length; i += chunkSize) {
        const chunk = results.slice(i, i + chunkSize);
        const toInsert = chunk.map(r => {
          const classLevel = VALID_CLASSES.includes(String(r.class)) ? String(r.class) : '9';
          const section = VALID_SECTIONS.includes((r.section || '').toUpperCase()) ? r.section.toUpperCase() : 'A';
          const streamVal = ['11', '12'].includes(classLevel)
            ? (VALID_STREAMS.includes(r.stream) ? r.stream : 'Science')
            : null;
          return {
            roll_no: r.roll_no,
            class: classLevel,
            section,
            stream: streamVal
          };
        });
        const { error } = await supabaseAdmin
          .from('students_data')
          .upsert(toInsert, { onConflict: 'roll_no' });
        if (error) {
          await supabaseAdmin.from('upload_logs').insert({
            filename: req.file.originalname,
            filesize: req.file.size,
            uploaded_by: req.user.id,
            status: 'FAILED',
            details: { error: error.message }
          });
          return res.status(500).json({ message: 'Bulk insert failed' });
        }
        inserted += toInsert.length;
      }
      await supabaseAdmin.from('upload_logs').insert({
        filename: req.file.originalname,
        filesize: req.file.size,
        uploaded_by: req.user.id,
        status: 'SUCCESS',
        details: { rows_inserted: inserted }
      });
      await supabaseAdmin.from('security_logs').insert({
        user_id: req.user.id,
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        event_type: 'BULK_UPLOAD',
        details: { filename: req.file.originalname, rows: inserted },
        severity: 'OK'
      });
      res.json({ message: `Uploaded ${inserted} records` });
    })
    .on('error', (err) => {
      console.error('CSV parsing error:', err);
      res.status(500).json({ message: 'CSV parsing failed' });
    });
});

// ─── 7. Broadcast Endpoints ───

// 7a. Get all broadcasts
app.get('/api/broadcasts', verifyTokenAPI, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('broadcasts')
      .select(`
        id,
        message,
        image_url,
        type,
        sent_at,
        profiles:sender_id (id, full_name, role)
      `)
      .order('sent_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Broadcast fetch error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// 7b. Create broadcast
app.post('/api/broadcasts', verifyTokenAPI, [
  body('message').optional().isLength({ max: 500 }).trim().escape(),
  body('image_url').optional().isURL(),
  body('type').isIn(['text', 'image'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  const { message, image_url, type } = req.body;
  const senderId = req.user.id;
  try {
    const { data, error } = await supabaseAdmin
      .from('broadcasts')
      .insert({
        sender_id: senderId,
        message: message || '',
        image_url: image_url || null,
        type: type || 'text'
      })
      .select()
      .single();
    if (error) throw error;
    await supabaseAdmin.from('security_logs').insert({
      user_id: senderId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'BROADCAST_CREATED',
      details: { type, id: data.id },
      severity: 'INFO'
    });
    res.json({ message: 'Broadcast created', broadcast: data });
  } catch (err) {
    console.error('Create broadcast error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// 7c. Update broadcast
app.put('/api/broadcasts/:id', verifyTokenAPI, [
  body('message').optional().isLength({ max: 500 }).trim().escape(),
  body('image_url').optional().isURL(),
  body('type').isIn(['text', 'image'])
], async (req, res) => {
  const { id } = req.params;
  const { message, image_url, type } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role;

  if (userRole !== 'teacher' && userRole !== 'admin') {
    return res.status(403).json({ message: 'Forbidden – insufficient privileges' });
  }

  try {
    const { data: existing, error: existsErr } = await supabaseAdmin
      .from('broadcasts')
      .select('id, sender_id')
      .eq('id', id)
      .single();
    if (existsErr || !existing) {
      return res.status(404).json({ message: 'Broadcast not found' });
    }

    if (userRole === 'teacher' && existing.sender_id !== userId) {
      return res.status(403).json({ message: 'You can only edit your own broadcasts' });
    }

    const updates = {};
    if (message !== undefined) updates.message = message;
    if (image_url !== undefined) updates.image_url = image_url;
    if (type !== undefined) updates.type = type;
    updates.updated_at = new Date();

    const { data, error } = await supabaseAdmin
      .from('broadcasts')
      .update(updates)
      .eq('id', id)
      .select()
      .single();
    if (error) throw error;

    await supabaseAdmin.from('security_logs').insert({
      user_id: userId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'BROADCAST_UPDATED',
      details: { id, role: userRole },
      severity: 'INFO'
    });

    res.json({ message: 'Broadcast updated', broadcast: data });
  } catch (err) {
    console.error('Update broadcast error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// 7d. Delete broadcast
app.delete('/api/broadcasts/:id', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabaseAdmin
      .from('broadcasts')
      .delete()
      .eq('id', id);
    if (error) throw error;

    await supabaseAdmin.from('security_logs').insert({
      user_id: req.user.id,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'BROADCAST_DELETED',
      details: { id },
      severity: 'INFO'
    });

    res.json({ message: 'Broadcast deleted' });
  } catch (err) {
    console.error('Delete broadcast error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 8. Change Role ───
app.post('/api/admin/change-role', verifyTokenAPI, requireRole('admin'), [
  body('user_id').notEmpty(),
  body('current_role').isIn(['student', 'teacher', 'admin']),
  body('new_role').isIn(['student', 'teacher', 'admin']),
  body('reason').isLength({ min: 3 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  const { user_id, current_role, new_role, reason } = req.body;
  const adminId = req.user.id;
  try {
    let target;
    if (user_id.includes('@') || user_id.includes(' ')) {
      const { data } = await supabaseAdmin
        .from('profiles')
        .select('id, role')
        .eq('full_name', user_id)
        .single();
      target = data;
    } else {
      const { data } = await supabaseAdmin
        .from('profiles')
        .select('id, role')
        .eq('id', user_id)
        .single();
      target = data;
    }
    if (!target || target.role !== current_role) {
      return res.status(400).json({ message: 'User not found or role mismatch' });
    }
    const { error } = await supabaseAdmin
      .from('profiles')
      .update({ role: new_role, updated_at: new Date() })
      .eq('id', target.id);
    if (error) throw error;
    await supabaseAdmin.from('role_audit').insert({
      target_user_id: target.id,
      old_role: current_role,
      new_role: new_role,
      changed_by: adminId,
      reason: reason
    });
    await supabaseAdmin.from('security_logs').insert({
      user_id: adminId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'ROLE_CHANGE',
      details: { target: target.id, old: current_role, new: new_role, reason },
      severity: new_role === 'admin' ? 'BLOCK' : 'OK'
    });
    res.json({ message: 'Role updated' });
  } catch (err) {
    console.error('Role change error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 9. Security Logs ───
app.get('/api/admin/security-logs', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('security_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Security logs error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 10. Admin: List Users (powers Dashboard counts + User Management pane) ───
app.get('/api/admin/users', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  try {
    const { role, search } = req.query;
    let query = supabaseAdmin
      .from('profiles')
      .select('id, full_name, role, created_at, activated, students_data(roll_no, class, section, stream)')
      .order('created_at', { ascending: false })
      .limit(500);
    if (role && ['student', 'teacher', 'admin'].includes(role)) {
      query = query.eq('role', role);
    }
    if (search && typeof search === 'string') {
      query = query.ilike('full_name', `%${search}%`);
    }
    const { data, error } = await query;
    if (error) throw error;
    const shaped = (data || []).map(u => ({
      id: u.id,
      full_name: u.full_name,
      role: u.role,
      created_at: u.created_at,
      activated: !!u.activated,
      roll_no: u.students_data ? u.students_data.roll_no : null,
      class: u.students_data ? u.students_data.class : null,
      section: u.students_data ? u.students_data.section : null,
      stream: u.students_data ? u.students_data.stream : null
    }));
    res.json(shaped);
  } catch (err) {
    console.error('Users list error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 11. Create Student / Teacher Account (Admin: any role. Teacher: students only, no approval needed) ───
app.post('/api/admin/create-user', verifyTokenAPI, requireRole(['admin', 'teacher']), [
  body('full_name').trim().isLength({ min: 3 }).withMessage('Full name must be at least 3 characters'),
  body('email').isEmail().withMessage('Enter a valid email address'),
  body('role').isIn(['student', 'teacher', 'admin']).withMessage('Role must be student, teacher, or admin'),
  body('roll_no').optional({ checkFalsy: true }).trim(),
  body('class_level').optional({ checkFalsy: true }).isIn(VALID_CLASSES),
  body('section').optional({ checkFalsy: true }).isIn(VALID_SECTIONS),
  body('stream').optional({ checkFalsy: true }).isIn(VALID_STREAMS),
  body('subjects').optional().isArray()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  const { full_name, email, role, roll_no, class_level, section, stream, subjects } = req.body;
  const creatorId = req.user.id, creatorRole = req.user.role;

  // Teachers can only create student accounts directly — a teacher account needs admin approval (see /api/teacher/request-teacher-account)
  if (creatorRole === 'teacher' && role !== 'student') {
    return res.status(403).json({ message: 'Teachers can create student accounts directly. To add a new teacher, submit a request for admin approval.' });
  }

  if (role === 'student') {
    if (!roll_no || !class_level || !section) {
      return res.status(400).json({ message: 'Roll number, class, and section are required for students' });
    }
    if (['11', '12'].includes(class_level) && !stream) {
      return res.status(400).json({ message: 'Stream is required for class 11 and 12' });
    }
  }

  let newUserId = null;
  try {
    const placeholderPassword = crypto.randomBytes(24).toString('hex');
    const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
      email, password: placeholderPassword, email_confirm: true
    });
    if (createErr || !created || !created.user) {
      return res.status(400).json({ message: (createErr && createErr.message) || 'Could not create account. Email may already be in use.' });
    }
    newUserId = created.user.id;

    const { error: profErr } = await supabaseAdmin.from('profiles').insert({
      id: newUserId, full_name, role, activated: false
    });
    if (profErr) throw profErr;

    if (role === 'student') {
      const finalStream = ['11', '12'].includes(class_level) ? stream : null;
      const { error: sErr } = await supabaseAdmin.from('students_data').insert({
        id: newUserId, roll_no, class: class_level, section, stream: finalStream
      });
      if (sErr) throw sErr;

      const subjectList = getSubjectsForClass(class_level, finalStream);
      for (const subj of subjectList) {
        const courseId = await findOrCreateCourse(class_level, finalStream, subj);
        await supabaseAdmin.from('enrollments').insert({ student_id: newUserId, course_id: courseId });
      }
    }

    if (role === 'teacher' && Array.isArray(subjects) && subjects.length) {
      for (const combo of subjects) {
        if (!combo || !combo.class_level || !combo.subject) continue;
        if (!VALID_CLASSES.includes(String(combo.class_level))) continue;
        const comboStream = ['11', '12'].includes(String(combo.class_level)) ? combo.stream : null;
        if (['11', '12'].includes(String(combo.class_level)) && !VALID_STREAMS.includes(comboStream)) continue;
        const courseId = await findOrCreateCourse(combo.class_level, comboStream, combo.subject);
        await supabaseAdmin.from('course_assignments').insert({ teacher_id: newUserId, course_id: courseId });
      }
    }

    const token = await createActivationToken(newUserId);
    const link = activationLink(req, token);

    await supabaseAdmin.from('security_logs').insert({
      user_id: creatorId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'USER_CREATED',
      details: { new_user_id: newUserId, role, full_name, email, created_by_role: creatorRole },
      severity: 'OK'
    });

    res.json({
      message: `${role === 'student' ? 'Student' : 'Teacher'} account created. Send the activation link below so they can set their password.`,
      user_id: newUserId,
      email,
      activation_link: link
    });
  } catch (err) {
    console.error('Create user error:', err);
    if (newUserId) {
      try { await supabaseAdmin.auth.admin.deleteUser(newUserId); } catch (cleanupErr) { console.error('Rollback failed:', cleanupErr); }
    }
    res.status(500).json({ message: 'Internal error creating user. Account was rolled back.' });
  }
});

// ─── 11b. Account Activation: validate token (used by activate.html to render the form) ───
app.get('/api/auth/activation-info', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ message: 'Missing token' });
  try {
    const { data: row, error } = await supabaseAdmin
      .from('activation_tokens').select('user_id, expires_at, used').eq('token', token).maybeSingle();
    if (error) throw error;
    if (!row) return res.status(404).json({ message: 'Invalid activation link.' });
    if (row.used) return res.status(400).json({ message: 'This activation link has already been used.' });
    if (new Date(row.expires_at) < new Date()) return res.status(400).json({ message: 'This activation link has expired. Ask your admin/teacher to resend it.' });

    const { data: profile, error: pErr } = await supabaseAdmin
      .from('profiles').select('full_name, role').eq('id', row.user_id).single();
    if (pErr || !profile) return res.status(404).json({ message: 'Account not found.' });

    const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(row.user_id);
    res.json({ full_name: profile.full_name, role: profile.role, email: authUser && authUser.user ? authUser.user.email : null });
  } catch (err) {
    console.error('Activation info error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 11c. Account Activation: set password ───
app.post('/api/auth/activate', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  const { token, password } = req.body;
  try {
    const { data: row, error } = await supabaseAdmin
      .from('activation_tokens').select('id, user_id, expires_at, used').eq('token', token).maybeSingle();
    if (error) throw error;
    if (!row) return res.status(404).json({ message: 'Invalid activation link.' });
    if (row.used) return res.status(400).json({ message: 'This activation link has already been used.' });
    if (new Date(row.expires_at) < new Date()) return res.status(400).json({ message: 'This activation link has expired.' });

    const { error: pwErr } = await supabaseAdmin.auth.admin.updateUserById(row.user_id, { password });
    if (pwErr) throw pwErr;

    await supabaseAdmin.from('activation_tokens').update({ used: true }).eq('id', row.id);
    await supabaseAdmin.from('profiles').update({ activated: true, updated_at: new Date() }).eq('id', row.user_id);
    await supabaseAdmin.from('security_logs').insert({
      user_id: row.user_id, ip_address: req.ip, user_agent: req.headers['user-agent'],
      event_type: 'ACCOUNT_ACTIVATED', severity: 'OK'
    });

    res.json({ message: 'Account activated. You can now log in.' });
  } catch (err) {
    console.error('Activation error:', err);
    res.status(500).json({ message: 'Internal error activating account' });
  }
});

// ─── 12. Teacher: My Subjects/Courses ───
app.get('/api/teacher/courses', verifyTokenAPI, requireRole('teacher'), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('course_assignments')
      .select('courses(id, code, title)')
      .eq('teacher_id', req.user.id);
    if (error) throw error;
    const courses = (data || []).map(r => r.courses).filter(Boolean);
    const withCounts = await Promise.all(courses.map(async c => {
      const { count } = await supabaseAdmin
        .from('enrollments')
        .select('id', { count: 'exact', head: true })
        .eq('course_id', c.id);
      return { id: c.id, code: c.code, title: c.title, student_count: count || 0 };
    }));
    res.json(withCounts);
  } catch (err) {
    console.error('Teacher courses error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 13. Teacher: Course Roster (for marking attendance / entering marks) ───
app.get('/api/teacher/course/:code/roster', verifyTokenAPI, requireRole('teacher'), async (req, res) => {
  const { code } = req.params;
  const { date, exam_type } = req.query;
  const teacherId = req.user.id;
  try {
    const { data: course, error: cErr } = await supabaseAdmin
      .from('courses').select('id, code, title').eq('code', code).single();
    if (cErr || !course) return res.status(404).json({ message: 'Course not found' });

    const { data: assign, error: aErr } = await supabaseAdmin
      .from('course_assignments').select('id').eq('teacher_id', teacherId).eq('course_id', course.id).single();
    if (aErr || !assign) return res.status(403).json({ message: 'You are not assigned to this course' });

    const { data: enrollments, error: eErr } = await supabaseAdmin
      .from('enrollments').select('id, student_id').eq('course_id', course.id);
    if (eErr) throw eErr;

    const studentIds = enrollments.map(e => e.student_id);
    let roster = [];
    if (studentIds.length) {
      const { data: studentsData, error: sErr } = await supabaseAdmin
        .from('students_data')
        .select('id, roll_no, class, section, stream, profiles(full_name)')
        .in('id', studentIds);
      if (sErr) throw sErr;
      const enrollMap = {};
      enrollments.forEach(e => { enrollMap[e.student_id] = e.id; });
      roster = (studentsData || []).map(s => ({
        enrollment_id: enrollMap[s.id],
        student_id: s.id,
        roll_no: s.roll_no,
        full_name: s.profiles ? s.profiles.full_name : 'Unknown',
        class: s.class,
        section: s.section,
        stream: s.stream
      })).sort((a, b) => (a.roll_no || '').localeCompare(b.roll_no || ''));
    }

    const enrollmentIds = roster.map(r => r.enrollment_id).filter(Boolean);
    if (date && enrollmentIds.length) {
      const { data: attRows } = await supabaseAdmin
        .from('attendance').select('enrollment_id, present').eq('date', date).in('enrollment_id', enrollmentIds);
      const attMap = {};
      (attRows || []).forEach(a => { attMap[a.enrollment_id] = a.present; });
      roster.forEach(r => { r.present = attMap.hasOwnProperty(r.enrollment_id) ? attMap[r.enrollment_id] : null; });
    }
    if (exam_type && enrollmentIds.length) {
      const { data: markRows } = await supabaseAdmin
        .from('marks').select('enrollment_id, internal_marks, external_marks').eq('exam_type', exam_type).in('enrollment_id', enrollmentIds);
      const markMap = {};
      (markRows || []).forEach(m => { markMap[m.enrollment_id] = m; });
      roster.forEach(r => {
        const m = markMap[r.enrollment_id];
        r.internal_marks = m ? m.internal_marks : null;
        r.external_marks = m ? m.external_marks : null;
      });
    }

    res.json({ course, roster });
  } catch (err) {
    console.error('Roster error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 14. Teacher: Dashboard Stats ───
app.get('/api/teacher/stats', verifyTokenAPI, requireRole('teacher'), async (req, res) => {
  const teacherId = req.user.id;
  try {
    const { data: assigns, error: aErr } = await supabaseAdmin
      .from('course_assignments').select('course_id').eq('teacher_id', teacherId);
    if (aErr) throw aErr;
    const courseIds = (assigns || []).map(a => a.course_id);
    if (!courseIds.length) {
      return res.json({ assigned_courses: 0, total_students: 0, avg_attendance_pct: 0, pending_marks: 0 });
    }

    const { data: enrollments, error: eErr } = await supabaseAdmin
      .from('enrollments').select('id, student_id, course_id').in('course_id', courseIds);
    if (eErr) throw eErr;
    const uniqueStudents = new Set(enrollments.map(e => e.student_id));
    const enrollmentIds = enrollments.map(e => e.id);

    let avgAttendance = 0;
    if (enrollmentIds.length) {
      const { data: attRows } = await supabaseAdmin.from('attendance').select('present').in('enrollment_id', enrollmentIds);
      if (attRows && attRows.length) {
        const presentCount = attRows.filter(a => a.present).length;
        avgAttendance = Math.round((presentCount / attRows.length) * 100);
      }
    }

    let pendingMarks = enrollmentIds.length;
    if (enrollmentIds.length) {
      const { data: markRows } = await supabaseAdmin.from('marks').select('enrollment_id').in('enrollment_id', enrollmentIds);
      const markedSet = new Set((markRows || []).map(m => m.enrollment_id));
      pendingMarks = Math.max(enrollmentIds.length - markedSet.size, 0);
    }

    res.json({
      assigned_courses: courseIds.length,
      total_students: uniqueStudents.size,
      avg_attendance_pct: avgAttendance,
      pending_marks: pendingMarks
    });
  } catch (err) {
    console.error('Teacher stats error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 15. Teacher: Request a New Teacher Account (needs admin approval) ───
app.post('/api/teacher/request-teacher-account', verifyTokenAPI, requireRole('teacher'), [
  body('full_name').trim().isLength({ min: 3 }).withMessage('Full name must be at least 3 characters'),
  body('email').isEmail().withMessage('Enter a valid email address'),
  body('subjects').optional().isArray()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  const { full_name, email, subjects } = req.body;
  try {
    const { data, error } = await supabaseAdmin.from('teacher_requests').insert({
      requested_by: req.user.id, full_name, email,
      subjects: Array.isArray(subjects) ? subjects : [],
      status: 'pending'
    }).select('id').single();
    if (error) throw error;
    res.json({ message: 'Request submitted. An admin will review it.', request_id: data.id });
  } catch (err) {
    console.error('Teacher request error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 16. Admin: List Teacher Requests ───
app.get('/api/admin/teacher-requests', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  try {
    const { status } = req.query;
    let query = supabaseAdmin.from('teacher_requests').select('*, profiles!teacher_requests_requested_by_fkey(full_name)').order('created_at', { ascending: false });
    if (status && ['pending', 'approved', 'rejected'].includes(status)) query = query.eq('status', status);
    const { data, error } = await query;
    if (error) throw error;
    const shaped = (data || []).map(r => ({
      id: r.id, full_name: r.full_name, email: r.email, subjects: r.subjects,
      status: r.status, created_at: r.created_at,
      requested_by_name: r.profiles ? r.profiles.full_name : 'Unknown'
    }));
    res.json(shaped);
  } catch (err) {
    console.error('Teacher requests list error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 17. Admin: Approve / Reject Teacher Request ───
app.post('/api/admin/teacher-requests/:id/approve', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  let newUserId = null;
  try {
    const { data: reqRow, error: rErr } = await supabaseAdmin.from('teacher_requests').select('*').eq('id', id).single();
    if (rErr || !reqRow) return res.status(404).json({ message: 'Request not found' });
    if (reqRow.status !== 'pending') return res.status(400).json({ message: 'This request has already been ' + reqRow.status });

    const placeholderPassword = crypto.randomBytes(24).toString('hex');
    const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
      email: reqRow.email, password: placeholderPassword, email_confirm: true
    });
    if (createErr || !created || !created.user) {
      return res.status(400).json({ message: (createErr && createErr.message) || 'Could not create account. Email may already be in use.' });
    }
    newUserId = created.user.id;

    const { error: profErr } = await supabaseAdmin.from('profiles').insert({
      id: newUserId, full_name: reqRow.full_name, role: 'teacher', activated: false
    });
    if (profErr) throw profErr;

    const subjects = Array.isArray(reqRow.subjects) ? reqRow.subjects : [];
    for (const combo of subjects) {
      if (!combo || !combo.class_level || !combo.subject) continue;
      if (!VALID_CLASSES.includes(String(combo.class_level))) continue;
      const comboStream = ['11', '12'].includes(String(combo.class_level)) ? combo.stream : null;
      if (['11', '12'].includes(String(combo.class_level)) && !VALID_STREAMS.includes(comboStream)) continue;
      const courseId = await findOrCreateCourse(combo.class_level, comboStream, combo.subject);
      await supabaseAdmin.from('course_assignments').insert({ teacher_id: newUserId, course_id: courseId });
    }

    const token = await createActivationToken(newUserId);
    const link = activationLink(req, token);

    await supabaseAdmin.from('teacher_requests').update({
      status: 'approved', reviewed_by: req.user.id, reviewed_at: new Date()
    }).eq('id', id);

    await supabaseAdmin.from('security_logs').insert({
      user_id: req.user.id, ip_address: req.ip, user_agent: req.headers['user-agent'],
      event_type: 'TEACHER_REQUEST_APPROVED', details: { request_id: id, new_user_id: newUserId }, severity: 'OK'
    });

    res.json({ message: 'Teacher account created. Send them the activation link.', user_id: newUserId, email: reqRow.email, activation_link: link });
  } catch (err) {
    console.error('Approve request error:', err);
    if (newUserId) { try { await supabaseAdmin.auth.admin.deleteUser(newUserId); } catch (e) { console.error('Rollback failed:', e); } }
    res.status(500).json({ message: 'Internal error approving request' });
  }
});

app.post('/api/admin/teacher-requests/:id/reject', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const { data: reqRow, error: rErr } = await supabaseAdmin.from('teacher_requests').select('status').eq('id', id).single();
    if (rErr || !reqRow) return res.status(404).json({ message: 'Request not found' });
    if (reqRow.status !== 'pending') return res.status(400).json({ message: 'This request has already been ' + reqRow.status });
    await supabaseAdmin.from('teacher_requests').update({
      status: 'rejected', reviewed_by: req.user.id, reviewed_at: new Date()
    }).eq('id', id);
    res.json({ message: 'Request rejected.' });
  } catch (err) {
    console.error('Reject request error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 18. Admin: Edit User Details ───
app.put('/api/admin/users/:id', verifyTokenAPI, requireRole('admin'), [
  body('full_name').optional({ checkFalsy: true }).trim().isLength({ min: 3 }),
  body('roll_no').optional({ checkFalsy: true }).trim(),
  body('class_level').optional({ checkFalsy: true }).isIn(VALID_CLASSES),
  body('section').optional({ checkFalsy: true }).isIn(VALID_SECTIONS),
  body('stream').optional({ checkFalsy: true }).isIn(VALID_STREAMS)
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  const { id } = req.params;
  const { full_name, roll_no, class_level, section, stream } = req.body;
  try {
    const { data: profile, error: pErr } = await supabaseAdmin.from('profiles').select('id, role').eq('id', id).single();
    if (pErr || !profile) return res.status(404).json({ message: 'User not found' });

    if (full_name) {
      await supabaseAdmin.from('profiles').update({ full_name, updated_at: new Date() }).eq('id', id);
    }
    if (profile.role === 'student' && (roll_no || class_level || section || stream)) {
      const patch = {};
      if (roll_no) patch.roll_no = roll_no;
      if (class_level) patch.class = class_level;
      if (section) patch.section = section;
      if (stream) patch.stream = stream;
      const { error: sErr } = await supabaseAdmin.from('students_data').update(patch).eq('id', id);
      if (sErr) throw sErr;
    }
    res.json({ message: 'User updated successfully' });
  } catch (err) {
    console.error('Edit user error:', err);
    res.status(500).json({ message: 'Internal error updating user' });
  }
});

// ─── 19. Admin: Delete User ───
app.delete('/api/admin/users/:id', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  if (id === req.user.id) return res.status(400).json({ message: 'You cannot delete your own account.' });
  try {
    const { error } = await supabaseAdmin.auth.admin.deleteUser(id);
    if (error) throw error;
    await supabaseAdmin.from('security_logs').insert({
      user_id: req.user.id, ip_address: req.ip, user_agent: req.headers['user-agent'],
      event_type: 'USER_DELETED', details: { deleted_user_id: id }, severity: 'WARN'
    });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ message: 'Internal error deleting user' });
  }
});

// ─── 20. Admin: Reset a User's Password (re-sends a fresh activation link) ───
app.post('/api/admin/users/:id/reset-password', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const { data: profile, error: pErr } = await supabaseAdmin.from('profiles').select('id').eq('id', id).single();
    if (pErr || !profile) return res.status(404).json({ message: 'User not found' });
    const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(id);
    const placeholderPassword = crypto.randomBytes(24).toString('hex');
    await supabaseAdmin.auth.admin.updateUserById(id, { password: placeholderPassword });
    await supabaseAdmin.from('profiles').update({ activated: false }).eq('id', id);
    const token = await createActivationToken(id);
    const link = activationLink(req, token);
    await supabaseAdmin.from('security_logs').insert({
      user_id: req.user.id, ip_address: req.ip, user_agent: req.headers['user-agent'],
      event_type: 'PASSWORD_RESET_ISSUED', details: { target_user_id: id }, severity: 'WARN'
    });
    res.json({ message: 'Password reset. Send this new link so they can set a fresh password.', activation_link: link, email: authUser && authUser.user ? authUser.user.email : null });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: 'Internal error resetting password' });
  }
});

// ─── 21. Admin: View / Update a Student's Enrolled Subjects ───
app.get('/api/admin/student/:id/subjects', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const { data: student, error: sErr } = await supabaseAdmin
      .from('students_data').select('id, roll_no, class, section, stream, profiles(full_name)').eq('id', id).single();
    if (sErr || !student) return res.status(404).json({ message: 'Student not found' });

    const allSubjects = getSubjectsForClass(student.class, student.stream);
    const { data: enrollments, error: eErr } = await supabaseAdmin
      .from('enrollments').select('id, courses(code, title)').eq('student_id', id);
    if (eErr) throw eErr;
    const enrolledCodes = new Set((enrollments || []).map(e => e.courses ? e.courses.code : null).filter(Boolean));

    const subjectsWithStatus = allSubjects.map(subj => {
      const code = courseCodeFor(student.class, student.stream, subj);
      return { subject: subj, code, enrolled: enrolledCodes.has(code) };
    });

    res.json({
      student: {
        id: student.id, full_name: student.profiles ? student.profiles.full_name : 'Unknown',
        roll_no: student.roll_no, class: student.class, section: student.section, stream: student.stream
      },
      subjects: subjectsWithStatus
    });
  } catch (err) {
    console.error('Get student subjects error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

app.post('/api/admin/student/:id/subjects', verifyTokenAPI, requireRole('admin'), [
  body('subjects').isArray().withMessage('subjects must be an array of subject names')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  const { id } = req.params;
  const { subjects } = req.body;
  try {
    const { data: student, error: sErr } = await supabaseAdmin.from('students_data').select('id, class, stream').eq('id', id).single();
    if (sErr || !student) return res.status(404).json({ message: 'Student not found' });

    const validSubjects = getSubjectsForClass(student.class, student.stream);
    const desired = subjects.filter(s => validSubjects.includes(s));
    const desiredCodes = new Set(desired.map(s => courseCodeFor(student.class, student.stream, s)));

    const { data: currentEnrollments, error: eErr } = await supabaseAdmin
      .from('enrollments').select('id, courses(code)').eq('student_id', id);
    if (eErr) throw eErr;

    const currentCodes = new Map(
      (currentEnrollments || []).filter(e => e.courses).map(e => [e.courses.code, e.id])
    );

    // Remove enrollments for subjects no longer desired
    for (const [code, enrollId] of currentCodes.entries()) {
      if (!desiredCodes.has(code)) {
        await supabaseAdmin.from('enrollments').delete().eq('id', enrollId);
      }
    }
    // Add enrollments for newly desired subjects
    for (const subj of desired) {
      const code = courseCodeFor(student.class, student.stream, subj);
      if (!currentCodes.has(code)) {
        const courseId = await findOrCreateCourse(student.class, student.stream, subj);
        await supabaseAdmin.from('enrollments').insert({ student_id: id, course_id: courseId });
      }
    }

    res.json({ message: 'Subjects updated successfully' });
  } catch (err) {
    console.error('Update student subjects error:', err);
    res.status(500).json({ message: 'Internal error updating subjects' });
  }
});

// ─── 22. Admin: View / Update a Teacher's Subject Assignments ───
app.get('/api/admin/teacher/:id/subjects', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const { data: teacher, error: tErr } = await supabaseAdmin.from('profiles').select('id, full_name, role').eq('id', id).single();
    if (tErr || !teacher || teacher.role !== 'teacher') return res.status(404).json({ message: 'Teacher not found' });

    const { data: assigned, error: aErr } = await supabaseAdmin
      .from('course_assignments').select('id, courses(code, title)').eq('teacher_id', id);
    if (aErr) throw aErr;
    const assignedCodes = new Set((assigned || []).map(a => a.courses ? a.courses.code : null).filter(Boolean));

    const allCombos = [];
    ['9', '10'].forEach(cls => SUBJECTS_BY_CLASS[cls].forEach(subj => allCombos.push({ class_level: cls, stream: null, subject: subj })));
    ['11', '12'].forEach(cls => VALID_STREAMS.forEach(str => SUBJECTS_BY_CLASS[cls][str].forEach(subj => allCombos.push({ class_level: cls, stream: str, subject: subj }))));

    const combosWithStatus = allCombos.map(c => {
      const code = courseCodeFor(c.class_level, c.stream, c.subject);
      return { ...c, code, assigned: assignedCodes.has(code) };
    });

    res.json({ teacher: { id: teacher.id, full_name: teacher.full_name }, combos: combosWithStatus });
  } catch (err) {
    console.error('Get teacher subjects error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

app.post('/api/admin/teacher/:id/subjects', verifyTokenAPI, requireRole('admin'), [
  body('subjects').isArray()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  const { id } = req.params;
  const { subjects } = req.body;
  try {
    const { data: teacher, error: tErr } = await supabaseAdmin.from('profiles').select('id, role').eq('id', id).single();
    if (tErr || !teacher || teacher.role !== 'teacher') return res.status(404).json({ message: 'Teacher not found' });

    const desiredCodes = new Set();
    for (const combo of subjects) {
      if (!combo || !combo.class_level || !combo.subject) continue;
      desiredCodes.add(courseCodeFor(combo.class_level, combo.stream || null, combo.subject));
    }

    const { data: currentAssigns, error: aErr } = await supabaseAdmin
      .from('course_assignments').select('id, courses(code)').eq('teacher_id', id);
    if (aErr) throw aErr;
    const currentCodes = new Map((currentAssigns || []).filter(a => a.courses).map(a => [a.courses.code, a.id]));

    for (const [code, assignId] of currentCodes.entries()) {
      if (!desiredCodes.has(code)) await supabaseAdmin.from('course_assignments').delete().eq('id', assignId);
    }
    for (const combo of subjects) {
      if (!combo || !combo.class_level || !combo.subject) continue;
      const comboStream = ['11', '12'].includes(String(combo.class_level)) ? combo.stream : null;
      const code = courseCodeFor(combo.class_level, comboStream, combo.subject);
      if (!currentCodes.has(code)) {
        const courseId = await findOrCreateCourse(combo.class_level, comboStream, combo.subject);
        await supabaseAdmin.from('course_assignments').insert({ teacher_id: id, course_id: courseId });
      }
    }

    res.json({ message: 'Teacher subjects updated successfully' });
  } catch (err) {
    console.error('Update teacher subjects error:', err);
    res.status(500).json({ message: 'Internal error updating subjects' });
  }
});

// ─── 23. Admin: Role-Change History & Upload History ───
app.get('/api/admin/role-audit', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('role_audit').select('*').order('created_at', { ascending: false }).limit(200);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Role audit error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

app.get('/api/admin/upload-logs', verifyTokenAPI, requireRole('admin'), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('upload_logs').select('*').order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Upload logs error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── 24. Any logged-in user: View / Edit own profile, change own password ───
app.get('/api/profile/me', verifyTokenAPI, async (req, res) => {
  try {
    const { data: profile, error } = await supabaseAdmin.from('profiles').select('full_name, role, activated').eq('id', req.user.id).single();
    if (error || !profile) return res.status(404).json({ message: 'Profile not found' });
    res.json({ full_name: profile.full_name, role: profile.role, email: req.user.email });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

app.put('/api/profile/me', verifyTokenAPI, [
  body('full_name').trim().isLength({ min: 3 }).withMessage('Full name must be at least 3 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  try {
    await supabaseAdmin.from('profiles').update({ full_name: req.body.full_name, updated_at: new Date() }).eq('id', req.user.id);
    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ message: 'Internal error updating profile' });
  }
});

app.put('/api/profile/password', verifyTokenAPI, [
  body('current_password').isLength({ min: 8 }),
  body('new_password').isLength({ min: 8 }).withMessage('New password must be at least 8 characters'),
  body('otp_code').isLength({ min: 6, max: 6 }).isNumeric().withMessage('OTP must be 6 digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  const { current_password, new_password, otp_code } = req.body;
  try {
    // ─── Verify OTP first ───
    const otpKey = `${req.user.id}:password_change`;
    const stored = otpStore.get(otpKey);
    if (!stored) return res.status(400).json({ message: 'OTP not found. Click "Send OTP" first.' });
    if (stored.expires < Date.now()) {
      otpStore.delete(otpKey);
      return res.status(400).json({ message: 'OTP has expired (5 min limit). Click "Send OTP" again.' });
    }
    if (stored.attempts >= 3) {
      otpStore.delete(otpKey);
      return res.status(429).json({ message: 'Too many incorrect OTP attempts. Click "Send OTP" again.' });
    }
    if (stored.code !== String(otp_code)) {
      stored.attempts++;
      otpStore.set(otpKey, stored);
      return res.status(401).json({ message: `Incorrect OTP. ${3 - stored.attempts} attempt(s) remaining.` });
    }
    otpStore.delete(otpKey); // OTP used — delete

    const { data: authUser, error: getErr } = await supabaseAdmin.auth.admin.getUserById(req.user.id);
    if (getErr || !authUser || !authUser.user) return res.status(404).json({ message: 'Account not found' });

    const { error: verifyErr } = await supabase.auth.signInWithPassword({ email: authUser.user.email, password: current_password });
    if (verifyErr) return res.status(401).json({ message: 'Current password is incorrect' });

    const { error: updErr } = await supabaseAdmin.auth.admin.updateUserById(req.user.id, { password: new_password });
    if (updErr) throw updErr;

    await supabaseAdmin.from('security_logs').insert({
      user_id: req.user.id, ip_address: req.ip, user_agent: req.headers['user-agent'],
      event_type: 'PASSWORD_CHANGED', severity: 'OK'
    });
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ message: 'Internal error changing password' });
  }
});

// ─── 25. Teacher: Drill-down history for one student in a course ───
app.get('/api/teacher/course/:code/student/:studentId/history', verifyTokenAPI, requireRole('teacher'), async (req, res) => {
  const { code, studentId } = req.params;
  const teacherId = req.user.id;
  try {
    const { data: course, error: cErr } = await supabaseAdmin.from('courses').select('id, code, title').eq('code', code).single();
    if (cErr || !course) return res.status(404).json({ message: 'Course not found' });
    const { data: assign, error: aErr } = await supabaseAdmin
      .from('course_assignments').select('id').eq('teacher_id', teacherId).eq('course_id', course.id).single();
    if (aErr || !assign) return res.status(403).json({ message: 'You are not assigned to this course' });

    const { data: enrollment, error: eErr } = await supabaseAdmin
      .from('enrollments').select('id, students_data(roll_no, class, section, profiles(full_name))')
      .eq('course_id', course.id).eq('student_id', studentId).single();
    if (eErr || !enrollment) return res.status(404).json({ message: 'Student not enrolled in this course' });

    const { data: attendance } = await supabaseAdmin
      .from('attendance').select('date, present').eq('enrollment_id', enrollment.id).order('date', { ascending: false });
    const { data: marks } = await supabaseAdmin
      .from('marks').select('exam_type, internal_marks, external_marks, total_marks').eq('enrollment_id', enrollment.id);

    res.json({
      course,
      student: {
        full_name: enrollment.students_data && enrollment.students_data.profiles ? enrollment.students_data.profiles.full_name : 'Unknown',
        roll_no: enrollment.students_data ? enrollment.students_data.roll_no : null,
        class: enrollment.students_data ? enrollment.students_data.class : null,
        section: enrollment.students_data ? enrollment.students_data.section : null
      },
      attendance: attendance || [],
      marks: marks || []
    });
  } catch (err) {
    console.error('Student history error:', err);
    res.status(500).json({ message: 'Internal error' });
  }
});

// ─── Custom 404 Page ───
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>404 - Page Not Found | UMS Laxman Nagar</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <style>
        body { font-family: 'Inter', sans-serif; background: #7f1d1d; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 20px; }
        .card { background: #991b1b; border: 2px solid #fca5a5; border-radius: 20px; padding: 60px 48px; text-align: center; max-width: 520px; box-shadow: 0 20px 60px rgba(0,0,0,0.6); position: relative; overflow: hidden; }
        .card::before { content: '⚠'; position: absolute; top: -30px; right: -30px; font-size: 120px; opacity: 0.1; transform: rotate(20deg); }
        h1 { font-size: 80px; font-weight: 800; color: #fca5a5; margin: 0; line-height: 1; }
        .sub { font-size: 22px; font-weight: 600; color: #fecaca; margin: 16px 0 8px; }
        .desc { color: #fca5a5; font-size: 15px; margin: 8px 0 24px; opacity: 0.9; }
        a { display: inline-block; background: #fca5a5; color: #7f1d1d; font-weight: 700; padding: 12px 28px; border-radius: 50px; text-decoration: none; }
        .security-badge { margin-top: 24px; font-size: 12px; color: #fca5a5; opacity: 0.6; }
        .security-badge span { display: inline-block; background: rgba(252,165,165,0.15); padding: 4px 14px; border-radius: 30px; border: 1px solid rgba(252,165,165,0.2); }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>404</h1>
        <div class="sub">⛔ Access Denied</div>
        <div class="desc">The page you requested does not exist or has been moved.<br>Please check the URL or return to the secure login.</div>
        <a href="/">← Back to Login Portal</a>
        <div class="security-badge"><span>🔒 Security Logged • Threat Detected</span></div>
      </div>
    </body>
    </html>
  `);
});

// ─── Global Error Handler ───
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: err.message });
  }
  if (err && err.message === 'Only CSV files allowed') {
    return res.status(400).json({ message: err.message });
  }
  const isProd = process.env.NODE_ENV === 'production';
  res.status(500).json({ message: 'Something went wrong', details: isProd ? undefined : err.message });
});

app.listen(PORT, () => {
  console.log(`UMS Laxman Nagar CMS server running on port ${PORT}`);
  console.log(`Public path: ${publicPath}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
