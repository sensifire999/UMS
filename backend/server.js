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

// ─── Supabase Clients ───
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ─── JWT Helpers ───
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// ─── API Middleware ───
function verifyTokenAPI(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ message: 'Invalid token' });
  }
  req.user = decoded;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
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

app.use(protectStatic);
app.use(express.static(publicPath));

// ─── Root route ───
app.get('/', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

// ─── CAPTCHA Store ───
const captchaStore = new Map();

// CAPTCHA cleanup — expire hue entries har 10 min mein delete karo
setInterval(() => {
  const now = Date.now();
  for (const [id, data] of captchaStore.entries()) {
    if (data.expires < now) captchaStore.delete(id);
  }
}, 600000);

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

// ─── 1. CAPTCHA ───
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
app.post('/api/auth/login', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 8 }),
  body('role').isIn(['student', 'teacher', 'admin']),
  // FIX 3: .toInt() add kiya — string "5" ko number 5 mein convert karo
  body('captcha_answer').isInt().toInt(),
  body('captcha_id').notEmpty(),
  body('device_fingerprint').optional().isString()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.error('Validation errors:', JSON.stringify(errors.array()));
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }

  const { username, password, role, captcha_answer, captcha_id, device_fingerprint } = req.body;

  if (!captchaStore.has(captcha_id)) {
    return res.status(400).json({ message: 'CAPTCHA expired or invalid. Please refresh.' });
  }
  const captcha = captchaStore.get(captcha_id);

  // FIX 3 cont: parseInt se ensure karo dono Number hain comparison ke time
  if (Number(captcha.answer) !== parseInt(captcha_answer, 10)) {
    captchaStore.delete(captcha_id); // ek baar use, phir delete
    return res.status(400).json({ message: 'Incorrect CAPTCHA answer.' });
  }
  captchaStore.delete(captcha_id);

  // FIX 4: Username mein email nahi, sirf username — server khud email banata hai
  // Agar user galti se poora email type kar de toh handle karo
  let cleanUsername = username;
  if (cleanUsername.includes('@')) {
    cleanUsername = cleanUsername.split('@')[0];
  }

  const email = `${cleanUsername}@umslaxmannagar.edu`;
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
        details: { username: cleanUsername, role, error: authError.message },
        severity: 'WARN'
      });
      return res.status(401).json({ message: 'Invalid credentials. Check username and password.' });
    }

    const { data: profile, error: profError } = await supabaseAdmin
      .from('profiles')
      .select('id, full_name, role')
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

    const token = generateToken({ id: profile.id, username: cleanUsername, role: profile.role });

    // FIX 5: Cookie sameSite — Render (HTTPS) pe 'none' nahi, 'strict' theek hai
    res.cookie('cms_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });

    await supabaseAdmin.from('security_logs').insert({
      user_id: profile.id,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'LOGIN_SUCCESS',
      browser_fingerprint: device_fingerprint,
      severity: 'OK'
    });

    console.log(`[LOGIN] Success: ${email}, role: ${profile.role}`);
    res.json({ token, role: profile.role, username: cleanUsername, full_name: profile.full_name });
  } catch (err) {
    console.error('[LOGIN] Unexpected error:', err);
    res.status(500).json({ message: 'Internal server error. Try again.' });
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
const upload = multer({ storage: multer.memoryStorage() });
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
      .select('id, full_name, role, created_at, students_data(roll_no, class, section, stream)')
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

// ─── 11. Admin: Create Student / Teacher Account ───
app.post('/api/admin/create-user', verifyTokenAPI, requireRole('admin'), [
  body('full_name').trim().isLength({ min: 3 }).withMessage('Full name must be at least 3 characters'),
  body('username').trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').isIn(['student', 'teacher']).withMessage('Role must be student or teacher'),
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
  const { full_name, username, password, role, roll_no, class_level, section, stream, subjects } = req.body;
  const adminId = req.user.id;

  if (role === 'student') {
    if (!roll_no || !class_level || !section) {
      return res.status(400).json({ message: 'Roll number, class, and section are required for students' });
    }
    if (['11', '12'].includes(class_level) && !stream) {
      return res.status(400).json({ message: 'Stream is required for class 11 and 12' });
    }
  }

  const cleanUsername = username.includes('@') ? username.split('@')[0] : username;
  const email = `${cleanUsername}@umslaxmannagar.edu`;
  let newUserId = null;

  try {
    const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
      email, password, email_confirm: true
    });
    if (createErr || !created || !created.user) {
      return res.status(400).json({ message: (createErr && createErr.message) || 'Could not create account. Username may already exist.' });
    }
    newUserId = created.user.id;

    const { error: profErr } = await supabaseAdmin.from('profiles').insert({
      id: newUserId, full_name, role
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

    await supabaseAdmin.from('security_logs').insert({
      user_id: adminId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      event_type: 'USER_CREATED',
      details: { new_user_id: newUserId, role, full_name, username: cleanUsername },
      severity: 'OK'
    });

    res.json({
      message: `${role === 'student' ? 'Student' : 'Teacher'} account created successfully`,
      user_id: newUserId,
      username: cleanUsername,
      email
    });
  } catch (err) {
    console.error('Create user error:', err);
    if (newUserId) {
      try { await supabaseAdmin.auth.admin.deleteUser(newUserId); } catch (cleanupErr) { console.error('Rollback failed:', cleanupErr); }
    }
    res.status(500).json({ message: 'Internal error creating user. Account was rolled back.' });
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
  res.status(500).json({ message: 'Something went wrong', details: err.message });
});

app.listen(PORT, () => {
  console.log(`UMS Laxman Nagar CMS server running on port ${PORT}`);
  console.log(`Public path: ${publicPath}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
