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

app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5500'],
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

// ─── Serve Static Files ───
const publicPath = path.join(__dirname, '../public');
app.use(protectStatic);
app.use(express.static(publicPath));

// ─── Root route ───
app.get('/', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

// ─── CAPTCHA Store ───
const captchaStore = new Map();

function sanitise(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'/\\`$&]/g, '')
            .replace(/alert|onerror|onload|script|javascript:/gi, '')
            .trim();
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
  captchaStore.set(id, { answer, expires: Date.now() + 300000 });
  res.json({ id, question });
});

// ─── 2. Login ───
app.post('/api/auth/login', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 8 }),
  body('role').isIn(['student', 'teacher', 'admin']),
  body('captcha_answer').isInt(),
  body('captcha_id').notEmpty(),
  body('device_fingerprint').optional().isString()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }

  const { username, password, role, captcha_answer, captcha_id, device_fingerprint } = req.body;

  if (!captchaStore.has(captcha_id)) {
    return res.status(400).json({ message: 'CAPTCHA expired or invalid' });
  }
  const captcha = captchaStore.get(captcha_id);
  if (captcha.answer !== captcha_answer) {
    return res.status(400).json({ message: 'Incorrect CAPTCHA' });
  }
  captchaStore.delete(captcha_id);

  const email = `${username}@umslaxmannagar.edu`;
  try {
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email,
      password
    });
    if (authError) {
      await supabaseAdmin.from('security_logs').insert({
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        event_type: 'FAILED_LOGIN',
        browser_fingerprint: device_fingerprint,
        details: { username, role },
        severity: 'WARN'
      });
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const { data: profile, error: profError } = await supabaseAdmin
      .from('profiles')
      .select('id, full_name, role')
      .eq('id', authData.user.id)
      .single();
    if (profError || !profile || profile.role !== role) {
      return res.status(401).json({ message: 'Role mismatch' });
    }

    const token = generateToken({ id: profile.id, username, role: profile.role });

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

    res.json({ token, role: profile.role, username, full_name: profile.full_name });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
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
        courses(code, title, credits),
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
    let totalCredits = 0, totalPoints = 0;
    enrollments.forEach(enr => {
      if (enr.marks && enr.marks.length) {
        const mark = enr.marks[enr.marks.length - 1];
        if (mark) {
          const gradePoints = mark.total_marks >= 90 ? 10 :
                              mark.total_marks >= 80 ? 9 :
                              mark.total_marks >= 70 ? 8 :
                              mark.total_marks >= 60 ? 7 :
                              mark.total_marks >= 50 ? 6 : 5;
          totalPoints += gradePoints * enr.courses.credits;
          totalCredits += enr.courses.credits;
        }
      }
    });
    const sgpa = totalCredits ? (totalPoints / totalCredits).toFixed(2) : '0.00';
    const { data: logs } = await supabaseAdmin
      .from('security_logs')
      .select('created_at, event_type, ip_address')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(5);
    res.json({
      profile,
      enrollments,
      attendance: { total, present, percentage: attendancePct },
      sgpa,
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
        const toInsert = chunk.map(r => ({
          roll_no: r.roll_no,
          branch: r.branch || 'CSE',
          semester: parseInt(r.semester) || 1,
        }));
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

// ─── Custom 404 Page (Red Warning Theme) ───
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
        body {
          font-family: 'Inter', sans-serif;
          background: #7f1d1d;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
          padding: 20px;
        }
        .card {
          background: #991b1b;
          border: 2px solid #fca5a5;
          border-radius: 20px;
          padding: 60px 48px;
          text-align: center;
          max-width: 520px;
          box-shadow: 0 20px 60px rgba(0,0,0,0.6);
          position: relative;
          overflow: hidden;
        }
        .card::before {
          content: '⚠';
          position: absolute;
          top: -30px;
          right: -30px;
          font-size: 120px;
          opacity: 0.1;
          transform: rotate(20deg);
        }
        h1 {
          font-size: 80px;
          font-weight: 800;
          color: #fca5a5;
          margin: 0;
          line-height: 1;
          text-shadow: 0 4px 20px rgba(252, 165, 165, 0.3);
        }
        .sub {
          font-size: 22px;
          font-weight: 600;
          color: #fecaca;
          margin: 16px 0 8px;
        }
        .desc {
          color: #fca5a5;
          font-size: 15px;
          margin: 8px 0 24px;
          opacity: 0.9;
        }
        a {
          display: inline-block;
          background: #fca5a5;
          color: #7f1d1d;
          font-weight: 700;
          padding: 12px 28px;
          border-radius: 50px;
          text-decoration: none;
          transition: background 0.2s, transform 0.1s;
          box-shadow: 0 4px 12px rgba(252, 165, 165, 0.4);
        }
        a:hover {
          background: #fecaca;
          transform: translateY(-2px);
        }
        .security-badge {
          margin-top: 24px;
          font-size: 12px;
          color: #fca5a5;
          opacity: 0.6;
          letter-spacing: 1px;
        }
        .security-badge span {
          display: inline-block;
          background: rgba(252, 165, 165, 0.15);
          padding: 4px 14px;
          border-radius: 30px;
          border: 1px solid rgba(252, 165, 165, 0.2);
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>404</h1>
        <div class="sub">⛔ Access Denied</div>
        <div class="desc">The page you requested does not exist or has been moved.<br>Please check the URL or return to the secure login.</div>
        <a href="/">← Back to Login Portal</a>
        <div class="security-badge">
          <span>🔒 Security Logged • Threat Detected</span>
        </div>
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
});