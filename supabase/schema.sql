-- =====================================================
-- 1. DROP ALL TABLES (CLEAN RESET)
-- =====================================================
DROP TABLE IF EXISTS upload_logs CASCADE;
DROP TABLE IF EXISTS broadcasts CASCADE;
DROP TABLE IF EXISTS role_audit CASCADE;
DROP TABLE IF EXISTS security_logs CASCADE;
DROP TABLE IF EXISTS marks CASCADE;
DROP TABLE IF EXISTS attendance CASCADE;
DROP TABLE IF EXISTS enrollments CASCADE;
DROP TABLE IF EXISTS course_assignments CASCADE;
DROP TABLE IF EXISTS courses CASCADE;
DROP TABLE IF EXISTS students_data CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;

-- =====================================================
-- 2. CREATE TABLES
-- =====================================================
CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT,
  role TEXT NOT NULL CHECK (role IN ('student', 'teacher', 'admin')),
  status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE students_data (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  roll_no TEXT UNIQUE NOT NULL,
  branch TEXT,
  semester INT,
  attendance_pct DECIMAL(5,2) DEFAULT 0,
  internal_marks JSONB DEFAULT '{}',
  fees_status TEXT DEFAULT 'pending' CHECK (fees_status IN ('pending', 'paid', 'overdue')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE courses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  credits INT NOT NULL,
  department TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE course_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  teacher_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  course_id UUID REFERENCES courses(id) ON DELETE CASCADE,
  section TEXT,
  schedule TEXT,
  room TEXT,
  UNIQUE(teacher_id, course_id, section)
);

CREATE TABLE enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID REFERENCES students_data(id) ON DELETE CASCADE,
  course_id UUID REFERENCES courses(id) ON DELETE CASCADE,
  enrollment_date TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(student_id, course_id)
);

CREATE TABLE attendance (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enrollment_id UUID REFERENCES enrollments(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  present BOOLEAN DEFAULT FALSE,
  marked_by UUID REFERENCES profiles(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(enrollment_id, date)
);

CREATE TABLE marks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enrollment_id UUID REFERENCES enrollments(id) ON DELETE CASCADE,
  exam_type TEXT CHECK (exam_type IN ('internal', 'midterm', 'final')),
  internal_marks INT CHECK (internal_marks BETWEEN 0 AND 30),
  external_marks INT CHECK (external_marks BETWEEN 0 AND 70),
  total_marks INT GENERATED ALWAYS AS (internal_marks + external_marks) STORED,
  marked_by UUID REFERENCES profiles(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(enrollment_id, exam_type)
);

CREATE TABLE security_logs (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  ip_address TEXT,
  user_agent TEXT,
  event_type TEXT NOT NULL,
  browser_fingerprint TEXT,
  details JSONB,
  severity TEXT CHECK (severity IN ('INFO','WARN','BLOCK','OK')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE role_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_user_id UUID REFERENCES profiles(id),
  old_role TEXT,
  new_role TEXT,
  changed_by UUID REFERENCES profiles(id),
  reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Broadcasts table (updated with image support)
CREATE TABLE broadcasts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id UUID REFERENCES profiles(id),
  message TEXT,
  image_url TEXT,
  type TEXT DEFAULT 'text' CHECK (type IN ('text', 'image')),
  sent_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE upload_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  filename TEXT,
  filesize INT,
  uploaded_by UUID REFERENCES profiles(id),
  status TEXT,
  details JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 3. ENABLE ROW LEVEL SECURITY
-- =====================================================
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE students_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE courses ENABLE ROW LEVEL SECURITY;
ALTER TABLE course_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;
ALTER TABLE marks ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE broadcasts ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload_logs ENABLE ROW LEVEL SECURITY;

-- =====================================================
-- 4. RLS POLICIES (BASIC)
-- =====================================================
CREATE POLICY "Users can view own profile" ON profiles
  FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own profile" ON profiles
  FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "Admins have full access to profiles" ON profiles
  FOR ALL USING (EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Students can view own data" ON students_data
  FOR SELECT USING (profile_id = auth.uid());
CREATE POLICY "Teachers can view all students_data" ON students_data
  FOR SELECT USING (EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'teacher'));
CREATE POLICY "Admins full access to students_data" ON students_data
  FOR ALL USING (EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Students view own enrollments" ON enrollments
  FOR SELECT USING (EXISTS (SELECT 1 FROM students_data s WHERE s.id = student_id AND s.profile_id = auth.uid()));
CREATE POLICY "Teachers/admins full access to enrollments" ON enrollments
  FOR ALL USING (EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('teacher', 'admin')));

-- Broadcast policies: viewable by all authenticated, insert/update/delete managed by backend
CREATE POLICY "Anyone can view broadcasts" ON broadcasts
  FOR SELECT USING (true);
CREATE POLICY "Users can insert broadcasts" ON broadcasts
  FOR INSERT WITH CHECK (auth.uid() = sender_id);
CREATE POLICY "Users can update own broadcasts" ON broadcasts
  FOR UPDATE USING (auth.uid() = sender_id);
CREATE POLICY "Admins can delete any broadcast" ON broadcasts
  FOR DELETE USING (EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin'));

-- =====================================================
-- 5. INSERT ADMIN PROFILE (AUTOMATIC BY EMAIL)
-- =====================================================
INSERT INTO profiles (id, full_name, role, status)
SELECT id, 'Administrator', 'admin', 'active'
FROM auth.users
WHERE email = 'anandsharma6183@gmail.com'
ON CONFLICT (id) DO NOTHING;

-- =====================================================
-- 6. INSERT SAMPLE COURSES
-- =====================================================
INSERT INTO courses (code, title, credits, department) VALUES
('CS501', 'Data Structures & Algorithms', 4, 'CSE'),
('CS502', 'Database Management Systems', 4, 'CSE'),
('CS503', 'Operating Systems', 4, 'CSE')
ON CONFLICT (code) DO NOTHING;