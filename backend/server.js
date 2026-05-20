/**
 * ============================================================
 *   MENTOR-MENTEE PORTAL — BACKEND SERVER
 *   Node.js + Express
 *   Run: node server.js  (or nodemon server.js)
 * ============================================================
 *
 *  HOW TO USE:
 *  1. npm install express bcryptjs jsonwebtoken express-rate-limit
 *               cors helmet morgan dotenv cookie-parser
 *  2. Create a .env file (see .env.example below)
 *  3. node server.js
 * ============================================================
 */

require('dotenv').config();

const express       = require('express');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const rateLimit     = require('express-rate-limit');
const cors          = require('cors');
const helmet        = require('helmet');
const morgan        = require('morgan');
const cookieParser  = require('cookie-parser');
const path          = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
//  SECURITY MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet());                    // Sets secure HTTP headers
app.use(cors({
  origin:      process.env.CLIENT_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));
app.use(morgan('dev'));                // Request logger
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve front-end static files (put your HTML/CSS/JS here)
app.use(express.static(path.join(__dirname, 'public')));


// ─────────────────────────────────────────────
//  RATE LIMITING  — brute-force protection
// ─────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15-minute window
  max:      10,                // max 10 attempts per window per IP
  message: {
    success: false,
    message: 'Too many login attempts. Please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders:   false,
});


// ─────────────────────────────────────────────
//  JWT HELPERS
// ─────────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'CHANGE_THIS_SECRET_IN_PRODUCTION';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '8h';   // token valid for 8 hrs

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}


// ─────────────────────────────────────────────
//  AUTH MIDDLEWARE (protects private routes)
// ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  // Accept token from Authorization header OR httpOnly cookie
  const authHeader = req.headers['authorization'];
  const token = (authHeader && authHeader.startsWith('Bearer '))
    ? authHeader.slice(7)
    : req.cookies.auth_token;

  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authenticated.' });
  }

  try {
    req.user = verifyToken(token);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
  }
}

// Role guard factory
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    next();
  };
}


// ─────────────────────────────────────────────
//  ██████╗  █████╗ ████████╗ █████╗ ██████╗  █████╗ ███████╗███████╗
//  ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝
//  ██║  ██║███████║   ██║   ███████║██████╔╝███████║███████╗█████╗
//  ██║  ██║██╔══██║   ██║   ██╔══██║██╔══██╗██╔══██║╚════██║██╔══╝
//  ██████╔╝██║  ██║   ██║   ██║  ██║██████╔╝██║  ██║███████║███████╗
//  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
//
//  REPLACE THE MOCK DATA BELOW WITH REAL DATABASE QUERIES
// ─────────────────────────────────────────────

/**
 * MOCK USER STORE
 *
 * **CONNECT TO DATABASE HERE**
 * Replace this object with actual DB queries.
 * Recommended: Sequelize (MySQL/PostgreSQL) or Mongoose (MongoDB)
 *
 * Each user record should contain at minimum:
 *   - id          : unique identifier (UUID / auto-increment)
 *   - universityId: student roll number or staff ID
 *   - email       : institutional email
 *   - passwordHash: bcrypt hash of the password
 *   - role        : 'mentee' | 'mentor' | 'management'
 *   - name        : display name
 *   - isActive    : boolean — block deactivated accounts
 */
const MOCK_USERS = [
  {
    id:           1,
    universityId: '2021CS001',
    email:        'alice@university.edu',
    // password: "student123"
    passwordHash: bcrypt.hashSync('student123', 10),
    role:         'mentee',
    name:         'Alice Johnson',
    isActive:     true,
  },
  {
    id:           2,
    universityId: 'MENTOR042',
    email:        'dr.kumar@university.edu',
    // password: "mentor123"
    passwordHash: bcrypt.hashSync('mentor123', 10),
    role:         'mentor',
    name:         'Dr. Rajesh Kumar',
    isActive:     true,
  },
  {
    id:           3,
    universityId: 'MGMT001',
    email:        'coordinator@university.edu',
    // password: "mgmt123"
    passwordHash: bcrypt.hashSync('mgmt123', 10),
    role:         'management',
    name:         'Prof. Sharma',
    isActive:     true,
  },
];

/**
 * **CONNECT TO DATABASE HERE**
 *
 * Replace this function with a real DB query, e.g.:
 *
 * // Sequelize (MySQL / PostgreSQL):
 * async function findUserByIdentifier(identifier) {
 *   return User.findOne({
 *     where: {
 *       [Op.or]: [{ universityId: identifier }, { email: identifier }]
 *     }
 *   });
 * }
 *
 * // Mongoose (MongoDB):
 * async function findUserByIdentifier(identifier) {
 *   return User.findOne({
 *     $or: [{ universityId: identifier }, { email: identifier }]
 *   });
 * }
 */
async function findUserByIdentifier(identifier) {
  // MOCK — scan in-memory array
  return MOCK_USERS.find(
    u => u.universityId === identifier || u.email === identifier
  ) || null;
}

/**
 * **CONNECT TO DATABASE HERE**
 *
 * Log failed login attempts for audit trail:
 *
 * // Sequelize:
 * async function recordLoginAttempt(userId, ip, success) {
 *   return LoginLog.create({ userId, ipAddress: ip, success, attemptedAt: new Date() });
 * }
 */
async function recordLoginAttempt(userId, ip, success) {
  // MOCK — just console-log; replace with DB insert
  console.log(`[LOGIN AUDIT] userId=${userId ?? 'unknown'} ip=${ip} success=${success} time=${new Date().toISOString()}`);
}


// ─────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────

/**
 * POST /api/auth/login
 * Body: { identifier, password, role }
 */
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { identifier, password, role } = req.body;

  // ── 1. Input validation ──────────────────────
  if (!identifier || typeof identifier !== 'string' || identifier.trim() === '') {
    return res.status(400).json({ success: false, message: 'University ID or email is required.' });
  }
  if (!password || typeof password !== 'string' || password.trim() === '') {
    return res.status(400).json({ success: false, message: 'Password is required.' });
  }
  const VALID_ROLES = ['mentee', 'mentor', 'management'];
  if (!role || !VALID_ROLES.includes(role)) {
    return res.status(400).json({ success: false, message: 'A valid role must be selected.' });
  }

  try {
    // ── 2. Look up user ───────────────────────────
    // **CONNECT TO DATABASE HERE** — see findUserByIdentifier() above
    const user = await findUserByIdentifier(identifier.trim());

    if (!user) {
      await recordLoginAttempt(null, req.ip, false);
      // Generic message — do NOT reveal "user not found" vs "wrong password"
      return res.status(401).json({ success: false, message: 'Invalid credentials. Please try again.' });
    }

    // ── 3. Check account is active ────────────────
    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Your account has been deactivated. Contact support.' });
    }

    // ── 4. Verify role matches ────────────────────
    if (user.role !== role) {
      await recordLoginAttempt(user.id, req.ip, false);
      return res.status(401).json({ success: false, message: 'Invalid credentials. Please try again.' });
    }

    // ── 5. Verify password ────────────────────────
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      await recordLoginAttempt(user.id, req.ip, false);
      return res.status(401).json({ success: false, message: 'Invalid credentials. Please try again.' });
    }

    // ── 6. Issue JWT ──────────────────────────────
    const tokenPayload = {
      sub:  user.id,
      name: user.name,
      role: user.role,
      uid:  user.universityId,
    };
    const token = signToken(tokenPayload);

    // ── 7. Record successful login ────────────────
    // **CONNECT TO DATABASE HERE** — store last login timestamp
    await recordLoginAttempt(user.id, req.ip, true);

    // ── 8. Set httpOnly cookie (optional; helps SPA auth) ──
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   8 * 60 * 60 * 1000,   // 8 hours in ms
    });

    // ── 9. Determine redirect destination ─────────
    const redirectMap = {
      mentee:     '/mentee/dashboard.html',
      mentor:     '/mentor_dash.html',
      management: '/management/dashboard.html',
    };

    return res.status(200).json({
      success:  true,
      message:  `Welcome, ${user.name}!`,
      token,                             // also send in body for localStorage-based SPA
      user: {
        id:   user.id,
        name: user.name,
        role: user.role,
        uid:  user.universityId,
      },
      redirectTo: redirectMap[user.role],
    });

  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    return res.status(500).json({ success: false, message: 'Internal server error. Please try again later.' });
  }
});


/**
 * POST /api/auth/logout
 * Clears the httpOnly auth cookie.
 */
app.post('/api/auth/logout', requireAuth, (req, res) => {
  res.clearCookie('auth_token');
  return res.status(200).json({ success: true, message: 'Logged out successfully.' });
});


/**
 * GET /api/auth/me
 * Returns the currently authenticated user's profile.
 */
app.get('/api/auth/me', requireAuth, async (req, res) => {
  // **CONNECT TO DATABASE HERE**
  // Fetch fresh user data from DB using req.user.sub (user ID):
  //   const user = await User.findByPk(req.user.sub);
  //   if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
  //   return res.json({ success: true, user });

  // MOCK — return decoded token payload
  return res.status(200).json({ success: true, user: req.user });
});


/**
 * POST /api/auth/forgot-password
 * Body: { email }
 *
 * Sends a password reset email.
 */
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, message: 'A valid email address is required.' });
  }

  try {
    // **CONNECT TO DATABASE HERE**
    // 1. Look up user by email:
    //    const user = await User.findOne({ where: { email } });
    //
    // 2. Generate a secure reset token:
    //    const resetToken = crypto.randomBytes(32).toString('hex');
    //    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    //
    // 3. Store token hash in DB:
    //    await user.update({ resetToken: hash(resetToken), resetExpiry });
    //
    // 4. Send email via Nodemailer / SendGrid:
    //    await sendResetEmail(user.email, resetToken);

    // Always return the same response to prevent email enumeration
    return res.status(200).json({
      success: true,
      message: 'If that email exists in our system, a reset link has been sent.',
    });

  } catch (err) {
    console.error('[FORGOT PASSWORD ERROR]', err);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


/**
 * POST /api/auth/reset-password
 * Body: { token, newPassword }
 */
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword || newPassword.length < 8) {
    return res.status(400).json({
      success: false,
      message: 'Token and a password of at least 8 characters are required.',
    });
  }

  try {
    // **CONNECT TO DATABASE HERE**
    // 1. Hash the incoming token and find the matching user:
    //    const hashedToken = hash(token);
    //    const user = await User.findOne({
    //      where: { resetToken: hashedToken, resetExpiry: { [Op.gt]: new Date() } }
    //    });
    //    if (!user) return res.status(400).json({ success: false, message: 'Token is invalid or expired.' });
    //
    // 2. Update password and clear reset fields:
    //    const passwordHash = await bcrypt.hash(newPassword, 12);
    //    await user.update({ passwordHash, resetToken: null, resetExpiry: null });

    return res.status(200).json({ success: true, message: 'Password reset successfully. Please log in.' });

  } catch (err) {
    console.error('[RESET PASSWORD ERROR]', err);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


// ─────────────────────────────────────────────
//  EXAMPLE PROTECTED DASHBOARD ROUTES
// ─────────────────────────────────────────────

/**
 * GET /api/mentee/dashboard
 * Only accessible to mentees.
 */
app.get('/api/mentee/dashboard', requireAuth, requireRole('mentee'), async (req, res) => {
  // **CONNECT TO DATABASE HERE**
  // const data = await MenteeProfile.findOne({ where: { userId: req.user.sub }, include: ['Mentor', 'Sessions'] });

  return res.status(200).json({
    success: true,
    message: `Welcome to your dashboard, ${req.user.name}!`,
    // data     ← real DB data would go here
  });
});

/**
 * GET /api/mentor/dashboard
 * Only accessible to mentors.
 */
app.get('/api/mentor/dashboard', requireAuth, requireRole('mentor'), async (req, res) => {
  // **CONNECT TO DATABASE HERE**
  // const data = await MentorProfile.findOne({ where: { userId: req.user.sub }, include: ['Mentees', 'Sessions'] });

  return res.status(200).json({
    success: true,
    message: `Welcome, ${req.user.name}. Here are your assigned students.`,
  });
});

/**
 * GET /api/management/dashboard
 * Only accessible to management.
 */
app.get('/api/management/dashboard', requireAuth, requireRole('management'), async (req, res) => {
  // **CONNECT TO DATABASE HERE**
  // const stats = await db.query('SELECT COUNT(*) as total FROM users GROUP BY role');

  return res.status(200).json({
    success: true,
    message: `Management dashboard for ${req.user.name}.`,
  });
});


// ─────────────────────────────────────────────
//  404 & GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found.' });
});

app.use((err, req, res, _next) => {
  console.error('[UNHANDLED ERROR]', err);
  res.status(500).json({ success: false, message: 'Something went wrong.' });
});


// ─────────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🎓 Mentor-Mentee Portal backend running on http://localhost:${PORT}`);
  console.log(`   Environment : ${process.env.NODE_ENV || 'development'}`);
  console.log(`   JWT Expiry  : ${JWT_EXPIRES}\n`);
});

module.exports = app; // export for testing (Jest / Supertest)
