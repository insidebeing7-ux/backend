require('dotenv').config();
const express = require('express');
const path = require("path");
const fs = require("fs");
const app = express();
app.set('trust proxy', 1);
app.use("/app", express.static(path.join(__dirname, "protected")));
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const session = require('express-session');
const axios = require('axios');
const http = require("http");
const csrf = require('csurf');
const helmet = require("helmet");
app.disable('x-powered-by');
const rateLimit = require("express-rate-limit");
const multer = require("multer");

const { requireAuth } = require("./middleware/auth");
const { validateRegister } = require("./middleware/validate");
const userRateMap = {};
const perUserRateLimit = require("./middleware/rateLimitPerUser");
const { OAuth2Client } = require('google-auth-library');
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "688424361924-drqcfv2qovlnf8i5htakiihe9i4peuv2.apps.googleusercontent.com";
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// NEW — separate credentials for Gmail inbox access (distinct from login)
const { google } = require('googleapis');
const GMAIL_CLIENT_ID = process.env.GMAIL_CLIENT_ID;
const GMAIL_CLIENT_SECRET = process.env.GMAIL_CLIENT_SECRET;
const GMAIL_REDIRECT_URI = process.env.GMAIL_REDIRECT_URI;
const GMAIL_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send"
];

console.log("🔑 GMAIL ENV CHECK:", {
  GMAIL_CLIENT_ID: GMAIL_CLIENT_ID ? GMAIL_CLIENT_ID.slice(0, 15) + "..." : "MISSING",
  GMAIL_CLIENT_SECRET: GMAIL_CLIENT_SECRET ? "present" : "MISSING",
  GMAIL_REDIRECT_URI: GMAIL_REDIRECT_URI || "MISSING"
});

function newGmailOAuthClient() {
  return new google.auth.OAuth2(GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REDIRECT_URI);
}

// NEW — builds an authenticated Gmail API client for a given user, using their stored refresh token
async function getGmailClientForUser(userId) {
  const row = await new Promise((resolve, reject) => {
    db.query("SELECT gmail_refresh_token FROM users WHERE id=?", [userId], (err, result) => {
      if (err) return reject(err);
      resolve(result[0]);
    });
  });
  if (!row || !row.gmail_refresh_token) {
    const err = new Error("GMAIL_NOT_CONNECTED");
    err.code = "GMAIL_NOT_CONNECTED";
    throw err;
  }
  const oauth2Client = newGmailOAuthClient();
  oauth2Client.setCredentials({ refresh_token: row.gmail_refresh_token });
  return google.gmail({ version: "v1", auth: oauth2Client });
}

const BLOCKED_EXTENSIONS = [".exe", ".bat", ".cmd", ".sh", ".php", ".py", ".rb", ".pl", ".cgi", ".msi", ".dll", ".vbs", ".ps1"];
const AUDIO_EXTENSIONS = [".webm", ".ogg", ".mp3", ".mp4", ".m4a", ".wav", ".opus", ".aac"];
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 10 MB

const cloudinary = require("cloudinary").v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Startup check — prints partial values so you can verify without exposing secrets
console.log("☁️ Cloudinary config check:", {
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "MISSING",
  api_key: process.env.CLOUDINARY_API_KEY ? process.env.CLOUDINARY_API_KEY.slice(0, 4) + "****" : "MISSING",
  api_secret: process.env.CLOUDINARY_API_SECRET ? process.env.CLOUDINARY_API_SECRET.slice(0, 4) + "****" : "MISSING",
});

// Hard crash if credentials are missing — prevents silent fallback to broken state
if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
  console.error("❌ FATAL: Cloudinary environment variables are missing. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET in Render.");
  process.exit(1);
}

// Files are held in memory only long enough to stream to Cloudinary —
// nothing touches local disk, so nothing gets wiped on restart.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (BLOCKED_EXTENSIONS.includes(ext)) {
      return cb(new Error("File type not allowed"));
    }
    cb(null, true);
  }
});

// Helper: upload an in-memory buffer to Cloudinary and resolve with the result
function uploadBufferToCloudinary(buffer, mimetype) {
  // Cloudinary requires resource_type "video" for audio files (mp3, m4a, aac, etc.)
  // "auto" sometimes misclassifies AMR/3GP as "raw" which produces unplayable URLs.
  // Explicitly list all audio MIME types including Android AMR variants.
  const isAudio = mimetype && (
    mimetype.startsWith("audio/") ||
    mimetype === "audio/3gpp"     ||   // Android AMR-NB in 3GP container
    mimetype === "audio/amr"      ||   // bare AMR
    mimetype === "application/octet-stream"  // mis-labeled fallback
  );
  const isVideo = mimetype && mimetype.startsWith("video/");
  const resourceType = (isAudio || isVideo) ? "video" : "image";

  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: "chat_uploads", resource_type: resourceType },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
    stream.end(buffer);
  });
}
// ===== END MULTER SETUP =====

const aiUserQuota = new Map();
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  handler: (req, res) => {
    res.status(429).json({ message: "Too many login attempts. Try again in 1 minute." });
  }
});
app.use(helmet({
  crossOriginResourcePolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: [
  "'self'",
  process.env.CLIENT_URL,
  "https://backend-1-liqz.onrender.com",
  "wss://chatflow-ai-o3e6.onrender.com",
  "wss://backend-1-liqz.onrender.com",
  "turn:global.relay.metered.ca",
  "stun:stun.l.google.com",
  "stun:stun1.l.google.com",
  "stun:",
  "turn:",
  "turns:"
],
    }
  }
}));
const port = process.env.PORT || 3000;

// ================= CORS =================
app.use(cors({
  origin: function(origin, callback) {
    callback(null, true); // allow Android (no origin) + web
  },
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "X-CSRF-Token", "x-csrf-token"]
}));

// ================= JSON =================
app.use(express.json({ limit: '10kb' }));
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30
});
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  handler: (req, res) => {
    return res.status(429).json({ message: "Max AI requests reached. Try again in 1 minute." });
  }
});
const aiQuota = {};

// ================= SESSION =================
const MySQLStore = require('express-mysql-session')(session);

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  createDatabaseTable: true,
  onError: function (error) { console.error("🔥 SESSION STORE ERROR:", error); },
  clearExpired: true,
  checkExpirationInterval: 900000,
  expiration: 86400000
});

app.use(session({
  key: 'chatapp.sid',
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "none",
    secure: true,
    path: "/",
    maxAge: 1000 * 60 * 60 * 24
  }
}));

const csrfProtection = csrf({ cookie: false });
app.use(csrfProtection);

// ================= PROTECTED PAGES =================
app.get("/app/user.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "protected/user.html"));
});
app.get("/app/messaging.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "protected/messaging.html"));
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public/signup.html"));
});

// ================= MYSQL =================
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectTimeout: 10000,
  ssl: { rejectUnauthorized: false }
});
db.connect(err => {
  if (err) { console.error('❌ MySQL connection error:', err); process.exit(1); }
  console.log('✅ Connected to MySQL');
});

db.on('error', (err) => {
  console.error('❌ MySQL runtime error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
    console.log('🔄 Reconnecting to MySQL...');
    db.connect();
  }
});

// ================= REGISTER =================
app.post('/register', authLimiter, csrfProtection, validateRegister, (req, res) => {
  if (!req.body.agreed) {
    return res.status(400).json({ message: "You must accept the Terms of Use" });
  }
  const clean = (v) => typeof v === "string" ? v.trim() : "";
  const username = clean(req.body.username);
  const password = clean(req.body.password);
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const usernameRegex = /^(?=.*\d)[a-zA-Z0-9_]{6,20}$/;
  if (!usernameRegex.test(username)) return res.status(400).json({ message: 'Invalid username' });
  if (!/^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(password)) return res.status(400).json({ message: 'Password length invalid' });
  if (!username || !password) return res.status(400).json({ message: 'All fields required' });

  db.query('SELECT * FROM users WHERE username=?', [username], (err, result) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (result.length > 0) return res.status(409).json({ message: 'Username exists' });

    db.query('SELECT * FROM users WHERE signup_ip=?', [ip], (err, ipResult) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      if (ipResult.length > 0) return res.status(429).json({ message: "This IP already created an account" });

      bcrypt.hash(password, 12, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        db.query('INSERT INTO users (username, password, signup_ip) VALUES (?,?,?)', [username, hash, ip], (err) => {
          if (err) return res.status(500).json({ message: 'Server error' });
          return res.json({ message: 'User created' });
        });
      });
    });
  });
});

// ================= LOGIN =================
// ================= LOGIN =================
// ================= GOOGLE AUTH =================
app.post('/auth/google', loginLimiter, async (req, res) => {
  const { idToken } = req.body;
  if (typeof idToken !== "string" || !idToken) {
    return res.status(400).json({ message: "Missing idToken" });
  }

  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } catch (err) {
    console.error("❌ GOOGLE TOKEN VERIFY ERROR:", err.message);
    return res.status(401).json({ message: "Invalid Google token" });
  }

  const googleId = payload.sub;
  const email = payload.email;
  if (!googleId || !email) {
    return res.status(400).json({ message: "Incomplete Google account info" });
  }

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  db.query('SELECT * FROM users WHERE google_id=?', [googleId], (err, result) => {
    if (err) return res.status(500).json({ message: 'Server error' });

    // finishLogin now also reports agreed_terms so the client knows
    // whether to show the Terms dialog — for BOTH new and existing users
    const finishLogin = (user, isNewUser = false) => {
  db.query(`DELETE FROM sessions WHERE data LIKE ?`, [`%"id":${user.id}%`], () => {
    req.session.user = { id: user.id, username: user.username, email: user.email || null };
    req.session.save((err) => {
      if (err) return res.status(500).json({ message: "Session error" });
      res.json({
        message: "Logged in with Google",
        isNewUser,
        agreedTerms: !!user.agreed_terms,
        usernameSet: !!user.username_set,
        username: user.username // NEW — so the client can show/confirm it
      });
    });
  });
};
    if (result.length > 0) {
      return finishLogin(result[0], false); // existing account — may still be unagreed
    }

    let base = email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '').slice(0, 20);
    if (base.length < 3) base = base + "user";

    const tryCreate = (candidate, attempt) => {
      db.query('SELECT id FROM users WHERE username=?', [candidate], (err, existing) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (existing.length > 0) {
          if (attempt > 5) return res.status(500).json({ message: 'Could not allocate username' });
          return tryCreate(base + Math.floor(Math.random() * 10000), attempt + 1);
        }
       db.query(
  'INSERT INTO users (username, password, signup_ip, google_id, email, agreed_terms, username_set) VALUES (?,?,?,?,?,?,?)',
  [candidate, null, ip, googleId, email, 0, 0], // username_set=0 — this is a placeholder, not a real choice
  (err, insertResult) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    finishLogin({ id: insertResult.insertId, username: candidate, email, agreed_terms: 0, username_set: 0 }, true);
  }
);
      });
    };

    tryCreate(base, 0);
  });
});
// ================= ACCEPT TERMS =================
app.post('/accept-terms', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  db.query('UPDATE users SET agreed_terms=1 WHERE id=?', [userId], (err) => {
    if (err) return res.status(500).json({ message: "Server error" });
    res.json({ message: "Terms accepted" });
  });
});
// ================= SET USERNAME (first-time Google sign-in) =================
app.post('/set-username', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const username = typeof req.body.username === "string" ? req.body.username.trim() : "";

  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  if (!usernameRegex.test(username)) {
    return res.status(400).json({ message: "Username must be 3-20 characters (letters, numbers, underscore)" });
  }

  db.query('SELECT id FROM users WHERE username=? AND id!=?', [username, userId], (err, existing) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (existing.length > 0) return res.status(409).json({ message: "Username already taken" });

    db.query('UPDATE users SET username=?, username_set=1 WHERE id=?', [username, userId], (updateErr) => {
      if (updateErr) return res.status(500).json({ message: "Server error" });
      req.session.user.username = username;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ message: "Session error" });
        res.json({ message: "Username set" });
      });
    });
  });
});

// ================= LOGIN =================
// ================= LOGIN =================
// ================= CANCEL SIGNUP (user declined Terms right after Google signup) =================
app.post('/cancel-signup', requireAuth, (req, res) => {
  const userId = req.session.user.id;

  // Only delete accounts that came from Google sign-up and have no messages yet —
  // this guards against ever deleting a real, already-used account.
  db.query(
    'SELECT google_id FROM users WHERE id=?',
    [userId],
    (err, result) => {
      if (err) return res.status(500).json({ message: "Server error" });
      if (result.length === 0 || !result[0].google_id) {
        return res.status(400).json({ message: "Not a Google signup account" });
      }

      db.query(
        'SELECT id FROM messages WHERE sender_id=? OR receiver_id=? LIMIT 1',
        [userId, userId],
        (msgErr, msgResult) => {
          if (msgErr) return res.status(500).json({ message: "Server error" });
          if (msgResult.length > 0) {
            return res.status(400).json({ message: "Account already in use" });
          }

          db.query('DELETE FROM users WHERE id=?', [userId], (delErr) => {
            if (delErr) return res.status(500).json({ message: "Server error" });

            req.session.destroy(() => {
              res.clearCookie("chatapp.sid", {
                path: "/",
                httpOnly: true,
                sameSite: "none",
                secure: true
              });
              res.json({ message: "Signup cancelled" });
            });
          });
        }
      );
    }
  );
});

// ================= LOGIN =================
// ================= LOGIN =================
app.post('/login', loginLimiter,  (req, res) => {
  const clean = (v) => typeof v === "string" ? v.trim() : "";
  const username = clean(req.body.username);
  const password = clean(req.body.password);
  if (!username || !password || username.length > 30 || password.length > 100) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  db.query('SELECT * FROM users WHERE username=?', [username], (err, result) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (result.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
    const user = result[0];
    if (!user.password) {
      return res.status(400).json({ message: 'This account uses Google sign-in. Please continue with Google.' });
    }
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
      db.query(
        `DELETE FROM sessions WHERE data LIKE ?`,
        [`%"id":${user.id}%`],
        (deleteErr) => {
          if (deleteErr) console.warn("⚠️ Could not clear old sessions:", deleteErr);
          req.session.user = { id: user.id, username: user.username };
          req.session.save((err) => {
            if (err) return res.status(500).json({ message: "Session error" });
            res.json({ message: "Logged in" });
          });
        }
      );
    });
  });
});

// ================= CURRENT USER =================
// ================= CURRENT USER =================
app.get('/user-data', requireAuth, (req, res) => {
  db.query('SELECT agreed_terms, username_set FROM users WHERE id=?', [req.session.user.id], (err, result) => {
    if (err || result.length === 0) return res.status(500).json({ message: "Server error" });
    res.json({
      ...req.session.user,
      agreedTerms: !!result[0].agreed_terms,
      usernameSet: !!result[0].username_set // NEW
    });
  });
});

// ================= CSRF TOKEN =================
app.get('/csrf-token', (req, res) => {
  try {
    const token = req.csrfToken();
    req.session.save(() => {
      res.json({ csrfToken: token });
    });
  } catch (err) {
    console.error("CSRF ERROR:", err);
    res.status(500).json({ message: "CSRF token error" });
  }
});

// ================= GET USER BY USERNAME =================
app.get('/user/:username', requireAuth, (req, res) => {
  const { username } = req.params;
  db.query('SELECT id, username FROM users WHERE username=?', [username], (err, result) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (result.length === 0) return res.status(404).json({ message: 'User not found' });
    res.json(result[0]);
  });
});

// ================= SEARCH USERS =================
// ================= SEARCH USERS =================
app.get('/search-users', authLimiter, requireAuth, (req, res) => {
  const raw = req.query.q || "";
  if (raw.length > 50) return res.status(400).json({ message: "Query too long" });

  const userId = req.session.user?.id;

  // If the query is a full email address, match it against the email
  // column directly (only Google-authenticated users have one).
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (emailRegex.test(raw.trim())) {
    return db.query(
      `SELECT id, username FROM users WHERE LOWER(email) = LOWER(?) AND id != ? LIMIT 10`,
      [raw.trim(), userId],
      (err, result) => {
        if (err) { console.error("❌ SEARCH ERROR:", err); return res.status(500).json({ message: "Server error" }); }
        res.json(result);
      }
    );
  }

  // Otherwise search by username prefix, same normalization as before
  // (matches the Gmail-derived prefix e.g. "john.doe" -> "johndoe").
  const normalized = raw.replace(/[^a-zA-Z0-9_]/g, "");
  if (normalized.length === 0) return res.json([]);

  db.query(
    `SELECT id, username FROM users WHERE LOWER(username) LIKE LOWER(?) AND id != ? LIMIT 10`,
    [`%${normalized}%`, userId],
    (err, result) => {
      if (err) { console.error("❌ SEARCH ERROR:", err); return res.status(500).json({ message: "Server error" }); }
      res.json(result);
    }
  );
});

// ================= SEND MESSAGE =================
app.post('/send', requireAuth, perUserRateLimit, (req, res) => {
  const sender_id = req.session.user.id;
  let { receiver_id, content } = req.body;
  const receiverId = Number(receiver_id);
  if (!Number.isInteger(receiverId)) return res.status(400).json({ message: "Invalid receiver_id" });
  if (receiver_id === sender_id) return res.status(400).json({ message: "Cannot message yourself" });

  const now = Date.now();
  if (!aiQuota[sender_id]) aiQuota[sender_id] = [];
  aiQuota[sender_id] = aiQuota[sender_id].filter(t => now - t < 60000);
  if (aiQuota[sender_id].length >= 10) return res.status(429).json({ message: "AI limit reached" });
  aiQuota[sender_id].push(now);

  const sanitize = require('sanitize-html');
  content = sanitize(content, { allowedTags: [], allowedAttributes: {}, disallowedTagsMode: 'discard' });
  if (content.length > 1000) return res.status(400).json({ message: 'Message too long' });

  receiver_id = Number(receiver_id);
  if (!Number.isInteger(receiver_id)) return res.status(400).json({ message: "Invalid receiver_id" });
  if (!content) return res.status(400).json({ message: "Missing content" });
  if (receiver_id === sender_id) return res.status(400).json({ message: "Cannot message yourself" });

 db.query("SELECT id FROM users WHERE id=?", [receiver_id], (err, result) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (result.length === 0) return res.status(404).json({ message: "Receiver does not exist" });
    db.query(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)',
      [sender_id, receiver_id, content],
      (err) => {
        if (err) { console.error("❌ SEND ERROR:", err); return res.status(500).json({ message: 'Error sending message' }); }
        io.to(String(receiver_id)).emit("new-message", {
          sender_id,
          sender_username: req.session.user.username,
          preview: content.slice(0, 80)
        });
        res.json({ message: 'Sent' });
      }
    );
  });
});

// ================= GET MESSAGES =================
app.get('/messages', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const receiver_id = parseInt(req.query.receiver_id);
  if (!Number.isInteger(receiver_id)) return res.status(400).json({ message: "Invalid receiver_id" });

  db.query(
    `SELECT * FROM messages
     WHERE ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?))
       AND NOT (sender_id=? AND deleted_for_sender=1)
       AND NOT (receiver_id=? AND deleted_for_receiver=1)
     ORDER BY id ASC`,
    [userId, receiver_id, receiver_id, userId, userId, userId],
    (err, result) => {
      if (err) { console.error("🔥 DB ERROR:", err); return res.status(500).json({ message: 'Error fetching messages' }); }
      const mapped = result.map(m => ({
        id: m.id,
        sender_id: m.sender_id,
        receiver_id: m.receiver_id,
        content: m.deleted_for_everyone ? "This message was deleted" : m.content,
        deleted: !!m.deleted_for_everyone
      }));
      // NEW: opening this chat means these are now read
      db.query(
        `UPDATE messages SET is_read=1 WHERE sender_id=? AND receiver_id=? AND is_read=0`,
        [receiver_id, userId],
        (readErr) => {
          if (!readErr) io.to(String(userId)).emit("messages-read", { sender_id: receiver_id });
        }
      );
      res.json(mapped);
    }
  );
});

// ================= UNREAD SUMMARY (for notification bell) =================
app.get('/unread-summary', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  db.query(
    `SELECT m.sender_id, u.username AS sender_username, COUNT(*) AS unread_count,
            MAX(m.id) AS last_id
     FROM messages m
     JOIN users u ON u.id = m.sender_id
     WHERE m.receiver_id=? AND m.is_read=0
       AND m.deleted_for_everyone=0 AND m.deleted_for_receiver=0
     GROUP BY m.sender_id, u.username
     ORDER BY last_id DESC`,
    [userId],
    (err, groups) => {
      if (err) { console.error("❌ UNREAD SUMMARY ERROR:", err); return res.status(500).json({ message: "Server error" }); }
      if (groups.length === 0) return res.json([]);
      const lastIds = groups.map(g => g.last_id);
      db.query(`SELECT id, content FROM messages WHERE id IN (?)`, [lastIds], (err2, msgs) => {
        if (err2) return res.status(500).json({ message: "Server error" });
        const contentById = {};
        msgs.forEach(m => contentById[m.id] = m.content);
        const result = groups.map(g => ({
          sender_id: g.sender_id,
          sender_username: g.sender_username,
          unread_count: g.unread_count,
          last_message: contentById[g.last_id] || "",
          last_message_id: g.last_id
        }));
        res.json(result);
      });
    }
  );
});

// ================= MARK MESSAGES READ =================
app.post('/mark-read', requireAuth, csrfProtection, (req, res) => {
  const userId = req.session.user.id;
  const senderId = Number(req.body.sender_id);
  if (!Number.isInteger(senderId)) return res.status(400).json({ message: "Invalid sender_id" });
  db.query(
    `UPDATE messages SET is_read=1 WHERE receiver_id=? AND sender_id=? AND is_read=0`,
    [userId, senderId],
    (err) => {
      if (err) return res.status(500).json({ message: "DB error" });
      io.to(String(userId)).emit("messages-read", { sender_id: senderId });
      res.json({ ok: true });
    }
  );
});

// ================= FILE UPLOAD =================

// ================= FILE UPLOAD =================
app.post('/upload', requireAuth, upload.single("file"), async (req, res) => {
  const sender_id = req.session.user.id;
  const receiver_id = Number(req.body.receiver_id);

  if (!Number.isInteger(receiver_id)) {
    return res.status(400).json({ message: "Invalid receiver_id" });
  }
  if (receiver_id === sender_id) {
    return res.status(400).json({ message: "Cannot message yourself" });
  }
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded" });
  }

  // check receiver exists
  db.query("SELECT id FROM users WHERE id=?", [receiver_id], async (err, result) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (result.length === 0) return res.status(404).json({ message: "Receiver does not exist" });

    let cloudResult;
   try {
      cloudResult = await uploadBufferToCloudinary(req.file.buffer, req.file.mimetype);
    } catch (uploadErr) {
      console.error("❌ CLOUDINARY UPLOAD ERROR:", uploadErr);
      return res.status(500).json({ message: "File upload failed" });
    }

    const fileUrl = cloudResult.secure_url;
    const originalName = req.file.originalname.replace(/[<>&"]/g, ""); // basic sanitize for display
    const ext = path.extname(req.file.originalname).toLowerCase();
    const imageExts = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"];
   const audioExts = [".webm", ".ogg", ".mp3", ".mp4", ".m4a", ".wav", ".opus", ".aac", ".3gp", ".3gpp"];
    const isImage = imageExts.includes(ext);
    const isAudio = audioExts.includes(ext);
    const content = isImage
      ? `🖼️ [${originalName}](${fileUrl})`
      : isAudio
      ? `🎤 [${originalName}](${fileUrl})`
      : `📎 [${originalName}](${fileUrl})`;

    db.query(
      "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)",
      [sender_id, receiver_id, content],
      (err) => {
        if (err) { console.error("❌ UPLOAD DB ERROR:", err); return res.status(500).json({ message: "DB error" }); }
        io.to(String(receiver_id)).emit("new-message", {
          sender_id,
          sender_username: req.session.user.username,
          preview: content.slice(0, 80)
        });
        res.json({ ok: true, url: fileUrl, isImage, isAudio });
      }
    );
  });
});



// ================= AI SEND =================
app.post('/ai-send', aiLimiter, requireAuth, perUserRateLimit, async (req, res) => {
  const sender_id = req.session.user.id;
  const userId = req.session.user.id;
  const now = Date.now();

  if (!aiUserQuota.has(userId)) aiUserQuota.set(userId, []);
  const timestamps = aiUserQuota.get(userId).filter(t => now - t < 60000);
  if (timestamps.length >= 10) return res.status(429).json({ message: "Too many AI requests. Wait 1 minute." });
  timestamps.push(now);
  aiUserQuota.set(userId, timestamps);

  const { receiver_id, content, context } = req.body;
  const parsedReceiver = Number(receiver_id);
  if (!Number.isInteger(parsedReceiver)) return res.status(400).json({ message: "Invalid receiver_id" });
  if (!receiver_id || !content) return res.status(400).json({ message: 'Missing data' });
  if (content.length > 2000) return res.status(400).json({ message: "Message too long" });
  if (content.includes("<script")) return res.status(400).json({ message: "Blocked content" });
  if (context && JSON.stringify(context).length > 5000) return res.status(400).json({ message: "Context too large" });

  try {
    const aiResponse = await callAIWithRetry({
      text: content,
      instructions: req.session.aiMode || "",
      mode: "chat"
    });

    let aiReply = aiResponse.data.reply;
    if (typeof aiReply !== "string") return res.status(500).json({ message: "Invalid AI response" });
    aiReply = aiReply.slice(0, 2000);

    const sanitize = require('sanitize-html');
    aiReply = sanitize(aiReply, { allowedTags: [], allowedAttributes: {} });

    const lastMessage = await new Promise((resolve, reject) => {
      db.query(
        "SELECT created_at FROM messages WHERE sender_id=? ORDER BY id DESC LIMIT 1",
        [sender_id],
        (err, result) => { if (err) return reject(err); resolve(result[0]); }
      );
    });
    if (lastMessage) {
      const diff = Date.now() - new Date(lastMessage.created_at).getTime();
      if (diff < 2000) return res.status(429).json({ message: "Sending too fast" });
    }

    db.query(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)',
      [sender_id, receiver_id, aiReply],
      (err) => {
        if (err) { console.error("❌ AI DB ERROR:", err); return res.status(500).json({ message: 'Error saving AI message' }); }
        io.to(String(receiver_id)).emit("new-message", {
          sender_id,
          sender_username: req.session.user.username,
          preview: aiReply.slice(0, 80)
        });
        res.json({ reply: aiReply });
      }
    );
  } catch (err) {
    console.error("🔥 AI ERROR:", err.message);
    res.status(500).json({ message: 'AI service error' });
  }
});

// ================= CONVERSATIONS =================
app.get('/conversations', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  db.query(
    `SELECT m.*, u.username AS other_username
     FROM messages m
     INNER JOIN (
       SELECT
         CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS other_user,
         MAX(id) AS last_id
       FROM messages
       WHERE sender_id = ? OR receiver_id = ?
       GROUP BY other_user
     ) latest ON m.id = latest.last_id
     JOIN users u ON u.id = latest.other_user
     ORDER BY m.id DESC`,
    [userId, userId, userId],
    (err, result) => {
      if (err) { console.error("❌ CONVERSATION ERROR:", err); return res.status(500).json({ message: "DB error" }); }
      res.json(result);
    }
  );
});

// ================= GET USER BY ID =================
app.get('/user-by-id/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  db.query('SELECT id, username FROM users WHERE id=?', [id], (err, result) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (result.length === 0) return res.status(404).json({ message: 'User not found' });
    res.json(result[0]);
  });
});

app.post('/logout', requireAuth, (req, res) => {
  const userId = req.session.user?.id;
  db.query(
    `DELETE FROM sessions WHERE data LIKE ?`,
    [`%"id":${userId}%`],
    (err) => {
      // Always destroy THIS request's in-memory session too — otherwise
      // express-session can resave/touch it after the handler returns and
      // silently recreate the row + cookie we just tried to clear.
      req.session.destroy((destroyErr) => {
        // Match the attributes used when the cookie was originally set,
        // or some clients won't actually drop it.
        res.clearCookie("chatapp.sid", {
          path: "/",
          httpOnly: true,
          sameSite: "none",
          secure: true
        });

        if (err || destroyErr) {
          console.error("⚠️ Logout cleanup error:", err || destroyErr);
          return res.json({ message: 'Logged out (partial)' });
        }
        res.json({ message: 'Logged out from all devices' });
      });
    }
  );
});
// ================= AI MODE =================
app.post('/set-ai-mode', requireAuth, (req, res) => {
  let instructions = req.body.instructions || "";
  if (instructions.length > 300) return res.status(400).json({ message: "Mode too long" });
  instructions = instructions.replace(/\0/g, "");
  req.session.aiMode = instructions;
  res.json({ ok: true });
});
app.get('/get-ai-mode', requireAuth, (req, res) => {
  res.json({ instructions: req.session.aiMode || "" });
});

// ================= TOGGLE AUTO AI =================
app.post('/toggle-auto-ai', requireAuth, (req, res) => {
  const user_id = req.session.user.id;
  const { receiver_id } = req.body;
  if (!Number.isInteger(Number(receiver_id))) return res.status(400).json({ message: "Invalid receiver" });

  db.query(
    `SELECT enabled FROM auto_ai_settings WHERE user_id=? AND receiver_id=?`,
    [user_id, receiver_id],
    (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });
      let newState = result.length > 0 ? (result[0].enabled ? 0 : 1) : 1;
      db.query(
        `INSERT INTO auto_ai_settings (user_id, receiver_id, enabled)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE enabled=?`,
        [user_id, receiver_id, newState, newState],
        (err) => {
          if (err) return res.status(500).json({ message: "DB error" });
          res.json({ enabled: !!newState });
        }
      );
    }
  );
});

// ================= AI REQUEST =================
// ================= AI REQUEST =================
app.post('/ai-request', aiLimiter, requireAuth, async (req, res) => {
  try {
    let { text, mode, instructions: bodyInstructions } = req.body;
    if (typeof text !== "string") return res.status(400).json({ message: "Invalid input" });
    text = text.trim().slice(0, 2000);
    const allowedModes = ["chat", "ai_writer", "summary", "greeting"];
    const safeMode = allowedModes.includes(mode) ? mode : "chat";

    // Sanitize instructions from request body
    let safeBodyInstructions = "";
    if (typeof bodyInstructions === "string") {
      safeBodyInstructions = bodyInstructions.trim().slice(0, 300).replace(/\0/g, "");
    }

    // Use session aiMode first, fall back to body instructions
    const instructions = safeMode === "ai_writer"
      ? ""
      : (req.session.aiMode || safeBodyInstructions || "");

    try {
      await axios.get(process.env.AI_URL + "/health", { timeout: 30000 });
    } catch (pingErr) {
      console.warn("⚠️ AI wake-up ping failed:", pingErr.code);
      return res.status(503).json({ message: "AI is starting up, please try again in 15 seconds.", waking: true });
    }

    const response = await callAIWithRetry({
      text,
      instructions,
      mode: safeMode
    });
    return res.json({ reply: response.data.reply });
  } catch (err) {
    console.error("AI REQUEST ERROR:", err.code, err?.response?.status);
    const isTimeout = err.code === "ECONNABORTED";
    const isDown = err.code === "ECONNREFUSED" || err.code === "ENOTFOUND";
    return res.status(503).json({
      message: isTimeout || isDown ? "AI is starting up, please try again in 15 seconds." : "AI error. Please try again.",
      waking: isTimeout || isDown
    });
  }
});

// ================= GET AUTO AI =================
// ================= VOICE SAMPLE STATUS =================
app.get('/voice-sample-status', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const targetUserId = Number(req.query.target_user_id);
  if (!Number.isInteger(targetUserId)) return res.status(400).json({ message: "Invalid target_user_id" });

  db.query(
    "SELECT url FROM voice_samples WHERE user_id=? AND target_user_id=?",
    [userId, targetUserId],
    (err, result) => {
      if (err) { console.error("❌ VOICE SAMPLE STATUS ERROR:", err); return res.status(500).json({ message: "Server error" }); }
      res.json({ exists: result.length > 0, url: result.length > 0 ? result[0].url : null });
    }
  );
});

app.post('/upload-voice-sample', requireAuth, upload.single("file"), async (req, res) => {
  const userId = req.session.user.id;
  const targetUserId = Number(req.body.target_user_id);

  if (!Number.isInteger(targetUserId)) return res.status(400).json({ message: "Invalid target_user_id" });
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  // NEW: verify target_user_id actually exists BEFORE inserting — a bad
  // target_user_id trips the FOREIGN KEY constraint on voice_samples and
  // previously surfaced only as an opaque "DB error".
  const targetExists = await new Promise((resolve, reject) => {
    db.query("SELECT id FROM users WHERE id=?", [targetUserId], (err, result) => {
      if (err) return reject(err);
      resolve(result.length > 0);
    });
  }).catch((err) => {
    console.error("❌ VOICE SAMPLE target lookup DB ERROR:", err.code, err.sqlMessage);
    return null;
  });

  if (targetExists === null) {
    return res.status(500).json({ message: "Server error checking target user" });
  }
  if (!targetExists) {
    return res.status(404).json({ message: "Target user does not exist" });
  }

  let cloudResult;
  try {
    cloudResult = await uploadBufferToCloudinary(req.file.buffer, req.file.mimetype);
  } catch (uploadErr) {
    console.error("❌ VOICE SAMPLE CLOUDINARY ERROR:", uploadErr);
    return res.status(500).json({ message: "Cloudinary upload failed: " + (uploadErr.message || "unknown") });
  }

  const fileUrl = cloudResult.secure_url;
  db.query(
    `INSERT INTO voice_samples (user_id, target_user_id, url) VALUES (?,?,?)
     ON DUPLICATE KEY UPDATE url=VALUES(url)`,
    [userId, targetUserId, fileUrl],
    (err) => {
      if (err) {
        // NEW: log + return the REAL MySQL error code/message instead of
        // the generic "DB error" — this is what actually lets us diagnose
        // FK violations, duplicate key issues, connection drops, etc.
        console.error("❌ VOICE SAMPLE DB ERROR:", err.code, err.sqlMessage || err.message);
        return res.status(500).json({
          message: `DB error: ${err.code || "UNKNOWN"} - ${err.sqlMessage || err.message || "no details"}`
        });
      }
      res.json({ ok: true, url: fileUrl });
    }
  );
});

// ================= GET AUTO AI =================
app.get('/get-auto-ai', requireAuth, (req, res) => {
  if (!req.session.user) return res.json({ enabled: false });
  const user_id = req.session.user.id;
  const receiver_id = req.query.receiver_id;
  db.query(
    `SELECT enabled FROM auto_ai_settings WHERE user_id=? AND receiver_id=?`,
    [user_id, receiver_id],
    (err, result) => {
      if (err || result.length === 0) return res.json({ enabled: false });
      res.json({ enabled: !!result[0].enabled });
    }
  );
});

// ================= GMAIL: CONNECTION STATUS =================
app.get('/gmail/status', requireAuth, (req, res) => {
  db.query("SELECT gmail_connected FROM users WHERE id=?", [req.session.user.id], (err, result) => {
    if (err || result.length === 0) return res.status(500).json({ message: "Server error" });
    res.json({ connected: !!result[0].gmail_connected });
  });
});

app.get('/auth/gmail/start', requireAuth, (req, res) => {
  const oauth2Client = newGmailOAuthClient();
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    // 'consent' forces re-approval every single time, even for users who
    // already granted access — only use it the first time we need a
    // refresh_token. Google returns a refresh_token WITHOUT prompt=consent
    // as long as this is the first authorization for this client+user pair,
    // so 'select_account' is enough for a smoother repeat experience.
    prompt: 'select_account',
    scope: GMAIL_SCOPES, // both scopes requested together = ONE combined consent screen, not two
    include_granted_scopes: true,
    state: String(req.session.user.id)
  });
  res.json({ url: authUrl });
});

// NEW — small helper: build an HTML page that immediately redirects into
// the app via custom scheme (myapp://gmail-connected) and, as a fallback
// for browsers that block the redirect, shows a manual "Return to app"
// link plus auto-closes the tab if it was opened as a popup/CustomTab.
function gmailResultPage({ success, message }) {
  const deepLink = success
    ? "chatflowapp://gmail-callback?status=success"
    : `chatflowapp://gmail-callback?status=error&message=${encodeURIComponent(message || "")}`;
  return `
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script>
          window.location.href = "${deepLink}";
          setTimeout(function() {
            // If the deep link didn't fire (app not installed / desktop
            // browser testing), give the user a manual way back.
            document.getElementById("fallback").style.display = "block";
          }, 800);
        </script>
        <style>
          body { font-family: sans-serif; text-align: center; padding: 40px 20px; }
          #fallback { display: none; }
          a.btn { display:inline-block; margin-top:16px; padding:12px 24px;
                  background:#1877F2; color:#fff; border-radius:8px; text-decoration:none; }
        </style>
      </head>
      <body>
        <h3>${success ? "Gmail connected ✅" : "Connection failed"}</h3>
        <p>${success ? "Returning you to the app..." : (message || "Something went wrong.")}</p>
        <div id="fallback">
          <p>If nothing happened, tap below:</p>
          <a class="btn" href="${deepLink}">Return to app</a>
        </div>
      </body>
    </html>
  `;
}

app.get('/auth/gmail/callback', async (req, res) => {
  const code = req.query.code;
  const userId = Number(req.query.state);
  if (!code || !Number.isInteger(userId)) {
    return res.status(400).send(gmailResultPage({ success: false, message: "Invalid callback parameters" }));
  }
  try {
    const oauth2Client = newGmailOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);

    // CHANGED — if no refresh_token came back (common on reconnect, since
    // Google only issues one on first-ever consent), fall back to keeping
    // whichever refresh_token we already have on file instead of failing.
    if (!tokens.refresh_token) {
      db.query("SELECT gmail_refresh_token FROM users WHERE id=?", [userId], (err, result) => {
        const hasExisting = !err && result.length > 0 && result[0].gmail_refresh_token;
        if (hasExisting) {
          db.query("UPDATE users SET gmail_connected=1 WHERE id=?", [userId], () => {
            res.send(gmailResultPage({ success: true }));
          });
        } else {
          res.status(400).send(gmailResultPage({
            success: false,
            message: "No refresh token returned. Remove app access in your Google Account (myaccount.google.com/permissions) and try connecting again."
          }));
        }
      });
      return;
    }

    db.query(
      "UPDATE users SET gmail_refresh_token=?, gmail_connected=1 WHERE id=?",
      [tokens.refresh_token, userId],
      (err) => {
        if (err) {
          console.error("❌ GMAIL TOKEN SAVE ERROR:", err);
          return res.status(500).send(gmailResultPage({ success: false, message: "Server error" }));
        }
        res.send(gmailResultPage({ success: true }));
      }
    );
  } catch (err) {
    console.error("❌ GMAIL CALLBACK ERROR:", err.message);
    res.status(500).send(gmailResultPage({ success: false, message: "Gmail authorization failed" }));
  }
});

// ================= GMAIL: INBOX LIST =================
app.get('/gmail/inbox', requireAuth, async (req, res) => {
  try {
    const gmail = await getGmailClientForUser(req.session.user.id);
    // NEW — allow the client to ask for more messages (used by pull-to-refresh
    // and "load more"); default raised from 20 to 50, capped at 100 so a
    // single request can't hammer the Gmail API.
    const requestedMax = Number(req.query.max_results) || 50;
    const maxResults = Math.min(Math.max(requestedMax, 1), 100);

    const list = await gmail.users.messages.list({
      userId: "me",
      maxResults,
      labelIds: ["INBOX"]
    });
    const messages = list.data.messages || [];

    const detailed = await Promise.all(messages.map(async (m) => {
      const full = await gmail.users.messages.get({
        userId: "me",
        id: m.id,
        format: "metadata",
        metadataHeaders: ["From", "Subject", "Date"]
      });
      const headers = full.data.payload.headers || [];
      const get = (name) => headers.find(h => h.name === name)?.value || "";
      return {
        id: m.id,
        from: get("From"),
        subject: get("Subject"),
        date: get("Date"),
        snippet: full.data.snippet || "",
        unread: (full.data.labelIds || []).includes("UNREAD")
      };
    }));

    res.json(detailed);
  } catch (err) {
    if (err.code === "GMAIL_NOT_CONNECTED") {
      return res.status(409).json({ message: "Gmail not connected", connected: false });
    }
    console.error("❌ GMAIL INBOX ERROR:", err.message);
    res.status(500).json({ message: "Could not fetch inbox" });
  }
});

// ================= GMAIL: SEND MAIL =================
// ================= GMAIL: MESSAGE DETAIL =================
app.get('/gmail/message/:id', requireAuth, async (req, res) => {
  try {
    const gmail = await getGmailClientForUser(req.session.user.id);
    const full = await gmail.users.messages.get({
      userId: "me",
      id: req.params.id,
      format: "full"
    });

    const headers = full.data.payload.headers || [];
    const get = (name) => headers.find(h => h.name === name)?.value || "";

    // Walk MIME parts to find text/plain (fallback: text/html stripped)
    function extractBody(payload) {
      if (!payload) return "";
      if (payload.body?.data && payload.mimeType === "text/plain") {
        return Buffer.from(payload.body.data, "base64").toString("utf-8");
      }
      if (payload.parts) {
        const plain = payload.parts.find(p => p.mimeType === "text/plain");
        if (plain?.body?.data) return Buffer.from(plain.body.data, "base64").toString("utf-8");
        for (const part of payload.parts) {
          const nested = extractBody(part);
          if (nested) return nested;
        }
      }
      if (payload.body?.data) {
        return Buffer.from(payload.body.data, "base64").toString("utf-8");
      }
      return "";
    }

    res.json({
      id: req.params.id,
      from: get("From"),
      to: get("To"),
      subject: get("Subject"),
      date: get("Date"),
      bodyText: extractBody(full.data.payload).slice(0, 20000),
      bodyHtml: null
    });
  } catch (err) {
    if (err.code === "GMAIL_NOT_CONNECTED") {
      return res.status(409).json({ message: "Gmail not connected", connected: false });
    }
    console.error("❌ GMAIL MESSAGE DETAIL ERROR:", err.message);
    res.status(500).json({ message: "Could not fetch message" });
  }
});

// ================= GMAIL: SEND MAIL =================
app.post('/gmail/send', requireAuth, async (req, res) => {
  const { to, subject, body } = req.body;
  if (typeof to !== "string" || typeof subject !== "string" || typeof body !== "string") {
    return res.status(400).json({ message: "Missing to/subject/body" });
  }
  try {
    const gmail = await getGmailClientForUser(req.session.user.id);
    const messageParts = [
      `To: ${to}`,
      `Subject: ${subject}`,
      "Content-Type: text/plain; charset=utf-8",
      "",
      body
    ];
    const raw = Buffer.from(messageParts.join("\n"))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw }
    });
    res.json({ message: "Sent" });
  } catch (err) {
    if (err.code === "GMAIL_NOT_CONNECTED") {
      return res.status(409).json({ message: "Gmail not connected", connected: false });
    }
    console.error("❌ GMAIL SEND ERROR:", err.message);
    res.status(500).json({ message: "Could not send email" });
  }
});

// ================= HTTP + SOCKET =================
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server, {
  cors: { 
    origin: [process.env.CLIENT_URL, "null", "*"],
    credentials: true 
  },
  transports: ["websocket", "polling"]
});
let activeCalls = new Map();

async function keepAIAlive() {
  try {
    await axios.get(process.env.AI_URL + "/health", { timeout: 30000 });
    console.log("✅ AI server pinged");
  } catch (err) {
    console.warn("⚠️ AI ping failed:", err.message);
  }
}
setInterval(keepAIAlive, 13 * 60 * 1000);
keepAIAlive();

async function callAIWithRetry(payload, retries = 1) {
  for (let i = 0; i <= retries; i++) {
    try {
      return await axios.post(process.env.AI_URL + "/ai", payload, { timeout: 30000 });
    } catch (err) {
      const isLast = i === retries;
      if (err?.response?.status && err.response.status < 500) throw err;
      if (isLast) throw err;
      await new Promise(r => setTimeout(r, 3000));
      console.warn(`⚠️ AI retry ${i + 1}/${retries}`);
    }
  }
}

io.on("connection", (socket) => {
  console.log("🔌 User connected:", socket.id);

  socket.on("join", (userId) => {
    socket.userId = String(userId);
    socket.join(socket.userId);
  });

  function getRoom(a, b) { return [a, b].sort().join("-"); }

  socket.on("call-user", (data) => {
    if (!socket.userId) { socket.emit("call-rejected", { message: "Not authenticated" }); return; }
    if (!data.offer) { socket.emit("call-rejected", { message: "Missing offer" }); return; }
    const room = getRoom(socket.userId, String(data.to));

    // NEW: if this is a RENEGOTIATION (ICE restart / m-line keepalive) on an
    // already-active call, don't treat it as a brand new call attempt — just
    // forward the offer and leave the existing activeCalls timer alone.
    const existing = activeCalls.get(room);
    if (existing && existing.answered) {
      io.to(String(data.to)).emit("incoming-call", { from: socket.userId, offer: data.offer });
      return;
    }
    if (existing) { socket.emit("call-rejected", { message: "Call already active" }); return; }

    // NEW: store the timer handle (not just `true`) so it can be cancelled later
    const missedTimer = setTimeout(() => {
      const current = activeCalls.get(room);
      if (current && !current.answered) {
        activeCalls.delete(room);
        const callerId = String(socket.userId);
        const calleeId = callerId === room.split("-")[0] ? room.split("-")[1] : room.split("-")[0];
        io.to(calleeId).emit("call-missed", { caller_id: callerId, callee_id: calleeId });
        io.to(callerId).emit("call-missed", { caller_id: callerId, callee_id: calleeId });
      }
    }, 30 * 1000);

    activeCalls.set(room, { answered: false, timer: missedTimer });
    io.to(String(data.to)).emit("incoming-call", { from: socket.userId, offer: data.offer });
  });

  socket.on("end-call", (data) => {
    if (!socket.userId) return;
    const room = getRoom(socket.userId, String(data.to));
    const current = activeCalls.get(room);
    if (current?.timer) clearTimeout(current.timer); // NEW: cancel pending missed-call timer
    activeCalls.delete(room);
    io.to(String(data.to)).emit("call-ended");
  });

  socket.on("answer-call", (data) => {
    if (!socket.userId) return;
    console.log(`📞 answer-call: from=${socket.userId} to="${data.to}"`);

    // NEW: this is the critical fix — mark the call as answered and CANCEL
    // the 30-second missed-call timer. Without this, every call gets force-
    // ended and marked "missed" exactly 30s after it started, even if it's
    // actively connected and working fine.
    const room = getRoom(socket.userId, String(data.to));
    const current = activeCalls.get(room);
    if (current?.timer) {
      clearTimeout(current.timer);
      activeCalls.set(room, { answered: true, timer: null });
      console.log(`✅ Call answered — cleared missed-call timeout for room ${room}`);
    }

    io.to(String(data.to)).emit("call-answered", { answer: data.answer });
  });

  socket.on("ice-candidate", (data) => {
    if (!socket.userId) return;
    io.to(String(data.to)).emit("ice-candidate", { candidate: data.candidate });
  });

  socket.on("decline-call", (data) => {
    if (!socket.userId) return;
    // NEW: clean up the timer on decline too
    const room = getRoom(socket.userId, String(data.to));
    const current = activeCalls.get(room);
    if (current?.timer) clearTimeout(current.timer);
    activeCalls.delete(room);
    io.to(String(data.to)).emit("call-declined");
  });
  socket.on("save-missed-call", (data) => {
    if (!socket.userId) return;
    const callerId = Number(data.caller_id);
    const calleeId = Number(data.callee_id);
    if (!Number.isInteger(callerId) || !Number.isInteger(calleeId)) return;
    db.query(
      "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)",
      [callerId, calleeId, "📵 Missed call"],
      (err) => {
        if (err) { console.error("❌ MISSED CALL DB ERROR:", err); return; }
        io.to(String(callerId)).emit("missed-call-saved", { caller_id: callerId, callee_id: calleeId });
        io.to(String(calleeId)).emit("missed-call-saved", { caller_id: callerId, callee_id: calleeId });
      }
    );
});

// NEW — single handler for all call outcomes (completed / missed / declined)
socket.on("save-call-log", (data) => {
    if (!socket.userId) return;
    const callerId = Number(data.caller_id);
    const calleeId = Number(data.callee_id);
    const status = data.status; // "completed" | "missed" | "declined"
    const duration = Number(data.duration) || 0;
    if (!Number.isInteger(callerId) || !Number.isInteger(calleeId)) return;

    let content;
    if (status === "missed") content = "📵 Missed call";
    else if (status === "declined") content = "📵 Call declined";
    else {
      const mins = Math.floor(duration / 60);
      const secs = duration % 60;
      content = `📞 Call · ${mins}:${secs.toString().padStart(2, "0")}`;
    }

    db.query(
      "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)",
      [callerId, calleeId, content],
      (err) => {
        if (err) { console.error("❌ CALL LOG DB ERROR:", err); return; }
        io.to(String(callerId)).emit("call-log-saved", { caller_id: callerId, callee_id: calleeId, status });
        io.to(String(calleeId)).emit("call-log-saved", { caller_id: callerId, callee_id: calleeId, status });
      }
    );
});
  socket.on("disconnect", () => {
    console.log("❌ Disconnected:", socket.id);
    const roomsToDelete = [];
    for (const [room] of activeCalls) {
      if (room.split("-").includes(socket.userId)) roomsToDelete.push(room);
    }
    for (const room of roomsToDelete) {
      const current = activeCalls.get(room);
      if (current?.timer) clearTimeout(current.timer); // NEW: cancel any pending timer
      activeCalls.delete(room);
      const otherId = room.split("-").find(p => p !== socket.userId);
      if (otherId) io.to(otherId).emit("call-ended");
    }
  });
});
app.post('/delete-message', requireAuth, csrfProtection, (req, res) => {
  const userId = req.session.user.id;
  const messageId = Number(req.body.message_id);
  const mode = req.body.mode; // "me" | "everyone"

  if (!Number.isInteger(messageId)) return res.status(400).json({ message: "Invalid message_id" });
  if (!["me", "everyone"].includes(mode)) return res.status(400).json({ message: "Invalid mode" });

  db.query("SELECT * FROM messages WHERE id=?", [messageId], (err, result) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (result.length === 0) return res.status(404).json({ message: "Message not found" });
    const msg = result[0];

    if (msg.sender_id !== userId && msg.receiver_id !== userId) {
      return res.status(403).json({ message: "Not authorized" });
    }

    if (mode === "everyone") {
      // Only the original sender can delete for everyone
      if (msg.sender_id !== userId) {
        return res.status(403).json({ message: "Only the sender can delete for everyone" });
      }
      db.query("UPDATE messages SET deleted_for_everyone=1 WHERE id=?", [messageId], (err) => {
        if (err) return res.status(500).json({ message: "DB error" });
        io.to(String(msg.sender_id)).emit("message-deleted", { message_id: messageId, mode: "everyone" });
        io.to(String(msg.receiver_id)).emit("message-deleted", { message_id: messageId, mode: "everyone" });
        res.json({ message: "Deleted for everyone" });
      });
    } else {
      // "Delete for me" — only affects the requesting user's own view
      const column = msg.sender_id === userId ? "deleted_for_sender" : "deleted_for_receiver";
      db.query(`UPDATE messages SET ${column}=1 WHERE id=?`, [messageId], (err) => {
        if (err) return res.status(500).json({ message: "DB error" });
        io.to(String(userId)).emit("message-deleted", { message_id: messageId, mode: "me" });
        res.json({ message: "Deleted for you" });
      });
    }
  });
});
// ================= ERROR HANDLER =================
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ message: "File too large. Max 10 MB." });
    return res.status(400).json({ message: err.message });
  }
  if (err.message === "File type not allowed") {
    return res.status(400).json({ message: "File type not allowed." });
  }
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ message: "Invalid CSRF token" });
  }
  next(err);
});

// ================= START =================
server.listen(port, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${port}`);
});
