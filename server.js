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

// ===== MULTER SETUP =====
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const BLOCKED_EXTENSIONS = [".exe", ".bat", ".cmd", ".sh", ".php", ".py", ".rb", ".pl", ".cgi", ".msi", ".dll", ".vbs", ".ps1"];
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 10 MB

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^a-z0-9.]/g, "");
    const safeName = `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`;
    cb(null, safeName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (BLOCKED_EXTENSIONS.includes(ext)) {
      return cb(new Error("File type not allowed"));
    }
    cb(null, true);
  }
});
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
        "wss://chatflow-ai-1.onrender.com",
        "https://backend-1-liqz.onrender.com",
        "wss://backend-1-liqz.onrender.com",
        "turn:openrelay.metered.ca",
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
  origin: process.env.CLIENT_URL,
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "X-CSRF-Token"]
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

// ================= REGISTER =================
app.post('/register', authLimiter, validateRegister, csrfProtection, (req, res) => {
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
app.post('/login', loginLimiter, (req, res) => {
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
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
      req.session.user = { id: user.id, username: user.username };
      req.session.save((err) => {
        if (err) return res.status(500).json({ message: "Session error" });
        res.json({ message: "Logged in" });
      });
    });
  });
});

// ================= CURRENT USER =================
app.get('/user-data', requireAuth, (req, res) => {
  res.json(req.session.user);
});

// ================= CSRF TOKEN =================
app.get('/csrf-token', (req, res) => {
  try {
    const token = req.csrfToken();
    res.json({ csrfToken: token });
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
app.get('/search-users', authLimiter, requireAuth, (req, res) => {
  const q = req.query.q || "";
  if (!/^[a-zA-Z0-9_ ]*$/.test(q)) return res.status(400).json({ message: "Invalid search query" });
  if (q.length > 50) return res.status(400).json({ message: "Query too long" });
  const userId = req.session.user?.id;
  db.query(
    `SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 10`,
    [`%${q}%`, userId],
    (err, result) => {
      if (err) { console.error("❌ SEARCH ERROR:", err); return res.status(500).json({ message: "Server error" }); }
      res.json(result);
    }
  );
});

// ================= SEND MESSAGE =================
app.post('/send', requireAuth, perUserRateLimit, csrfProtection, (req, res) => {
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
  if (!receiver_id) return res.status(400).json({ message: 'Invalid receiver_id' });

  db.query(
    `SELECT * FROM messages
     WHERE (sender_id=? AND receiver_id=?)
     OR (sender_id=? AND receiver_id=?)
     ORDER BY id ASC`,
    [userId, receiver_id, receiver_id, userId],
    (err, result) => {
      if (err) { console.error("🔥 DB ERROR:", err); return res.status(500).json({ message: 'Error fetching messages' }); }
      res.json(result);
    }
  );
});

// ================= FILE UPLOAD =================
app.post('/upload', requireAuth, csrfProtection, upload.single("file"), async (req, res) => {
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
  db.query("SELECT id FROM users WHERE id=?", [receiver_id], (err, result) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (result.length === 0) return res.status(404).json({ message: "Receiver does not exist" });

    const fileUrl = `/uploads/${req.file.filename}`;
    const originalName = req.file.originalname.replace(/[<>&"]/g, ""); // basic sanitize for display
    const ext = path.extname(req.file.originalname).toLowerCase();
    const imageExts = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"];
    const isImage = imageExts.includes(ext);

    // images get a different prefix so the front-end can render them inline
    const content = isImage
      ? `🖼️ [${originalName}](${fileUrl})`
      : `📎 [${originalName}](${fileUrl})`;

    db.query(
      "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)",
      [sender_id, receiver_id, content],
      (err) => {
        if (err) { console.error("❌ UPLOAD DB ERROR:", err); return res.status(500).json({ message: "DB error" }); }
        res.json({ ok: true, url: fileUrl, isImage });
      }
    );
  });
});

// ================= SERVE UPLOADS (auth-protected) =================
app.use("/uploads", requireAuth, express.static(path.join(__dirname, "uploads")));

// ================= AI SEND =================
app.post('/ai-send', aiLimiter, requireAuth, perUserRateLimit, csrfProtection, async (req, res) => {
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

// ================= LOGOUT =================
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: 'Logout failed' });
    res.clearCookie("chatapp.sid");
    res.json({ message: 'Logged out' });
  });
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
app.post('/toggle-auto-ai', requireAuth, csrfProtection, (req, res) => {
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
app.post('/ai-request', aiLimiter, requireAuth, csrfProtection, async (req, res) => {
  try {
    let { text, mode } = req.body;
    if (typeof text !== "string") return res.status(400).json({ message: "Invalid input" });
    text = text.trim().slice(0, 2000);
    const allowedModes = ["chat", "ai_writer", "summary", "greeting"];
    const safeMode = allowedModes.includes(mode) ? mode : "chat";

    try {
      await axios.get(process.env.AI_URL + "/health", { timeout: 30000 });
    } catch (pingErr) {
      console.warn("⚠️ AI wake-up ping failed:", pingErr.code);
      return res.status(503).json({ message: "AI is starting up, please try again in 15 seconds.", waking: true });
    }

    const response = await callAIWithRetry({
      text,
      instructions: safeMode === "ai_writer" ? "" : (req.session.aiMode || ""),
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

// ================= HTTP + SOCKET =================
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server, {
  cors: { origin: process.env.CLIENT_URL, credentials: true },
  transports: ["websocket", "polling"]
});
let activeCalls = new Map();

function keepAIAlive() {
  axios.get(process.env.AI_URL + "/health", { timeout: 10000 })
    .then(() => console.log("✅ AI server pinged"))
    .catch(err => console.warn("⚠️ AI ping failed:", err.message));
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
    if (activeCalls.has(room)) { socket.emit("call-rejected", { message: "Call already active" }); return; }
    activeCalls.set(room, true);
    setTimeout(() => { if (activeCalls.has(room)) { activeCalls.delete(room); } }, 2 * 60 * 1000);
    io.to(String(data.to)).emit("incoming-call", { from: socket.userId, offer: data.offer });
  });

  socket.on("end-call", (data) => {
    if (!socket.userId) return;
    activeCalls.delete(getRoom(socket.userId, String(data.to)));
    io.to(String(data.to)).emit("call-ended");
  });

  socket.on("answer-call", (data) => {
    if (!socket.userId) return;
    io.to(String(data.to)).emit("call-answered", { answer: data.answer });
  });

  socket.on("ice-candidate", (data) => {
    if (!socket.userId) return;
    io.to(String(data.to)).emit("ice-candidate", { candidate: data.candidate });
  });

  socket.on("decline-call", (data) => {
    if (!socket.userId) return;
    io.to(String(data.to)).emit("call-declined");
  });

  socket.on("disconnect", () => {
    console.log("❌ Disconnected:", socket.id);
    const roomsToDelete = [];
    for (const [room] of activeCalls) {
      if (room.split("-").includes(socket.userId)) roomsToDelete.push(room);
    }
    for (const room of roomsToDelete) {
      activeCalls.delete(room);
      const otherId = room.split("-").find(p => p !== socket.userId);
      if (otherId) io.to(otherId).emit("call-ended");
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
