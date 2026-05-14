require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require("path");
const app = express();
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "X-CSRF-Token"]
}));
app.set('trust proxy', 1);
app.use("/app", express.static(path.join(__dirname, "protected")));
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

const session = require('express-session');
const axios = require('axios');
const http = require("http");
const csrf = require('csurf');

const helmet = require("helmet");
app.disable('x-powered-by');
const rateLimit = require("express-rate-limit");

const { requireAuth } = require("./middleware/auth");
const { validateRegister } = require("./middleware/validate");
const userRateMap = {};
const perUserRateLimit = require("./middleware/rateLimitPerUser");


const aiUserQuota = new Map();
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  
  handler: (req, res) => {
    res.status(429).json({
      message: "Too many login attempts. Try again in 1 minute."
    });
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
  process.env.AI_URL
      ],
    }
  }
}));
const port = process.env.PORT || 3000;



//////////////////////////////////////////////////////

// ================= CORS =================


// ================= JSON =================
app.use(express.json({ limit: '1mb'  }));
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30
});
// ✅ ADD HERE
const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10  ,            // max 10 AI requests per minute
  handler: (req, res) => {
    return res.status(429).json({
      message: "Max AI requests reached. Try again in 1 minute."
    });
  }
});
const aiQuota = {};

// ================= SESSION =================
const MySQLStore = require('express-mysql-session')(session);

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  createDatabaseTable: true,
  onError: function (error) {
    console.error("🔥 SESSION STORE ERROR:", error);
  },
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
    httpOnly: true, // 🔐 prevents JS access (VERY IMPORTANT)("need to be true")
    sameSite: 'none', // 🔐 stronger CSRF protection
    secure:process.env.NODE_ENV === "production",
     
    path: "/",   // 🔥 ADD THIS  // true in production (HTTPS)
    maxAge: 1000 * 60 * 60 * 24
  }
}));
// ✅ PUT THIS HERE (IMPORTANT)
// ✅ ADD THIS RIGHT AFTER SESSION
const csrfProtection = csrf({
  cookie: false
});

// ✅ PUT THIS HERE (IMPORTANT)
// ✅ ADD THIS RIGHT AFTER SESSION
app.get('/csrf-token', (req, res, next) => {
  try {
    res.json({ csrfToken: req.csrfToken() });
  } catch (err) {
    next(err);
  }
});



// 2. PROTECTED PAGES
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





///////////////////////////////////////////////////////
// 4. 🔐 PROTECTION MIDDLEWARE (PUT HERE)

// 5. static files AFTER protection


// ================= MYSQL =================
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});
db.connect(err => {
  if (err) {
    console.error('❌ MySQL connection error:', err);
  } else {
    console.log('✅ Connected to MySQL');
  }
});

// ================= REGISTER =================
app.post('/register', authLimiter, validateRegister, csrfProtection,(req, res) => {

    // ✅ ADD THIS BLOCK HERE
  if (!req.body.agreed) {
    return res.status(400).json({
      message: "You must accept the Terms of Use"
    });
  }

  const clean = (v) => typeof v === "string" ? v.trim() : "";

  const username = clean(req.body.username);
  const password = clean(req.body.password);
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const usernameRegex = /^(?=.*\d)[a-zA-Z0-9_]{6,20}$/;

  if (!usernameRegex.test(username)) {
    return res.status(400).json({ message: 'Invalid username' });
  }

  if (!/^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(password)) {
    return res.status(400).json({ message: 'Password length invalid' });
  }

  if (!username || !password) {
    return res.status(400).json({ message: 'All fields required' });
  }

  // STEP 1: check username
  db.query('SELECT * FROM users WHERE username=?', [username], (err, result) => {
    if (err) return res.status(500).json({ message: 'Server error' });

    if (result.length > 0) {
      return res.status(409).json({ message: 'Username exists' });
    }

    // STEP 2: check IP
    db.query('SELECT * FROM users WHERE signup_ip=?', [ip], (err, ipResult) => {
      if (err) return res.status(500).json({ message: 'Server error' });

      if (ipResult.length > 0) {
        return res.status(429).json({
          message: "This IP already created an account"
        });
      }

      // STEP 3: create user
      bcrypt.hash(password, 12, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        db.query(
          'INSERT INTO users (username, password, signup_ip) VALUES (?,?,?)',
          [username, hash, ip],
          (err) => {
            if (err) return res.status(500).json({ message: 'Server error' });

            return res.json({ message: 'User created' });
          }
        );
      });
    });
  });
});
// ================= LOGIN =================
app.post('/login', loginLimiter,csrfProtection, (req, res) => {
  const clean = (v) => typeof v === "string" ? v.trim() : "";

  const username = clean(req.body.username);
  const password = clean(req.body.password);
  if (
  !username ||
  !password ||
  username.length > 30 ||
  password.length > 100
) {
  return res.status(400).json({
    message: 'Invalid input'
  });
}

  db.query('SELECT * FROM users WHERE username=?', [username], (err, result) => {
  if (err) return res.status(500).json({ message: 'Server error' });

  // 🔒 DO NOT reveal if user exists
  if (result.length === 0)
    return res.status(401).json({ message: 'Invalid credentials' });

  const user = result[0];

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (!isMatch)
      return res.status(401).json({ message: 'Invalid credentials' });

      req.session.user = { id: user.id, username: user.username };
      console.log("LOGIN SESSION:", req.session); // ✅ ADD HERE

req.session.save((err) => {
  if (err) {
    return res.status(500).json({ message: "Session error" });
  }

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

// ================= GET USER BY USERNAME =================
app.get('/user/:username', requireAuth, (req, res) => {
  const { username } = req.params;

 


  db.query(
    'SELECT id, username FROM users WHERE username=?',
    [username],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      if (result.length === 0)
        return res.status(404).json({ message: 'User not found' });

      res.json(result[0]);
    }
  );
});

// ================= 🔥 NEW: SEARCH USERS =================
app.get('/search-users', authLimiter, requireAuth,(req, res)  => {
  const q = req.query.q || "";
  if (!/^[a-zA-Z0-9_ ]*$/.test(q)) {
    return res.status(400).json({ message: "Invalid search query" });
  }

  if (q.length > 50) {
  return res.status(400).json({ message: "Query too long" });
}
  const userId = req.session.user?.id;

  db.query(
    `SELECT id, username 
     FROM users 
     WHERE username LIKE ? 
     AND id != ?
     LIMIT 10`,
    [`%${q}%`, userId],
    (err, result) => {
      if (err) {
        console.error("❌ SEARCH ERROR:", err);
        return res.status(500).json({ message: "Server error" });
      }

      res.json(result);
    }
  );
});

// ================= SEND MESSAGE =================
app.post('/send', requireAuth, perUserRateLimit, csrfProtection,(req, res) => {
 
  const sender_id = req.session.user.id;
  let { receiver_id, content } = req.body;

  // 🔥 ADD THIS HERE
  const receiverId = Number(receiver_id);

if (!Number.isInteger(receiverId)) {
  return res.status(400).json({ message: "Invalid receiver_id" });
}
if (receiver_id === sender_id) {
  return res.status(400).json({ message: "Cannot message yourself" });
}
  const now = Date.now();

if (!aiQuota[sender_id]) {
  aiQuota[sender_id] = [];
}

aiQuota[sender_id] = aiQuota[sender_id].filter(t => now - t < 60000);

if (aiQuota[sender_id].length >= 10) {
  return res.status(429).json({ message: "AI limit reached" });
}

aiQuota[sender_id].push(now);
 const sanitize = require('sanitize-html');





content = sanitize(content, {
  allowedTags: [],
  allowedAttributes: {},
  disallowedTagsMode: 'discard'
});
  if (content.length > 1000) {
  return res.status(400).json({
    message: 'Message too long'
  });
}

  receiver_id = Number(receiver_id);

if (!Number.isInteger(receiver_id)) {
  return res.status(400).json({ message: "Invalid receiver_id" });
}

if (!content) {
  return res.status(400).json({ message: "Missing content" });
}

// ❌ prevent self messaging
if (receiver_id === sender_id) {
  return res.status(400).json({ message: "Cannot message yourself" });
}

 db.query(
  "SELECT id FROM users WHERE id=?",
  [receiver_id],
  (err, result) => {

    if (err) {
      return res.status(500).json({ message: "Server error" });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Receiver does not exist" });
    }

    // ✅ INSERT ONLY AFTER SUCCESS
    db.query(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)',
      [sender_id, receiver_id, content],
      (err) => {

        if (err) {
          console.error("❌ SEND ERROR:", err);
          return res.status(500).json({ message: 'Error sending message' });
        }

        res.json({ message: 'Sent' });
      }
    );

  }
);});

// ================= GET MESSAGES =================
app.get('/messages', requireAuth, (req, res) => {
 

  const userId = req.session.user.id;
  const receiver_id = parseInt(req.query.receiver_id);
  if (!Number.isInteger(receiver_id)) {
  return res.status(400).json({ message: "Invalid receiver_id" });
}


  if (!receiver_id)
    return res.status(400).json({ message: 'Invalid receiver_id' });

  db.query(
    `SELECT * FROM messages
     WHERE (sender_id=? AND receiver_id=?)
     OR (sender_id=? AND receiver_id=?)
     ORDER BY id ASC`,
    [userId, receiver_id, receiver_id, userId],
    (err, result) => {
      if (err) {
        console.error("🔥 DB ERROR:", err);
        return res.status(500).json({ message: 'Error fetching messages' });
      }
      res.json(result);
    }
  );
});

// ================= AI SEND =================
app.post('/ai-send', aiLimiter, requireAuth, perUserRateLimit,csrfProtection, async (req, res) => {

  const sender_id = req.session.user.id;
  const userId = req.session.user.id;
  const now = Date.now();

  if (!aiUserQuota.has(userId)) {
    aiUserQuota.set(userId, []);
  }

  const timestamps = aiUserQuota.get(userId).filter(t => now - t < 60000);

  if (timestamps.length >= 10) {
    return res.status(429).json({
      message: "Too many AI requests. Wait 1 minute."
    });
  }

  timestamps.push(now);
  aiUserQuota.set(userId, timestamps);

  const {
    receiver_id,
    content,
    context
  } = req.body;
  const instructions = req.session.aiMode || "";

  const parsedReceiver = Number(receiver_id);

  if (!Number.isInteger(parsedReceiver)) {
    return res.status(400).json({ message: "Invalid receiver_id" });
  }

  if (!receiver_id || !content)
    return res.status(400).json({ message: 'Missing data' });

  if (content.length > 2000)
    return res.status(400).json({ message: "Message too long" });

  if (content.includes("<script")) {
    return res.status(400).json({ message: "Blocked content" });
  }

  if (context && JSON.stringify(context).length > 5000) {
    return res.status(400).json({
      message: "Context too large"
  });}

  try {
    const finalInstructions = req.session.aiMode || "";
    const aiResponse =await axios.post(process.env.AI_URL + "/ai", {
  text: content,
  instructions: finalInstructions,
  context: context || []
}, {
  timeout: 3000
});

    let aiReply = aiResponse.data.reply;

// ❌ ensure it's valid
if (typeof aiReply !== "string") {
  return res.status(500).json({ message: "Invalid AI response" });
}

// 🔒 hard limit (prevents abuse / huge payloads)
aiReply = aiReply.slice(0, 2000);

// 🧼 sanitize (prevent XSS)
const sanitize = require('sanitize-html');

aiReply = sanitize(aiReply, {
  allowedTags: [],
  allowedAttributes: {}
});
//////////////////////////////////////////////////////
// 🔥 ADD RATE LIMIT HERE (BEFORE INSERT)
const lastMessage = await new Promise((resolve, reject) => {
  db.query(
    "SELECT created_at FROM messages WHERE sender_id=? ORDER BY id DESC LIMIT 1",
    [sender_id],
    (err, result) => {
      if (err) return reject(err);
      resolve(result[0]);
    }
  );
});

if (lastMessage) {
  const diff = Date.now() - new Date(lastMessage.created_at).getTime();

  if (diff < 2000) {
    return res.status(429).json({
      message: "Sending too fast"
    });
  }
}

//////////////////////////////////////////////////////
    db.query(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)',
      [sender_id, receiver_id, aiReply],
      (err) => {
        if (err) {
          console.error("❌ AI DB ERROR:", err);
          return res.status(500).json({ message: 'Error saving AI message' });
        }

        res.json({ reply: aiReply });
      }
    );

  } catch (err) {
    console.error("🔥 AI ERROR:", err.message);
    res.status(500).json({ message: 'AI service error' });
  }
});
/////////////////////////////////////////////////////////
app.get('/conversations', requireAuth, (req, res) => {
 

  const userId = req.session.user.id;

  db.query(
    `
    SELECT m.*, u.username AS other_username
    FROM messages m
    INNER JOIN (
      SELECT
        CASE
          WHEN sender_id = ? THEN receiver_id
          ELSE sender_id
        END AS other_user,
        MAX(id) AS last_id
      FROM messages
      WHERE sender_id = ? OR receiver_id = ?
      GROUP BY other_user
    ) latest
    ON m.id = latest.last_id
    JOIN users u
    ON u.id = latest.other_user
    ORDER BY m.id DESC
    `,
    [userId, userId, userId],
    (err, result) => {
      if (err) {
        console.error("❌ CONVERSATION ERROR:", err);
        return res.status(500).json({ message: "DB error" });
      }

      res.json(result);
    }
  );
});
/////////////////////////////////////
// ================= GET USER BY ID =================
app.get('/user-by-id/:id', requireAuth, (req, res) => {
  const { id } = req.params;
 

  db.query(
    'SELECT id, username FROM users WHERE id=?',
    [id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      if (result.length === 0)
        return res.status(404).json({ message: 'User not found' });

      res.json(result[0]);
    }
  );
});
//////////////////////log out//////////////////////
app.post('/logout',  (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: 'Logout failed' });

    res.clearCookie("chatapp.sid");
    res.json({ message: 'Logged out' });
  });
});
// ================= AI MODE SAVE =================
app.post('/set-ai-mode', requireAuth, (req, res) => {
  let instructions = req.body.instructions || "";

  // limit size
  if (instructions.length > 300) {
    return res.status(400).json({ message: "Mode too long" });
  }

  // sanitize
    instructions = instructions.replace(/\0/g, "");

  req.session.aiMode = instructions;

  res.json({ ok: true });
});

// ================= AI MODE GET =================
app.get('/get-ai-mode', requireAuth, (req, res) => {

  res.json({
    instructions: req.session.aiMode || ""
  });
});
//////////////////////////////////////
app.post('/toggle-auto-ai', requireAuth, csrfProtection, (req, res) => {

  const user_id = req.session.user.id;
  const { receiver_id } = req.body;

  if (!Number.isInteger(Number(receiver_id))) {
    return res.status(400).json({ message: "Invalid receiver" });
  }

  db.query(
    `SELECT enabled FROM auto_ai_settings 
     WHERE user_id=? AND receiver_id=?`,
    [user_id, receiver_id],
    (err, result) => {

      if (err) {
        return res.status(500).json({ message: "DB error" });
      }

      let newState = 1;

      if (result.length > 0) {
        newState = result[0].enabled ? 0 : 1;
      }

      db.query(
        `INSERT INTO auto_ai_settings (user_id, receiver_id, enabled)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE enabled=?`,
        [user_id, receiver_id, newState, newState],
        (err) => {

          if (err) {
            return res.status(500).json({ message: "DB error" });
          }

          res.json({ enabled: !!newState });
        }
      );
    }
  );
});
///////////////////////////////////////////////////
app.post('/ai-request', aiLimiter, requireAuth,  csrfProtection,async (req, res) => {

  const userId = req.session.user.id;
  let { text, receiver_id } = req.body;

  // 🔐 validate input
  if (typeof text !== "string") {
    return res.status(400).json({ message: "Invalid input" });
  }

  text = text.trim().slice(0, 2000);

  // 🔐 enforce AI mode from SERVER ONLY
  const instructions = req.session.aiMode || "";

  try {

    const aiResponse = await axios.post(`${process.env.AI_URL}/ai`, {
      text,
      instructions,
      mode: "auto_ai" // fixed, not client-controlled
    }, {
      timeout: 3000
    });

    const reply = aiResponse.data.reply || "";

    res.json({ reply });

  } catch (err) {
    return res.status(500).json({ message: "AI error" });
  }
});
//////////////////////////////////////////////////
app.get('/get-auto-ai',  requireAuth,(req, res) => {
  if (!req.session.user)
    return res.json({ enabled: false });

  const user_id = req.session.user.id;
  const receiver_id = req.query.receiver_id;

  db.query(
    `SELECT enabled FROM auto_ai_settings
     WHERE user_id=? AND receiver_id=?`,
    [user_id, receiver_id],
    (err, result) => {
      if (err || result.length === 0) {
        return res.json({ enabled: false });
      }

      res.json({ enabled: !!result[0].enabled });
    }
  );
});


// ================= HTTP + SOCKET =================
const server = http.createServer(app);
const { Server } = require("socket.io");

const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL,
    credentials: true
  }
});
io.on("connection", (socket) => {
  console.log("🔌 User connected:", socket.id);

  socket.on("join", (userId) => {
    socket.join(userId);
  });

  socket.on("disconnect", () => {
    console.log("❌ Disconnected:", socket.id);
  });
});

app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ message: "Invalid CSRF token" });
  }
  next(err);
});
// ================= START =================
server.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
}); 
