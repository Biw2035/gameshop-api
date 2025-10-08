require('dotenv').config();

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

// --- CORS สำหรับ frontend dev ---
app.use(cors({
  origin: 'http://localhost:4200', // หรือ '*' สำหรับทุก origin
  credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = process.env.SECRET_KEY;
const BASE_URL = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

// --- สร้างโฟลเดอร์ uploads ถ้าไม่มี ---
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// --- static middleware สำหรับเข้าถึงไฟล์รูป ---
app.use("/uploads", express.static("uploads"));

// --- Multer สำหรับอัปโหลดรูป ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, `${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

// --- MySQL Connection Pool ---
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: 3306,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DBNAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: { rejectUnauthorized: false }
});

// --- Helper: query with promise ---
const query = (sql, params) => new Promise((resolve, reject) => {
  pool.query(sql, params, (err, results) => {
    if (err) reject(err);
    else resolve(results);
  });
});

// --- สร้าง Admin อัตโนมัติ ---
async function ensureAdminExists() {
  const adminEmail = "admin@gameshop.com";
  const adminUsername = "admin";
  const adminPassword = "123";

  try {
    const results = await query("SELECT * FROM users WHERE email = ?", [adminEmail]);
    if (results.length === 0) {
      console.log("Admin user not found, creating one...");
      const hashedPassword = bcrypt.hashSync(adminPassword, 10);

      await query(
        "INSERT INTO users (username, email, password, profile_image, wallet_balance, role) VALUES (?, ?, ?, ?, ?, ?)",
        [adminUsername, adminEmail, hashedPassword, null, 999999.99, 'admin']
      );

      console.log(`✅ Admin user '${adminUsername}' created successfully.`);
    } else {
      console.log("Admin user already exists.");
    }
  } catch (err) {
    console.error("Error ensuring admin exists:", err);
  }
}

// --- Register ---
app.post("/api/register", upload.single("profile_image"), async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) 
    return res.status(400).json({ error: "Please fill all fields" });

  try {
    const existing = await query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0) return res.status(400).json({ error: "Email already exists" });

    let profileImagePath = null;
    if (req.file) profileImagePath = `${BASE_URL}/uploads/${req.file.filename}`;

    const hashedPassword = bcrypt.hashSync(password, 10);

    await query(
      "INSERT INTO users (username, email, password, role, profile_image) VALUES (?, ?, ?, 'user', ?)",
      [username, email, hashedPassword, profileImagePath]
    );

    res.json({ message: "Registration successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// --- Login ---
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const users = await query("SELECT * FROM users WHERE email = ?", [email]);
    if (users.length === 0) return res.status(404).json({ error: "User not found" });

    const user = users[0];
    if (!bcrypt.compareSync(password, user.password)) 
      return res.status(401).json({ error: "Incorrect password" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    const userPayload = {
      id: user.id,
      username: user.username,
      email: user.email,
      profile_image: user.profile_image,
      wallet_balance: user.wallet_balance,
      role: user.role
    };

    res.json({ message: "Login successful", token, user: userPayload });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// --- JWT Middleware ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- Profile routes ---
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const results = await query(
      "SELECT id, username, email, profile_image, wallet_balance, role FROM users WHERE id = ?",
      [req.user.id]
    );
    if (results.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ message: "Protected data", user: results[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/profile', authenticateToken, upload.single('profile_image'), async (req, res) => {
  const { username, email } = req.body;
  let profile_image = null;
  if (req.file) profile_image = `${BASE_URL}/uploads/${req.file.filename}`;

  try {
    await query(
      'UPDATE users SET username = ?, email = ?, profile_image = COALESCE(?, profile_image) WHERE id = ?',
      [username, email, profile_image, req.user.id]
    );

    const results = await query(
      'SELECT id, username, email, profile_image, wallet_balance, role FROM users WHERE id = ?',
      [req.user.id]
    );

    res.json({ message: 'Profile updated', user: results[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.send('🎮 Gameshop API is running!2035');
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`✅ gameshop-api running at ${BASE_URL}`);
  await ensureAdminExists();
});
