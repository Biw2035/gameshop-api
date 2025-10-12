require('dotenv').config(); // ต้องอยู่บนสุด
const cloudinary = require('cloudinary').v2;

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const multer = require("multer");
const { CloudinaryStorage } = require('multer-storage-cloudinary');


const app = express();

// --- CORS ---
app.use(cors({
  origin: 'http://localhost:4200',
  credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT || 3000;

// --- Cloudinary Config ---
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET
});

// --- Multer Storage สำหรับเกม ---
const gameStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'gameshop/games',
    allowed_formats: ['jpg','jpeg','png']
  }
});
const uploadGame = multer({ storage: gameStorage });

// --- Multer Storage สำหรับโปรไฟล์ ---
const profileStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'gameshop/profile',
    allowed_formats: ['jpg','jpeg','png']
  }
});
const uploadProfile = multer({ storage: profileStorage });

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

const query = (sql, params) => new Promise((resolve, reject) => {
  pool.query(sql, params, (err, results) => {
    if(err) reject(err);
    else resolve(results);
  });
});

// --- JWT Middleware ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if(err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- Ensure Admin Exists ---
async function ensureAdminExists() {
  const adminEmail = "admin@gameshop.com";
  const adminUsername = "admin";
  const adminPassword = "123";

  try {
    const results = await query("SELECT * FROM users WHERE email = ?", [adminEmail]);
    if (results.length === 0) {
      const hashedPassword = bcrypt.hashSync(adminPassword, 10);
      await query(
        "INSERT INTO users (username, email, password, profile_image, wallet_balance, role) VALUES (?, ?, ?, ?, ?, ?)",
        [adminUsername, adminEmail, hashedPassword, null, 999999.99, 'admin']
      );
      console.log(`✅ Admin created: ${adminUsername}`);
    }
  } catch (err) {
    console.error(err);
  }
}

// --- Register ---
app.post("/api/register", uploadProfile.single("profile_image"), async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Please fill all fields" });

  try {
    const existing = await query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0) return res.status(400).json({ error: "Email already exists" });

    const profileImagePath = req.file ? req.file.path : null; // Cloudinary URL
    const hashedPassword = bcrypt.hashSync(password, 10);

    await query(
      "INSERT INTO users (username, email, password, role, profile_image) VALUES (?, ?, ?, 'user', ?)",
      [username, email, hashedPassword, profileImagePath]
    );

    res.json({ message: "Registration successful" });
  } catch (err) {
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
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Incorrect password" });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ message: "Login successful", token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Profile GET ---
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const results = await query("SELECT id, username, email, profile_image, wallet_balance, role FROM users WHERE id = ?", [req.user.id]);
    if (results.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: results[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Profile UPDATE ---
app.put("/api/profile", authenticateToken, uploadProfile.single('profile_image'), async (req, res) => {
  const { username, email } = req.body;
  const profile_image = req.file ? req.file.path : null; // Cloudinary URL

  try {
    await query(
      'UPDATE users SET username = ?, email = ?, profile_image = COALESCE(?, profile_image) WHERE id = ?',
      [username, email, profile_image, req.user.id]
    );
    const updated = await query('SELECT id, username, email, profile_image, wallet_balance, role FROM users WHERE id = ?', [req.user.id]);
    res.json({ message: 'Profile updated', user: updated[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// เติมเงิน
app.put('/api/profile/topup', authenticateToken, async (req, res) => {
  const { topUp } = req.body;
  if (!topUp || topUp <= 0) return res.status(400).json({ error: 'จำนวนเงินไม่ถูกต้อง' });

  try {
    // ดึง user ปัจจุบัน
    const users = await query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const currentBalance = parseFloat(users[0].wallet_balance) || 0;
    const newBalance = currentBalance + parseFloat(topUp);

    // อัปเดต wallet_balance
    await query('UPDATE users SET wallet_balance = ? WHERE id = ?', [newBalance, req.user.id]);

    // ✅ บันทึก transaction
    await query(
      'INSERT INTO transactions(user_id, type, amount) VALUES (?, "topup", ?)',
      [req.user.id, topUp]
    );

    const updatedUser = await query(
      'SELECT id, username, email, role, wallet_balance, profile_image FROM users WHERE id = ?',
      [req.user.id]
    );

    res.json({ user: updatedUser[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// --- GET all games ---
app.get("/api/games", async (req, res) => {
  try {
    const games = await query("SELECT * FROM games ORDER BY id DESC");
    res.json(games);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Add Game ---
app.post("/api/games", authenticateToken, uploadGame.single('image'), async (req, res) => {
  const { title, description, price, category } = req.body;
  if (!title || !description || !price || !category) return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบ' });

  const imagePath = req.file ? req.file.path : null; // Cloudinary URL
  try {
    const result = await query(
      'INSERT INTO games (title, description, price, category, image) VALUES (?, ?, ?, ?, ?)',
      [title, description, price, category, imagePath]
    );
    res.json({ message: 'Game added successfully', gameId: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Delete Game ---
app.delete("/api/games/:id", authenticateToken, async (req, res) => {
  const gameId = req.params.id;

  try {
    // ตรวจสอบว่าเกมมีอยู่หรือไม่
    const games = await query("SELECT * FROM games WHERE id = ?", [gameId]);
    if (games.length === 0) return res.status(404).json({ error: "Game not found" });

    // ลบเกม
    await query("DELETE FROM games WHERE id = ?", [gameId]);
    res.json({ message: "Game deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ---edit game ---
app.put("/api/games/:id", authenticateToken, uploadGame.single('image'), async (req, res) => {
  const gameId = req.params.id;
  const { title, description, price, category } = req.body;
  const imagePath = req.file ? req.file.path : null; // Cloudinary URL

  try {
    const games = await query("SELECT * FROM games WHERE id = ?", [gameId]);
    if (games.length === 0) return res.status(404).json({ error: "Game not found" });

    await query(
      `UPDATE games 
       SET title = ?, description = ?, price = ?, category = ?, image = COALESCE(?, image) 
       WHERE id = ?`,
      [title, description, price, category, imagePath, gameId]
    );

    res.json({ message: "Game updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// --- GET game by ID  เรียกมาตอนหน้าedit---
app.get("/api/games/:id", async (req, res) => {
  const gameId = req.params.id;
  try {
    const games = await query("SELECT * FROM games WHERE id = ?", [gameId]);
    if (games.length === 0) return res.status(404).json({ error: "Game not found" });
    res.json(games[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ซื้อเกม
app.post('/api/checkout', authenticateToken, async (req, res) => {
  const cartItems = req.body.cartItems;
  const discountCode = req.body.discountCode || null; // รับโค้ดลดราคา
  const userId = req.user.id;

  try {
    // 1. ดึงข้อมูล user
    const users = await query('SELECT * FROM users WHERE id = ?', [userId]);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = users[0];
    let walletBalance = parseFloat(user.wallet_balance);

    // 2. คำนวณยอดรวม
    let totalPrice = cartItems.reduce((sum, g) => sum + parseFloat(g.price), 0);

    // 3. ตรวจสอบโค้ดลดราคา
    if (discountCode) {
      const codes = await query('SELECT * FROM codes WHERE code = ? AND type = "discount"', [discountCode]);
      if (codes.length === 0) return res.status(400).json({ error: 'โค้ดไม่ถูกต้อง' });

      const code = codes[0];
      totalPrice -= parseFloat(code.value);
      if (totalPrice < 0) totalPrice = 0;
    }

    // 4. ตรวจสอบยอดเงินเพียงพอ
    if (walletBalance < totalPrice) return res.status(400).json({ error: 'ยอดเงินไม่พอ' });

    // 5. หักเงิน
    walletBalance -= totalPrice;
    await query('UPDATE users SET wallet_balance = ? WHERE id = ?', [walletBalance, userId]);

    // 6. บันทึกเกมและ transactions
    for (const game of cartItems) {
      await query('INSERT IGNORE INTO user_games(user_id, game_id) VALUES (?, ?)', [userId, game.id]);
      await query('INSERT INTO transactions(user_id, type, amount, game_id) VALUES (?, "purchase", ?, ?)',
                  [userId, game.price, game.id]);
    }

    // 7. ดึงข้อมูล user ใหม่
    const updatedUserRows = await query(
      'SELECT id, username, email, role, wallet_balance, profile_image FROM users WHERE id = ?',
      [userId]
    );
    const updatedUser = updatedUserRows[0];

    res.json({ message: 'ซื้อเกมทั้งหมดสำเร็จ', walletBalance, updatedUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});



// ดึงประวัติ
app.get('/api/profile/transactions', authenticateToken, async (req, res) => {
  console.log('User in request:', req.user); 
  try {


    const transactions = await query(`
      SELECT 
        t.id,
        t.type,
        t.amount,
        t.game_id,
        t.created_at,
        g.title AS game_name
      FROM transactions t
      LEFT JOIN games g ON t.game_id = g.id
      WHERE t.user_id = ?
      ORDER BY t.created_at DESC
    `, [req.user.id]);

    res.json({ transactions: transactions || [] });
  } catch (err) {
    console.error('Failed to get transactions:', err);
    res.status(500).json({ error: err.message });
  }
});


// ดึงเกมทั้งหมดของผู้ใช้
app.get('/api/mygames', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const games = await query(`
      SELECT g.* 
      FROM games g
      INNER JOIN user_games ug ON g.id = ug.game_id
      WHERE ug.user_id = ?
      ORDER BY g.id DESC
    `, [userId]);

    res.json({ games });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  next();
}

// ดึง transaction ของ user
app.get('/api/admin/user/:userId/transactions', authenticateToken, isAdmin, async (req, res) => {
  const userId = req.params.userId;

  try {
    const transactions = await query(`
      SELECT t.id, t.type, t.amount, t.game_id, g.title AS game_name, t.created_at
      FROM transactions t
      LEFT JOIN games g ON t.game_id = g.id
      WHERE t.user_id = ?
      ORDER BY t.created_at DESC
    `, [userId]);

    res.json({ transactions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ดึงรายการผู้ใช้ทั้งหมด (สำหรับ dropdown เลือก)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await query('SELECT id, username, email, wallet_balance FROM users ORDER BY username ASC');
    res.json({ users });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


// ================== GET ALL CODES ==================
app.get('/api/admin/codes', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const codes = await query('SELECT * FROM codes ORDER BY id DESC');
    res.json({ codes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================== CREATE NEW CODE ==================
app.post('/api/admin/codes', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const { code, type, value } = req.body;

  try {
    await query('INSERT INTO codes (code, type, value) VALUES (?, ?, ?)', 
      [code, type, value]);
    res.json({ message: 'สร้างโค้ดสำเร็จ' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================== DELETE CODE ==================
app.delete('/api/admin/codes/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    await query('DELETE FROM codes WHERE id = ?', [req.params.id]);
    res.json({ message: 'ลบโค้ดเรียบร้อย' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




// --- Root ---
app.get('/', (req, res) => res.send('🎮 Gameshop API is running!'));

// --- Start server ---
app.listen(PORT, async () => {
  console.log(`✅ Server running at port ${PORT}`);
  await ensureAdminExists();
});
