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
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = "gameshop_secret";

// --- สร้างโฟลเดอร์ uploads ถ้าไม่มี ---
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// --- static middleware สำหรับเข้าถึงไฟล์รูป ---
app.use("/uploads", express.static("uploads"));

// --- Multer สำหรับอัปโหลดรูป ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, `${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

// --- เชื่อมต่อ MySQL ---
const db = mysql.createConnection({
  host: "localhost",
  user: "admin_gameshop",
  password: "admin_gameshop",
  database: "gameshop"
});

db.connect(err => {
  if (err) return console.error("❌ Database connection failed:", err);
  console.log("✅ Connected to MySQL: gameshop");
  
  // ตรวจสอบและสร้าง Admin อัตโนมัติ
  ensureAdminExists();
});

// --- สร้าง Admin อัตโนมัติ ---
function ensureAdminExists() {
  const adminEmail = "admin@gameshop.com";
  const adminUsername = "admin";
  const adminPassword = "123";

  db.query("SELECT * FROM users WHERE email = ?", [adminEmail], (err, results) => {
    if (err) return console.error("Error checking for admin user:", err);

    if (results.length === 0) {
      console.log("Admin user not found, creating one...");
      const hashedPassword = bcrypt.hashSync(adminPassword, 10);

      const newAdmin = {
        username: adminUsername,
        email: adminEmail,
        password: hashedPassword,
        profile_image: null,
        wallet_balance: 999999.99,
        role: "admin"
      };

      db.query("INSERT INTO users SET ?", newAdmin, (err) => {
        if (err) console.error("Failed to create admin user:", err);
        else console.log(`✅ Admin user '${adminUsername}' created successfully.`);
      });
    } else {
      console.log("Admin user already exists.");
    }
  });
}

// --- Register ---
app.post("/api/register", upload.single("profile_image"), (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) 
    return res.status(400).json({ error: "Please fill all fields" });

  // ตรวจสอบ email ซ้ำ
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length > 0) return res.status(400).json({ error: "Email already exists" });

    // ถัดไป hash password และ insert
    let profileImagePath = null;
    if (req.file) {
      profileImagePath = `http://localhost:3000/uploads/${req.file.filename}`;
    }
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.query(
      "INSERT INTO users (username, email, password, role, profile_image) VALUES (?, ?, ?, 'user', ?)",
      [username, email, hashedPassword, profileImagePath],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Registration successful" });
      }
    );
  });
});

// --- Login ---
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: "User not found" });

    const user = results[0];
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
  });
});

// --- Middleware ตรวจสอบ JWT ---
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

// --- Route Profile (ต้อง login) ---
app.get("/api/profile", authenticateToken, (req, res) => {
  db.query(
    "SELECT id, username, email, profile_image, wallet_balance, role FROM users WHERE id = ?",
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(404).json({ error: "User not found" });
      res.json({ message: "Protected data", user: results[0] });
    }
  );
});


// --- อัปเดต profile ---
app.put('/api/profile', authenticateToken, upload.single('profile_image'), (req, res) => {
  const { username, email } = req.body;
  let profile_image = null;

  if (req.file) {
    profile_image = `http://localhost:3000/uploads/${req.file.filename}`;
  }

  db.query(
    'UPDATE users SET username = ?, email = ?, profile_image = COALESCE(?, profile_image) WHERE id = ?',
    [username, email, profile_image, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });

      db.query(
        'SELECT id, username, email, profile_image, wallet_balance, role FROM users WHERE id = ?',
        [req.user.id],
        (err2, results) => {
          if (err2) return res.status(500).json({ error: err2.message });
          res.json({ message: 'Profile updated', user: results[0] });
        }
      );
    }
  );
});


// --- เปิด server ---
const PORT = 3000;
app.listen(PORT, () => console.log(`✅ gameshop-api server running at http://localhost:${PORT}`));
