require('dotenv').config();

const express = require('express');
const db = require('./db');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require('cors');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Use Render port
const port = process.env.PORT || 3000;

// Test route
app.get('/', (req, res) => {
  res.send('Payroll backend is running');
});

// ================= TOKEN MIDDLEWARE =================
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.json({ message: "Access denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.json({ message: "Invalid token" });
  }
}

// ================= EMPLOYEE ROUTES =================
app.get("/employees", verifyToken, (req, res) => {
  const userId = req.userId;

  db.query("SELECT * FROM employees WHERE user_id=?", [userId], (err, result) => {
    if (err) return res.json([]);
    res.json(result);
  });
});

app.post("/add-employee", verifyToken, (req, res) => {
  const { name, email, department, salary } = req.body;
  const userId = req.userId;

  const sql = "INSERT INTO employees (name,email,department,salary,user_id) VALUES (?,?,?,?,?)";

  db.query(sql, [name, email, department, salary, userId], (err, result) => {
    if (err) {
      console.log(err);
      return res.json({ message: "Error adding employee" });
    }
    res.json({ message: "Employee added" });
  });
});

app.post("/update-employee/:id", (req, res) => {
  const id = req.params.id;
  const { name, email, department, salary } = req.body;

  const sql = "UPDATE employees SET name=?, email=?, department=?, salary=? WHERE id=?";

  db.query(sql, [name, email, department, salary, id], (err, result) => {
    if (err) {
      console.log(err);
      return res.json({ message: "Error updating employee" });
    }
    res.json({ message: "Employee updated successfully" });
  });
});

app.delete("/delete-employee/:id", (req, res) => {
  const id = req.params.id;

  const sql = "DELETE FROM employees WHERE id=?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
      return res.json({ message: "Error deleting employee" });
    }
    res.json({ message: "Employee deleted" });
  });
});

// ================= AUTH ROUTES =================
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ message: "All fields are required" });
  }

  if (password.length < 8) {
    return res.json({ message: "Password must be at least 8 characters" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (name,email,password) VALUES (?,?,?)",
    [name, email, hashedPassword],
    (err, result) => {
      if (err) {
        return res.json({ message: "Email already exists" });
      }
      res.json({ message: "User registered successfully" });
    }
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
    if (err) {
      console.log(err);
      return res.json({ message: "Server error" });
    }

    if (result.length === 0) {
      return res.json({ message: "User not found" });
    }

    const user = result[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.json({ message: "Wrong password" });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);

    res.json({ token });
  });
});

// ================= START SERVER =================
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
