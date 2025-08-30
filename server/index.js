const express = require("express");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, "../client")));

// Get all users
app.get("/api/users", (req, res) => {
  try {
    const users = JSON.parse(fs.readFileSync(path.join(__dirname, "users.json")));
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error reading users" });
  }
});

// Get all sessions
app.get("/api/sessions", (req, res) => {
  try {
    const sessions = JSON.parse(fs.readFileSync(path.join(__dirname, "sessions.json")));
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ message: "Error reading sessions" });
  }
});

// Default route (homepage)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../client/index.html"));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
