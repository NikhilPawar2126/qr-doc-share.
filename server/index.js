const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve client files
app.use(express.static(path.join(__dirname, "../client")));

// Default route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../client/index.html"));
});

const PORT = process.env.PORT || 5501;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

