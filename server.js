const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());


const pool = mysql.createPool({
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

const authenticateJWT = (req, res, next) => {
    const token = req.headers["Authorization"]?.split(" ")[1] || req.headers["authorization"]?.split(" ")[1];
    if(!token) {
        return res.status(403).json({ message: "Access Denied" });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if(err) {
            return res.status(403).json({ message: "Invalid Token" });
        }
        req.user = user;
        next();
    });
};
module.exports= authenticateJWT;

app.post("/signup", async (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    pool.query(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        [username, hashedPassword],
        (err, result) => {
            if(err){
                return res.status(500).json({message: "Error signing up user"});
            }
            res.status(201).json({ message: "USer created successfully"});
        }
    );
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    pool.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, results) => {
            if(err || results.length == 0){
                return res.status(400).json({ message: "invalid username or password" });
            }

            const user = results[0];
            const match = await bcrypt.compare(password, user.password_hash);

            if(!match) {
                return res.status(400).json({ message: "Invalid username or password" });
            }
            const jwt_secret = process.env.JWT_SECRET || "default-secret-key";

            const token = jwt.sign({ id: user.id, username: user.username }, jwt_secret, { expiresIn: "1h"});
            res.json({ token });
        }
    );
});

app.post("/save-cards", authenticateJWT, (req, res) => {
    const user_id = req.user.id;
    const { Card1, Card2, suited, turn1, turn2, turn3, turn4 } = req.body;
    console.log(`Recived cards: ${Card1}, ${Card2}, ${suited}, ${user_id}`);

    const query = "INSERT INTO cards (user_id, card1, card2, suited, turn1, turn2, turn3, turn4, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    const date = new Date();
    pool.query(query, [user_id, Card1, Card2, suited, turn1, turn2, turn3, turn4, date], (err, result) => {
        if(err) {
            console.error("Error saving cards:", err);
            return res.status(500).json({ message: "Error saving cards" });
        }

        res.json({ message: "Cards saved successfully"});
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));