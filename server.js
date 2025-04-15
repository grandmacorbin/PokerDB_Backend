const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const handRanks = require('./data/hand_percentiles.json');

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

pool.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err);
        return res.status(500).json({ message: 'Database connection error' });
    }
    connection.release();
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

app.use(`/public`, express.static('public'));

app.post("/signup", async (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    pool.query(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        [username, hashedPassword],
        (err) => {
            if(err){
                return res.status(500).json({message: "Error signing up user"});
            }
            res.status(201).json({ message: "User created successfully"});
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
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hour = String(date.getHours()).padStart(2, '0');
    const minute = String(date.getMinutes()).padStart(2, '0');
    const second = String(date.getSeconds()).padStart(2, '0');
    const FullDate = `${year}-${month}-${day} ${hour}:${minute}:${second}`;
    console.log(FullDate)
    pool.query(query, [user_id, Card1, Card2, suited, turn1, turn2, turn3, turn4, FullDate], (err) => {
        if(err) {
            console.error("Error saving cards:", err);
            return res.status(500).json({ message: "Error saving cards" });
        }
        const jwt_secret = process.env.JWT_SECRET || "default-secret-key";
        const newToken = jwt.sign({ id: req.user.id, username: req.user.username }, jwt_secret, { expiresIn: "3h" });

        res.json({ message: "Cards saved successfully", token: newToken});

    });
});

app.post("/data", authenticateJWT, (req, res) => {
    const user_id = req.user.id;
    pool.query(`
        SELECT 
            u.username, c.card1, c.card2, c.suited, 
            c.turn1, c.turn2, c.turn3, c.turn4 
        FROM 
            users u 
        JOIN 
            cards c 
        ON 
            u.id = c.user_id 
        WHERE 
            c.user_id = ?`, 
        [user_id], 
        (err, result) => {
            if(err) {
                console.error("Error selecting user", err);
                return res.status(500).json({ error: "Internal server error" });
            }
            let total = 0;
            let premiumHandCount = 0;
            let midHandCount = 0;
            let badhandCount = 0;
            let foldCount = 0;
            let raiseCount = 0;
            let callCount = 0;
            let playedCount = 0;
            const cardOrder = {
                "Ace": 14,
                "King": 13,
                "Queen": 12,
                "Jack": 11,
                "Ten": 10,
                "Nine": 9,
                "Eight": 8,
                "Seven": 7,
                "Six": 6,
                "Five": 5,
                "Four": 4,
                "Three": 3,
                "Two": 2
            };
            
            result.forEach(hands => {
                total += 1;

                let Card1 = hands.card1;
                let Card2 = hands.card2;

                if(cardOrder[hands.card1] < cardOrder[hands.card2]){
                    Card1 = hands.card2;
                    Card2 = hands.card1;
                }

                let key = `${Card1},${Card2}`

                let handrank = hands.suited ? handRanks[key].suited : handRanks[key].offsuit;
                if(handrank >= 90){
                    premiumHandCount += 1;
                }
                
                else if(handrank <= 89 && handrank >= 75){
                    midHandCount += 1;
                }
                else{
                    badhandCount += 1;
                }
                if(hands.turn1 == "fold" || hands.turn2 == "fold" || hands.turn3 == "fold" || hands.turn4 == "fold"){
                    foldCount += 1;
                }
                if(hands.turn1 == "raise" || hands.turn2 == "riase" || hands.turn3 == "raise" || hands.turn4 == "raise"){
                    raiseCount += 1;
                }
                if(hands.turn1 == "call" || hands.turn2 == "call" || hands.turn3 == "call" || hands.turn4 == "call"){
                    callCount += 1;
                }
                if(hands.turn1 != "fold" && hands.turn2 != "fold" && hands.turn3 != "fold" && hands.turn4 != "fold"){
                    playedCount += 1;
                }
            })
            const preFlopFoldPerc = Math.round(foldCount / total * 1000)/10;
            const preFlopRaisePerc = Math.round(raiseCount / total * 1000)/10;
            const preFlopCallPerc = Math.round(callCount / total * 1000)/10;
            const preFlopPlayedPerc = Math.round(playedCount / total * 1000)/10;
            const premiumHandPerc = Math.round(premiumHandCount / total * 1000)/10;
            const midHandPerc = Math.round(midHandCount / total * 1000)/10;
            const badHandPerc = Math.round(badhandCount / total * 1000)/10;
            console.log(badHandPerc);
            console.log(midHandPerc);
            console.log(premiumHandPerc);

            res.status(200).json({
                data: result,
                preFlopFold: preFlopFoldPerc,
                preFlopPlayed: preFlopPlayedPerc,
                preFlopRaise: preFlopRaisePerc,
                preFlopCall: preFlopCallPerc,
                premiumHands: premiumHandPerc,
                midHands: midHandPerc,
                badHands: badHandPerc 
            });
        });

})



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));