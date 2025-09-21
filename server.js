const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const BOT_TOKEN = process.env.BOT_TOKEN;
const WHITELIST_RAW = process.env.WHITELIST || "";
const WHITELIST = WHITELIST_RAW.split(",").map(id => id.trim());

function checkTelegramAuth(data) {
    const { hash, ...rest } = data;
    const secret = crypto.createHash("sha256").update(BOT_TOKEN).digest();
    const checkString = Object.keys(rest)
        .filter(k => k !== 'hash')
        .sort()
        .map((k) => `${k}=${rest[k]}`)
        .join("\n");
    const hmac = crypto.createHmac("sha256", secret).update(checkString).digest("hex");
    return hmac === hash;
}

app.post("/auth", (req, res) => {
    const data = req.body;
    if (!data.hash) {
        return res.status(400).json({ allowed: false, error: "no hash" });
    }

    if (!checkTelegramAuth(data)) {
        return res.json({ allowed: false, reason: "invalid signature" });
    }

    const allowed = WHITELIST.includes(String(data.id));
    res.json({ allowed, user: data });
});

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server listening on " + PORT));
