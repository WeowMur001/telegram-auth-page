const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// Ваш BOT_TOKEN должен быть установлен как переменная окружения на Render
// const BOT_TOKEN = process.env.BOT_TOKEN; 
// Для локального тестирования:
const BOT_TOKEN = "ЗАМЕНИТЕ_НА_ВАШ_BOT_TOKEN_В_КАВЫЧКАХ";

// WHITELIST должен быть установлен как переменная окружения
// const WHITELIST = (process.env.WHITELIST || "").split(",");
// Для локального тестирования:
const WHITELIST = ["2030246487"]; // Ваш ID по умолчанию

// Проверка подписи от Telegram
function checkTelegramAuth(data) {
    const { hash, ...rest } = data;
    const secret = crypto.createHash("sha256").update(BOT_TOKEN).digest();
    const checkString = Object.keys(rest)
        .filter(k => k !== 'hash' && k !== 'auth_date') // Исключаем hash и auth_date
        .sort()
        .map((k) => `${k}=${rest[k]}`)
        .join("\n");
    const hmac = crypto.createHmac("sha256", secret).update(checkString).digest("hex");
    return hmac === hash;
}

// API для проверки
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

// Страница логина (убедитесь, что эта страница соответствует вашей public/login.html)
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

// Главная страница
app.get("/", (req, res) => res.send("Telegram Auth API is running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server listening on " + PORT));
