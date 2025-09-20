const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

const BOT_TOKEN = process.env.BOT_TOKEN; // токен бота из Render переменных
const WHITELIST = (process.env.WHITELIST || "2030246487").split(",");

// проверка подписи от Telegram
function checkTelegramAuth(data) {
  const { hash, ...rest } = data;
  const secret = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const checkString = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("\n");

  const hmac = crypto.createHmac("sha256", secret).update(checkString).digest("hex");
  return hmac === hash;
}

// эндпоинт проверки
app.post("/auth", (req, res) => {
  const data = req.body;
  if (!data.hash) return res.status(400).json({ error: "no hash" });

  if (!checkTelegramAuth(data)) {
    return res.json({ allowed: false, reason: "invalid signature" });
  }

  const allowed = WHITELIST.includes(String(data.id));
  res.json({ allowed, user: data });
});

app.get("/", (req, res) => res.send("Telegram Auth API is running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server listening on " + PORT));
