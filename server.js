const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

const BOT_TOKEN = process.env.BOT_TOKEN;
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

// API для проверки
app.post("/auth", (req, res) => {
  const data = req.body;
  if (!data.hash) return res.status(400).json({ error: "no hash" });

  if (!checkTelegramAuth(data)) {
    return res.json({ allowed: false, reason: "invalid signature" });
  }

  const allowed = WHITELIST.includes(String(data.id));
  res.json({ allowed, user: data });
});

// Страница логина
app.get("/login", (req, res) => {
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>Telegram login</title>
    </head>
    <body style="display:flex;align-items:center;justify-content:center;height:100vh;background:#111;color:#fff;">
      <div style="text-align:center">
        <h2>Вход через Telegram</h2>
        <div id="widget"></div>
        <div id="msg" style="margin-top:12px;color:#f88"></div>
      </div>

      <script src="https://telegram.org/js/telegram-widget.js?22"
        data-telegram-login="AibmCheck_bot"
        data-size="large"
        data-onauth="onTelegramAuth(user)"
        data-request-access="write">
      </script>

      <script>
  async function onTelegramAuth(user) {
    try {
      const r = await fetch('/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(user)
      });
      const data = await r.json();
      // ✅ отправляем результат в родительский iframe
      try {
        window.parent.postMessage({ type: 'telegram-auth', result: data }, '*');
      } catch(e){}
      if (data.allowed) {
        document.getElementById('msg').style.color = '#8ef08e';
        document.getElementById('msg').innerText = '✅ Доступ разрешён';
      } else {
        document.getElementById('msg').innerText = '⛔ Доступ запрещён';
      }
    } catch (err) {
      document.getElementById('msg').innerText = 'Ошибка проверки';
      try {
        window.parent.postMessage({ type:'telegram-auth', result: { allowed:false, error:'network' } }, '*');
      } catch(e){}
    }
  }
</script>
    </body>
    </html>
  `);
});

// Главная
app.get("/", (req, res) => res.send("Telegram Auth API is running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server listening on " + PORT));

