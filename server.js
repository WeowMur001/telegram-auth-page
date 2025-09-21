// server.js
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const path = require("path");
const qs = require("qs");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ENV variables (set in Render)
const CLIENT_ID = process.env.DISCORD_CLIENT_ID; // из Discord
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET; // из Discord
const BASE = process.env.BASE_URL || ("https://" + (process.env.RENDER_EXTERNAL_URL || "your-host.example.com")); // альтернативно задавать BASE напрямую
const REDIRECT_URI = (process.env.DISCORD_REDIRECT || (BASE + "/discord/callback"));
const WHITELIST_RAW = process.env.WHITELIST || ""; // comma-separated discord IDs
const WHITELIST = WHITELIST_RAW.split(",").map(x => x.trim()).filter(Boolean);

// Простая in-memory map для state -> timestamp (простейшая защита от CSRF)
const states = new Map();
function genState() {
  const s = crypto.randomBytes(12).toString("hex");
  states.set(s, Date.now());
  // чистка старых (10 минут)
  for (const [k, t] of states) {
    if (Date.now() - t > 10 * 60 * 1000) states.delete(k);
  }
  return s;
}

// 1) стартовый роут — редиректит на Discord OAuth
app.get("/discord/login", (req, res) => {
  const state = genState();
  const authorize = `https://discord.com/api/oauth2/authorize?client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify&state=${state}`;
  res.redirect(authorize);
});

// 2) callback от Discord
app.get("/discord/callback", async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  if (!code || !state || !states.has(state)) {
    return res.status(400).send("Invalid OAuth callback (missing code/state).");
  }
  // удалить state (одноразовый)
  states.delete(state);

  try {
    // обмен code -> token
    const tokenRes = await axios.post("https://discord.com/api/oauth2/token",
      qs.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const accessToken = tokenRes.data.access_token;

    // получить user info
    const userRes = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const user = userRes.data; // { id, username, discriminator, avatar, ... }
    const allowed = WHITELIST.includes(String(user.id));

    // Отправляем простую HTML-страницу, которая делает postMessage в opener/parent и закрывается
    const payload = JSON.stringify({ allowed, user }).replace(/</g, "\\u003c");
    const html = `
      <!doctype html>
      <html><head><meta charset="utf-8"><title>Auth result</title></head>
      <body style="background:#111;color:#fff;font-family:Arial, sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
        <div style="text-align:center;max-width:600px">
          <h2 style="color:${allowed ? '#8ef08e' : '#f88'}">${allowed ? 'Доступ разрешён' : 'Доступ запрещён'}</h2>
          <p style="color:#ccc">${allowed ? 'Можно вернуться в игру' : 'Свяжитесь с админом для добавления в whitelist'}</p>
        </div>
        <script>
          (function(){
            var data = ${payload};
            try {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({ type: 'discord-auth', result: data }, '*');
                window.close();
                return;
              }
            } catch(e){}
            try {
              if (window.parent && window.parent !== window) {
                window.parent.postMessage({ type: 'discord-auth', result: data }, '*');
              }
            } catch(e){}
            // если открыт напрямую — оставляем результат на странице
          })();
        </script>
      </body></html>
    `;
    res.send(html);
  } catch (err) {
    console.error("OAuth error:", err?.response?.data || err.message || err);
    return res.status(500).send("OAuth error");
  }
});

// health
app.get("/", (req, res) => res.send("Discord auth API running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server listening on " + PORT));
