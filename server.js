// server.js
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors()); // разрешаем запросы из браузера (можно ограничить по origin)
app.use(express.json());

// WHITELIST можно задать через переменную окружения WHITELIST="2030246487,11111111"
const raw = process.env.WHITELIST || '2030246487';
const whitelist = new Set(String(raw).split(',').map(s => s.trim()).filter(Boolean));

app.post('/check', (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'no id provided' });
  const allowed = whitelist.has(String(id));
  res.json({ allowed });
});

// Админ API: добавить ID (необязательно). Защити ADMIN_SECRET в env если будешь включать.
app.post('/admin/add', (req, res) => {
  const secret = process.env.ADMIN_SECRET || '';
  if (secret && req.headers['x-admin-secret'] !== secret) return res.status(403).json({ error: 'forbidden' });
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'no id' });
  whitelist.add(String(id));
  return res.json({ added: id });
});

app.get('/', (req, res) => res.send('whitelist API is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server listening on', PORT));
