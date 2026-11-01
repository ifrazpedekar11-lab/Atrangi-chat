import express from 'express';
import http from 'http';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Server } from 'socket.io';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());

// Allow the frontend (hosted on another domain) to call this API
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 1e5 });

const DAY = 24 * 60 * 60 * 1000;
const rooms = new Map();  // normalized name -> room
const tokens = new Map(); // session token -> normalized name
const SIGNALS = new Set(['call-request', 'call-accepted', 'call-declined', 'call-end', 'offer', 'answer', 'ice']);

const norm = (s) => String(s ?? '').trim().toLowerCase();
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const issueToken = (key) => {
  const t = crypto.randomBytes(24).toString('hex');
  tokens.set(t, key);
  return t;
};

app.post('/api/rooms', (req, res) => {
  const name = String(req.body.name ?? '').trim();
  const password = String(req.body.password ?? '');
  const key = norm(name);
  if (name.length < 3 || name.length > 30)
    return res.status(400).json({ error: 'Room name must be 3 to 30 characters.' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  if (rooms.has(key))
    return res.status(409).json({ error: 'That room name is already taken.' });
  const salt = crypto.randomBytes(16).toString('hex');
  rooms.set(key, { name, salt, hash: hashPw(password, salt), members: new Set(), messages: [], lastActive: Date.now() });
  res.json({ name, token: issueToken(key) });
});

app.post('/api/join', (req, res) => {
  const key = norm(req.body.name);
  const room = rooms.get(key);
  if (!room) return res.status(404).json({ error: 'No room with that name.' });
  const given = Buffer.from(hashPw(String(req.body.password ?? ''), room.salt), 'hex');
  if (!crypto.timingSafeEqual(given, Buffer.from(room.hash, 'hex')))
    return res.status(401).json({ error: 'Wrong password.' });
  res.json({ name: room.name, token: issueToken(key) });
});

io.use((socket, next) => {
  const key = tokens.get(socket.handshake.auth?.token);
  if (!key || !rooms.has(key)) return next(new Error('unauthorized'));
  socket.roomKey = key;
  next();
});

io.on('connection', (socket) => {
  const key = socket.roomKey;
  const room = rooms.get(key);
  if (room.members.size >= 2) {
    socket.emit('full');
    return socket.disconnect();
  }
  room.members.add(socket.id);
  room.lastActive = Date.now();
  socket.join(key);
  socket.emit('history', room.messages);
  io.to(key).emit('presence', room.members.size);

  socket.on('chat', (text) => {
    const body = String(text ?? '').trim().slice(0, 1000);
    if (!body) return;
    const msg = { id: crypto.randomUUID(), from: socket.id, text: body, at: Date.now() };
    room.messages.push(msg);
    if (room.messages.length > 200) room.messages.shift();
    room.lastActive = Date.now();
    io.to(key).emit('chat', msg);
  });

  socket.on('signal', (data) => {
    if (!SIGNALS.has(data?.type)) return;
    socket.to(key).emit('signal', { type: data.type, payload: data.payload });
  });

  socket.on('disconnect', () => {
    room.members.delete(socket.id);
    room.lastActive = Date.now();
    io.to(key).emit('presence', room.members.size);
    io.to(key).emit('signal', { type: 'call-end' });
  });
});

// Remove empty rooms after 24 hours of inactivity
setInterval(() => {
  const now = Date.now();
  for (const [key, room] of rooms) {
    if (room.members.size === 0 && now - room.lastActive > DAY) rooms.delete(key);
  }
  for (const [t, key] of tokens) if (!rooms.has(key)) tokens.delete(t);
}, 60 * 60 * 1000);

// Serve the chat app itself from this same server
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Unknown API routes always return JSON, never the HTML page
app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found.' }));

// Serve the built frontend in production
const dist = path.join(__dirname, '../client/dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.use((req, res) => res.sendFile(path.join(dist, 'index.html')));
}

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`Atrangi Chat running at http://localhost:${PORT}`));
