// Zero-dependency local development & play server with SQLite User Accounts & Admin API
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const db = require('./db.js');

const PORT = process.env.PORT || 3000;
const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// In-memory brute force rate limiter for logins: 5 failed attempts per min
const loginFailures = new Map();

// In-memory Room Store for PvP Race and Co-Op Team Play
const rooms = new Map();

function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 4; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

function sanitizeRoom(room) {
  if (!room) return null;
  return {
    code: room.code,
    type: room.type,
    duration: room.duration,
    state: room.state,
    hostId: room.hostId,
    countdownStart: room.countdownStart,
    raceStart: room.raceStart,
    players: Object.fromEntries(room.players)
  };
}

// Periodically clean up stale rooms (>15 minutes inactive)
setInterval(() => {
  const now = Date.now();
  for (const [code, r] of rooms.entries()) {
    if (now - r.lastActivity > 15 * 60 * 1000) {
      rooms.delete(code);
    }
  }
}, 60000);

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(JSON.stringify(data));
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) { // 5MB limit
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error('Invalid JSON format'));
      }
    });
    req.on('error', reject);
  });
}

function getAuthUser(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  return db.getUserByToken(token);
}

const server = http.createServer(async (req, res) => {
  const urlParts = req.url.split('?');
  const reqPath = urlParts[0];

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    return res.end();
  }

  // Health check endpoint for Render and Uptime monitors
  if (reqPath === '/health' || reqPath === '/healthz') {
    return sendJson(res, 200, { status: 'ok', uptime: process.uptime() });
  }

  // ==========================================
  // API ENDPOINTS
  // ==========================================
  if (reqPath.startsWith('/api/')) {
    try {
      // 1. User Registration
      if (req.method === 'POST' && reqPath === '/api/register') {
        const body = await parseJsonBody(req);
        const result = db.register(body.username, body.password, body.gameData);
        return sendJson(res, 201, { success: true, ...result });
      }

      // 2. User Login
      if (req.method === 'POST' && reqPath === '/api/login') {
        const ip = req.socket.remoteAddress || 'unknown';
        const body = await parseJsonBody(req);
        const username = (body.username || '').trim().toLowerCase();
        const rateKey = `${ip}_${username}`;
        const record = loginFailures.get(rateKey);

        if (record && record.count >= 5 && Date.now() < record.resetAt) {
          return sendJson(res, 429, {
            success: false,
            error: 'Too many failed login attempts. Please wait 1 minute.'
          });
        }

        try {
          const result = db.login(body.username, body.password);
          loginFailures.delete(rateKey);
          return sendJson(res, 200, { success: true, ...result });
        } catch (loginErr) {
          const now = Date.now();
          if (!record || now >= record.resetAt) {
            loginFailures.set(rateKey, { count: 1, resetAt: now + 60000 });
          } else {
            record.count++;
          }
          throw loginErr;
        }
      }

      // 3. User Logout
      if (req.method === 'POST' && reqPath === '/api/logout') {
        const authHeader = req.headers['authorization'] || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();
        db.logout(token);
        return sendJson(res, 200, { success: true });
      }

      // 4. Current User Session Check
      if (req.method === 'GET' && reqPath === '/api/me') {
        const user = getAuthUser(req);
        if (!user) {
          return sendJson(res, 401, { success: false, error: 'Unauthorized or expired session.' });
        }
        return sendJson(res, 200, { success: true, user });
      }

      // 5. Cloud Save Sync
      if (req.method === 'POST' && reqPath === '/api/sync') {
        const user = getAuthUser(req);
        if (!user) {
          return sendJson(res, 401, { success: false, error: 'Unauthorized' });
        }
        if (user.banned || user.status === 'banned') {
          return sendJson(res, 403, {
            success: false,
            banned: true,
            error: 'Account has been banned or suspended by an administrator.'
          });
        }
        const body = await parseJsonBody(req);
        const result = db.syncUserData(
          user.id,
          body.rev,
          body.coins ?? user.coins,
          body.crystals ?? user.crystals,
          body.gameData
        );

        if (result.banned) {
          return sendJson(res, 403, {
            success: false,
            banned: true,
            error: 'Account has been banned or suspended by an administrator.'
          });
        }

        if (result.conflict) {
          return sendJson(res, 409, {
            success: false,
            conflict: true,
            rev: result.rev,
            coins: result.coins,
            crystals: result.crystals,
            gameData: result.gameData,
            message: 'Account progress updated by administrator.'
          });
        }

        return sendJson(res, 200, { success: true, synced: true, rev: result.rev });
      }

      // ==========================================
      // MULTIPLAYER ROOMS (PVP RACE & CO-OP TEAM)
      // ==========================================
      if (req.method === 'POST' && reqPath === '/api/rooms/create') {
        const body = await parseJsonBody(req);
        let code = generateRoomCode();
        while (rooms.has(code)) { code = generateRoomCode(); }
        const playerId = 'p_' + Math.random().toString(36).slice(2, 9);
        const duration = Math.max(10, Math.min(600, parseInt(body.duration, 10) || 60));
        const newRoom = {
          code,
          type: body.type === 'coop' ? 'coop' : 'race',
          duration,
          state: 'lobby',
          hostId: playerId,
          countdownStart: null,
          raceStart: null,
          createdAt: Date.now(),
          lastActivity: Date.now(),
          players: new Map([
            [playerId, {
              id: playerId,
              username: (body.username || 'Host').slice(0, 16),
              character: body.character || null,
              distance: 0,
              speed: 0,
              hp: 100,
              maxHp: 100,
              x: 180,
              y: 0,
              isGrounded: true,
              isAttacking: false,
              finished: false,
              lastPing: Date.now()
            }]
          ])
        };
        rooms.set(code, newRoom);
        return sendJson(res, 201, { success: true, roomCode: code, playerId, role: 'host', room: sanitizeRoom(newRoom) });
      }

      if (req.method === 'POST' && reqPath === '/api/rooms/join') {
        const body = await parseJsonBody(req);
        const code = (body.roomCode || '').trim().toUpperCase();
        const room = rooms.get(code);
        if (!room) {
          return sendJson(res, 404, { success: false, error: 'Room not found. Check code.' });
        }
        if (room.players.size >= 4) {
          return sendJson(res, 400, { success: false, error: 'Room is full (max 4 players).' });
        }
        const playerId = 'p_' + Math.random().toString(36).slice(2, 9);
        room.lastActivity = Date.now();
        room.players.set(playerId, {
          id: playerId,
          username: (body.username || 'Operative').slice(0, 16),
          character: body.character || null,
          distance: 0,
          speed: 0,
          hp: 100,
          maxHp: 100,
          x: 180,
          y: 0,
          isGrounded: true,
          isAttacking: false,
          finished: false,
          lastPing: Date.now()
        });
        return sendJson(res, 200, { success: true, roomCode: code, playerId, role: 'guest', room: sanitizeRoom(room) });
      }

      if (req.method === 'POST' && reqPath === '/api/rooms/start') {
        const body = await parseJsonBody(req);
        const code = (body.roomCode || '').trim().toUpperCase();
        const room = rooms.get(code);
        if (!room) return sendJson(res, 404, { success: false, error: 'Room not found.' });
        room.state = 'countdown';
        room.countdownStart = Date.now();
        room.raceStart = Date.now() + 3000;
        room.lastActivity = Date.now();
        return sendJson(res, 200, { success: true, room: sanitizeRoom(room) });
      }

      if (req.method === 'POST' && reqPath === '/api/rooms/sync') {
        const body = await parseJsonBody(req);
        const code = (body.roomCode || '').trim().toUpperCase();
        const room = rooms.get(code);
        if (!room) return sendJson(res, 404, { success: false, error: 'Room not found.' });
        const pId = body.playerId;
        if (pId && room.players.has(pId)) {
          const p = room.players.get(pId);
          if (body.state) {
            Object.assign(p, body.state, { lastPing: Date.now() });
          }
        }
        if (room.type === 'race' && room.state === 'countdown' && Date.now() >= room.raceStart) {
          room.state = 'racing';
        }
        if (room.type === 'race' && room.state === 'racing') {
          const elapsed = (Date.now() - room.raceStart) / 1000;
          if (elapsed >= room.duration) {
            room.state = 'finished';
          }
        }
        room.lastActivity = Date.now();
        const now = Date.now();
        for (const [id, pl] of room.players.entries()) {
          if (now - pl.lastPing > 20000 && id !== room.hostId) {
            room.players.delete(id);
          }
        }
        return sendJson(res, 200, { success: true, room: sanitizeRoom(room) });
      }

      if (req.method === 'GET' && reqPath === '/api/rooms/details') {
        const urlObj = new URL(req.url, 'http://localhost');
        const code = (urlObj.searchParams.get('code') || '').trim().toUpperCase();
        const room = rooms.get(code);
        if (!room) return sendJson(res, 404, { success: false, error: 'Room not found.' });
        return sendJson(res, 200, { success: true, room: sanitizeRoom(room) });
      }

      // ==========================================
      // ADMIN ENDPOINTS (Requires role === 'admin')
      // ==========================================
      if (reqPath.startsWith('/api/admin/')) {
        const user = getAuthUser(req);
        if (!user || user.role !== 'admin') {
          return sendJson(res, 403, { success: false, error: 'Access denied: Administrator privileges required.' });
        }

        // Admin: List all users
        if (req.method === 'GET' && reqPath === '/api/admin/users') {
          const users = db.adminGetAllUsers();
          return sendJson(res, 200, { success: true, users });
        }

        // Admin: Modify user coins & crystals
        if (req.method === 'POST' && reqPath === '/api/admin/modify') {
          const body = await parseJsonBody(req);
          const coins = parseInt(body.coins, 10) || 0;
          const crystals = parseInt(body.crystals, 10) || 0;
          const result = db.adminModifyCoinsCrystals(body.targetUsername, coins, crystals);
          return sendJson(res, 200, result);
        }

        // Admin: Ban / Unban user
        if (req.method === 'POST' && reqPath === '/api/admin/ban') {
          const body = await parseJsonBody(req);
          const result = db.adminToggleBan(body.targetUsername, !!body.ban);
          return sendJson(res, 200, result);
        }

        // Admin: Reset user progress to fresh state
        if (req.method === 'POST' && reqPath === '/api/admin/reset') {
          const body = await parseJsonBody(req);
          const result = db.adminResetUser(body.targetUsername, body.defaultState || null);
          return sendJson(res, 200, result);
        }
      }

      return sendJson(res, 404, { success: false, error: 'Endpoint not found' });
    } catch (err) {
      console.error('[API Error]', err.message);
      return sendJson(res, 400, { success: false, error: err.message });
    }
  }

  // ==========================================
  // STATIC FILE SERVING WITH STRICT WHITELIST
  // ==========================================
  const PUBLIC_EXACT = new Set(['/', '', '/index.html', '/favicon.ico']);
  const PUBLIC_DIRS = ['/css/', '/js/', '/assets/'];

  // Normalize path and prevent directory traversal
  let safePath = path.normalize(decodeURIComponent(reqPath)).replace(/\\/g, '/');
  if (!safePath.startsWith('/')) safePath = '/' + safePath;

  // Block sensitive files and directory traversal
  if (
    safePath.includes('..') ||
    safePath.toLowerCase().includes('database.sqlite') ||
    safePath.toLowerCase().includes('server.js') ||
    safePath.toLowerCase().includes('db.js') ||
    safePath.toLowerCase().includes('package.json')
  ) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('404 Not Found');
  }

  const isAllowed = PUBLIC_EXACT.has(safePath) || PUBLIC_DIRS.some(d => safePath.startsWith(d));
  if (!isAllowed) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('404 Not Found');
  }

  let localPath = safePath;
  if (localPath === '/' || localPath === '') localPath = '/index.html';

  const filePath = path.join(__dirname, localPath);
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Internal Server Error');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`===============================================`);
    console.log(`  HEADLESS HERO 4K ULTRA-HD SERVER STARTED`);
    console.log(`  Listening on 0.0.0.0:${PORT}`);
    console.log(`  Admin User: admin | Admin Password: ${process.env.HH_ADMIN_PASSWORD || 'admin123'}`);
    console.log(`===============================================`);
  });
}

module.exports = server;
