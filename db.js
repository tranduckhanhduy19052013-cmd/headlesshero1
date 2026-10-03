// Persistent Database Manager for User Accounts and Admin Controls
// Dual-Engine Architecture:
// 1. Native SQLite (node:sqlite DatabaseSync) when running on Node 22.5+
// 2. Seamless Zero-Dependency JSON Engine (database.json) when running on Node 18/20 (e.g. default Render environments)
// Both engines share identical API signatures, PBKDF2 encryption, session management, and revision conflict tracking.

const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

let sqliteModule = null;
try {
  sqliteModule = require('node:sqlite');
} catch (e) {
  // node:sqlite is not present in Node < 22.5
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// =========================================================================
// ENGINE 1: NATIVE SQLITE (Node >= 22.5)
// =========================================================================
function createSqliteEngine(DatabaseSync) {
  const DB_PATH = path.join(__dirname, 'database.sqlite');
  const db = new DatabaseSync(DB_PATH);

  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      status TEXT DEFAULT 'active',
      coins INTEGER DEFAULT 0,
      crystals INTEGER DEFAULT 0,
      game_data TEXT,
      rev INTEGER DEFAULT 0,
      created_at TEXT,
      last_login TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  try { db.exec(`ALTER TABLE users ADD COLUMN rev INTEGER DEFAULT 0;`); } catch (e) {}
  try { db.exec(`ALTER TABLE users ADD COLUMN best_kills INTEGER DEFAULT 0;`); } catch (e) {}
  try { db.exec(`ALTER TABLE users ADD COLUMN best_wave INTEGER DEFAULT 1;`); } catch (e) {}

  function seedAdmin() {
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
    if (!existing) {
      const adminPass = process.env.HH_ADMIN_PASSWORD || 'admin123';
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(adminPass, salt);
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO users (username, password_hash, salt, role, status, coins, crystals, game_data, rev, created_at, last_login)
        VALUES (?, ?, ?, 'admin', 'active', 999999, 99999, NULL, 0, ?, ?)
      `).run('admin', hash, salt, now, now);
      console.log(`[DB-SQLite] Admin account seeded (Username: admin | Password: ${adminPass})`);
    }
  }
  seedAdmin();

  return {
    register(username, password, initialGameData = null) {
      const trimmed = (username || '').trim();
      if (!trimmed || trimmed.length < 3 || trimmed.length > 20) {
        throw new Error('Username must be between 3 and 20 characters.');
      }
      if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
        throw new Error('Username can only contain letters, numbers, and underscores.');
      }
      if (!password || password.length < 4) {
        throw new Error('Password must be at least 4 characters long.');
      }

      if (db.prepare('SELECT id FROM users WHERE username = ?').get(trimmed)) {
        throw new Error(`Username "${trimmed}" is already registered.`);
      }

      let initialCoins = 0;
      let initialCrystals = 0;
      if (initialGameData) {
        try {
          const parsed = typeof initialGameData === 'string' ? JSON.parse(initialGameData) : initialGameData;
          if (typeof parsed.coins === 'number') initialCoins = parsed.coins;
          if (typeof parsed.crystals === 'number') initialCrystals = parsed.crystals;
        } catch (e) {}
      }

      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(password, salt);
      const now = new Date().toISOString();
      const gameDataStr = initialGameData ? (typeof initialGameData === 'string' ? initialGameData : JSON.stringify(initialGameData)) : null;

      const result = db.prepare(`
        INSERT INTO users (username, password_hash, salt, role, status, coins, crystals, game_data, rev, created_at, last_login)
        VALUES (?, ?, ?, 'user', 'active', ?, ?, ?, 0, ?, ?)
      `).run(trimmed, hash, salt, initialCoins, initialCrystals, gameDataStr, now, now);

      const userId = result.lastInsertRowid;
      const token = generateToken();
      const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
      db.prepare(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`).run(token, userId, now, expiresAt);

      return {
        token,
        user: {
          id: userId,
          username: trimmed,
          role: 'user',
          status: 'active',
          coins: initialCoins,
          crystals: initialCrystals,
          rev: 0,
          gameData: initialGameData
        }
      };
    },

    login(username, password) {
      const trimmed = (username || '').trim();
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(trimmed);
      if (!user) throw new Error('Invalid username or password.');

      const hash = hashPassword(password, user.salt);
      const userHashBuf = Buffer.from(user.password_hash, 'hex');
      const calcHashBuf = Buffer.from(hash, 'hex');
      if (userHashBuf.length !== calcHashBuf.length || !crypto.timingSafeEqual(userHashBuf, calcHashBuf)) {
        throw new Error('Invalid username or password.');
      }

      if (user.status === 'banned') {
        throw new Error('This account has been banned/suspended by an administrator.');
      }

      const now = new Date().toISOString();
      db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now, user.id);

      const token = generateToken();
      const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
      db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(token, user.id, now, expiresAt);

      let parsedGameData = null;
      if (user.game_data) {
        try { parsedGameData = JSON.parse(user.game_data); } catch (e) {}
      }

      return {
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          status: user.status,
          coins: user.coins,
          crystals: user.crystals,
          rev: user.rev || 0,
          gameData: parsedGameData
        }
      };
    },

    logout(token) {
      if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
      return true;
    },

    getUserByToken(token) {
      if (!token) return null;
      const row = db.prepare(`
        SELECT s.user_id, s.expires_at, u.id, u.username, u.role, u.status, u.coins, u.crystals, u.game_data, u.rev
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
      `).get(token);

      if (!row) return null;
      if (row.expires_at < Date.now()) {
        db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        return null;
      }
      if (row.status === 'banned') {
        return { id: row.id, username: row.username, status: 'banned', banned: true };
      }

      let parsedGameData = null;
      if (row.game_data) {
        try { parsedGameData = JSON.parse(row.game_data); } catch (e) {}
      }

      return {
        id: row.id,
        username: row.username,
        role: row.role,
        status: row.status,
        coins: row.coins,
        crystals: row.crystals,
        rev: row.rev || 0,
        gameData: parsedGameData
      };
    },

    syncUserData(userId, clientRev, coins, crystals, gameData) {
      const user = db.prepare('SELECT rev, coins, crystals, game_data, status FROM users WHERE id = ?').get(userId);
      if (!user) throw new Error('User not found.');
      if (user.status === 'banned') return { banned: true };

      if (clientRev !== undefined && clientRev !== null && clientRev !== user.rev) {
        let serverGameData = null;
        if (user.game_data) {
          try { serverGameData = JSON.parse(user.game_data); } catch (e) {}
        }
        return { conflict: true, rev: user.rev, coins: user.coins, crystals: user.crystals, gameData: serverGameData };
      }

      const gameDataStr = typeof gameData === 'string' ? gameData : JSON.stringify(gameData);
      let bestKills = 0;
      let bestWave = 1;
      try {
        const parsed = typeof gameData === 'string' ? JSON.parse(gameData) : gameData;
        if (parsed && parsed.stats) {
          bestKills = parsed.stats.bestKillsInRun || 0;
          bestWave = parsed.stats.bestWaveInRun || 1;
        }
      } catch (e) {}

      db.prepare(`
        UPDATE users
        SET coins = ?, crystals = ?, game_data = ?,
            best_kills = MAX(COALESCE(best_kills, 0), ?),
            best_wave = MAX(COALESCE(best_wave, 1), ?)
        WHERE id = ?
      `).run(coins, crystals, gameDataStr, bestKills, bestWave, userId);

      return { conflict: false, rev: user.rev };
    },

    adminGetAllUsers() {
      const rows = db.prepare(`
        SELECT id, username, role, status, coins, crystals, game_data, rev, best_kills, best_wave, created_at, last_login
        FROM users ORDER BY id ASC
      `).all();

      return rows.map(r => {
        let stats = null;
        if (r.game_data) {
          try { stats = JSON.parse(r.game_data).stats || null; } catch (e) {}
        }
        return {
          id: r.id,
          username: r.username,
          role: r.role,
          status: r.status,
          coins: r.coins,
          crystals: r.crystals,
          rev: r.rev || 0,
          bestKills: r.best_kills || (stats ? stats.bestKillsInRun : 0) || 0,
          bestWave: r.best_wave || (stats ? stats.bestWaveInRun : 1) || 1,
          stats,
          createdAt: r.created_at,
          lastLogin: r.last_login
        };
      });
    },

    adminModifyCoinsCrystals(targetUsername, coins, crystals) {
      const user = db.prepare('SELECT id, game_data FROM users WHERE username = ?').get(targetUsername);
      if (!user) throw new Error(`User "${targetUsername}" not found.`);

      let updatedGameDataStr = null;
      if (user.game_data) {
        try {
          const parsed = JSON.parse(user.game_data);
          parsed.coins = coins;
          parsed.crystals = crystals;
          updatedGameDataStr = JSON.stringify(parsed);
        } catch (e) {}
      }

      if (updatedGameDataStr) {
        db.prepare('UPDATE users SET coins = ?, crystals = ?, game_data = ?, rev = rev + 1 WHERE id = ?')
          .run(coins, crystals, updatedGameDataStr, user.id);
      } else {
        db.prepare('UPDATE users SET coins = ?, crystals = ?, rev = rev + 1 WHERE id = ?')
          .run(coins, crystals, user.id);
      }

      return { success: true, username: targetUsername, coins, crystals };
    },

    adminToggleBan(targetUsername, shouldBan) {
      const user = db.prepare('SELECT id, role FROM users WHERE username = ?').get(targetUsername);
      if (!user) throw new Error(`User "${targetUsername}" not found.`);
      if (user.role === 'admin') throw new Error('Cannot ban an administrator account.');

      const newStatus = shouldBan ? 'banned' : 'active';
      db.prepare('UPDATE users SET status = ? WHERE id = ?').run(newStatus, user.id);
      return { success: true, username: targetUsername, status: newStatus };
    },

    adminResetUser(targetUsername, defaultState) {
      const user = db.prepare('SELECT id, role FROM users WHERE username = ?').get(targetUsername);
      if (!user) throw new Error(`User "${targetUsername}" not found.`);

      const defaultStr = JSON.stringify(defaultState);
      db.prepare(`UPDATE users SET coins = 0, crystals = 0, game_data = ?, rev = rev + 1 WHERE id = ?`).run(defaultStr, user.id);
      return { success: true, username: targetUsername };
    }
  };
}

// =========================================================================
// ENGINE 2: ZERO-DEPENDENCY JSON STORE (For Node 18 / 20 / Older Platforms)
// =========================================================================
function createJsonEngine() {
  const JSON_PATH = path.join(__dirname, 'database.json');
  console.log(`[DB] Using zero-dependency JSON database engine (${JSON_PATH})`);

  let store = { nextUserId: 1, users: [], sessions: [] };
  if (fs.existsSync(JSON_PATH)) {
    try {
      const raw = fs.readFileSync(JSON_PATH, 'utf-8');
      store = JSON.parse(raw);
      if (!store.nextUserId) store.nextUserId = (store.users && store.users.length > 0) ? Math.max(...store.users.map(u => u.id)) + 1 : 1;
      if (!Array.isArray(store.users)) store.users = [];
      if (!Array.isArray(store.sessions)) store.sessions = [];
    } catch (e) {
      console.error('[DB] Warning loading database.json, starting fresh:', e.message);
    }
  }

  function persist() {
    try {
      fs.writeFileSync(JSON_PATH, JSON.stringify(store, null, 2), 'utf-8');
    } catch (e) {
      console.error('[DB] Persist error:', e.message);
    }
  }

  // Seed Admin Account
  const adminUser = store.users.find(u => u.username.toLowerCase() === 'admin');
  if (!adminUser) {
    const adminPass = process.env.HH_ADMIN_PASSWORD || 'admin123';
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(adminPass, salt);
    const now = new Date().toISOString();
    store.users.push({
      id: store.nextUserId++,
      username: 'admin',
      password_hash: hash,
      salt: salt,
      role: 'admin',
      status: 'active',
      coins: 999999,
      crystals: 99999,
      game_data: null,
      rev: 0,
      best_kills: 0,
      best_wave: 1,
      created_at: now,
      last_login: now
    });
    persist();
    console.log(`[DB-JSON] Admin account seeded (Username: admin | Password: ${adminPass})`);
  }

  return {
    register(username, password, initialGameData = null) {
      const trimmed = (username || '').trim();
      if (!trimmed || trimmed.length < 3 || trimmed.length > 20) {
        throw new Error('Username must be between 3 and 20 characters.');
      }
      if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
        throw new Error('Username can only contain letters, numbers, and underscores.');
      }
      if (!password || password.length < 4) {
        throw new Error('Password must be at least 4 characters long.');
      }

      if (store.users.some(u => u.username.toLowerCase() === trimmed.toLowerCase())) {
        throw new Error(`Username "${trimmed}" is already registered.`);
      }

      let initialCoins = 0;
      let initialCrystals = 0;
      if (initialGameData) {
        try {
          const parsed = typeof initialGameData === 'string' ? JSON.parse(initialGameData) : initialGameData;
          if (typeof parsed.coins === 'number') initialCoins = parsed.coins;
          if (typeof parsed.crystals === 'number') initialCrystals = parsed.crystals;
        } catch (e) {}
      }

      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(password, salt);
      const now = new Date().toISOString();
      const gameDataStr = initialGameData ? (typeof initialGameData === 'string' ? initialGameData : JSON.stringify(initialGameData)) : null;

      const userId = store.nextUserId++;
      const newUser = {
        id: userId,
        username: trimmed,
        password_hash: hash,
        salt: salt,
        role: 'user',
        status: 'active',
        coins: initialCoins,
        crystals: initialCrystals,
        game_data: gameDataStr,
        rev: 0,
        best_kills: 0,
        best_wave: 1,
        created_at: now,
        last_login: now
      };
      store.users.push(newUser);

      const token = generateToken();
      const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
      store.sessions.push({ token, user_id: userId, created_at: now, expires_at: expiresAt });
      persist();

      return {
        token,
        user: {
          id: userId,
          username: trimmed,
          role: 'user',
          status: 'active',
          coins: initialCoins,
          crystals: initialCrystals,
          rev: 0,
          gameData: initialGameData
        }
      };
    },

    login(username, password) {
      const trimmed = (username || '').trim();
      const user = store.users.find(u => u.username.toLowerCase() === trimmed.toLowerCase());
      if (!user) throw new Error('Invalid username or password.');

      const hash = hashPassword(password, user.salt);
      const userHashBuf = Buffer.from(user.password_hash, 'hex');
      const calcHashBuf = Buffer.from(hash, 'hex');
      if (userHashBuf.length !== calcHashBuf.length || !crypto.timingSafeEqual(userHashBuf, calcHashBuf)) {
        throw new Error('Invalid username or password.');
      }

      if (user.status === 'banned') {
        throw new Error('This account has been banned/suspended by an administrator.');
      }

      const now = new Date().toISOString();
      user.last_login = now;

      const token = generateToken();
      const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
      store.sessions.push({ token, user_id: user.id, created_at: now, expires_at: expiresAt });
      persist();

      let parsedGameData = null;
      if (user.game_data) {
        try { parsedGameData = JSON.parse(user.game_data); } catch (e) {}
      }

      return {
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          status: user.status,
          coins: user.coins,
          crystals: user.crystals,
          rev: user.rev || 0,
          gameData: parsedGameData
        }
      };
    },

    logout(token) {
      if (token) {
        store.sessions = store.sessions.filter(s => s.token !== token);
        persist();
      }
      return true;
    },

    getUserByToken(token) {
      if (!token) return null;
      const session = store.sessions.find(s => s.token === token);
      if (!session) return null;

      if (session.expires_at < Date.now()) {
        store.sessions = store.sessions.filter(s => s.token !== token);
        persist();
        return null;
      }

      const user = store.users.find(u => u.id === session.user_id);
      if (!user) return null;

      if (user.status === 'banned') {
        return { id: user.id, username: user.username, status: 'banned', banned: true };
      }

      let parsedGameData = null;
      if (user.game_data) {
        try { parsedGameData = JSON.parse(user.game_data); } catch (e) {}
      }

      return {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status,
        coins: user.coins,
        crystals: user.crystals,
        rev: user.rev || 0,
        gameData: parsedGameData
      };
    },

    syncUserData(userId, clientRev, coins, crystals, gameData) {
      const user = store.users.find(u => u.id === userId);
      if (!user) throw new Error('User not found.');
      if (user.status === 'banned') return { banned: true };

      if (clientRev !== undefined && clientRev !== null && clientRev !== user.rev) {
        let serverGameData = null;
        if (user.game_data) {
          try { serverGameData = JSON.parse(user.game_data); } catch (e) {}
        }
        return { conflict: true, rev: user.rev, coins: user.coins, crystals: user.crystals, gameData: serverGameData };
      }

      const gameDataStr = typeof gameData === 'string' ? gameData : JSON.stringify(gameData);
      let bestKills = 0;
      let bestWave = 1;
      try {
        const parsed = typeof gameData === 'string' ? JSON.parse(gameData) : gameData;
        if (parsed && parsed.stats) {
          bestKills = parsed.stats.bestKillsInRun || 0;
          bestWave = parsed.stats.bestWaveInRun || 1;
        }
      } catch (e) {}

      user.coins = coins;
      user.crystals = crystals;
      user.game_data = gameDataStr;
      user.best_kills = Math.max(user.best_kills || 0, bestKills);
      user.best_wave = Math.max(user.best_wave || 1, bestWave);
      persist();

      return { conflict: false, rev: user.rev };
    },

    adminGetAllUsers() {
      return store.users.map(u => {
        let stats = null;
        if (u.game_data) {
          try { stats = JSON.parse(u.game_data).stats || null; } catch (e) {}
        }
        return {
          id: u.id,
          username: u.username,
          role: u.role,
          status: u.status,
          coins: u.coins,
          crystals: u.crystals,
          rev: u.rev || 0,
          bestKills: u.best_kills || (stats ? stats.bestKillsInRun : 0) || 0,
          bestWave: u.best_wave || (stats ? stats.bestWaveInRun : 1) || 1,
          stats,
          createdAt: u.created_at,
          lastLogin: u.last_login
        };
      });
    },

    adminModifyCoinsCrystals(targetUsername, coins, crystals) {
      const user = store.users.find(u => u.username.toLowerCase() === targetUsername.toLowerCase());
      if (!user) throw new Error(`User "${targetUsername}" not found.`);

      user.coins = coins;
      user.crystals = crystals;
      user.rev = (user.rev || 0) + 1;

      if (user.game_data) {
        try {
          const parsed = JSON.parse(user.game_data);
          parsed.coins = coins;
          parsed.crystals = crystals;
          user.game_data = JSON.stringify(parsed);
        } catch (e) {}
      }
      persist();

      return { success: true, username: targetUsername, coins, crystals };
    },

    adminToggleBan(targetUsername, shouldBan) {
      const user = store.users.find(u => u.username.toLowerCase() === targetUsername.toLowerCase());
      if (!user) throw new Error(`User "${targetUsername}" not found.`);
      if (user.role === 'admin') throw new Error('Cannot ban an administrator account.');

      user.status = shouldBan ? 'banned' : 'active';
      persist();
      return { success: true, username: targetUsername, status: user.status };
    },

    adminResetUser(targetUsername, defaultState) {
      const user = store.users.find(u => u.username.toLowerCase() === targetUsername.toLowerCase());
      if (!user) throw new Error(`User "${targetUsername}" not found.`);

      user.coins = 0;
      user.crystals = 0;
      user.game_data = JSON.stringify(defaultState);
      user.rev = (user.rev || 0) + 1;
      persist();

      return { success: true, username: targetUsername };
    }
  };
}

// Instantiate active engine based on runtime capabilities
const activeEngine = sqliteModule && sqliteModule.DatabaseSync
  ? createSqliteEngine(sqliteModule.DatabaseSync)
  : createJsonEngine();

module.exports = activeEngine;
