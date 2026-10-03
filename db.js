// Persistent SQLite Database Manager for User Accounts and Admin Controls
// Utilizes Node 24 native node:sqlite DatabaseSync with PBKDF2 cryptography

const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');

const DB_PATH = path.join(__dirname, 'database.sqlite');
const db = new DatabaseSync(DB_PATH);

// Enable WAL mode and foreign keys for high-performance concurrent reads/writes
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

// Schema auto-migration: add rev, best_kills, best_wave columns if existing DB lacked them
try {
  db.exec(`ALTER TABLE users ADD COLUMN rev INTEGER DEFAULT 0;`);
} catch (e) {}
try {
  db.exec(`ALTER TABLE users ADD COLUMN best_kills INTEGER DEFAULT 0;`);
} catch (e) {}
try {
  db.exec(`ALTER TABLE users ADD COLUMN best_wave INTEGER DEFAULT 1;`);
} catch (e) {}

// Password hashing utility
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Seed pre-configured Admin Account if it doesn't exist
function seedAdmin() {
  const checkStmt = db.prepare('SELECT id FROM users WHERE username = ?');
  const existing = checkStmt.get('admin');

  if (!existing) {
    const adminPass = process.env.HH_ADMIN_PASSWORD || 'admin123';
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(adminPass, salt);
    const now = new Date().toISOString();

    const insertStmt = db.prepare(`
      INSERT INTO users (username, password_hash, salt, role, status, coins, crystals, game_data, rev, created_at, last_login)
      VALUES (?, ?, ?, 'admin', 'active', 999999, 99999, NULL, 0, ?, ?)
    `);
    insertStmt.run('admin', hash, salt, now, now);
    console.log(`[DB] Pre-configured Admin account created (Username: admin | Password: ${adminPass})`);
  }
}
seedAdmin();

// Register a new user
function register(username, password, initialGameData = null) {
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

  const existingStmt = db.prepare('SELECT id FROM users WHERE username = ?');
  if (existingStmt.get(trimmed)) {
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

  const insertStmt = db.prepare(`
    INSERT INTO users (username, password_hash, salt, role, status, coins, crystals, game_data, rev, created_at, last_login)
    VALUES (?, ?, ?, 'user', 'active', ?, ?, ?, 0, ?, ?)
  `);
  const result = insertStmt.run(trimmed, hash, salt, initialCoins, initialCrystals, gameDataStr, now, now);
  const userId = result.lastInsertRowid;

  // Create session
  const token = generateToken();
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
  const sessionStmt = db.prepare(`
    INSERT INTO sessions (token, user_id, created_at, expires_at)
    VALUES (?, ?, ?, ?)
  `);
  sessionStmt.run(token, userId, now, expiresAt);

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
}

// Log in an existing user
function login(username, password) {
  const trimmed = (username || '').trim();
  const userStmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const user = userStmt.get(trimmed);

  if (!user) {
    throw new Error('Invalid username or password.');
  }

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

  // Create session
  const token = generateToken();
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(token, user.id, now, expiresAt);

  let parsedGameData = null;
  if (user.game_data) {
    try {
      parsedGameData = JSON.parse(user.game_data);
    } catch (e) {}
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
}

// Validate session token
function getUserByToken(token) {
  if (!token) return null;

  const sessionStmt = db.prepare(`
    SELECT s.user_id, s.expires_at, u.id, u.username, u.role, u.status, u.coins, u.crystals, u.game_data, u.rev
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ?
  `);
  const row = sessionStmt.get(token);

  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  if (row.status === 'banned') {
    return {
      id: row.id,
      username: row.username,
      status: 'banned',
      banned: true
    };
  }

  let parsedGameData = null;
  if (row.game_data) {
    try {
      parsedGameData = JSON.parse(row.game_data);
    } catch (e) {}
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
}

// Sync player progress (save game state)
function syncUserData(userId, clientRev, coins, crystals, gameData) {
  const user = db.prepare('SELECT rev, coins, crystals, game_data, status FROM users WHERE id = ?').get(userId);
  if (!user) throw new Error('User not found.');
  if (user.status === 'banned') {
    return { banned: true };
  }

  // Conflict check: if client sent an outdated rev, return latest server state
  if (clientRev !== undefined && clientRev !== null && clientRev !== user.rev) {
    let serverGameData = null;
    if (user.game_data) {
      try { serverGameData = JSON.parse(user.game_data); } catch (e) {}
    }
    return {
      conflict: true,
      rev: user.rev,
      coins: user.coins,
      crystals: user.crystals,
      gameData: serverGameData
    };
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

  const stmt = db.prepare(`
    UPDATE users
    SET coins = ?, crystals = ?, game_data = ?,
        best_kills = MAX(COALESCE(best_kills, 0), ?),
        best_wave = MAX(COALESCE(best_wave, 1), ?)
    WHERE id = ?
  `);
  stmt.run(coins, crystals, gameDataStr, bestKills, bestWave, userId);
  return { conflict: false, rev: user.rev };
}

// Delete session on logout
function logout(token) {
  if (token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }
  return true;
}

// ADMIN API: Get all registered users
function adminGetAllUsers() {
  const stmt = db.prepare(`
    SELECT id, username, role, status, coins, crystals, game_data, rev, best_kills, best_wave, created_at, last_login
    FROM users
    ORDER BY id ASC
  `);
  const rows = stmt.all();
  return rows.map(r => {
    let stats = null;
    if (r.game_data) {
      try {
        const parsed = JSON.parse(r.game_data);
        stats = parsed.stats || null;
      } catch (e) {}
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
}

// ADMIN API: Modify coins and crystals for any user
function adminModifyCoinsCrystals(targetUsername, coins, crystals) {
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
}

// ADMIN API: Ban or Unban any user
function adminToggleBan(targetUsername, shouldBan) {
  const user = db.prepare('SELECT id, role FROM users WHERE username = ?').get(targetUsername);
  if (!user) throw new Error(`User "${targetUsername}" not found.`);
  if (user.role === 'admin') throw new Error('Cannot ban an administrator account.');

  const newStatus = shouldBan ? 'banned' : 'active';
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(newStatus, user.id);

  return { success: true, username: targetUsername, status: newStatus };
}

// ADMIN API: Reset any user's progress to fresh default state
function adminResetUser(targetUsername, defaultState) {
  const user = db.prepare('SELECT id, role FROM users WHERE username = ?').get(targetUsername);
  if (!user) throw new Error(`User "${targetUsername}" not found.`);

  const defaultStr = JSON.stringify(defaultState);
  db.prepare(`
    UPDATE users
    SET coins = 0, crystals = 0, game_data = ?, rev = rev + 1
    WHERE id = ?
  `).run(defaultStr, user.id);

  return { success: true, username: targetUsername };
}

module.exports = {
  register,
  login,
  logout,
  getUserByToken,
  syncUserData,
  adminGetAllUsers,
  adminModifyCoinsCrystals,
  adminToggleBan,
  adminResetUser
};
