"use strict";
/**
 * RAWfit Gym — data layer.
 *
 * Two dialects, selected by the presence of DATABASE_URL:
 *   - PostgreSQL (production, Neon)  -> require("pg") Pool
 *   - SQLite (local/dev fallback)    -> node:sqlite (built in), better-sqlite3 as fallback
 *
 * Dialect note
 * ------------
 * PostgreSQL folds every UNQUOTED identifier to lowercase, so `createdAt` is stored and
 * returned as `createdat`, and `u.name AS packageName` comes back as `packagename`.
 * SQLite preserves declared case. The frontends are written against camelCase, so every
 * row is normalized through `camelizeRow()` before leaving this layer — both dialects
 * then return identical key casing.
 */
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const DATABASE_URL = process.env.DATABASE_URL;
const isPostgres = !!DATABASE_URL;

/* ------------------------------------------------------------------ *
 * Identifier normalization
 * ------------------------------------------------------------------ */

// Every column name and every SQL alias the app uses, in canonical camelCase.
const CAMEL_FIELDS = [
  // users
  "id", "uniqueCode", "name", "phone", "password", "role", "dob", "address", "email",
  "gender", "photo", "height", "weight", "medicalIssues", "startDate", "endDate",
  "discount", "extraDays", "totalAmount", "packageId", "createdAt", "updatedAt",
  // packages
  "duration", "price", "description", "isActive",
  // attendance
  "memberId", "checkIn", "checkOut", "isManual", "markedBy",
  // exercises
  "category", "videoUrl", "gifUrl", "difficulty", "muscleGroup",
  // templates / charts / notifications / payments / foods / settings
  "targetCalories", "meals", "exercises", "type", "content", "history",
  "isRead", "message", "amount", "method", "notes", "date",
  "serving", "calories", "key", "value",
  // common SQL aliases
  "packageName", "packageDuration", "packagePrice",
  "memberName", "memberCode", "memberPhone",
  // read-only aggregates
  "count", "total", "rows", "c",
];
const LOWER_TO_CAMEL = new Map(CAMEL_FIELDS.map((f) => [f.toLowerCase(), f]));

/**
 * Rewrite a row's keys to their canonical camelCase form. Unknown keys pass through
 * untouched so dialect-specific oddities are never mangled.
 */
function camelizeRow(row) {
  if (!row || typeof row !== "object") return row;
  const out = {};
  for (const key of Object.keys(row)) {
    out[LOWER_TO_CAMEL.get(key) || key] = row[key];
  }
  return out;
}

function camelizeRows(rows) {
  if (!Array.isArray(rows)) return rows;
  return rows.map(camelizeRow);
}

/* ------------------------------------------------------------------ *
 * SQLite driver — node:sqlite first, better-sqlite3 as fallback
 * ------------------------------------------------------------------ */

/** SQLite file path — overridable so tests can run against an isolated database. */
const SQLITE_PATH = process.env.SQLITE_PATH || path.join(__dirname, "..", "data", "gym.db");
let _sqliteDriver = null;

function loadSqliteDriver() {
  if (_sqliteDriver) return _sqliteDriver;
  const attempts = [
    ["node:sqlite", () => {
      const { DatabaseSync } = require("node:sqlite");
      return (file) => new DatabaseSync(file);
    }],
    ["better-sqlite3", () => {
      const BetterSqlite3 = require("better-sqlite3");
      return (file) => new BetterSqlite3(file);
    }],
  ];
  const failures = [];
  for (const [label, load] of attempts) {
    try {
      _sqliteDriver = { label, open: load() };
      return _sqliteDriver;
    } catch (err) {
      failures.push(`${label}: ${String(err.message).split("\n")[0]}`);
    }
  }
  throw new Error(`No SQLite driver available (${failures.join(" | ")})`);
}

/* ------------------------------------------------------------------ *
 * Connections — one cached handle per dialect (the original opened a new
 * SQLite connection on every single query and never closed any of them)
 * ------------------------------------------------------------------ */

let _pgPool = null;
let _sqliteDb = null;

function getDb() {
  if (isPostgres) {
    if (!_pgPool) {
      const { Pool } = require("pg");
      // RejectUnauthorized is env-controlled rather than hard-coded false: flipping it
      // blind against the live Neon endpoint could take production down, so the current
      // behaviour is preserved by default and documented in .env.example as a hardening
      // step to verify before enabling.
      const rejectUnauthorized = process.env.PG_SSL_REJECT_UNAUTHORIZED === "true";
      _pgPool = new Pool({
        connectionString: DATABASE_URL,
        ssl: { rejectUnauthorized },
        connectionTimeoutMillis: 10000,
        idleTimeoutMillis: 30000,
        max: 10,
      });
    }
    return { dialect: "postgres", pool: _pgPool, query: (text, params) => _pgPool.query(text, params) };
  }

  if (!_sqliteDb) {
    const driver = loadSqliteDriver();
    fs.mkdirSync(path.dirname(SQLITE_PATH), { recursive: true });
    const db = driver.open(SQLITE_PATH);
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA foreign_keys = ON");
    _sqliteDb = db;
  }
  return { dialect: "sqlite", raw: _sqliteDb, driver: _sqliteDriver ? _sqliteDriver.label : "unknown" };
}

/** Close cached handles (used by tests and graceful shutdown). */
function closeDb() {
  if (_pgPool) {
    const pool = _pgPool;
    _pgPool = null;
    return pool.end().catch(() => {});
  }
  if (_sqliteDb) {
    const db = _sqliteDb;
    _sqliteDb = null;
    try { db.close(); } catch (_) { /* already closed */ }
  }
  return Promise.resolve();
}

/* ------------------------------------------------------------------ *
 * Dialect-aware query helpers
 * ------------------------------------------------------------------ */

/** Rewrite `?` placeholders into `$1..$n` for PostgreSQL. No-op on SQLite. */
function sql(sqlStr) {
  if (!isPostgres) return sqlStr;
  let i = 0;
  return sqlStr.replace(/\?/g, () => `$${++i}`);
}

async function dbGet(sqlStr, params = []) {
  const db = getDb();
  if (db.dialect === "postgres") {
    const { rows } = await db.pool.query(sql(sqlStr), params);
    return camelizeRow(rows[0]);
  }
  return camelizeRow(db.raw.prepare(sqlStr).get(...params));
}

async function dbAll(sqlStr, params = []) {
  const db = getDb();
  if (db.dialect === "postgres") {
    const { rows } = await db.pool.query(sql(sqlStr), params);
    return camelizeRows(rows);
  }
  return camelizeRows(db.raw.prepare(sqlStr).all(...params));
}

async function dbRun(sqlStr, params = []) {
  const db = getDb();
  if (db.dialect === "postgres") {
    return db.pool.query(sql(sqlStr), params);
  }
  return db.raw.prepare(sqlStr).run(...params);
}

/** Run a multi-statement script (DDL only). */
async function dbExec(script) {
  const db = getDb();
  if (db.dialect === "postgres") {
    await db.pool.query(script);
    return;
  }
  db.raw.exec(script);
}

/* ------------------------------------------------------------------ *
 * Schema
 * ------------------------------------------------------------------ */

const PG_DDL = `
  CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    duration INTEGER NOT NULL,
    price REAL NOT NULL,
    description TEXT,
    isActive INTEGER DEFAULT 1,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    uniqueCode TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'MEMBER',
    dob TEXT,
    address TEXT,
    email TEXT,
    gender TEXT,
    photo TEXT,
    height REAL,
    weight REAL,
    medicalIssues TEXT,
    startDate TEXT,
    endDate TEXT,
    discount REAL DEFAULT 0,
    extraDays INTEGER DEFAULT 0,
    totalAmount REAL,
    packageId TEXT,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    updatedAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    FOREIGN KEY (packageId) REFERENCES packages(id)
  );

  CREATE TABLE IF NOT EXISTS attendance (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    checkIn TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    checkOut TEXT,
    isManual INTEGER DEFAULT 0,
    markedBy TEXT,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS exercises (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    videoUrl TEXT,
    gifUrl TEXT,
    difficulty TEXT DEFAULT 'beginner',
    muscleGroup TEXT,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  );

  CREATE TABLE IF NOT EXISTS diet_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    targetCalories INTEGER,
    meals TEXT,
    description TEXT,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  );

  CREATE TABLE IF NOT EXISTS workout_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    exercises TEXT,
    difficulty TEXT,
    description TEXT,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  );

  CREATE TABLE IF NOT EXISTS member_charts (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    startDate TEXT,
    endDate TEXT,
    history TEXT DEFAULT '[]',
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    updatedAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT,
    isRead INTEGER DEFAULT 0,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    amount REAL NOT NULL,
    method TEXT,
    notes TEXT,
    date TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS foods (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    serving TEXT,
    calories INTEGER DEFAULT 0,
    category TEXT NOT NULL,
    createdAt TEXT DEFAULT (to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  );

  CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

  `;

const SQLITE_DDL = `
  CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    duration INTEGER NOT NULL,
    price REAL NOT NULL,
    description TEXT,
    isActive INTEGER DEFAULT 1,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z')
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    uniqueCode TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'MEMBER',
    dob TEXT,
    address TEXT,
    email TEXT,
    gender TEXT,
    photo TEXT,
    height REAL,
    weight REAL,
    medicalIssues TEXT,
    startDate TEXT,
    endDate TEXT,
    discount REAL DEFAULT 0,
    extraDays INTEGER DEFAULT 0,
    totalAmount REAL,
    packageId TEXT,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    updatedAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    FOREIGN KEY (packageId) REFERENCES packages(id)
  );

  CREATE TABLE IF NOT EXISTS attendance (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    checkIn TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    checkOut TEXT,
    isManual INTEGER DEFAULT 0,
    markedBy TEXT,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS exercises (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    videoUrl TEXT,
    gifUrl TEXT,
    difficulty TEXT DEFAULT 'beginner',
    muscleGroup TEXT,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z')
  );

  CREATE TABLE IF NOT EXISTS diet_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    targetCalories INTEGER,
    meals TEXT,
    description TEXT,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z')
  );

  CREATE TABLE IF NOT EXISTS workout_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    exercises TEXT,
    difficulty TEXT,
    description TEXT,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z')
  );

  CREATE TABLE IF NOT EXISTS member_charts (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    startDate TEXT,
    endDate TEXT,
    history TEXT DEFAULT '[]',
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    updatedAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT,
    isRead INTEGER DEFAULT 0,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    memberId TEXT NOT NULL,
    amount REAL NOT NULL,
    method TEXT,
    notes TEXT,
    date TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z'),
    FOREIGN KEY (memberId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS foods (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    serving TEXT,
    calories INTEGER DEFAULT 0,
    category TEXT NOT NULL,
    createdAt TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now') || 'Z')
  );

  CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`;

/**
 * Columns added after the first production deploy. `CREATE TABLE IF NOT EXISTS` will not
 * touch an existing table, so upgrades run as idempotent ALTERs; failures on databases
 * that already carry the column are expected and ignored.
 */
const PG_UPGRADES = [
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT",
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT",
];
const SQLITE_UPGRADES = [
  { column: "email", ddl: "ALTER TABLE users ADD COLUMN email TEXT" },
  { column: "gender", ddl: "ALTER TABLE users ADD COLUMN gender TEXT" },
];

/**
 * Data migrations that are not schema changes. Idempotent, so they are safe to run on
 * every boot.
 */
async function dataMigrations() {
  // STAFF was the only non-admin staff role before trainers and reception split out of
  // it. Reception is the closest equivalent, so an existing front-desk login keeps the
  // narrow access it already had rather than silently gaining a trainer's powers.
  try {
    await dbRun("UPDATE users SET role = 'RECEPTION' WHERE role = 'STAFF'");
  } catch (err) {
    console.warn(`[schema] STAFF -> RECEPTION migration skipped: ${err.message}`);
  }
}

async function initDatabase() {
  await dbExec(isPostgres ? PG_DDL : SQLITE_DDL);

  // Partial unique index: at most one OPEN check-in per member. Created separately from
  // the table DDL so that a pre-existing duplicate row in production degrades to a logged
  // warning instead of aborting schema init — and the check-in handler still does its own
  // read-then-insert guard, so behaviour stays correct either way.
  try {
    await dbExec(
      "CREATE UNIQUE INDEX IF NOT EXISTS uq_open_attendance ON attendance (memberId) WHERE checkOut IS NULL"
    );
  } catch (err) {
    console.warn(
      "[schema] could not create uq_open_attendance (duplicate open check-ins already present?): "
      + err.message
    );
  }

  if (isPostgres) {
    for (const stmt of PG_UPGRADES) {
      try {
        await dbRun(stmt);
      } catch (err) {
        // 42701 duplicate column = already applied
        if (!/duplicate column/i.test(String(err.message))) {
          console.error(`[schema] upgrade skipped: ${err.message}`);
        }
      }
    }
    await dataMigrations();
    return;
  }

  const db = getDb();
  const existing = new Set(
    db.raw.prepare("SELECT name FROM pragma_table_info('users')").all().map((r) => r.name)
  );
  for (const up of SQLITE_UPGRADES) {
    if (existing.has(up.column)) continue;
    try {
      db.raw.exec(up.ddl);
    } catch (err) {
      console.error(`[schema] upgrade skipped (${up.column}): ${err.message}`);
    }
  }

  await dataMigrations();
}

/* ------------------------------------------------------------------ *
 * Seed data
 * ------------------------------------------------------------------ */

const SEED_PACKAGES = [
  ["basic-monthly", "Basic Monthly", 30, 500, "Access to gym equipment for 30 days"],
  ["premium-monthly", "Premium Monthly", 30, 800, "Access to gym + classes for 30 days"],
  ["quarterly", "Quarterly", 90, 1400, "3 months premium membership"],
  ["half-yearly", "Half Yearly", 180, 2500, "6 months premium membership"],
  ["annual", "Annual", 365, 4500, "1 year premium membership"],
];

const SEED_DIET_TEMPLATES = [
  ["Weight Loss Plan", 1500, "Low calorie diet for weight loss", [
    { time: "7:00 AM", name: "Oatmeal with fruits", calories: 300, items: ["Oats", "Banana", "Honey", "Milk"] },
    { time: "10:00 AM", name: "Mid-morning snack", calories: 150, items: ["Apple", "Almonds"] },
    { time: "1:00 PM", name: "Lunch", calories: 450, items: ["Brown rice", "Grilled chicken", "Salad", "Dal"] },
    { time: "4:00 PM", name: "Pre-workout", calories: 150, items: ["Banana", "Protein shake"] },
    { time: "7:00 PM", name: "Dinner", calories: 350, items: ["Roti", "Vegetables", "Paneer"] },
    { time: "9:00 PM", name: "Before bed", calories: 100, items: ["Warm milk", "Turmeric"] },
  ]],
  ["Muscle Gain Plan", 2500, "High protein diet for muscle building", [
    { time: "6:00 AM", name: "Early breakfast", calories: 400, items: ["Eggs (4)", "Whole wheat toast", "Banana"] },
    { time: "9:00 AM", name: "Post-workout", calories: 400, items: ["Protein shake", "Oats", "Peanut butter"] },
    { time: "12:00 PM", name: "Lunch", calories: 600, items: ["Rice", "Chicken breast", "Vegetables", "Dal"] },
    { time: "3:00 PM", name: "Snack", calories: 300, items: ["Greek yogurt", "Mixed nuts", "Fruits"] },
    { time: "6:00 PM", name: "Pre-workout", calories: 200, items: ["Banana", "Black coffee"] },
    { time: "8:00 PM", name: "Dinner", calories: 500, items: ["Roti", "Fish/Paneer", "Vegetables", "Salad"] },
    { time: "10:00 PM", name: "Before bed", calories: 100, items: ["Casein protein", "Milk"] },
  ]],
  ["Maintenance Plan", 2000, "Balanced diet for maintaining weight", [
    { time: "7:00 AM", name: "Breakfast", calories: 400, items: ["Poha/Upma", "Eggs", "Fruits"] },
    { time: "10:00 AM", name: "Snack", calories: 200, items: ["Nuts", "Green tea"] },
    { time: "1:00 PM", name: "Lunch", calories: 500, items: ["Rice", "Dal", "Vegetables", "Curd"] },
    { time: "4:00 PM", name: "Evening snack", calories: 200, items: ["Sprouts", "Fruits"] },
    { time: "7:00 PM", name: "Dinner", calories: 500, items: ["Roti", "Paneer/Chicken", "Salad"] },
    { time: "9:00 PM", name: "Before bed", calories: 200, items: ["Milk", "Dry fruits"] },
  ]],
];

const SEED_WORKOUT_TEMPLATES = [
  ["Beginner Full Body", "beginner", "Full body workout for beginners", [
    { name: "Warm-up", duration: "5 min", type: "cardio" },
    { name: "Push-ups", sets: 3, reps: 10, rest: "60s" },
    { name: "Squats", sets: 3, reps: 12, rest: "60s" },
    { name: "Bent Over Row", sets: 3, reps: 10, rest: "60s" },
    { name: "Plank", sets: 3, duration: "30s", rest: "45s" },
    { name: "Bicep Curls", sets: 3, reps: 12, rest: "45s" },
    { name: "Cool down", duration: "5 min", type: "stretching" },
  ]],
  ["Chest & Triceps", "intermediate", "Upper body push workout", [
    { name: "Warm-up", duration: "5 min", type: "cardio" },
    { name: "Bench Press", sets: 4, reps: 8, rest: "90s" },
    { name: "Incline Bench Press", sets: 3, reps: 10, rest: "90s" },
    { name: "Dumbbell Fly", sets: 3, reps: 12, rest: "60s" },
    { name: "Tricep Dips", sets: 3, reps: 10, rest: "60s" },
    { name: "Tricep Pushdown", sets: 3, reps: 12, rest: "60s" },
    { name: "Cool down", duration: "5 min", type: "stretching" },
  ]],
  ["Back & Biceps", "intermediate", "Upper body pull workout", [
    { name: "Warm-up", duration: "5 min", type: "cardio" },
    { name: "Deadlift", sets: 4, reps: 6, rest: "120s" },
    { name: "Pull-ups", sets: 3, reps: 8, rest: "90s" },
    { name: "Bent Over Row", sets: 3, reps: 10, rest: "90s" },
    { name: "Lat Pulldown", sets: 3, reps: 12, rest: "60s" },
    { name: "Bicep Curls", sets: 3, reps: 12, rest: "60s" },
    { name: "Cool down", duration: "5 min", type: "stretching" },
  ]],
  ["Leg Day", "intermediate", "Lower body workout", [
    { name: "Warm-up", duration: "5 min", type: "cardio" },
    { name: "Squats", sets: 4, reps: 10, rest: "120s" },
    { name: "Leg Press", sets: 3, reps: 12, rest: "90s" },
    { name: "Lunges", sets: 3, reps: 12, rest: "90s" },
    { name: "Calf Raises", sets: 4, reps: 15, rest: "45s" },
    { name: "Cool down", duration: "5 min", type: "stretching" },
  ]],
  ["HIIT Cardio", "advanced", "High intensity interval training", [
    { name: "Jumping Jacks", duration: "30s", rest: "15s", type: "cardio" },
    { name: "Burpees", duration: "30s", rest: "15s", type: "cardio" },
    { name: "Mountain Climbers", duration: "30s", rest: "15s", type: "cardio" },
    { name: "High Knees", duration: "30s", rest: "15s", type: "cardio" },
    { name: "Squat Jumps", duration: "30s", rest: "15s", type: "cardio" },
    { name: "Plank", duration: "30s", rest: "15s", type: "core" },
    { name: "Repeat 3 rounds", type: "note" },
  ]],
];

/**
 * Every seed block is independently guarded. The original ran them inside one
 * try/catch, so a failure after the admin insert silently left packages, diet
 * templates and workout templates all empty — which made member admission impossible.
 */
async function seedDatabase() {
  const results = { admin: false, packages: false, diet: false, workout: false, foods: false, errors: [] };

  await runSeedBlock(results, "admin", async () => {
    const existing = await dbGet("SELECT id FROM users WHERE phone = ?", ["9999999999"]);
    if (existing) return;
    const password = process.env.ADMIN_PASSWORD || "admin";
    if (!process.env.ADMIN_PASSWORD) {
      console.warn("[seed] Creating default admin 9999999999 / admin — set ADMIN_PASSWORD to override, " +
        "or change it from the admin panel after first login.");
    }
    await dbRun(
      "INSERT INTO users (id, uniqueCode, name, phone, password, role) VALUES (?, ?, ?, ?, ?, ?)",
      [uuidv4(), "RM-2024-ADMIN", "Admin", "9999999999", await bcrypt.hash(password, 10), "ADMIN"]
    );
  });

  await runSeedBlock(results, "packages", async () => {
    // Upsert instead of "insert if empty": production shipped with an empty packages
    // table, which made new-member admission impossible. This is idempotent + self-healing.
    for (const [id, name, duration, price, description] of SEED_PACKAGES) {
      const row = await dbGet("SELECT id FROM packages WHERE id = ?", [id]);
      if (row) {
        await dbRun(
          "UPDATE packages SET name = ?, duration = ?, price = ?, description = ?, isActive = 1 WHERE id = ?",
          [name, duration, price, description, id]
        );
      } else {
        await dbRun(
          "INSERT INTO packages (id, name, duration, price, description, isActive) VALUES (?, ?, ?, ?, ?, 1)",
          [id, name, duration, price, description]
        );
      }
    }
  });

  await runSeedBlock(results, "diet", async () => {
    const row = await dbGet("SELECT COUNT(*) as count FROM diet_templates");
    if (Number(row.count) > 0) return;
    for (const [name, targetCalories, description, meals] of SEED_DIET_TEMPLATES) {
      await dbRun(
        "INSERT INTO diet_templates (id, name, targetCalories, meals, description) VALUES (?, ?, ?, ?, ?)",
        [uuidv4(), name, targetCalories, JSON.stringify(meals), description]
      );
    }
  });

  await runSeedBlock(results, "workout", async () => {
    const row = await dbGet("SELECT COUNT(*) as count FROM workout_templates");
    if (Number(row.count) > 0) return;
    for (const [name, difficulty, description, exercises] of SEED_WORKOUT_TEMPLATES) {
      await dbRun(
        "INSERT INTO workout_templates (id, name, difficulty, exercises, description) VALUES (?, ?, ?, ?, ?)",
        [uuidv4(), name, difficulty, JSON.stringify(exercises), description]
      );
    }
  });

  await runSeedBlock(results, "foods", async () => {
    const row = await dbGet("SELECT COUNT(*) as count FROM foods");
    if (Number(row.count) > 0) return;
    const file = path.join(__dirname, "..", "data", "foods.json");
    if (!fs.existsSync(file)) return;
    const foods = JSON.parse(fs.readFileSync(file, "utf8"));
    for (const f of foods) {
      await dbRun(
        "INSERT INTO foods (id, name, serving, calories, category) VALUES (?, ?, ?, ?, ?)",
        [uuidv4(), f.name, f.serving || null, Number(f.calories) || 0, f.category]
      );
    }
    results.foodCount = foods.length;
  });

  return results;
}

async function runSeedBlock(results, label, fn) {
  try {
    await fn();
    results[label] = true;
  } catch (err) {
    results.errors.push(`${label}: ${err.message}`);
    console.error(`[seed] ${label} failed: ${err.message}`);
  }
}

/* ------------------------------------------------------------------ *
 * JWT secret — env var wins; otherwise a generated value persisted in
 * app_settings so it survives restarts and never appears in git.
 * ------------------------------------------------------------------ */

let _jwtSecret = null;

async function getJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (_jwtSecret) return _jwtSecret;

  const row = await dbGet("SELECT value FROM app_settings WHERE key = ?", ["jwt_secret"]);
  if (row && row.value) {
    _jwtSecret = row.value;
    return _jwtSecret;
  }

  const generated = crypto.randomBytes(48).toString("hex");
  await dbRun(
    isPostgres
      ? "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
      : "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    ["jwt_secret", generated]
  );
  _jwtSecret = generated;
  console.warn("[auth] JWT_SECRET not set — generated a persistent secret in app_settings. " +
    "Set JWT_SECRET explicitly if you want to control it.");
  return _jwtSecret;
}

module.exports = {
  getDb,
  closeDb,
  initDatabase,
  seedDatabase,
  getJwtSecret,
  camelizeRow,
  camelizeRows,
  isPostgres,
  dbGet,
  dbAll,
  dbRun,
  dbExec,
  sql,
  loadSqliteDriver,
};