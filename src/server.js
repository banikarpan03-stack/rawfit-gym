"use strict";
/**
 * RAWfit Gym — Express API server.
 *
 * Security model
 * --------------
 * Every /api route requires a bearer token except POST /api/auth/login. Route-specific
 * guards are declared next to each route:
 *   allow("<capability>")    — the roles listed for that capability in CAN below
 *   requireSelf("memberId")  — the token's own id, or any staff role
 *
 * Errors
 * ------
 * Handlers throw ApiError for anything the caller should see. Everything else falls
 * through to a single error handler that logs the real cause and returns a generic
 * message — database internals are never echoed back to a client.
 */
const express = require("express");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const {
  initDatabase, seedDatabase, getJwtSecret, isPostgres,
  dbGet, dbAll, dbRun,
} = require("./database");

const app = express();

/* ------------------------------------------------------------------ *
 * Configuration
 * ------------------------------------------------------------------ */

const PORT = process.env.PORT || process.env.LIGHTNING_STUDIO_PORT || 3000;
const IS_PROD = process.env.NODE_ENV === "production";

const GYM_LAT = Number(process.env.GYM_LAT || 22.944691);
const GYM_LON = Number(process.env.GYM_LON || 88.5377882);
const GYM_RADIUS = Number(process.env.GYM_RADIUS || 100);

/** The gym runs on IST; every "today" boundary uses this zone, not UTC. */
const GYM_TZ = process.env.GYM_TZ || "Asia/Kolkata";

const PUBLIC = path.join(__dirname, "..", "public");
const EXERCISE_DIR = path.join(PUBLIC, "exercises");

/* ------------------------------------------------------------------ *
 * Errors
 * ------------------------------------------------------------------ */

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
    this.apiError = true;
  }
}

const badRequest = (msg) => new ApiError(400, msg);
const notFound = (msg = "Not found") => new ApiError(404, msg);
const forbidden = (msg = "Forbidden") => new ApiError(403, msg);

/**
 * Map a driver error onto a safe HTTP response. Unique-violation and FK-violation get
 * meaningful 409s; everything else becomes a generic 500 with the real cause logged
 * server-side only.
 */
function handleError(res, err, fallback = "Request failed") {
  if (err && err.apiError) {
    return res.status(err.status).json({ error: err.message });
  }
  const message = String((err && err.message) || "");
  const pgCode = err && err.code;
  if (pgCode === "23505" || /UNIQUE constraint failed|duplicate key|duplicate entry/i.test(message)) {
    return res.status(409).json({ error: "That value is already in use" });
  }
  if (pgCode === "23503" || /FOREIGN KEY constraint failed|violates foreign key/i.test(message)) {
    return res.status(409).json({ error: "Related record does not exist" });
  }
  console.error(`[error] ${fallback}:`, message);
  return res.status(500).json({ error: fallback });
}

/* ------------------------------------------------------------------ *
 * Middleware — headers, CORS, body parsing, rate limiting
 * ------------------------------------------------------------------ */

app.disable("x-powered-by");
app.set("trust proxy", true);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "geolocation=(self), camera=(), microphone=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  if (IS_PROD) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data: https:; " +
    "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; " +
    "frame-src https://www.youtube.com https://www.youtube-nocookie.com; " +
    "object-src 'none'; base-uri 'self'; form-action 'self'"
  );
  next();
});

// Deny cross-origin by default in production. Both frontends are served from this
// same origin and call the API with a relative base (API = ""), so nothing
// legitimate ever needs a CORS grant; reflecting arbitrary origins only widened
// the surface. An explicit CORS_ORIGINS allow-list opts specific origins back in,
// and development stays permissive for convenience.
const allowedOrigins = (process.env.CORS_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: IS_PROD ? (allowedOrigins.length ? allowedOrigins : false) : true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 600,
}));

app.use(express.json({ limit: "2mb" }));

/** Fixed-window in-memory limiter. Resets on restart — good enough for abuse damping. */
function createRateLimiter({ windowMs, max, keyOf }) {
  const buckets = new Map();
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (now - bucket.start >= windowMs) buckets.delete(key);
    }
  }, windowMs);
  sweeper.unref();

  return function rateLimit(req, res, next) {
    const key = keyOf(req);
    if (!key) return next();
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || now - bucket.start >= windowMs) {
      bucket = { start: now, count: 0 };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (bucket.count > max) {
      const retry = Math.ceil((bucket.start + windowMs - now) / 1000);
      res.setHeader("Retry-After", String(retry));
      return res.status(429).json({ error: `Too many requests. Try again in ${retry}s` });
    }
    return next();
  };
}

const clientIp = (req) => req.ip || req.socket.remoteAddress || "unknown";
// Limits are env-tunable so an operator can tighten or relax them without a redeploy.
const RATE_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 5 * 60_000);
const RATE_MAX = Number(process.env.RATE_LIMIT_MAX || 600);
const LOGIN_WINDOW_MS = Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS || 15 * 60_000);
const LOGIN_MAX = Number(process.env.LOGIN_RATE_LIMIT_MAX || 10);
const LOGIN_IP_MAX = Number(process.env.LOGIN_RATE_LIMIT_IP_MAX || 50);

const apiLimiter = createRateLimiter({ windowMs: RATE_WINDOW_MS, max: RATE_MAX, keyOf: clientIp });
// Login is keyed by IP *and* phone so credential stuffing against a single account is
// throttled even when clients share an IP (front desk PC, CGNAT, cafe wifi).
const loginLimiter = createRateLimiter({
  windowMs: LOGIN_WINDOW_MS, max: LOGIN_MAX,
  keyOf: (req) => `${clientIp(req)}|${(req.body && req.body.phone) || "nophone"}`,
});
const loginIpLimiter = createRateLimiter({
  windowMs: LOGIN_WINDOW_MS, max: LOGIN_IP_MAX, keyOf: clientIp,
});

app.use("/api", (req, res, next) => {
  if (req.path === "/auth/login") return next();
  return apiLimiter(req, res, next);
});

app.use(express.static(PUBLIC, {
  index: "index.html",
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-cache");
    } else if (/\.(webp|png|jpg|jpeg|gif|svg|woff2?|css|js|json)$/.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=86400");
    }
  },
}));

/* ------------------------------------------------------------------ *
 * Time helpers
 * ------------------------------------------------------------------ */

const nowIso = () => new Date().toISOString();

/** Calendar date in the gym's timezone, formatted YYYY-MM-DD. */
function todayGym(now = new Date()) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: GYM_TZ, year: "numeric", month: "2-digit", day: "2-digit",
  }).format(now);
}

/** UTC ISO bounds of "today" in the gym's timezone — half-open [start, end). */
function gymDayBounds(today = todayGym()) {
  const startMs = Date.parse(`${today}T00:00:00+05:30`);
  return {
    start: new Date(startMs).toISOString(),
    end: new Date(startMs + 86_400_000).toISOString(),
  };
}

/**
 * UTC ISO bounds of the current calendar month in the gym's timezone — half-open.
 * Separate from gymDayBounds, which spans exactly 24h: using a day window here would
 * report zero revenue for every day after the 1st.
 */
function gymMonthBounds(ym = todayGym().slice(0, 7)) {
  const [year, month] = ym.split("-").map(Number);
  const nextYear = month === 12 ? year + 1 : year;
  const nextMonth = month === 12 ? 1 : month + 1;
  const nextStart = `${nextYear}-${String(nextMonth).padStart(2, "0")}-01T00:00:00+05:30`;
  return {
    start: new Date(Date.parse(`${ym}-01T00:00:00+05:30`)).toISOString(),
    end: new Date(Date.parse(nextStart)).toISOString(),
  };
}

/**
 * SQL fragment comparing a stored timestamp column against a half-open ISO range.
 * PostgreSQL gets `::timestamptz` casts so legacy `2026-09-16 19:09:37+00` rows and new
 * ISO-8601 rows both compare correctly. SQLite only ever stores ISO-8601 here (its date
 * functions reject the legacy `+00` form, so no migration is needed on a fresh DB).
 */
function tsBetween(column) {
  if (isPostgres) {
    return `(${column}::timestamptz >= ?::timestamptz AND ${column}::timestamptz < ?::timestamptz)`;
  }
  return `(datetime(${column}) >= datetime(?) AND datetime(${column}) < datetime(?))`;
}

/** Single upper-bound comparison against a stored timestamp column. */
function tsBefore(column) {
  return isPostgres
    ? `${column}::timestamptz < ?::timestamptz`
    : `datetime(${column}) < datetime(?)`;
}

/* ------------------------------------------------------------------ *
 * Auth
 * ------------------------------------------------------------------ */

let _jwtSecretPromise = null;
function jwtSecret() {
  if (!_jwtSecretPromise) _jwtSecretPromise = getJwtSecret();
  return _jwtSecretPromise;
}

async function signToken(user) {
  return jwt.sign(
    { userId: user.id, role: user.role, name: user.name, phone: user.phone },
    await jwtSecret(),
    { expiresIn: "7d" }
  );
}

async function verifyToken(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  try {
    req.user = jwt.verify(header.slice(7), await jwtSecret());
    return next();
  } catch (err) {
    const expired = err && err.name === "TokenExpiredError";
    return res.status(401).json({ error: expired ? "Session expired" : "Invalid session" });
  }
}

/**
 * The three staff roles. MEMBER is the fourth, but members never reach these guards:
 * they only touch their own records, through requireSelf.
 */
const STAFF_ROLES = new Set(["ADMIN", "TRAINER", "RECEPTION"]);

/**
 * Who may do what, in one table. Declaring it here rather than sprinkling role checks
 * across thirty routes matters for two reasons: "what can a trainer actually do?" was
 * previously answerable only by reading every route, and the dashboard ended up showing
 * the gym's revenue to every staff member because nobody could see the whole picture.
 */
const CAN = {
  // Running the gym day to day
  viewDashboard:  new Set(["ADMIN", "TRAINER", "RECEPTION"]),
  viewMembers:    new Set(["ADMIN", "TRAINER", "RECEPTION"]),
  viewAttendance: new Set(["ADMIN", "TRAINER", "RECEPTION"]),
  notifyMembers:  new Set(["ADMIN", "TRAINER", "RECEPTION"]),
  viewPackages:   new Set(["ADMIN", "TRAINER", "RECEPTION"]),

  // The front desk: signing people up and keeping their records straight
  admitMember:    new Set(["ADMIN", "RECEPTION"]),
  editMember:     new Set(["ADMIN", "RECEPTION"]),

  // Training: prescribing work is the trainer's job, not the desk's
  assignCharts:   new Set(["ADMIN", "TRAINER"]),
  viewTemplates:  new Set(["ADMIN", "TRAINER"]),

  // Money. What the gym takes is the owner's business, not the desk's, so the revenue
  // summary and the payment ledger are admin-only. Recording a payment is a desk task
  // and exposes nothing, so reception keeps that.
  seeRevenue:     new Set(["ADMIN"]),
  viewLedger:     new Set(["ADMIN"]),
  recordPayment:  new Set(["ADMIN", "RECEPTION"]),

  // Owner-only
  manageStaff:    new Set(["ADMIN"]),
  managePackages: new Set(["ADMIN"]),
  curateLibrary:  new Set(["ADMIN"]),
  deleteMember:   new Set(["ADMIN"]),
  adminTools:     new Set(["ADMIN"]),
};

/** True when this user's role is listed for the capability. */
function can(user, capability) {
  const roles = CAN[capability];
  if (!roles) throw new Error(`Unknown capability: ${capability}`);
  return !!user && roles.has(String(user.role));
}

function allow(capability) {
  if (!CAN[capability]) throw new Error(`Unknown capability: ${capability}`);
  return (req, res, next) => {
    if (can(req.user, capability)) return next();
    return res.status(403).json({ error: "Your role does not allow this" });
  };
}

// Checks path params, query string and body — check-in/checkout carry memberId in the
// body rather than the URL, and a body-blind check would have locked members out.
// A missing id is a 400 (bad request); a present id that isn't yours is a 403.
function requireSelf(param) {
  return (req, res, next) => {
    const target = (req.params && req.params[param])
      || (req.query && req.query[param])
      || (req.body && req.body[param]);
    if (!target) return res.status(400).json({ error: `${param} is required` });
    const role = req.user.role;
    if (STAFF_ROLES.has(String(role)) || req.user.userId === target) return next();
    return res.status(403).json({ error: "You may only access your own records" });
  };
}

// Every /api route is authenticated from here on; login opts out explicitly. Individual
// routes add allow() / requireSelf on top of this.
app.use("/api", (req, res, next) => {
  if (req.method === "POST" && req.path === "/auth/login") return next();
  return verifyToken(req, res, next);
});

/* ------------------------------------------------------------------ *
 * Validation helpers
 * ------------------------------------------------------------------ */

function requireFields(body, fields) {
  const missing = fields.filter((f) => body[f] === undefined || body[f] === null || body[f] === "");
  if (missing.length) {
    throw badRequest(`Missing required field${missing.length > 1 ? "s" : ""}: ${missing.join(", ")}`);
  }
}

function asInt(value, { min = -Infinity, max = Infinity, label = "value" } = {}) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) throw badRequest(`${label} must be a whole number`);
  if (n < min || n > max) throw badRequest(`${label} must be between ${min} and ${max}`);
  return n;
}

function asNumber(value, { min = -Infinity, max = Infinity, label = "value" } = {}) {
  const n = Number(value);
  if (!Number.isFinite(n)) throw badRequest(`${label} must be a number`);
  if (n < min || n > max) throw badRequest(`${label} must be between ${min} and ${max}`);
  return n;
}

function asDate(value, label) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) throw badRequest(`${label} must be a valid date (YYYY-MM-DD)`);
  const iso = d.toISOString();
  if (iso < "1900-01-01" || iso > "2200-01-01") throw badRequest(`${label} is out of range`);
  return d;
}

function asPhone(value) {
  const phone = String(value).trim();
  if (!/^\d{7,15}$/.test(phone)) throw badRequest("Phone must be 7-15 digits");
  return phone;
}

/** Only http(s) and root-relative URLs survive — closes the javascript: URL vector. */
function asSafeUrl(value, { allowRelative = true, label = "URL" } = {}) {
  if (value === undefined || value === null || value === "") return null;
  const raw = String(value).trim();
  if (allowRelative && raw.startsWith("/")) return raw;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (_) {
    throw badRequest(`${label} must be a valid URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw badRequest(`${label} must use http or https`);
  }
  return raw;
}

const MAX_HISTORY = 50;

function appendHistory(existing, content) {
  let history = [];
  try {
    const parsed = JSON.parse(existing || "[]");
    if (Array.isArray(parsed)) history = parsed;
  } catch (_) {
    history = [];
  }
  history.push({ content, updatedAt: nowIso() });
  return JSON.stringify(history.slice(-MAX_HISTORY));
}

const affected = (result) => {
  if (!result) return 0;
  if (result.changes !== undefined) return Number(result.changes);
  if (result.rowCount !== undefined) return Number(result.rowCount);
  return 0;
};

/* ------------------------------------------------------------------ *
 * Auth routes
 * ------------------------------------------------------------------ */

app.post("/api/auth/login", loginIpLimiter, loginLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const phone = asPhone(body.phone || "");
    // `password` is the current field name; `name` is accepted for older clients
    // (the admin panel used to send the password under that key).
    const secret = String(body.password || body.name || "").trim();
    if (!secret) throw badRequest("Phone and password are required");

    const user = await dbGet(
      "SELECT id, uniqueCode, name, phone, password, role FROM users WHERE phone = ?", [phone]
    );
    // Identical message for "no such account" and "wrong secret" — no enumeration.
    const invalid = new ApiError(401, "Invalid phone or password");
    if (!user) throw invalid;

    // Everyone is verified against their stored hash. Members used to be matched on
    // their own name, so their "secret" was the one fact anyone who knew them had.
    if (!(await bcrypt.compare(secret, user.password))) throw invalid;
    // A member whose password is their phone number has no second factor at all —
    // the phone is the username. Legacy rows were seeded as hash(phone); refuse them
    // rather than let a known value stand in for a secret.
    if (user.role === "MEMBER" && secret === user.phone) {
      throw new ApiError(403, "Set a password first — ask the front desk to reset it");
    }

    const token = await signToken(user);
    res.json({
      token,
      user: { id: user.id, uniqueCode: user.uniqueCode, name: user.name, phone: user.phone, role: user.role },
    });
  } catch (err) {
    handleError(res, err, "Login failed");
  }
});

/** Change your own password (admin and member). */
app.post("/api/auth/password", async (req, res) => {
  try {
    const body = req.body || {};
    const { currentPassword, newPassword } = body;
    if (!currentPassword || !newPassword) throw badRequest("currentPassword and newPassword are required");
    if (String(newPassword).length < 6) throw badRequest("New password must be at least 6 characters");

    const user = await dbGet("SELECT id, password FROM users WHERE id = ?", [req.user.userId]);
    if (!user) throw notFound("User not found");
    if (!(await bcrypt.compare(String(currentPassword), user.password))) {
      // 400, not 401: the admin UI treats any 401 as an expired session and
      // logs the user out, so a mistyped current password would eject them.
      throw new ApiError(400, "Current password is incorrect");
    }

    await dbRun("UPDATE users SET password = ?, updatedAt = ? WHERE id = ?", [
      await bcrypt.hash(String(newPassword), 10), nowIso(), user.id,
    ]);
    res.json({ message: "Password updated" });
  } catch (err) {
    handleError(res, err, "Could not update password");
  }
});

/* ------------------------------------------------------------------ *
 * Staff accounts
 *
 * Members are people who train here; staff are people who run the place. Staff
 * live in the same users table (role distinguishes them) so a single login flow
 * serves everyone, but every mutation below guards against the two ways an
 * installation can lock itself out: removing the last admin, and an admin
 * removing their own account.
 * ------------------------------------------------------------------ */

const STAFF_SELECT =
  "SELECT id, uniqueCode, name, phone, role, createdAt FROM users WHERE role IN ('ADMIN', 'TRAINER', 'RECEPTION')";

app.get("/api/staff", allow("manageStaff"), async (req, res) => {
  try {
    const staff = await dbAll(`${STAFF_SELECT} ORDER BY createdAt ASC`);
    res.json({ staff });
  } catch (err) {
    handleError(res, err, "Could not load staff");
  }
});

app.post("/api/staff", allow("manageStaff"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["name", "phone", "password"]);

    const name = String(body.name).trim();
    if (name.length < 2) throw badRequest("Name is too short");

    const phone = asPhone(body.phone);
    const password = String(body.password);
    if (password.length < 6) throw badRequest("Password must be at least 6 characters");
    if (password === phone) throw badRequest("The password cannot be the phone number");

    const role = String(body.role || "RECEPTION").toUpperCase();
    if (!STAFF_ROLES.has(role)) throw badRequest("role must be ADMIN, TRAINER or RECEPTION");

    const clash = await dbGet("SELECT id FROM users WHERE phone = ?", [phone]);
    if (clash) throw new ApiError(409, "That phone number is already in use");

    const id = uuidv4();
    const uniqueCode = await generateUniqueCode();
    await dbRun(
      `INSERT INTO users (id, uniqueCode, name, phone, password, role, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, uniqueCode, name, phone, await bcrypt.hash(password, 10), role, nowIso(), nowIso()]
    );

    res.status(201).json({
      message: "Staff account created",
      staff: { id, uniqueCode, name, phone, role },
    });
  } catch (err) {
    handleError(res, err, "Could not create staff account");
  }
});

/** How many admins remain — used to refuse the change that would leave none. */
async function countAdmins() {
  const row = await dbGet("SELECT COUNT(*) AS n FROM users WHERE role = 'ADMIN'");
  return Number(row && row.n) || 0;
}

app.put("/api/staff/:id", allow("manageStaff"), async (req, res) => {
  try {
    const id = req.params.id;
    const body = req.body || {};

    const target = await dbGet("SELECT id, role, phone FROM users WHERE id = ?", [id]);
    if (!target) throw notFound("Staff account not found");
    if (!STAFF_ROLES.has(String(target.role))) throw badRequest("That account is not a staff account");

    const sets = [];
    const params = [];

    if (body.name !== undefined && body.name !== null && body.name !== "") {
      const name = String(body.name).trim();
      if (name.length < 2) throw badRequest("Name is too short");
      sets.push("name = ?");
      params.push(name);
    }

    if (body.phone !== undefined && body.phone !== null && body.phone !== "") {
      const phone = asPhone(body.phone);
      const clash = await dbGet("SELECT id FROM users WHERE phone = ? AND id <> ?", [phone, id]);
      if (clash) throw new ApiError(409, "That phone number is already in use");
      sets.push("phone = ?");
      params.push(phone);
    }

    if (body.password !== undefined && body.password !== null && body.password !== "") {
      const password = String(body.password);
      if (password.length < 6) throw badRequest("Password must be at least 6 characters");
      // Compare against the phone this account will have after the update.
      const candidatePhone = body.phone ? String(body.phone).trim() : String(target.phone || "");
      if (password === candidatePhone) {
        throw badRequest("The password cannot be the account's own phone number");
      }
      sets.push("password = ?");
      params.push(await bcrypt.hash(password, 10));
    }

    if (body.role !== undefined && body.role !== null && body.role !== "") {
      const role = String(body.role).toUpperCase();
      if (!STAFF_ROLES.has(role)) throw badRequest("role must be ADMIN, TRAINER or RECEPTION");
      if (target.role === "ADMIN" && role !== "ADMIN" && (await countAdmins()) <= 1) {
        throw badRequest("There must always be at least one admin");
      }
      sets.push("role = ?");
      params.push(role);
    }

    if (!sets.length) throw badRequest("Nothing to update");
    sets.push("updatedAt = ?");
    params.push(nowIso(), id);

    await dbRun(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`, params);
    res.json({ message: "Staff account updated" });
  } catch (err) {
    handleError(res, err, "Could not update staff account");
  }
});

app.delete("/api/staff/:id", allow("manageStaff"), async (req, res) => {
  try {
    const id = req.params.id;
    const target = await dbGet("SELECT id, role FROM users WHERE id = ?", [id]);
    if (!target) throw notFound("Staff account not found");
    if (!STAFF_ROLES.has(String(target.role))) throw badRequest("That account is not a staff account");
    if (target.id === req.user.userId) throw badRequest("You cannot remove your own account");
    if (target.role === "ADMIN" && (await countAdmins()) <= 1) {
      throw badRequest("There must always be at least one admin");
    }

    await dbRun("DELETE FROM users WHERE id = ?", [id]);
    res.json({ message: "Staff account removed" });
  } catch (err) {
    handleError(res, err, "Could not remove staff account");
  }
});

/**
 * Register a new member — admin only, because members are admitted by staff.
 * Writes the user and the matching payment row together so revenue reporting agrees
 * with admissions instead of running two independent ledgers.
 */
app.post("/api/auth/register", allow("admitMember"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["name", "phone", "packageId", "startDate"]);

    const name = String(body.name).trim();
    if (name.length < 2) throw badRequest("Name is too short");

    const phone = asPhone(body.phone);
    const pkg = await dbGet("SELECT id, duration, price FROM packages WHERE id = ?", [String(body.packageId)]);
    if (!pkg) throw notFound("Package not found");

    const start = asDate(body.startDate, "startDate");
    const hasExtra = body.extraDays !== undefined && body.extraDays !== null && body.extraDays !== "";
    const extraDays = hasExtra ? asInt(body.extraDays, { min: 0, max: 365, label: "extraDays" }) : 0;
    const hasDiscount = body.discount !== undefined && body.discount !== null && body.discount !== "";
    const discount = hasDiscount ? asNumber(body.discount, { min: 0, max: 100, label: "discount" }) : 0;

    const end = new Date(start.getTime());
    end.setUTCDate(end.getUTCDate() + pkg.duration + extraDays);
    const totalAmount = Math.max(0, Math.round(pkg.price * (1 - discount / 100) * 100) / 100);

    const existing = await dbGet("SELECT id FROM users WHERE phone = ?", [phone]);
    if (existing) throw new ApiError(409, "A member with that phone number already exists");

    // Members sign in with a real password. Use the supplied one, or generate a
    // readable one and return it exactly once so the front desk can hand it over.
    const supplied = body.password === undefined || body.password === null || body.password === ""
      ? null : String(body.password);
    if (supplied !== null && supplied.length < 6) {
      throw badRequest("Member password must be at least 6 characters");
    }
    // The phone is the username, so it cannot also be the password.
    if (supplied !== null && supplied === phone) {
      throw badRequest("The password cannot be the phone number");
    }
    const generatedPassword = supplied === null ? generateReadablePassword() : null;
    const effectivePassword = supplied || generatedPassword;

    const id = uuidv4();
    const uniqueCode = await generateUniqueCode();

    await dbRun(
      `INSERT INTO users (id, uniqueCode, name, phone, password, role, dob, address, email, gender,
         height, weight, medicalIssues, packageId, startDate, endDate, discount, extraDays,
         totalAmount, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, 'MEMBER', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id, uniqueCode, name, phone, await bcrypt.hash(effectivePassword, 10),
        body.dob ? asDate(body.dob, "dob").toISOString() : null,
        body.address ? String(body.address).slice(0, 500) : null,
        body.email ? String(body.email).slice(0, 200) : null,
        body.gender ? String(body.gender).slice(0, 40) : null,
        body.height === undefined || body.height === null || body.height === ""
          ? null : asNumber(body.height, { min: 0, max: 300, label: "height" }),
        body.weight === undefined || body.weight === null || body.weight === ""
          ? null : asNumber(body.weight, { min: 0, max: 500, label: "weight" }),
        body.medicalIssues ? String(body.medicalIssues).slice(0, 1000) : null,
        pkg.id, start.toISOString(), end.toISOString(),
        discount, extraDays, totalAmount, nowIso(), nowIso(),
      ]
    );

    // The fee belongs to the month the membership was sold for, not the month the
    // record happened to be typed in. Stamping today's date here meant that
    // backfilling a member whose membership had already lapsed still pushed their
    // fee into the current month's revenue. Default to the start date; paymentDate
    // overrides it for the genuine case where cash arrived on a different day.
    const paymentDate = body.paymentDate ? asDate(body.paymentDate, "paymentDate") : start;

    await dbRun(
      "INSERT INTO payments (id, memberId, amount, method, notes, date) VALUES (?, ?, ?, ?, ?, ?)",
      [uuidv4(), id, totalAmount, "admission", `Admission - ${name}`, paymentDate.toISOString()]
    );

    res.status(201).json({
      message: "Member registered",
      member: {
        id, uniqueCode, name, phone, totalAmount,
        startDate: start.toISOString(), endDate: end.toISOString(),
        // Present only when we generated it: shown once, never retrievable again.
        ...(generatedPassword ? { generatedPassword } : {}),
      },
    });
  } catch (err) {
    handleError(res, err, "Could not register member");
  }
});

/* ------------------------------------------------------------------ *
 * Dashboard
 * ------------------------------------------------------------------ */

app.get("/api/dashboard", allow("viewDashboard"), async (req, res) => {
  try {
    const today = todayGym();
    const day = gymDayBounds(today);
    const monthStart = gymMonthBounds(today.slice(0, 7));

    const totalMembersRow = await dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'MEMBER'");
    // endDate is a full ISO timestamp and `today` is a bare date, so lexicographic
    // comparison naturally means "valid through the end of that day".
    const activeRow = await dbGet(
      "SELECT COUNT(*) as count FROM users WHERE role = 'MEMBER' AND endDate >= ? AND endDate <> ''",
      [today]
    );
    const attendanceRow = await dbGet(
      `SELECT COUNT(*) as count FROM attendance WHERE ${tsBetween("checkIn")}`,
      [day.start, day.end]
    );
    // What the gym takes is the owner's information, so the figures are not merely
    // hidden in the UI — they are never queried, never put in the response, and so
    // cannot be read out of the network tab by a trainer or the front desk.
    let revenueRow = null;
    let monthlyRow = null;
    if (can(req.user, "seeRevenue")) {
      revenueRow = await dbGet("SELECT COALESCE(SUM(amount), 0) as total FROM payments");
      monthlyRow = await dbGet(
        `SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE ${tsBetween("date")}`,
        [monthStart.start, monthStart.end]
      );
    }

    const recentMembers = await dbAll(
      `SELECT u.id, u.name, u.phone, u.uniqueCode, u.startDate, u.endDate, u.createdAt,
              p.name AS packageName
       FROM users u LEFT JOIN packages p ON u.packageId = p.id
       WHERE u.role = 'MEMBER' ORDER BY u.createdAt DESC LIMIT 5`
    );
    const todayAttendees = await dbAll(
      `SELECT a.id, a.memberId, a.checkIn, a.checkOut, a.isManual,
              u.name AS memberName, u.uniqueCode AS memberCode
       FROM attendance a JOIN users u ON a.memberId = u.id
       WHERE ${tsBetween("a.checkIn")} ORDER BY a.checkIn DESC LIMIT 10`,
      [day.start, day.end]
    );

    res.json({
      stats: {
        totalMembers: Number(totalMembersRow.count) || 0,
        activeMembers: Number(activeRow.count) || 0,
        todayAttendance: Number(attendanceRow.count) || 0,
        // Absent rather than zeroed for other roles: a zero would claim the gym took
        // no money, which is a different and equally false statement.
        ...(revenueRow ? { totalRevenue: Number(revenueRow.total) || 0 } : {}),
        ...(monthlyRow ? { monthlyRevenue: Number(monthlyRow.total) || 0 } : {}),
      },
      recentMembers,
      todayAttendees,
    });
  } catch (err) {
    handleError(res, err, "Could not load dashboard");
  }
});

/* ------------------------------------------------------------------ *
 * Members
 * ------------------------------------------------------------------ */

// Explicit column list — never `u.*`, which would ship the bcrypt hash to clients.
const MEMBER_SELECT = `
  SELECT u.id, u.uniqueCode, u.name, u.phone, u.role, u.dob, u.address, u.email, u.gender,
         u.height, u.weight, u.medicalIssues, u.startDate, u.endDate, u.discount,
         u.extraDays, u.totalAmount, u.packageId, u.createdAt, u.updatedAt,
         p.name AS packageName, p.duration AS packageDuration, p.price AS packagePrice
  FROM users u LEFT JOIN packages p ON u.packageId = p.id`;

/** Columns a bulk update may touch. password/uniqueCode/id/createdAt are server-owned. */
const MEMBER_UPDATABLE = new Set([
  "name", "phone", "dob", "address", "email", "gender", "photo", "height", "weight",
  "medicalIssues", "startDate", "endDate", "discount", "extraDays", "totalAmount",
  "packageId", "role",
]);

app.get("/api/members", allow("viewMembers"), async (req, res) => {
  try {
    const q = String((req.query && req.query.q) || "").trim();
    let query = `${MEMBER_SELECT} WHERE u.role = 'MEMBER'`;
    const params = [];
    if (q) {
      query += " AND (LOWER(u.name) LIKE ? OR u.phone LIKE ? OR LOWER(u.uniqueCode) LIKE ?)";
      params.push(`%${q.toLowerCase()}%`, `%${q}%`, `%${q.toLowerCase()}%`);
    }
    query += " ORDER BY u.createdAt DESC";
    res.json({ members: await dbAll(query, params) });
  } catch (err) {
    handleError(res, err, "Could not load members");
  }
});

app.get("/api/members/:id", requireSelf("id"), async (req, res) => {
  try {
    const member = await dbGet(`${MEMBER_SELECT} WHERE u.id = ?`, [req.params.id]);
    if (!member || member.role !== "MEMBER") throw notFound("Member not found");

    const attendance = await dbAll(
      "SELECT id, memberId, checkIn, checkOut, isManual, markedBy FROM attendance WHERE memberId = ? ORDER BY checkIn DESC LIMIT 30",
      [req.params.id]
    );
    const charts = await dbAll(
      "SELECT id, memberId, type, content, startDate, endDate, history, createdAt, updatedAt FROM member_charts WHERE memberId = ? ORDER BY createdAt DESC",
      [req.params.id]
    );
    res.json({ member, attendance, charts });
  } catch (err) {
    handleError(res, err, "Could not load member");
  }
});

app.put("/api/members/:id", allow("editMember"), async (req, res) => {
  try {
    const body = req.body || {};
    const keys = Object.keys(body);
    if (keys.length === 0) throw badRequest("No fields to update");

    // Whitelist before interpolation: this route used to splice request keys straight
    // into the SET clause, which is a remote SQL-injection hole.
    for (const key of keys) {
      if (!MEMBER_UPDATABLE.has(key)) {
        if (key === "password") throw badRequest("Use POST /api/auth/password to change a password");
        throw badRequest(`Field "${key}" cannot be updated`);
      }
    }

    const sets = [];
    const params = [];
    for (const [key, raw] of Object.entries(body)) {
      let value;
      if (["height", "weight", "discount", "totalAmount"].includes(key)) {
        value = raw === null || raw === "" ? null
          : asNumber(raw, {
            min: key === "discount" ? 0 : key === "totalAmount" ? 0 : -Infinity,
            max: key === "discount" ? 100 : Infinity,
            label: key,
          });
      } else if (key === "extraDays") {
        value = raw === null || raw === "" ? 0 : asInt(raw, { min: 0, max: 365, label: key });
      } else if (["startDate", "endDate", "dob"].includes(key)) {
        value = raw === null || raw === "" ? null : asDate(raw, key).toISOString();
      } else if (key === "phone") {
        value = asPhone(raw);
      } else if (key === "role") {
        if (!["MEMBER", "ADMIN"].includes(raw)) throw badRequest("role must be MEMBER or ADMIN");
      } else {
        value = raw === null ? null : String(raw).slice(0, 2000);
      }
      sets.push(`${key} = ?`);
      params.push(value);
    }

    sets.push("updatedAt = ?");
    params.push(nowIso());

    // Switching a package must keep endDate and totalAmount describing the NEW package,
    // otherwise the stored membership dates silently disagree with what was billed.
    // Explicit body values still win over the derived ones.
    if (Object.prototype.hasOwnProperty.call(body, "packageId")) {
      const pkg = await dbGet("SELECT id, duration, price FROM packages WHERE id = ?", [String(body.packageId)]);
      if (!pkg) throw notFound("Package not found");

      const current = await dbGet(
        "SELECT startDate, discount, extraDays FROM users WHERE id = ?", [req.params.id]
      );
      if (!current) throw notFound("Member not found");

      const startIso = (body.startDate !== undefined && body.startDate !== null && body.startDate !== "")
        ? asDate(body.startDate, "startDate").toISOString()
        : current.startDate;
      const discountValue = (body.discount !== undefined && body.discount !== null && body.discount !== "")
        ? asNumber(body.discount, { min: 0, max: 100, label: "discount" })
        : Number(current.discount || 0);
      const extraValue = (body.extraDays !== undefined && body.extraDays !== null && body.extraDays !== "")
        ? asInt(body.extraDays, { min: 0, max: 365, label: "extraDays" })
        : Number(current.extraDays || 0);

      if (startIso) {
        const end = new Date(startIso);
        end.setUTCDate(end.getUTCDate() + pkg.duration + extraValue);
        const derived = {
          endDate: end.toISOString(),
          totalAmount: Math.max(0, Math.round(pkg.price * (1 - discountValue / 100) * 100) / 100),
        };
        for (const [key, value] of Object.entries(derived)) {
          if (Object.prototype.hasOwnProperty.call(body, key)) continue;
          sets.push(`${key} = ?`);
          params.push(value);
        }
      }
    }

    const result = await dbRun(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`, [...params, req.params.id]);
    if (!affected(result)) throw notFound("Member not found");
    res.json({ message: "Updated" });
  } catch (err) {
    handleError(res, err, "Could not update member");
  }
});

app.delete("/api/members/:id", allow("deleteMember"), async (req, res) => {
  try {
    const member = await dbGet("SELECT id FROM users WHERE id = ?", [req.params.id]);
    if (!member) throw notFound("Member not found");

    // Children are removed explicitly: the FKs carry no ON DELETE CASCADE, so deleting
    // the user first would fail the moment any attendance/payment/notification existed.
    for (const table of ["attendance", "payments", "notifications", "member_charts"]) {
      await dbRun(`DELETE FROM ${table} WHERE memberId = ?`, [req.params.id]);
    }
    await dbRun("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "Member deleted" });
  } catch (err) {
    handleError(res, err, "Could not delete member");
  }
});

/* ------------------------------------------------------------------ *
 * Packages
 * ------------------------------------------------------------------ */

app.get("/api/packages", allow("viewPackages"), async (req, res) => {
  try {
    const packages = await dbAll(
      "SELECT id, name, duration, price, description, isActive, createdAt FROM packages WHERE isActive = 1 ORDER BY price ASC"
    );
    res.json({ packages });
  } catch (err) {
    handleError(res, err, "Could not load packages");
  }
});

function readPackageBody(body) {
  const name = String((body && body.name) || "").trim();
  if (!name) throw badRequest("Package name is required");
  if (name.length > 80) throw badRequest("Package name is too long");
  return {
    name,
    duration: asInt(body.duration, { min: 1, max: 3650, label: "duration" }),
    price: asNumber(body.price, { min: 0, max: 1_000_000, label: "price" }),
    description: body.description ? String(body.description).slice(0, 500) : null,
  };
}

app.post("/api/packages", allow("managePackages"), async (req, res) => {
  try {
    const body = req.body || {};
    const fields = readPackageBody(body);

    if (body.id) {
      const result = await dbRun(
        "UPDATE packages SET name = ?, duration = ?, price = ?, description = ? WHERE id = ?",
        [fields.name, fields.duration, fields.price, fields.description, String(body.id)]
      );
      if (!affected(result)) throw notFound("Package not found");
      return res.json({ package: { id: body.id, ...fields } });
    }

    // Deterministic slug, but never silently collide with an existing package id.
    const base = fields.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "package";
    let id = base;
    if (await dbGet("SELECT id FROM packages WHERE id = ?", [id])) {
      if (await dbGet("SELECT id FROM packages WHERE LOWER(name) = ?", [fields.name.toLowerCase()])) {
        throw new ApiError(409, "A package with that name already exists");
      }
      id = `${base}-${crypto.randomBytes(3).toString("hex")}`;
    }

    await dbRun(
      "INSERT INTO packages (id, name, duration, price, description, isActive) VALUES (?, ?, ?, ?, ?, 1)",
      [id, fields.name, fields.duration, fields.price, fields.description]
    );
    return res.status(201).json({ package: { id, ...fields } });
  } catch (err) {
    return handleError(res, err, "Could not save package");
  }
});

app.put("/api/packages", allow("managePackages"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["id"]);
    const fields = readPackageBody(body);
    // isActive arrives as 0/1 from one client and true/false from another. Normalise
    // before the truthiness test — `0 !== false` used to reactivate a deactivated row.
    const isActive = body.isActive === undefined ? 1
      : (body.isActive === false || body.isActive === 0 || body.isActive === "0" || body.isActive === "false" ? 0 : 1);

    const result = await dbRun(
      "UPDATE packages SET name = ?, duration = ?, price = ?, description = ?, isActive = ? WHERE id = ?",
      [fields.name, fields.duration, fields.price, fields.description, isActive, String(body.id)]
    );
    if (!affected(result)) throw notFound("Package not found");
    res.json({ message: "Updated" });
  } catch (err) {
    handleError(res, err, "Could not update package");
  }
});

app.delete("/api/packages", allow("managePackages"), async (req, res) => {
  try {
    const id = req.body && req.body.id;
    if (!id) throw badRequest("id is required in the request body");
    const result = await dbRun("UPDATE packages SET isActive = 0 WHERE id = ?", [String(id)]);
    if (!affected(result)) throw notFound("Package not found");
    res.json({ message: "Deactivated" });
  } catch (err) {
    handleError(res, err, "Could not deactivate package");
  }
});

/* ------------------------------------------------------------------ *
 * Attendance
 * ------------------------------------------------------------------ */

app.get("/api/attendance", allow("viewAttendance"), async (req, res) => {
  try {
    const day = gymDayBounds();
    const attendance = await dbAll(
      `SELECT a.id, a.memberId, a.checkIn, a.checkOut, a.isManual, a.markedBy,
              u.name AS memberName, u.uniqueCode AS memberCode, u.phone AS memberPhone
       FROM attendance a JOIN users u ON a.memberId = u.id
       WHERE ${tsBetween("a.checkIn")} ORDER BY a.checkIn DESC`,
      [day.start, day.end]
    );
    res.json({ attendance, date: todayGym() });
  } catch (err) {
    handleError(res, err, "Could not load attendance");
  }
});

app.get("/api/attendance/history/:memberId", requireSelf("memberId"), async (req, res) => {
  try {
    const records = await dbAll(
      "SELECT id, memberId, checkIn, checkOut, isManual FROM attendance WHERE memberId = ? ORDER BY checkIn DESC LIMIT 60",
      [req.params.memberId]
    );
    res.json({ records });
  } catch (err) {
    handleError(res, err, "Could not load attendance history");
  }
});

app.post("/api/attendance/checkin", requireSelf("memberId"), async (req, res) => {
  try {
    const body = req.body || {};
    const memberId = String(body.memberId || "");
    if (!memberId) throw badRequest("memberId is required");

    const member = await dbGet("SELECT id, endDate, role FROM users WHERE id = ?", [memberId]);
    if (!member) throw notFound("Member not found");
    if (member.role !== "MEMBER") throw badRequest("Only members can check in");

    // Expired memberships no longer check in.
    if (member.endDate) {
      const endDay = String(member.endDate).slice(0, 10);
      if (endDay < todayGym()) throw new ApiError(403, "Membership has expired");
    }

    // Belt and braces alongside the partial unique index: if the index could not be
    // created (legacy duplicate rows), this read-then-insert guard still refuses a
    // second open check-in instead of silently creating one.
    const open = await dbGet(
      "SELECT id FROM attendance WHERE memberId = ? AND checkOut IS NULL", [memberId]
    );
    if (open) throw new ApiError(409, "Already checked in");

    // The geofence is enforced server-side. Coordinates are mandatory for members; an
    // admin doing a manual check-in on someone's behalf may omit them.
    const manual = req.user.role === "ADMIN" && body.isManual;
    if (!manual) {
      const lat = Number(body.latitude);
      const lon = Number(body.longitude);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
        throw badRequest("latitude and longitude are required to check in");
      }
      const distance = calcDistance(lat, lon, GYM_LAT, GYM_LON);
      if (distance > GYM_RADIUS) {
        throw new ApiError(403, `You must be at the gym to check in (${Math.round(distance)}m away, max ${GYM_RADIUS}m)`);
      }
    }

    const id = uuidv4();
    await dbRun(
      "INSERT INTO attendance (id, memberId, checkIn, isManual, markedBy, createdAt) VALUES (?, ?, ?, ?, ?, ?)",
      [id, memberId, nowIso(), manual ? 1 : 0, manual ? req.user.name : null, nowIso()]
    );
    const attendance = await dbGet(
      "SELECT id, memberId, checkIn, checkOut, isManual FROM attendance WHERE id = ?", [id]
    );
    res.status(201).json({ attendance });
  } catch (err) {
    const message = String((err && err.message) || "");
    if ((err && err.code === "23505") || message.includes("uq_open_attendance")) {
      return res.status(409).json({ error: "Already checked in" });
    }
    return handleError(res, err, "Could not check in");
  }
});

app.post("/api/attendance/checkout", requireSelf("memberId"), async (req, res) => {
  try {
    const memberId = String((req.body && req.body.memberId) || "");
    if (!memberId) throw badRequest("memberId is required");

    const open = await dbGet(
      "SELECT id FROM attendance WHERE memberId = ? AND checkOut IS NULL", [memberId]
    );
    if (!open) throw notFound("No open check-in");

    await dbRun("UPDATE attendance SET checkOut = ? WHERE id = ?", [nowIso(), open.id]);
    const attendance = await dbGet(
      "SELECT id, memberId, checkIn, checkOut, isManual FROM attendance WHERE id = ?", [open.id]
    );
    res.json({ attendance });
  } catch (err) {
    handleError(res, err, "Could not check out");
  }
});

app.get("/api/gps-check", async (req, res) => {
  try {
    const lat = Number(req.query && req.query.lat);
    const lon = Number(req.query && req.query.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      throw badRequest("lat and lon are required");
    }
    const distance = calcDistance(lat, lon, GYM_LAT, GYM_LON);
    res.json({ atGym: distance <= GYM_RADIUS, distance: Math.round(distance), radius: GYM_RADIUS });
  } catch (err) {
    return handleError(res, err, "Location check failed");
  }
});

/* ------------------------------------------------------------------ *
 * Exercises
 * ------------------------------------------------------------------ */

/**
 * Build the library from the thumbnail tree. Deterministic ids (`fs-<slug>`) plus
 * ON CONFLICT DO NOTHING make this idempotent: concurrent requests, retries and partial
 * failures can no longer duplicate rows (the original re-ran the whole seed on every
 * request until the background insert happened to finish).
 */
let exerciseSeedPromise = null;
function ensureExercisesSeeded() {
  if (exerciseSeedPromise) return exerciseSeedPromise;

  exerciseSeedPromise = (async () => {
    const fsMod = require("fs");
    if (!fsMod.existsSync(EXERCISE_DIR)) return 0;

    const rows = [];
    const categories = fsMod.readdirSync(EXERCISE_DIR)
      .filter((entry) => fsMod.statSync(path.join(EXERCISE_DIR, entry)).isDirectory());

    for (const category of categories) {
      const thumbs = fsMod.readdirSync(path.join(EXERCISE_DIR, category))
        .filter((file) => file.endsWith(".thumb.webp"));
      for (const thumb of thumbs) {
        const slug = thumb.replace(".thumb.webp", "");
        const name = slug.split("-")
          .map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(" ");
        rows.push([`fs-${slug}`, name, category, "beginner", category, `/exercises/${category}/${thumb}`]);
      }
    }
    if (!rows.length) return 0;

    const conflict = isPostgres ? " ON CONFLICT (id) DO NOTHING" : " ON CONFLICT(id) DO NOTHING";
    let inserted = 0;
    for (let i = 0; i < rows.length; i += 200) {
      const batch = rows.slice(i, i + 200);
      const placeholders = batch.map(() => "(?, ?, ?, ?, ?, ?)").join(", ");
      const result = await dbRun(
        `INSERT INTO exercises (id, name, category, difficulty, muscleGroup, gifUrl) VALUES ${placeholders}${conflict}`,
        batch.flat()
      );
      inserted += affected(result);
    }
    return inserted;
  })().catch((err) => {
    exerciseSeedPromise = null;
    throw err;
  });

  return exerciseSeedPromise;
}

app.get("/api/exercises", async (req, res) => {
  try {
    const category = String((req.query && req.query.category) || "").trim().toLowerCase();
    const q = String((req.query && req.query.q) || "").trim().toLowerCase();
    const limit = Math.min(Number(req.query && req.query.limit) || 5000, 5000);

    const countRow = await dbGet("SELECT COUNT(*) as count FROM exercises");
    if (Number(countRow.count) === 0) await ensureExercisesSeeded();

    let query = "SELECT id, name, category, description, videoUrl, gifUrl, difficulty, muscleGroup, createdAt FROM exercises";
    const params = [];
    const where = [];
    if (category && category !== "all") {
      where.push("LOWER(category) = ?");
      params.push(category);
    }
    if (q) {
      where.push("(LOWER(name) LIKE ? OR LOWER(COALESCE(muscleGroup, '')) LIKE ? OR LOWER(category) LIKE ?)");
      params.push(`%${q}%`, `%${q}%`, `%${q}%`);
    }
    if (where.length) query += ` WHERE ${where.join(" AND ")}`;
    query += " ORDER BY category, name LIMIT ?";
    params.push(limit);

    const exercises = await dbAll(query, params);
    const categories = await dbAll("SELECT DISTINCT category FROM exercises ORDER BY category");

    // 1300+ rows / ~470KB: short private cache so repeat loads revalidate instead of
    // refetching the whole library on every screen.
    res.setHeader("Cache-Control", "private, max-age=60");
    res.json({
      exercises,
      categories: categories.map((c) => c.category),
      total: exercises.length,
    });
  } catch (err) {
    handleError(res, err, "Could not load exercises");
  }
});

app.post("/api/exercises", allow("curateLibrary"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["name", "category"]);

    const payload = {
      name: String(body.name).trim(),
      category: String(body.category).trim().toLowerCase(),
      description: body.description ? String(body.description).slice(0, 2000) : null,
      videoUrl: asSafeUrl(body.videoUrl, { allowRelative: false, label: "videoUrl" }),
      gifUrl: asSafeUrl(body.gifUrl, { label: "gifUrl" }),
      difficulty: ["beginner", "intermediate", "advanced"].includes(body.difficulty)
        ? body.difficulty : "beginner",
      muscleGroup: body.muscleGroup ? String(body.muscleGroup).slice(0, 120) : null,
    };

    // Editing sends an id; creating does not. The old handler ignored `id` and inserted
    // a fresh row on every "save", so every edit produced a duplicate.
    if (body.id) {
      const result = await dbRun(
        "UPDATE exercises SET name = ?, category = ?, description = ?, videoUrl = ?, gifUrl = ?, difficulty = ?, muscleGroup = ? WHERE id = ?",
        [payload.name, payload.category, payload.description, payload.videoUrl, payload.gifUrl,
          payload.difficulty, payload.muscleGroup, String(body.id)]
      );
      if (!affected(result)) throw notFound("Exercise not found");
      return res.json({ exercise: { id: body.id, ...payload } });
    }

    const id = uuidv4();
    await dbRun(
      `INSERT INTO exercises (id, name, category, description, videoUrl, gifUrl, difficulty, muscleGroup, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, payload.name, payload.category, payload.description, payload.videoUrl, payload.gifUrl,
        payload.difficulty, payload.muscleGroup, nowIso()]
    );
    return res.status(201).json({ exercise: { id, ...payload } });
  } catch (err) {
    return handleError(res, err, "Could not save exercise");
  }
});

app.delete("/api/exercises", allow("curateLibrary"), async (req, res) => {
  try {
    const id = req.body && req.body.id;
    if (!id) throw badRequest("id is required in the request body");
    const result = await dbRun("DELETE FROM exercises WHERE id = ?", [String(id)]);
    if (!affected(result)) throw notFound("Exercise not found");
    res.json({ message: "Deleted" });
  } catch (err) {
    handleError(res, err, "Could not delete exercise");
  }
});

/* ------------------------------------------------------------------ *
 * Templates
 * ------------------------------------------------------------------ */

app.get("/api/templates", allow("viewTemplates"), async (req, res) => {
  try {
    const dietTemplates = await dbAll(
      "SELECT id, name, targetCalories, meals, description, createdAt FROM diet_templates ORDER BY name"
    );
    const workoutTemplates = await dbAll(
      "SELECT id, name, exercises, difficulty, description, createdAt FROM workout_templates ORDER BY name"
    );
    res.json({ dietTemplates, workoutTemplates });
  } catch (err) {
    handleError(res, err, "Could not load templates");
  }
});

app.post("/api/templates/diet", allow("curateLibrary"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["name"]);
    const meals = typeof body.meals === "string" ? body.meals : JSON.stringify(body.meals ?? {});
    if (meals.length > 200_000) throw badRequest("Meal plan is too large");

    const id = uuidv4();
    await dbRun(
      "INSERT INTO diet_templates (id, name, targetCalories, meals, description, createdAt) VALUES (?, ?, ?, ?, ?, ?)",
      [id, String(body.name).trim().slice(0, 120),
        body.targetCalories === undefined || body.targetCalories === ""
          ? 0 : asInt(body.targetCalories, { min: 0, max: 20000, label: "targetCalories" }),
        meals, body.description ? String(body.description).slice(0, 1000) : null, nowIso()]
    );
    res.status(201).json({ template: { id, name: String(body.name).trim() } });
  } catch (err) {
    handleError(res, err, "Could not save diet template");
  }
});

app.post("/api/templates/workout", allow("curateLibrary"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["name"]);
    const exercises = typeof body.exercises === "string" ? body.exercises : JSON.stringify(body.exercises ?? []);
    if (exercises.length > 200_000) throw badRequest("Workout is too large");

    const id = uuidv4();
    await dbRun(
      "INSERT INTO workout_templates (id, name, difficulty, exercises, description, createdAt) VALUES (?, ?, ?, ?, ?, ?)",
      [id, String(body.name).trim().slice(0, 120),
        ["beginner", "intermediate", "advanced"].includes(body.difficulty) ? body.difficulty : "beginner",
        exercises, body.description ? String(body.description).slice(0, 1000) : null, nowIso()]
    );
    res.status(201).json({ template: { id, name: String(body.name).trim() } });
  } catch (err) {
    handleError(res, err, "Could not save workout template");
  }
});

async function deleteTemplate(table, id) {
  const result = await dbRun(`DELETE FROM ${table} WHERE id = ?`, [id]);
  if (!affected(result)) throw notFound("Template not found");
}

app.delete("/api/templates/diet/:id", allow("curateLibrary"), async (req, res) => {
  try {
    await deleteTemplate("diet_templates", req.params.id);
    res.json({ ok: true });
  } catch (err) {
    handleError(res, err, "Could not delete template");
  }
});

app.delete("/api/templates/workout/:id", allow("curateLibrary"), async (req, res) => {
  try {
    await deleteTemplate("workout_templates", req.params.id);
    res.json({ ok: true });
  } catch (err) {
    handleError(res, err, "Could not delete template");
  }
});

/* ------------------------------------------------------------------ *
 * Charts
 * ------------------------------------------------------------------ */

app.get("/api/charts/member/:memberId", requireSelf("memberId"), async (req, res) => {
  try {
    const charts = await dbAll(
      "SELECT id, memberId, type, content, startDate, endDate, history, createdAt, updatedAt FROM member_charts WHERE memberId = ? ORDER BY createdAt DESC",
      [req.params.memberId]
    );
    res.json({ charts });
  } catch (err) {
    handleError(res, err, "Could not load charts");
  }
});

app.post("/api/charts", allow("assignCharts"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["memberId", "type", "content"]);

    // Stored and compared lowercase: the admin sends 'diet'/'workout' while the member
    // portal checked 'DIET'/'WORKOUT', so charts rendered as empty boxes.
    const type = String(body.type).toLowerCase();
    if (!["diet", "workout"].includes(type)) throw badRequest("type must be 'diet' or 'workout'");

    const member = await dbGet("SELECT id FROM users WHERE id = ? AND role = 'MEMBER'", [String(body.memberId)]);
    if (!member) throw notFound("Member not found");

    const content = typeof body.content === "string" ? body.content : JSON.stringify(body.content);
    if (content.length > 200_000) throw badRequest("Chart content is too large");

    const id = uuidv4();
    await dbRun(
      "INSERT INTO member_charts (id, memberId, type, content, startDate, endDate, history, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?)",
      [id, member.id, type, content,
        body.startDate ? asDate(body.startDate, "startDate").toISOString() : null,
        body.endDate ? asDate(body.endDate, "endDate").toISOString() : null,
        nowIso(), nowIso()]
    );
    res.status(201).json({ chart: { id, type } });
  } catch (err) {
    handleError(res, err, "Could not create chart");
  }
});

app.put("/api/charts/:id", allow("assignCharts"), async (req, res) => {
  try {
    const body = req.body || {};
    const existing = await dbGet("SELECT id, content, endDate FROM member_charts WHERE id = ?", [req.params.id]);
    if (!existing) throw notFound("Chart not found");

    const content = typeof body.content === "string" ? body.content : JSON.stringify(body.content ?? "");
    if (content.length > 200_000) throw badRequest("Chart content is too large");

    await dbRun(
      "UPDATE member_charts SET content = ?, history = ?, endDate = ?, updatedAt = ? WHERE id = ?",
      [
        content,
        appendHistory(existing.history, existing.content),
        body.endDate === undefined || body.endDate === null || body.endDate === ""
          ? existing.endDate : asDate(body.endDate, "endDate").toISOString(),
        nowIso(),
        existing.id,
      ]
    );
    res.json({ message: "Updated" });
  } catch (err) {
    handleError(res, err, "Could not update chart");
  }
});

app.delete("/api/charts/:id", allow("assignCharts"), async (req, res) => {
  try {
    const result = await dbRun("DELETE FROM member_charts WHERE id = ?", [req.params.id]);
    if (!affected(result)) throw notFound("Chart not found");
    res.json({ message: "Deleted" });
  } catch (err) {
    handleError(res, err, "Could not delete chart");
  }
});

/* ------------------------------------------------------------------ *
 * Notifications
 * ------------------------------------------------------------------ */

function assertOwnMember(req, memberId) {
  if (req.user.role === "ADMIN") return;
  if (req.user.userId !== memberId) throw forbidden("You may only access your own records");
}

app.get("/api/notifications", async (req, res) => {
  try {
    const memberId = String((req.query && req.query.memberId) || "");
    if (!memberId) throw badRequest("memberId is required");
    assertOwnMember(req, memberId);

    const notifications = await dbAll(
      "SELECT id, memberId, message, type, isRead, createdAt FROM notifications WHERE memberId = ? ORDER BY createdAt DESC LIMIT 50",
      [memberId]
    );
    res.json({ notifications });
  } catch (err) {
    handleError(res, err, "Could not load notifications");
  }
});

app.post("/api/notifications", allow("notifyMembers"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["memberId", "message"]);
    const member = await dbGet("SELECT id FROM users WHERE id = ?", [String(body.memberId)]);
    if (!member) throw notFound("Member not found");

    const id = uuidv4();
    await dbRun(
      "INSERT INTO notifications (id, memberId, message, type, isRead, createdAt) VALUES (?, ?, ?, ?, 0, ?)",
      [id, member.id, String(body.message).slice(0, 1000),
        String(body.type || "general").slice(0, 40), nowIso()]
    );
    res.status(201).json({ notification: { id } });
  } catch (err) {
    handleError(res, err, "Could not send notification");
  }
});

/** `isRead` previously existed in the schema but was never written by any route. */
app.put("/api/notifications/read", async (req, res) => {
  try {
    const memberId = String((req.body && req.body.memberId) || "");
    if (!memberId) throw badRequest("memberId is required");
    assertOwnMember(req, memberId);

    await dbRun("UPDATE notifications SET isRead = 1 WHERE memberId = ?", [memberId]);
    res.json({ message: "Marked as read" });
  } catch (err) {
    handleError(res, err, "Could not mark notifications as read");
  }
});

/* ------------------------------------------------------------------ *
 * Payments
 * ------------------------------------------------------------------ */

app.get("/api/payments", allow("viewLedger"), async (req, res) => {
  try {
    const limit = Math.min(Number((req.query && req.query.limit) || 100), 500);
    const offset = Math.max(Number((req.query && req.query.offset) || 0), 0);

    const payments = await dbAll(
      "SELECT id, memberId, amount, method, notes, date FROM payments ORDER BY date DESC LIMIT ? OFFSET ?",
      [limit, offset]
    );
    const totalRow = await dbGet("SELECT COUNT(*) as count FROM payments");
    const total = Number(totalRow.count) || 0;

    res.json({
      payments,
      pagination: { limit, offset, total, hasMore: offset + payments.length < total },
    });
  } catch (err) {
    handleError(res, err, "Could not load payments");
  }
});

app.post("/api/payments", allow("recordPayment"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["memberId", "amount"]);
    const member = await dbGet("SELECT id FROM users WHERE id = ? AND role = 'MEMBER'", [String(body.memberId)]);
    if (!member) throw notFound("Member not found");

    const amount = asNumber(body.amount, { min: 0, max: 10_000_000, label: "amount" });
    // Optional: record a payment that was actually received earlier. Without this
    // every row was stamped "now", so a historical entry landed in the month it
    // was keyed in rather than the month it was paid.
    const date = body.date ? asDate(body.date, "date") : new Date();
    const id = uuidv4();
    await dbRun(
      "INSERT INTO payments (id, memberId, amount, method, notes, date) VALUES (?, ?, ?, ?, ?, ?)",
      [id, member.id, amount, body.method ? String(body.method).slice(0, 40) : null,
        body.notes ? String(body.notes).slice(0, 500) : null, date.toISOString()]
    );
    res.status(201).json({ payment: { id, amount } });
  } catch (err) {
    handleError(res, err, "Could not record payment");
  }
});

/* ------------------------------------------------------------------ *
 * Foods — DB-backed, replacing the 196-row table hard-coded into admin.html
 * ------------------------------------------------------------------ */

app.get("/api/foods", async (req, res) => {
  try {
    const q = String((req.query && req.query.q) || "").trim().toLowerCase();
    let query = "SELECT id, name, serving, calories, category, createdAt FROM foods";
    const params = [];
    if (q) {
      query += " WHERE LOWER(name) LIKE ? OR LOWER(category) LIKE ?";
      params.push(`%${q}%`, `%${q}%`);
    }
    query += " ORDER BY category, name";
    res.json({ foods: await dbAll(query, params) });
  } catch (err) {
    handleError(res, err, "Could not load foods");
  }
});

app.post("/api/foods", allow("curateLibrary"), async (req, res) => {
  try {
    const body = req.body || {};
    requireFields(body, ["name", "category"]);

    const id = uuidv4();
    await dbRun(
      "INSERT INTO foods (id, name, serving, calories, category, createdAt) VALUES (?, ?, ?, ?, ?, ?)",
      [id, String(body.name).trim().slice(0, 120),
        body.serving ? String(body.serving).slice(0, 80) : null,
        asInt(body.calories ?? 0, { min: 0, max: 20000, label: "calories" }),
        String(body.category).trim().toLowerCase().slice(0, 60), nowIso()]
    );
    res.status(201).json({ food: { id } });
  } catch (err) {
    handleError(res, err, "Could not save food");
  }
});

app.delete("/api/foods", allow("curateLibrary"), async (req, res) => {
  try {
    const id = req.body && req.body.id;
    if (!id) throw badRequest("id is required in the request body");
    const result = await dbRun("DELETE FROM foods WHERE id = ?", [String(id)]);
    if (!affected(result)) throw notFound("Food not found");
    res.json({ message: "Deleted" });
  } catch (err) {
    handleError(res, err, "Could not delete food");
  }
});

/* ------------------------------------------------------------------ *
 * Diagnostics & maintenance
 * ------------------------------------------------------------------ */

app.get("/ping", (req, res) => {
  res.json({ status: "ok", time: nowIso() });
});

// Mounted under /api so it sits behind the same auth middleware as everything else —
// the original /dbcheck was public and reported database internals to anyone.
app.get("/api/dbcheck", allow("adminTools"), async (req, res) => {
  try {
    const exercises = await dbGet("SELECT COUNT(*) as count FROM exercises");
    const packages = await dbGet("SELECT COUNT(*) as count FROM packages");
    const members = await dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'MEMBER'");
    res.json({
      db: isPostgres ? "postgresql" : "sqlite",
      isPostgres,
      exercises: Number(exercises.count) || 0,
      packages: Number(packages.count) || 0,
      members: Number(members.count) || 0,
    });
  } catch (err) {
    handleError(res, err, "Database check failed");
  }
});

/** Re-runs every seed block. Idempotent, so it doubles as a repair tool. */
app.post("/api/admin/reseed", allow("adminTools"), async (req, res) => {
  try {
    const results = await seedDatabase();
    const exercisesSeeded = await ensureExercisesSeeded();
    res.json({ results, exercisesSeeded });
  } catch (err) {
    handleError(res, err, "Reseed failed");
  }
});

/* ------------------------------------------------------------------ *
 * SPA fallbacks and error boundary
 * ------------------------------------------------------------------ */

app.get("/member/*", (req, res) => {
  res.sendFile(path.join(PUBLIC, "member", "index.html"));
});

app.get("/admin*", (req, res) => {
  res.sendFile(path.join(PUBLIC, "admin.html"));
});

// JSON 404 for unmatched API routes — the clients call res.json() unconditionally, so an
// HTML 404 used to surface as a confusing parse error.
app.use("/api", (req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(PUBLIC, "index.html"));
});

// Single error boundary: JSON parse failures, oversized bodies and anything thrown
// outside a route handler all become JSON instead of an HTML stack trace.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Request body is not valid JSON" });
  }
  if (err && err.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body is too large" });
  }
  if (err && err.apiError) {
    return res.status(err.status).json({ error: err.message });
  }
  console.error("[unhandled]", err);
  return res.status(500).json({ error: "Internal server error" });
});

/* ------------------------------------------------------------------ *
 * Utilities
 * ------------------------------------------------------------------ */

function calcDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/**
 * Codes are `RM-YYYY-NNNN` — only 10,000 combinations, so collisions are expected past a
 * few hundred members. Each attempt is checked against the UNIQUE index and retried,
 * with a crypto-random suffix as the final fallback. (Math.random is no longer used.)
 */
/**
 * A short human-transcribable password: read off a printed slip at the front desk.
 * Excludes 0/O, 1/l/I and similar so it cannot be misread.
 */
function generateReadablePassword(len = 8) {
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const bytes = crypto.randomBytes(len);
  let out = "";
  for (let i = 0; i < len; i += 1) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

async function generateUniqueCode() {
  const year = new Date().getFullYear();
  for (let attempt = 0; attempt < 25; attempt += 1) {
    const code = `RM-${year}-${crypto.randomInt(0, 10000).toString().padStart(4, "0")}`;
    const clash = await dbGet("SELECT id FROM users WHERE uniqueCode = ?", [code]);
    if (!clash) return code;
  }
  return `RM-${year}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

/* ------------------------------------------------------------------ *
 * Background jobs
 * ------------------------------------------------------------------ */

async function autoCheckout() {
  try {
    const cutoff = new Date(Date.now() - 4 * 3600_000).toISOString();
    const stale = await dbAll(
      `SELECT a.id, a.memberId FROM attendance a
       WHERE a.checkOut IS NULL AND ${tsBefore("a.checkIn")}`,
      [cutoff]
    );
    for (const record of stale) {
      await dbRun("UPDATE attendance SET checkOut = ? WHERE id = ?", [nowIso(), record.id]);
      await dbRun(
        "INSERT INTO notifications (id, memberId, message, type, isRead, createdAt) VALUES (?, ?, ?, 'auto_checkout', 0, ?)",
        [uuidv4(), record.memberId,
          "Auto-checked out after 4 hours. Please check in again if you are still at the gym.",
          nowIso()]
      );
    }
    if (stale.length) console.log(`[auto-checkout] closed ${stale.length} stale check-in(s)`);
  } catch (err) {
    console.error("[auto-checkout] failed:", err.message);
  }
}

/* ------------------------------------------------------------------ *
 * Startup
 * ------------------------------------------------------------------ */

async function start() {
  let ready = true;

  try {
    await initDatabase();
  } catch (err) {
    ready = false;
    console.error("[startup] schema init failed:", err.message);
  }

  if (ready) {
    // Seeding is independent of schema init, and every block is guarded internally, so a
    // failure in one can no longer strand the others (the original failure mode that
    // left packages and templates empty in production).
    const seed = await seedDatabase();
    if (seed.errors.length) console.error("[startup] seed errors:", seed.errors.join(" | "));
    else console.log(`[startup] seeded: ${Object.keys(seed).filter((k) => seed[k] === true).join(", ")}`);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`RAWfit Gym server on http://0.0.0.0:${PORT}`);
    console.log(`  database: ${isPostgres ? "PostgreSQL" : "SQLite"}`);
    console.log(`  gym: ${GYM_LAT}, ${GYM_LON} (${GYM_RADIUS}m) | timezone: ${GYM_TZ}`);
    console.log(`  jwt secret: ${process.env.JWT_SECRET ? "from JWT_SECRET env" : "generated in app_settings"}`);
  });

  if (ready) {
    // Warm the library off the request path so the first page load is fast.
    ensureExercisesSeeded()
      .then((n) => { if (n) console.log(`[startup] exercise library seeded: ${n}`); })
      .catch((err) => console.error("[startup] exercise seed failed:", err.message));

    const timer = setInterval(autoCheckout, 60_000);
    timer.unref();
  } else {
    console.error("[startup] running with limited functionality - database unavailable");
  }
}

start().catch((err) => {
  console.error("[startup] fatal:", err);
  process.exit(1);
});

module.exports = {
  app,
  start,
  calcDistance,
  todayGym,
  gymDayBounds,
  gymMonthBounds,
  tsBetween,
  generateUniqueCode,
  ApiError,
};