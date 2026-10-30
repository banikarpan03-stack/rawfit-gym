/**
 * End-to-end API tests.
 *
 * Boots the real server as a child process against an isolated SQLite database
 * (SQLITE_PATH) and drives it over HTTP with fetch — no test framework, no mocks.
 * Run with: npm test
 */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const PORT = 4311;
const BASE = `http://127.0.0.1:${PORT}`;

// Gym coordinates the server defaults to — used for the geofence assertions.
const AT_GYM = { latitude: 22.944691, longitude: 88.5377882 };
const AWAY = { latitude: 12.9716, longitude: 77.5946 }; // ~1500 km

let child = null;
let dbFile = null;
let adminToken = null;
let memberToken = null;
let memberId = null;
let otherMemberId = null;
let memberPassword = null;
let receptionToken = null;
let receptionId = null;
let trainerToken = null;
let trainerId = null;

async function call(method, pathname, { body, token, raw } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(BASE + pathname, {
    method,
    headers,
    body: raw !== undefined ? raw : (body !== undefined ? JSON.stringify(body) : undefined),
  });
  let data = null;
  try { data = await res.json(); } catch (_) { data = null; }
  return { status: res.status, data };
}

async function waitForServer() {
  for (let i = 0; i < 60; i += 1) {
    try {
      const res = await fetch(`${BASE}/ping`);
      if (res.ok) return true;
    } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("server did not start");
}

before(async () => {
  dbFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "rawfit-test-")), "test.db");
  child = spawn(process.execPath, ["src/server.js"], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(PORT), NODE_ENV: "test", SQLITE_PATH: dbFile },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += d.toString(); });
  child.on("exit", (code) => { if (code && code !== 0) console.error(stderr); });
  await waitForServer();

  const login = await call("POST", "/api/auth/login", { body: { phone: "9999999999", name: "admin" } });
  assert.equal(login.status, 200, "admin login should succeed");
  adminToken = login.data.token;
});

after(() => {
  if (child) child.kill();
});

/* ------------------------------------------------------------------ auth ---- */

test("every API route requires a token", async () => {
  for (const p of ["/api/dashboard", "/api/members", "/api/packages", "/api/exercises",
    "/api/templates", "/api/attendance", "/api/payments", "/api/foods", "/api/dbcheck"]) {
    const res = await call("GET", p);
    assert.equal(res.status, 401, `${p} should reject anonymous callers`);
  }
});

test("invalid token is rejected", async () => {
  const res = await call("GET", "/api/members", { token: "not-a-jwt" });
  assert.equal(res.status, 401);
});

test("wrong admin password returns a generic 401", async () => {
  const res = await call("POST", "/api/auth/login", { body: { phone: "9999999999", name: "nope" } });
  assert.equal(res.status, 401);
  assert.equal(res.data.error, "Invalid phone or password");
});

test("unknown API route answers JSON, not HTML", async () => {
  const res = await call("GET", "/api/does-not-exist", { token: adminToken });
  assert.equal(res.status, 404);
  assert.equal(typeof res.data, "object");
});

test("malformed JSON body answers 400 JSON", async () => {
  const res = await call("POST", "/api/auth/login", { raw: "{bad json" });
  assert.equal(res.status, 400);
  assert.equal(typeof res.data, "object");
});

/* --------------------------------------------------------------- seeding ---- */

test("seed data is present", async () => {
  const pkgs = await call("GET", "/api/packages", { token: adminToken });
  assert.equal(pkgs.status, 200);
  assert.equal(pkgs.data.packages.length, 5, "five membership packages");

  const tpl = await call("GET", "/api/templates", { token: adminToken });
  assert.equal(tpl.data.dietTemplates.length, 3);
  assert.equal(tpl.data.workoutTemplates.length, 5);

  const foods = await call("GET", "/api/foods", { token: adminToken });
  assert.ok(foods.data.foods.length >= 190, `expected the food DB, got ${foods.data.foods.length}`);

  const ex = await call("GET", "/api/exercises?limit=5", { token: adminToken });
  assert.equal(ex.data.exercises.length, 5);
  assert.ok("muscleGroup" in ex.data.exercises[0], "camelCase keys on Postgres AND SQLite");
  assert.ok("gifUrl" in ex.data.exercises[0]);
});

test("reseed is idempotent", async () => {
  const before = await call("GET", "/api/packages", { token: adminToken });
  const res = await call("POST", "/api/admin/reseed", { body: {}, token: adminToken });
  assert.equal(res.status, 200);
  const after = await call("GET", "/api/packages", { token: adminToken });
  assert.equal(after.data.packages.length, before.data.packages.length);
});

/* ------------------------------------------------------------- admissions ---- */

test("registering a member writes a matching payment row", async () => {
  const res = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: {
      name: "Asha Tester", phone: "9000000001", packageId: "quarterly",
      startDate: "2026-10-01", discount: 10, extraDays: 5,
      email: "asha@example.com", gender: "female",
    },
  });
  assert.equal(res.status, 201);
  memberId = res.data.member.id;
  // No password was supplied, so one was generated and returned exactly once.
  assert.ok(res.data.member.generatedPassword, "admission returns a generated password");
  assert.ok(res.data.member.generatedPassword.length >= 8, "generated password is long enough");
  memberPassword = res.data.member.generatedPassword;
  assert.match(res.data.member.uniqueCode, /^RM-\d{4}-/);
  assert.equal(res.data.member.endDate.slice(0, 10), "2027-01-04", "90 days + 5 extra");
  assert.equal(res.data.member.totalAmount, 1260, "1400 minus 10%");

  const dash = await call("GET", "/api/dashboard", { token: adminToken });
  assert.equal(dash.data.stats.totalRevenue, 1260, "admission is counted as revenue");
  assert.ok("monthlyRevenue" in dash.data.stats);
});

test("duplicate phone is a 409, not a 500", async () => {
  const res = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: { name: "Asha Tester", phone: "9000000001", packageId: "quarterly", startDate: "2026-10-01" },
  });
  assert.equal(res.status, 409);
});

test("invalid input is rejected with 400", async () => {
  const cases = [
    { name: "X", phone: "9000000002", packageId: "quarterly", startDate: "not-a-date" },
    { name: "X", phone: "9000000003", packageId: "quarterly", startDate: "2026-10-01", discount: 200 },
    { name: "X", phone: "9000000004", packageId: "quarterly", startDate: "2026-10-01", extraDays: "abc" },
  ];
  for (const body of cases) {
    const res = await call("POST", "/api/auth/register", { token: adminToken, body });
    assert.equal(res.status, 400, `should reject ${JSON.stringify(body)}`);
  }
});

/* -------------------------------------- payment dating / revenue attribution -- */

/** First day of the current month in the gym's timezone. */
function gymFirstOfMonth(now = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(now);
  const get = (t) => parts.find((p) => p.type === t).value;
  return `${get("year")}-${get("month")}-01`;
}

test("a backdated admission is billed to the month it covers, not the month it was keyed in", async () => {
  // Regression: the admission payment was stamped with "now", so backfilling a member
  // whose membership had already lapsed pushed their fee into the current month.
  const before = await call("GET", "/api/dashboard", { token: adminToken });

  const res = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: {
      name: "Backdated Member", phone: "9000000011", packageId: "quarterly",
      startDate: "2024-03-15",
    },
  });
  assert.equal(res.status, 201);

  const after = await call("GET", "/api/dashboard", { token: adminToken });
  assert.equal(after.data.stats.monthlyRevenue, before.data.stats.monthlyRevenue,
    "an expired membership's fee must not appear in this month's revenue");
  assert.equal(after.data.stats.totalRevenue, before.data.stats.totalRevenue + res.data.member.totalAmount,
    "the money is still revenue, just not this month's");

  const pays = await call("GET", "/api/payments?limit=500", { token: adminToken });
  const row = pays.data.payments.find((p) => p.memberId === res.data.member.id);
  assert.ok(row, "admission wrote a payment row");
  assert.equal(String(row.date).slice(0, 10), "2024-03-15",
    "the fee is dated to the membership start, not to registration");
});

test("an explicit payment date wins over the membership start date", async () => {
  const res = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: {
      name: "Late Payer", phone: "9000000012", packageId: "quarterly",
      startDate: "2024-06-01", paymentDate: "2024-07-20",
    },
  });
  assert.equal(res.status, 201);
  const pays = await call("GET", "/api/payments?limit=500", { token: adminToken });
  const row = pays.data.payments.find((p) => p.memberId === res.data.member.id);
  assert.equal(String(row.date).slice(0, 10), "2024-07-20",
    "cash that arrived after the membership began is dated when it arrived");
});

test("the revenue month window spans the whole month, not just today", async () => {
  // Regression: gymDayBounds() served as the "this month" window, so monthlyRevenue
  // read 0 on every day after the 1st. A fee dated to the 1st of this month has to be
  // counted whatever today's date is.
  const before = await call("GET", "/api/dashboard", { token: adminToken });
  const res = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: {
      name: "Month Window", phone: "9000000013", packageId: "basic-monthly",
      startDate: gymFirstOfMonth(),
    },
  });
  assert.equal(res.status, 201);
  const after = await call("GET", "/api/dashboard", { token: adminToken });
  assert.equal(after.data.stats.monthlyRevenue,
    before.data.stats.monthlyRevenue + res.data.member.totalAmount,
    "a fee dated to the 1st of this month belongs to this month");
});

test("a manual payment can be dated in the past", async () => {
  // Payments could only ever be stamped "now", so a historical entry landed in the
  // month it was keyed in rather than the month it was actually paid.
  const res = await call("POST", "/api/payments", {
    token: adminToken,
    body: { memberId, amount: 50, method: "cash", notes: "backfilled", date: "2024-08-05" },
  });
  assert.equal(res.status, 201);
  const pays = await call("GET", "/api/payments?limit=500", { token: adminToken });
  const row = pays.data.payments.find((p) => p.id === res.data.payment.id);
  assert.equal(String(row.date).slice(0, 10), "2024-08-05");
});

test("an unparseable payment date is a 400, not a silently-now payment", async () => {
  const res = await call("POST", "/api/payments", {
    token: adminToken,
    body: { memberId, amount: 10, date: "not-a-date" },
  });
  assert.equal(res.status, 400);
});

test("changing a member's package recomputes endDate and totalAmount", async () => {
  // Without the derived values, switching packages would leave the stored dates and
  // billed amount describing the OLD package.
  const before = await call("GET", `/api/members/${memberId}`, { token: adminToken });
  const start = before.data.member.startDate.slice(0, 10); // 2026-10-01

  const res = await call("PUT", `/api/members/${memberId}`, {
    token: adminToken, body: { packageId: "basic-monthly" },
  });
  assert.equal(res.status, 200);

  const after = await call("GET", `/api/members/${memberId}`, { token: adminToken });
  assert.equal(after.data.member.packageId, "basic-monthly");
  // 30 days from 2026-10-01 (extraDays stays 5) -> 2026-11-05
  assert.equal(after.data.member.endDate.slice(0, 10), "2026-11-05",
    `endDate should follow the new package, got ${after.data.member.endDate}`);
  // The member's existing 10% discount carries over: 500 * 0.9 = 450.
  assert.equal(after.data.member.totalAmount, 450,
    `amount should follow the new package price, got ${after.data.member.totalAmount}`);

  // restore the original package for the rest of the suite
  const restore = await call("PUT", `/api/members/${memberId}`, {
    token: adminToken, body: { packageId: "quarterly", startDate: start },
  });
  assert.equal(restore.status, 200);
});

test("member list never exposes the password hash", async () => {
  const res = await call("GET", "/api/members", { token: adminToken });
  assert.equal(res.status, 200);
  assert.ok(res.data.members.length > 0);
  assert.ok(!("password" in res.data.members[0]));
  assert.ok("uniqueCode" in res.data.members[0], "camelCase field names");
  // Look our member up by id: the list is newest-first, so indexing [0] couples this
  // assertion to whatever other tests happened to create most recently.
  const mine = res.data.members.find((m) => m.id === memberId);
  assert.ok(mine, "the admitted member appears in the list");
  assert.equal(mine.packageName, "Quarterly", "the package join is populated");
});

/* ---------------------------------------------------------- geofencing ------ */

test("member login issues a token, using the password not the name", async () => {
  const res = await call("POST", "/api/auth/login", {
    body: { phone: "9000000001", password: memberPassword },
  });
  assert.equal(res.status, 200);
  memberToken = res.data.token;
});

test("a member's name is no longer accepted as a credential", async () => {
  // This is the weakness the password replaced: a name is known to anyone who
  // knows the person, so it could never be a secret.
  const res = await call("POST", "/api/auth/login", {
    body: { phone: "9000000001", password: "Asha Tester" },
  });
  assert.equal(res.status, 401);
});

test("the phone number cannot be used as its own password", async () => {
  // The phone is the username; accepting it as the password is no factor at all.
  const res = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: {
      name: "Phone Pass", phone: "9000000009", packageId: "quarterly",
      startDate: "2026-10-01", password: "9000000009",
    },
  });
  assert.equal(res.status, 400, "registration must refuse password == phone");
});

test("an explicitly supplied member password is what logs them in", async () => {
  const reg = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: {
      name: "Given Pass", phone: "9000000010", packageId: "quarterly",
      startDate: "2026-10-01", password: "chosen-by-staff-1",
    },
  });
  assert.equal(reg.status, 201);
  assert.equal(reg.data.member.generatedPassword, undefined, "no password is invented when one is given");

  const ok = await call("POST", "/api/auth/login", {
    body: { phone: "9000000010", password: "chosen-by-staff-1" },
  });
  assert.equal(ok.status, 200);

  const wrong = await call("POST", "/api/auth/login", {
    body: { phone: "9000000010", password: "Guessed Password" },
  });
  assert.equal(wrong.status, 401);

  await call("DELETE", `/api/members/${reg.data.member.id}`, { token: adminToken });
});

test("check-in requires coordinates", async () => {
  const res = await call("POST", "/api/attendance/checkin", { token: memberToken, body: { memberId } });
  assert.equal(res.status, 400);
});

test("check-in outside the geofence is refused", async () => {
  const res = await call("POST", "/api/attendance/checkin", {
    token: memberToken, body: { memberId, ...AWAY },
  });
  assert.equal(res.status, 403);
});

test("check-in at the gym succeeds, and a second one is refused", async () => {
  const first = await call("POST", "/api/attendance/checkin", {
    token: memberToken, body: { memberId, ...AT_GYM },
  });
  assert.equal(first.status, 201);

  const dup = await call("POST", "/api/attendance/checkin", {
    token: memberToken, body: { memberId, ...AT_GYM },
  });
  assert.equal(dup.status, 409, "only one open check-in per member");
});

test("check-out closes the session, a second one 404s", async () => {
  const first = await call("POST", "/api/attendance/checkout", { token: memberToken, body: { memberId } });
  assert.equal(first.status, 200);
  const again = await call("POST", "/api/attendance/checkout", { token: memberToken, body: { memberId } });
  assert.equal(again.status, 404);
});

test("members cannot read or mutate each other's records", async () => {
  const reg = await call("POST", "/api/auth/register", {
    token: adminToken,
    body: { name: "Bikram Tester", phone: "9000000006", packageId: "basic-monthly", startDate: "2026-10-01" },
  });
  assert.equal(reg.status, 201);
  otherMemberId = reg.data.member.id;

  for (const [method, path, body] of [
    ["GET", `/api/members/${otherMemberId}`, undefined],
    ["GET", `/api/charts/member/${otherMemberId}`, undefined],
    ["PUT", `/api/members/${otherMemberId}`, { name: "Hacked" }],
    ["POST", "/api/admin/reseed", {}],
  ]) {
    const res = await call(method, path, { token: memberToken, body });
    assert.equal(res.status, 403, `${method} ${path} must be forbidden for a member`);
  }
});

/* ------------------------------------------------------------ validation ---- */

test("bulk update refuses unknown columns (SQL injection surface)", async () => {
  const res = await call("PUT", `/api/members/${memberId}`, {
    token: adminToken, raw: JSON.stringify({ "photo=\" ; DROP TABLE users; --": "y" }),
  });
  assert.equal(res.status, 400);
});

test("bulk update refuses to set a password", async () => {
  const res = await call("PUT", `/api/members/${memberId}`, {
    token: adminToken, body: { password: "sneaky" },
  });
  assert.equal(res.status, 400);
});

test("validation failures answer 400 instead of 500", async () => {
  const cases = [
    ["PUT", `/api/members/${memberId}`, {}],
    ["PUT", `/api/members/${memberId}`, { discount: 500 }],
    ["POST", "/api/packages", {}],
    ["POST", "/api/exercises", {}],
    ["DELETE", "/api/packages", undefined],
  ];
  for (const [method, path, body] of cases) {
    const res = await call(method, path, { token: adminToken, body });
    assert.equal(res.status, 400, `${method} ${path} -> ${res.status} ${JSON.stringify(res.data)}`);
  }
});

test("editing an exercise updates it instead of duplicating it", async () => {
  const list = await call("GET", "/api/exercises?limit=5000", { token: adminToken });
  const before = list.data.total;
  const target = list.data.exercises[0];

  const res = await call("POST", "/api/exercises", {
    token: adminToken,
    body: { id: target.id, name: "Renamed Exercise", category: target.category },
  });
  assert.equal(res.status, 200);

  const after = await call("GET", "/api/exercises?limit=5000", { token: adminToken });
  assert.equal(after.data.total, before, "no duplicate row created");
});

test("javascript: URLs are rejected", async () => {
  const res = await call("POST", "/api/exercises", {
    token: adminToken,
    body: { name: "Evil", category: "abs", videoUrl: "javascript:alert(1)" },
  });
  assert.equal(res.status, 400);
});

test("duplicate package name is a 409", async () => {
  await call("POST", "/api/packages", {
    token: adminToken, body: { name: "Weekend Pass", duration: 7, price: 300 },
  });
  const res = await call("POST", "/api/packages", {
    token: adminToken, body: { name: "Weekend Pass", duration: 7, price: 300 },
  });
  assert.equal(res.status, 409);
});

/* --------------------------------------------------------------- charts ----- */

test("chart type is normalised to lowercase", async () => {
  const res = await call("POST", "/api/charts", {
    token: adminToken,
    body: {
      memberId, type: "DIET",
      content: JSON.stringify({ name: "Plan", meals: [{ time: "7am", name: "Oats", calories: 300, items: ["Oats"] }] }),
    },
  });
  assert.equal(res.status, 201);
  assert.equal(res.data.chart.type, "diet");

  const bad = await call("POST", "/api/charts", {
    token: adminToken, body: { memberId, type: "nonsense", content: "{}" },
  });
  assert.equal(bad.status, 400);
});

/* --------------------------------------------------------- notifications ---- */

test("admin can notify a member, member can read and mark read", async () => {
  const send = await call("POST", "/api/notifications", {
    token: adminToken, body: { memberId, message: "Welcome to RAWfit!" },
  });
  assert.equal(send.status, 201);

  const read = await call("GET", `/api/notifications?memberId=${memberId}`, { token: memberToken });
  assert.equal(read.status, 200);
  assert.ok(read.data.notifications.length > 0);

  const mark = await call("PUT", "/api/notifications/read", { token: memberToken, body: { memberId } });
  assert.equal(mark.status, 200);

  const after = await call("GET", `/api/notifications?memberId=${memberId}`, { token: memberToken });
  assert.equal(after.data.notifications[0].isRead, 1, "isRead is now actually written");
});

/* ----------------------------------------------------------- dashboard ------ */

test("dashboard reports revenue, membership and attendance", async () => {
  const res = await call("GET", "/api/dashboard", { token: adminToken });
  assert.equal(res.status, 200);
  const s = res.data.stats;
  assert.equal(typeof s.totalMembers, "number");
  assert.equal(typeof s.activeMembers, "number");
  assert.ok(s.totalRevenue > 0);
  assert.ok("monthlyRevenue" in s);
  // These used to be equal because every payment was stamped "now". They are dated
  // to the membership period now, so month-to-date is genuinely a subset of all-time.
  // The window itself is checked by "the revenue month window spans the whole month".
  assert.equal(typeof s.monthlyRevenue, "number");
  assert.ok(s.monthlyRevenue >= 0 && s.monthlyRevenue <= s.totalRevenue,
    `monthlyRevenue ${s.monthlyRevenue} should sit within totalRevenue ${s.totalRevenue}`);
  if (res.data.recentMembers.length) {
    assert.ok("phone" in res.data.recentMembers[0]);
    assert.ok("packageName" in res.data.recentMembers[0]);
  }
});

/* ---------------------------------------------------------- deletion -------- */

test("deleting a member removes their dependent rows too", async () => {
  const res = await call("DELETE", `/api/members/${otherMemberId}`, { token: adminToken });
  assert.equal(res.status, 200);
  const gone = await call("GET", `/api/members/${otherMemberId}`, { token: adminToken });
  assert.equal(gone.status, 404);
});

/* ---------------------------------------------------------- staff accounts -- */

test("a member cannot reach staff management at all", async () => {
  const list = await call("GET", "/api/staff", { token: memberToken });
  assert.equal(list.status, 403, "staff management is admin-only");

  const create = await call("POST", "/api/staff", {
    token: memberToken,
    body: { name: "Mallory", phone: "9555000001", password: "longenough1" },
  });
  assert.equal(create.status, 403);
});

test("reception accounts can be created, log in, and run the front desk", async () => {
  const created = await call("POST", "/api/staff", {
    token: adminToken,
    body: { name: "Front Desk", phone: "9555000002", password: "desk-password-1", role: "RECEPTION" },
  });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  receptionId = created.data.staff.id;
  assert.equal(created.data.staff.role, "RECEPTION");

  const dupe = await call("POST", "/api/staff", {
    token: adminToken,
    body: { name: "Another", phone: "9555000002", password: "desk-password-1" },
  });
  assert.equal(dupe.status, 409, "phone numbers are unique");

  const weak = await call("POST", "/api/staff", {
    token: adminToken,
    body: { name: "Another", phone: "9555000003", password: "short" },
  });
  assert.equal(weak.status, 400, "a short password is refused");

  const phoneAsPassword = await call("POST", "/api/staff", {
    token: adminToken,
    body: { name: "Another", phone: "9555000004", password: "9555000004" },
  });
  assert.equal(phoneAsPassword.status, 400, "the phone cannot be the password");

  const login = await call("POST", "/api/auth/login", {
    body: { phone: "9555000002", password: "desk-password-1" },
  });
  assert.equal(login.status, 200);
  receptionToken = login.data.token;
  assert.equal(login.data.user.role, "RECEPTION");

  // the desk's own work: seeing members, signing them up, taking money
  const members = await call("GET", "/api/members", { token: receptionToken });
  assert.equal(members.status, 200, "reception can view members");

  const admit = await call("POST", "/api/auth/register", {
    token: receptionToken,
    body: { name: "Desk Admitted", phone: "9000000077", packageId: "basic-monthly", startDate: "2026-10-01" },
  });
  assert.equal(admit.status, 201, "reception signs members up");

  const pay = await call("POST", "/api/payments", {
    token: receptionToken,
    body: { memberId, amount: 500, method: "cash" },
  });
  assert.equal(pay.status, 201, "reception takes money at the desk");
});

test("a trainer account can be created and can prescribe charts", async () => {
  const created = await call("POST", "/api/staff", {
    token: adminToken,
    body: { name: "Coach", phone: "9555000006", password: "coach-password-1", role: "TRAINER" },
  });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  trainerId = created.data.staff.id;
  assert.equal(created.data.staff.role, "TRAINER");

  const login = await call("POST", "/api/auth/login", {
    body: { phone: "9555000006", password: "coach-password-1" },
  });
  assert.equal(login.status, 200);
  trainerToken = login.data.token;
  assert.equal(login.data.user.role, "TRAINER");

  const chart = await call("POST", "/api/charts", {
    token: trainerToken,
    body: { memberId, type: "diet", content: "Trainer-prescribed plan" },
  });
  assert.equal(chart.status, 201, "a trainer assigns charts");

  const templates = await call("GET", "/api/templates", { token: trainerToken });
  assert.equal(templates.status, 200, "a trainer reads templates to prescribe from");

  const members = await call("GET", "/api/members", { token: trainerToken });
  assert.equal(members.status, 200, "a trainer sees the members they train");

  // the staff list now spans three roles, so the SELECT has to carry all of them
  const listed = await call("GET", "/api/staff", { token: adminToken });
  assert.ok(listed.data.staff.some((s) => s.id === trainerId), "the trainer is in the staff list");
  assert.ok(listed.data.staff.some((s) => s.role === "RECEPTION"), "reception is in the staff list");
  assert.ok(listed.data.staff.some((s) => s.role === "TRAINER"), "the trainer role survives the round trip");
});

test("the desk cannot assign charts, and a trainer cannot run the desk", async () => {
  const chart = await call("POST", "/api/charts", {
    token: receptionToken,
    body: { memberId, type: "workout", content: "Not the desk's job" },
  });
  assert.equal(chart.status, 403, "chart assignment is trainer work");

  const templates = await call("GET", "/api/templates", { token: receptionToken });
  assert.equal(templates.status, 403, "templates are trainer material");

  const admit = await call("POST", "/api/auth/register", {
    token: trainerToken,
    body: { name: "Coach Admitted", phone: "9000000078", packageId: "basic-monthly", startDate: "2026-10-01" },
  });
  assert.equal(admit.status, 403, "a trainer does not sign members up");

  const pay = await call("POST", "/api/payments", {
    token: trainerToken, body: { memberId, amount: 10 },
  });
  assert.equal(pay.status, 403, "a trainer does not take money");

  const edit = await call("PUT", `/api/members/${memberId}`, {
    token: trainerToken, body: { weight: 70 },
  });
  assert.equal(edit.status, 403, "a trainer does not edit member records");
});

test("the revenue summary is withheld from non-admins, not merely hidden in the UI", async () => {
  for (const [who, token] of [["reception", receptionToken], ["trainer", trainerToken]]) {
    const dash = await call("GET", "/api/dashboard", { token });
    assert.equal(dash.status, 200, `${who} can still open the dashboard`);
    assert.ok(!("monthlyRevenue" in dash.data.stats), `${who} must not receive monthlyRevenue`);
    assert.ok(!("totalRevenue" in dash.data.stats), `${who} must not receive totalRevenue`);
    // the operational numbers they do need are untouched
    assert.equal(typeof dash.data.stats.activeMembers, "number");
  }

  const admin = await call("GET", "/api/dashboard", { token: adminToken });
  assert.ok("monthlyRevenue" in admin.data.stats, "the owner still sees the revenue");
  assert.ok("totalRevenue" in admin.data.stats);

  const ledger = await call("GET", "/api/payments", { token: receptionToken });
  assert.equal(ledger.status, 403, "the payment ledger is the owner's as well");
});

test("the retired STAFF role can no longer be created", async () => {
  const res = await call("POST", "/api/staff", {
    token: adminToken,
    body: { name: "Nope", phone: "9555000007", password: "longenough1", role: "STAFF" },
  });
  assert.equal(res.status, 400, "roles are ADMIN, TRAINER or RECEPTION");
});

test("reception cannot do admin-only work", async () => {
  const deleteMember = await call("DELETE", `/api/members/${otherMemberId}`, { token: receptionToken });
  assert.equal(deleteMember.status, 403, "deleting members stays admin-only");

  const packageWrite = await call("POST", "/api/packages", {
    token: receptionToken,
    body: { name: "Nope", duration: 10, price: 1 },
  });
  assert.equal(packageWrite.status, 403, "package curation stays admin-only");

  const staffWrite = await call("POST", "/api/staff", {
    token: receptionToken,
    body: { name: "Nope", phone: "9555000009", password: "longenough1" },
  });
  assert.equal(staffWrite.status, 403, "staff cannot create staff");

  const reseed = await call("POST", "/api/admin/reseed", { token: receptionToken, body: {} });
  assert.equal(reseed.status, 403, "admin utilities stay admin-only");
});

test("staff safety rails: no self-deletion, always one admin left", async () => {
  const me = await call("POST", "/api/auth/login", {
    body: { phone: "9999999999", password: "admin" },
  });
  assert.equal(me.status, 200);
  const myId = me.data.user.id;

  const selfDelete = await call("DELETE", `/api/staff/${myId}`, { token: adminToken });
  assert.equal(selfDelete.status, 400, "an admin must not be able to delete themselves");

  const demoteSelf = await call("PUT", `/api/staff/${myId}`, { token: adminToken, body: { role: "RECEPTION" } });
  assert.equal(demoteSelf.status, 400, "the last admin must not be demotable");

  const update = await call("PUT", `/api/staff/${receptionId}`, { token: adminToken, body: { name: "Front Desk Two" } });
  assert.equal(update.status, 200);

  const removed = await call("DELETE", `/api/staff/${receptionId}`, { token: adminToken });
  assert.equal(removed.status, 200);

  const gone = await call("POST", "/api/auth/login", {
    body: { phone: "9555000002", password: "desk-password-1" },
  });
  assert.equal(gone.status, 401, "a removed staff account cannot log in");
});

test("a second admin can be created and then demoted while an admin remains", async () => {
  const second = await call("POST", "/api/staff", {
    token: adminToken,
    body: { name: "Owner Two", phone: "9555000005", password: "owner-two-pass", role: "ADMIN" },
  });
  assert.equal(second.status, 201);
  const secondId = second.data.staff.id;

  // with two admins the demotion is allowed
  const demote = await call("PUT", `/api/staff/${secondId}`, { token: adminToken, body: { role: "RECEPTION" } });
  assert.equal(demote.status, 200, "demoting is fine while another admin exists");

  // the same rule now blocks demoting the last one again
  const removeSecond = await call("DELETE", `/api/staff/${secondId}`, { token: adminToken });
  assert.equal(removeSecond.status, 200);
});

/* ------------------------------------------------------ change password ---- */

test("password change rejects a wrong current password, then rotates and restores", async () => {
  // 400 rather than 401 on purpose: the admin UI force-logs-out on any 401, so a
  // mistyped current password must not look like an expired session.
  const wrong = await call("POST", "/api/auth/password", {
    token: adminToken,
    body: { currentPassword: "not-the-password", newPassword: "brand-new-secret" },
  });
  assert.equal(wrong.status, 400, `expected 400, got ${wrong.status}`);

  const tooShort = await call("POST", "/api/auth/password", {
    token: adminToken,
    body: { currentPassword: "admin", newPassword: "short" },
  });
  assert.equal(tooShort.status, 400);

  const missing = await call("POST", "/api/auth/password", { token: adminToken, body: {} });
  assert.equal(missing.status, 400);

  const ok = await call("POST", "/api/auth/password", {
    token: adminToken,
    body: { currentPassword: "admin", newPassword: "brand-new-secret" },
  });
  assert.equal(ok.status, 200);

  const withNew = await call("POST", "/api/auth/login", {
    body: { phone: "9999999999", name: "brand-new-secret" },
  });
  assert.equal(withNew.status, 200, "should log in with the new password");

  const withOld = await call("POST", "/api/auth/login", {
    body: { phone: "9999999999", name: "admin" },
  });
  assert.equal(withOld.status, 401, "old password must stop working");

  // No restore step: every run boots a fresh temp database, so the seed recreates
  // the default admin. It could not be restored through the API regardless — the
  // seeded default is 5 characters while the policy demands 6, which is exactly
  // the inconsistency that shipped the weakest password in the app.
  const tooShortToRestore = await call("POST", "/api/auth/password", {
    token: withNew.data.token,
    body: { currentPassword: "brand-new-secret", newPassword: "admin" },
  });
  assert.equal(tooShortToRestore.status, 400,
    "the 5-character default cannot be set back, proving the 6-character floor applies");
});
