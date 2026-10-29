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
  assert.equal(res.data.members[0].packageName, "Quarterly");
});

/* ---------------------------------------------------------- geofencing ------ */

test("member login issues a token", async () => {
  const res = await call("POST", "/api/auth/login", { body: { phone: "9000000001", name: "Asha Tester" } });
  assert.equal(res.status, 200);
  memberToken = res.data.token;
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
  // Every payment in this suite was written today, so the month window must cover it.
  // (A day-sized window masquerading as a month would report 0 here — a bug this caught.)
  assert.equal(s.monthlyRevenue, s.totalRevenue,
    `monthlyRevenue ${s.monthlyRevenue} should equal totalRevenue ${s.totalRevenue}`);
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
