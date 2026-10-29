/**
 * CORS regression tests.
 *
 * These boot the server in production mode on purpose. The main API suite runs
 * with NODE_ENV=test, where CORS is deliberately permissive, so it could never
 * catch a production-only regression in the origin policy — which is exactly how
 * the API ended up reflecting arbitrary origins in production while every test
 * passed.
 *
 * Both frontends are served from the app's own origin (API = ""), so production
 * must not grant cross-origin access unless CORS_ORIGINS names the origin.
 */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const LOCKED_PORT = 4312; // production, no CORS_ORIGINS
const ALLOWED_PORT = 4313; // production, CORS_ORIGINS allow-list
const ALLOWED_ORIGIN = "https://gym.example.com";

const children = [];
const tempDirs = [];

function boot(port, extraEnv) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rawfit-cors-"));
  tempDirs.push(dir);
  const child = spawn(process.execPath, ["src/server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      NODE_ENV: "production",
      SQLITE_PATH: path.join(dir, "test.db"),
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(child);
  return child;
}

async function waitFor(port) {
  for (let i = 0; i < 80; i += 1) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/ping`);
      if (res.ok) return true;
    } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`server on ${port} did not start`);
}

before(async () => {
  boot(LOCKED_PORT, {});
  boot(ALLOWED_PORT, { CORS_ORIGINS: ALLOWED_ORIGIN });
  await waitFor(LOCKED_PORT);
  await waitFor(ALLOWED_PORT);
});

after(() => {
  for (const c of children) c.kill();
  for (const d of tempDirs) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  }
});

test("production does NOT reflect an arbitrary Origin", async () => {
  const res = await fetch(`http://127.0.0.1:${LOCKED_PORT}/ping`, {
    headers: { Origin: "https://evil.example.com" },
  });
  assert.equal(res.status, 200, "the service itself stays reachable");
  assert.equal(
    res.headers.get("access-control-allow-origin"), null,
    "must not grant cross-origin access when no allow-list is configured"
  );
});

test("production does not answer a cross-origin preflight with a grant", async () => {
  const res = await fetch(`http://127.0.0.1:${LOCKED_PORT}/api/dashboard`, {
    method: "OPTIONS",
    headers: {
      Origin: "https://evil.example.com",
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Headers": "authorization",
    },
  });
  assert.equal(
    res.headers.get("access-control-allow-origin"), null,
    "a preflight from an unlisted origin must not be granted"
  );
});

test("ordinary same-origin traffic is unaffected", async () => {
  const res = await fetch(`http://127.0.0.1:${LOCKED_PORT}/ping`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, "ok");
});

test("security headers are still applied in production", async () => {
  const res = await fetch(`http://127.0.0.1:${LOCKED_PORT}/ping`);
  assert.ok(res.headers.get("strict-transport-security"), "HSTS should be present");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
});

test("an explicit allow-list grants only the listed origin", async () => {
  const allowed = await fetch(`http://127.0.0.1:${ALLOWED_PORT}/ping`, {
    headers: { Origin: ALLOWED_ORIGIN },
  });
  assert.equal(allowed.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN);

  const denied = await fetch(`http://127.0.0.1:${ALLOWED_PORT}/ping`, {
    headers: { Origin: "https://evil.example.com" },
  });
  assert.equal(
    denied.headers.get("access-control-allow-origin"), null,
    "an origin outside the allow-list must not be granted"
  );
});
