# RAWfit Gym Management

Member admissions, GPS-verified attendance, an exercise library with GIF previews, and
diet/workout chart assignment for RAWfit Gym (Dighapara, West Bengal).

Two frontends, one JSON API, no build step:

| Surface | Path | Who |
|---|---|---|
| Landing page | `/` | anyone |
| Admin panel | `/admin.html` | staff (ADMIN role) |
| Member portal | `/member/` | members |

---

## Quick start

```bash
npm install
npm start          # http://localhost:3000
```

With no `DATABASE_URL` set, the app runs entirely on SQLite (file at `data/gym.db`) and
seeds itself on first boot. Open `http://localhost:3000/admin.html` and sign in with the
seeded admin account:

- **Phone:** `9999999999`
- **Password:** `admin` — *set `ADMIN_PASSWORD` before your first real deploy, or change
  it from the admin panel afterwards.*

```bash
npm test           # end-to-end API tests (spins up its own server + database)
npm run lint       # ESLint
node scripts/check-frontend-js.js   # syntax + output-encoding check on the frontends
```

---

## Architecture

```
src/
  server.js      Express app: 40+ routes, auth, geofencing, rate limiting, error boundary
  database.js    Dual-dialect data layer (PostgreSQL | SQLite), DDL, seeds, JWT secret
public/
  index.html         landing page
  admin.html         admin SPA  (vanilla JS, 10 screens)
  member/index.html  member portal (vanilla JS, 5 screens)
  exercises/         1,323 exercise thumbnails across 19 muscle categories
data/
  foods.json         194-item Indian/Bengali food database (seeds the `foods` table)
test/
  api.test.js    end-to-end tests against a real server process
scripts/
  check-frontend-js.js   extracts inline <script> blocks, syntax-checks and audits encoding
```

### Database dialects

`DATABASE_URL` picks the dialect at runtime:

- **set** → PostgreSQL (production, Neon) via `pg` Pool
- **unset** → SQLite via the built-in `node:sqlite`, falling back to `better-sqlite3`

Both are normalised through `camelizeRow()` in `database.js`. This matters because
PostgreSQL folds unquoted identifiers to lowercase (`createdAt` → `createdat`,
`AS packageName` → `packagename`) while SQLite preserves declared case; the frontends
are written against camelCase, so every row is re-cased on the way out. **If you add a
column or alias, add its canonical camelCase name to `CAMEL_FIELDS`.**

Tables: `packages`, `users`, `attendance`, `exercises`, `diet_templates`,
`workout_templates`, `member_charts`, `notifications`, `payments`, `foods`,
`app_settings`.

Seeding is idempotent and self-healing: every block is independently guarded, packages
are upserted (not "insert if empty"), and exercise rows use deterministic `fs-<slug>`
primary keys with `ON CONFLICT DO NOTHING`, so concurrent boots can never duplicate.
`POST /api/admin/reseed` re-runs all of it on demand.

### Domain rules

- **Geofence** — check-in requires coordinates; the server recomputes the haversine
  distance against `GYM_LAT`/`GYM_LON` within `GYM_RADIUS` metres. A client that omits
  coordinates is refused (admins doing a manual check-in may omit them).
- **Timezone** — every "today" boundary (attendance, monthly revenue, membership expiry)
  uses `GYM_TZ` (default `Asia/Kolkata`), not the server's UTC clock.
- **Auto check-out** — a background job closes check-ins older than 4 hours and notifies
  the member.
- **Membership expiry** — an expired member cannot check in.
- **Admissions** — registering a member writes the `users` row and the matching `payments`
  row together, so revenue reporting always agrees with admissions.

---

## Configuration

Everything is environment-driven — see [`.env.example`](.env.example) for the full list.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string; unset = SQLite |
| `JWT_SECRET` | JWT signing key; unset = generated once and stored in `app_settings` |
| `ADMIN_PASSWORD` | Password for the seeded admin (default `admin`) |
| `CORS_ORIGINS` | Comma-separated allow-list, enforced when `NODE_ENV=production` |
| `GYM_LAT` / `GYM_LON` / `GYM_RADIUS` | Geofence centre and radius (metres) |
| `GYM_TZ` | IANA timezone for all day boundaries |
| `RATE_LIMIT_*`, `LOGIN_RATE_LIMIT_*` | Throttling windows and caps |

---

## Deployment (Render)

`render.yaml` describes the service:

```yaml
buildCommand: npm install --production
startCommand: node src/server.js
healthCheckPath: /ping
```

1. Set `DATABASE_URL`, `JWT_SECRET` and `ADMIN_PASSWORD` in Render's Environment tab.
2. Deploy — the schema creates itself and seeds on first boot.
3. Log in and change the admin password.

Local development needs no Render; SQLite is the default.

---

## API

All `/api/*` routes require `Authorization: Bearer <token>` except `POST /api/auth/login`.
On top of that, mutations and admin reads additionally require the `ADMIN` role, and
member-scoped routes require the token's own id (or an admin).

| Area | Routes |
|---|---|
| Auth | `POST /api/auth/login`, `POST /api/auth/password`, `POST /api/auth/register` *(admin)* |
| Dashboard | `GET /api/dashboard` *(admin)* |
| Members | `GET/POST /api/members`, `GET/PUT/DELETE /api/members/:id` *(admin; GET :id allows self)* |
| Packages | `GET/POST/PUT/DELETE /api/packages` *(admin)* |
| Attendance | `GET /api/attendance`, `GET /api/attendance/history/:memberId`, `POST /api/attendance/checkin`, `POST /api/attendance/checkout` |
| Exercises | `GET /api/exercises`, `POST/DELETE /api/exercises` *(write: admin)* |
| Templates | `GET /api/templates`, `POST/DELETE /api/templates/{diet,workout}` *(admin)* |
| Charts | `GET /api/charts/member/:memberId`, `POST/PUT/DELETE /api/charts` *(write: admin)* |
| Notifications | `GET /api/notifications`, `POST /api/notifications` *(admin)*, `PUT /api/notifications/read` |
| Payments | `GET/POST /api/payments` *(admin)* |
| Foods | `GET /api/foods`, `POST/DELETE /api/foods` *(write: admin)* |
| Misc | `GET /ping`, `GET /api/dbcheck` *(admin)*, `POST /api/admin/reseed` *(admin)* |

Error responses are always JSON: `400` validation, `401` auth, `403` forbidden,
`404` missing, `409` conflict, `429` rate-limited, `500` generic. Database internals are
logged server-side and never echoed to a client.

---

## Security model

- **Authentication** on every route; `verifyToken` plus `requireAdmin` / `requireSelf`.
- **Authorization** — members can only read their own records; IDs in the URL are checked
  against the token.
- **Output encoding** — every value written into `innerHTML` passes through `esc()`
  (text), `jsq()` (a JS string inside an HTML attribute) or `safeUrl()` (URLs). The
  checker in `scripts/check-frontend-js.js` fails CI if an interpolation is added
  without one.
- **SQL** — fully parameterised. The one bulk-update route whitelists its column names
  instead of interpolating request keys.
- **URLs** — `http:`/`https:`/root-relative only, so `javascript:` hrefs cannot survive.
- **Rate limiting** — login is throttled per IP *and* per phone number; the API has a
  global window.
- **Headers** — CSP, `X-Frame-Options`, `nosniff`, referrer policy, HSTS in production.
- **Secrets** — no credentials in the repo; `.env` is gitignored and `.env.example`
  documents every variable with placeholders.

### Known residual risk

Member login is **phone + name** by design — gym members are issued no password, and
changing that would lock them out. Names are therefore a bearer credential for a member
account. Attempts are rate-limited per phone and error messages do not reveal whether an
account exists. The backend fully supports optional per-member passwords
(`POST /api/auth/password`, bcrypt-stored) if you later want to require one at admission.

---

## History

The project was originally written with an AI coding assistant; this repository is the
recovered source (the original working directory was lost with its hard drive). A full
audit found 63 issues — no authentication on any route, SQL injection in a member-update
handler, password hashes returned in API responses, unescaped output throughout both
frontends, an empty packages table that made admission impossible, and PostgreSQL's
identifier lowercasing silently breaking camelCase reads in the UI. All of them are
addressed here, with the end-to-end tests in `test/api.test.js` acting as the regression
guard.