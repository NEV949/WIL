# The console (PWA)

The console is a progressive web application for the Oracle-HCM auto-coding
engine. It is built with React 19, TypeScript and Vite, using `react-router-dom`
for routing. It has no heavy UI frameworks: the footprint is kept light so it
builds and runs efficiently even on low-spec laptops.

The frontend compiles to plain static files that are served directly by the
FastAPI gateway at `/`. Because the page and the API share a single origin,
authentication cookies and CSRF tokens work seamlessly without cross-origin
coordination.

---

## Architecture & Safety

- **Same-origin serving**: The production build in `web/dist` is served by the
  FastAPI gateway. The API routes match first; unmatched routes fall back to the
  SPA shell (`index.html`) with strict `Content-Security-Policy` and `no-store`
  caching headers.
- **Authentication**: Cookie-based session using an `HttpOnly`, `SameSite=Strict`
  cookie. The session token never leaves the browser. On any `401 Unauthorized`
  response from the API, the console automatically drops state and redirects to
  the login screen.
- **CSRF protection**: On login, the gateway supplies a `csrf_token`. The console
  holds this token in memory and tab-scoped `sessionStorage`. State-changing
  requests (`POST`) send it back via the `X-CSRF-Token` header.
- **No secrets in storage**: Secrets and JWT tokens are never stored in
  `localStorage`.
- **Content Security Policy**: The gateway attaches `SPA_CSP`:
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; object-src 'none'`.
  There are no inline scripts, no inline styles and no `eval`.
- **Safe rendering**: All LLM outputs, logs, code, diffs and artifact payloads
  render as plain text via preformatted blocks (`<pre>`). `dangerouslySetInnerHTML`
  and raw HTML insertion are forbidden and verified by static safety tests.
- **Mobile-first responsive design**: Works cleanly down to 360px viewport width
  with 16px side gutters and zero horizontal scroll. On screens wider than 900px,
  a sticky sidebar navigation replaces the mobile header menu. Light and dark
  themes are supported via CSS variables.

---

## Screens

1. **Login (`/login`)**:
   Authenticates against `POST /auth/login`. Displays lockout error messages
   with the gateway's `Retry-After` delay when rate-limited.
2. **Dashboard (`/`)**:
   Lists active and historical tasks for the tenant with their stage, risk tier
   badge, attempt count, and approval status. Includes a requirement submission
   form specifying the requirement prompt and SOP ID.
3. **Task Detail (`/tasks/:taskId`)**:
   Displays the task's state, metadata, and requirement text. Connects to the
   live server-sent events stream (`/events/stream`) to render a real-time
   audit event timeline.
4. **Approvals (`/approvals`)**:
   Restricted to users with the `admin` role. Displays pending gates requiring
   human sign-off, showing the artifact type (specification or tests), the exact
   SHA-256 hash of the artifact under review, and buttons to approve or reject
   with an administrator comment. Refuses decisions if the artifact hash changed.
5. **Security Findings (`/security`)**:
   Aggregates security findings by severity (`critical`, `high`, `medium`, `low`)
   with visual proportion bars and signal counters.
6. **Artifact & Verification (`/artifacts/:taskId`)**:
   Inspects the signed artifact manifest: root hash, test report hash, security
   report hash, acceptance hash, log head hash, file-level SHA-256 hashes and
   sizes, Ed25519 signature status, and individual verification check results.
7. **Deployment (`/deployment`)**:
   Monitors canary rollout steps (10% -> 50% -> 100%), traffic split percentages,
   error rates, health checks, and rollback/refusal statuses.
8. **Metrics (`/metrics`)**:
   Displays today's token usage per model compared to configured RPM/TPM limits,
   overall tenant task pass rate, completed vs failed counts, and attempts per task.

---

## Development

During development, run the FastAPI backend gateway and the Vite development
server concurrently. Vite proxies all API prefixes (`/auth`, `/tasks`,
`/approvals`, `/events`, `/metrics`, `/health`) to `http://127.0.0.1:8000`.

### 1. Start the API gateway

```bash
# Generate keypair and admin user if not already done:
python -m oracle_hcm keygen
python -m oracle_hcm create-admin --username admin --tenant default

# Start the gateway on port 8000:
python -m oracle_hcm serve
```

### 2. Start the Vite dev server

```bash
cd web
npm install
npm run dev
```

Visit `http://localhost:5173` in your browser.

---

## Production Build

### 1. Generate icons and model limits (optional / pre-build)

The PWA icons and model limit definitions are generated without third-party
image dependencies using Python's standard library:

```bash
python scripts/make_web_icons.py
npm --prefix web run gen:limits
```

### 2. Build the static bundle

```bash
npm --prefix web run build
```

This runs `tsc --noEmit` in strict mode followed by `vite build`. The compiled
static assets, web manifest, service worker and offline fallback page are placed
in `web/dist`. A Vite plugin generates `precache.json` listing all hashed assets
and app shell files.

### 3. Serve via FastAPI

Once `web/dist` exists, starting the gateway automatically mounts the console at
`/`:

```bash
python -m oracle_hcm serve
```

Navigate to `http://127.0.0.1:8000` to access the production PWA.

---

## PWA & Mobile Installation

The console is an installable Progressive Web Application (PWA).

### Components

- **Web Manifest (`public/manifest.webmanifest`)**: Defines name, `standalone`
  display mode, theme colors, and icons (192x192, 512x512, and 512x512 maskable).
- **Service Worker (`public/sw.js`)**:
  - Caches only the app shell (assets, CSS, JS, HTML).
  - **Never** caches API responses, auth routes, or state-changing requests.
  - Serves cached shell on navigation when online or cached, and falls back to
    `offline.html` when network is completely unavailable.
- **Offline Fallback (`public/offline.html`)**: Clean offline status page when the
  network is unreachable and the shell cannot be loaded.

### Installing on a Phone

#### Android (Google Chrome / Chromium)

1. Open the console URL in Chrome on your Android device.
2. Sign in to your account.
3. Tap the browser menu (**⋮**) in the top right corner.
4. Select **Add to Home screen** or **Install app**.
5. Tap **Install** in the prompt. The app icon will appear on your home screen
   and app drawer, launching in full-screen standalone mode without browser chrome.

#### iOS / iPadOS (Safari)

1. Open the console URL in Safari on your iPhone or iPad.
2. Sign in to your account.
3. Tap the **Share** button (the square icon with an arrow pointing upward).
4. Scroll down and tap **Add to Home Screen**.
5. Tap **Add** in the top right corner. The console launches in standalone display
   mode directly from your home screen.

### HTTPS Requirement for Mobile

> [!IMPORTANT]
> **Service Workers and PWA installation strictly require a Secure Context (HTTPS).**

- Modern mobile browsers (Chrome on Android, Safari on iOS) will **only** register
  a service worker and show the install prompt if the page is served over **HTTPS**
  (the only exception is `http://localhost` on the local machine itself).
- If you access the server across a local area network (e.g. `http://192.168.1.50:8000`)
  over plain HTTP, mobile browsers disable service workers and PWA installation.
- To install on a mobile device:
  1. Place the FastAPI gateway behind a reverse proxy (e.g. Caddy, Traefik, or
     nginx) that terminates TLS with a valid certificate (such as Let's Encrypt or
     a locally trusted CA like `mkcert`).
  2. Set `ORACLE_HCM_COOKIE_SECURE=1` so cookies require HTTPS.
  3. Access the console via `https://<your-host-or-domain>`.

---

## Verification & Quality Gates

The frontend must pass all TypeScript, linting, unit test, and production build
gates:

```bash
# Strict TypeScript compilation
npm --prefix web run typecheck

# ESLint check
npm --prefix web run lint

# Vitest test suite (35 tests covering login, lockout, approvals, SSE timeline, roles, safety)
npm --prefix web test

# Production build
npm --prefix web run build

# Python gates (backend and static serving verification)
python -m mypy src
python -m ruff check src tests
pytest
```
