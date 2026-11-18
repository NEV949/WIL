/* The service worker of the console.
 *
 * It caches the app shell only: the files of the build, the manifest and the
 * offline page. The API is never cached, and no request that carries the
 * session is ever stored: the answers of the gateway change with every
 * decision, and the cookie must never leave the browser.
 */

const CACHE_NAME = "oracle-hcm-shell-v1";
const PRECACHE_URL = "/precache.json";
const OFFLINE_URL = "/offline.html";
const SHELL_URL = "/";

const API_PREFIXES = [
  "/auth",
  "/tasks",
  "/approvals",
  "/events",
  "/metrics",
  "/health",
  "/docs",
  "/redoc",
  "/openapi.json",
];

self.addEventListener("install", (event) => {
  event.waitUntil(precache());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") {
    return;
  }
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) {
    return;
  }
  if (API_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
    return;
  }
  if (request.mode === "navigate") {
    event.respondWith(shellOrOffline(request));
    return;
  }
  event.respondWith(caches.match(request).then((cached) => cached || fetch(request)));
});

async function precache() {
  const cache = await caches.open(CACHE_NAME);
  const files = await shellFiles();
  await Promise.all(
    files.map((file) => cache.add(file).catch(() => undefined)),
  );
  await self.skipWaiting();
}

async function shellFiles() {
  try {
    const response = await fetch(PRECACHE_URL, { cache: "no-store" });
    if (!response.ok) {
      return [];
    }
    const body = await response.json();
    if (!body || !Array.isArray(body.files)) {
      return [];
    }
    return body.files.filter((file) => typeof file === "string");
  } catch (error) {
    return [];
  }
}

async function shellOrOffline(request) {
  try {
    return await fetch(request);
  } catch (error) {
    const cache = await caches.open(CACHE_NAME);
    const shell = await cache.match(SHELL_URL);
    if (shell) {
      return shell;
    }
    const offline = await cache.match(OFFLINE_URL);
    if (offline) {
      return offline;
    }
    return new Response("the console is offline", {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
}
