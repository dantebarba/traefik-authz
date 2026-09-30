/**
 * traefik-authz panel service worker, adapted from Preview Hub's.
 *
 * Precaches the app shell under a versioned cache so the PWA opens offline, and
 * drops older cache versions on activate. API traffic is always network-only so
 * grants are never stale; shell assets are served network-first (refreshing the
 * cache on every online load) and fall back to the cache — then to the cached
 * shell for navigations — when offline.
 */

const CACHE = "traefik-authz-v1";

const SCOPE_PATH = new URL("./", self.location).pathname;

const SHELL_ASSETS = [
  "./",
  "index.html",
  "styles.css",
  "app.js",
  "manifest.webmanifest",
  "icons/icon.svg",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "icons/maskable-512.png",
  "icons/apple-touch-icon.png",
];

async function precache() {
  const cache = await caches.open(CACHE);
  await Promise.allSettled(
    SHELL_ASSETS.map(async (asset) => {
      const request = new Request(asset, { cache: "reload", credentials: "include" });
      const response = await fetch(request);
      if (response.ok) await cache.put(asset, response);
    })
  );
}

async function dropOldCaches() {
  const keys = await caches.keys();
  await Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)));
}

async function networkFirst(request) {
  const cache = await caches.open(CACHE);
  try {
    const response = await fetch(request);
    if (response.ok && response.type === "basic") cache.put(request, response.clone());
    return response;
  } catch (error) {
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached) return cached;
    if (request.mode === "navigate") {
      const fallback = await cache.match("index.html");
      if (fallback) return fallback;
    }
    throw error;
  }
}

self.addEventListener("install", (event) => {
  event.waitUntil(precache().then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(dropOldCaches().then(() => self.clients.claim()));
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname.startsWith(`${SCOPE_PATH}api/`)) {
    event.respondWith(fetch(request));
    return;
  }

  event.respondWith(networkFirst(request));
});
