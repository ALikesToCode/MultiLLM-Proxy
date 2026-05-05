const CACHE_NAME = 'multillm-proxy-v2';
const OFFLINE_URL = '/static/offline.html';
const PRECACHE_URLS = [
  OFFLINE_URL,
  '/static/css/style.css',
  '/static/css/openrouter.css',
  '/static/js/app.js',
  '/static/js/openrouter.js',
  '/static/favicon.ico',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  '/apple-touch-icon.png',
];
const STATIC_FILE_PREFIX = '/static/';
const SHELL_FILE_PATHS = new Set([
  '/manifest.webmanifest',
  '/service-worker.js',
  '/apple-touch-icon.png',
  '/favicon.ico',
]);

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') {
    return;
  }

  const requestUrl = new URL(event.request.url);
  if (requestUrl.origin !== self.location.origin) {
    return;
  }

  if (requestUrl.pathname.startsWith('/health') || requestUrl.pathname.startsWith('/api/')) {
    return;
  }

  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .catch(() => caches.match(OFFLINE_URL))
    );
    return;
  }

  if (
    !requestUrl.pathname.startsWith(STATIC_FILE_PREFIX) &&
    !SHELL_FILE_PATHS.has(requestUrl.pathname)
  ) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }

      return fetch(event.request).then((response) => {
        const responseClone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseClone));
        return response;
      });
    })
  );
});
