const CACHE_NAME = 'multillm-proxy-v12';
const OFFLINE_URL = '/static/offline.html';
const PRECACHE_URLS = [
  OFFLINE_URL,
  '/static/css/style.css',
  '/static/css/shell.css',
  '/static/css/auto-routes.css?v=7',
  '/static/css/documentation.css?v=9',
  '/static/css/operations.css',
  '/static/css/surfaces.css',
  '/static/js/app.js',
  '/static/js/auto-route-catalog.js?v=8',
  '/static/js/auto-routes.js?v=7',
  '/static/js/dashboard.js',
  '/static/js/documentation.js?v=10',
  '/static/js/openrouter.js',
  '/static/js/users.js',
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
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key.startsWith('multillm-proxy-v') && key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

async function cachedAsset(request) {
  try {
    const cache = await caches.open(CACHE_NAME);
    return await cache.match(request);
  } catch {
    return undefined;
  }
}

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
        .catch(async () => await cachedAsset(OFFLINE_URL) || Response.error())
    );
    return;
  }

  if (
    !requestUrl.pathname.startsWith(STATIC_FILE_PREFIX) &&
    !SHELL_FILE_PATHS.has(requestUrl.pathname)
  ) {
    return;
  }

  // Revalidate stable asset URLs so cached scripts cannot mask a new deployment.
  const network = fetch(event.request, { cache: 'no-cache' });
  event.waitUntil(network.then(async (response) => {
    if (response.status === 200 && !response.redirected &&
        !/\b(no-store|private)\b/i.test(response.headers.get('Cache-Control') || '')) {
      const copy = response.clone();
      const cache = await caches.open(CACHE_NAME);
      await cache.put(event.request, copy);
    }
  }).catch(() => {
    // Offline and storage-quota failures must not discard a usable response.
  }));
  event.respondWith(network.then(async (response) => {
    if (!response.ok || response.redirected) {
      return await cachedAsset(event.request) || response;
    }
    return response;
  }).catch(async () => await cachedAsset(event.request) || Response.error()));
});
