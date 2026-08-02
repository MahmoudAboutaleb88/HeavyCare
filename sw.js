// sw.js
//
// Minimal service worker — just enough to satisfy PWA "installability"
// requirements (a registered service worker with a fetch handler) and
// give a small speed boost by caching static assets (fonts/icons/CSS/JS).
//
// Deliberately NOT caching API responses or HTML pages: this is a live
// workshop system (equipment status, job cards...) where showing stale
// data would be actively harmful. Only truly static files are cached.

const CACHE_NAME = 'heavycare-static-v1';

const STATIC_ASSETS = [
  'assets/style.css',
  'assets/search.js',
  'assets/notifications.js',
  'assets/pagination.js',
  'assets/upload.js',
  'icons/icon-192.png',
  'icons/icon-512.png',
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.addAll(STATIC_ASSETS).catch(function () {
        // Don't fail install if one asset is missing — best effort caching.
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (key) { return key !== CACHE_NAME; })
            .map(function (key) { return caches.delete(key); })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', function (event) {
  const url = new URL(event.request.url);

  // Never intercept API calls or navigation to HTML pages — always go to
  // the network so data (equipment status, job cards, etc.) is fresh.
  if (url.pathname.startsWith('/api/') || event.request.mode === 'navigate') {
    return; // let the browser handle it normally
  }

  // Static assets: try cache first, fall back to network.
  if (STATIC_ASSETS.some(function (asset) { return url.pathname.endsWith(asset); })) {
    event.respondWith(
      caches.match(event.request).then(function (cached) {
        return cached || fetch(event.request);
      })
    );
  }
});
