// assets/pwa.js
//
// Registers the service worker so the browser recognizes this site as an
// installable PWA. Silent — no UI needed; Chrome/Edge/Safari show their
// own native "Install app" / "Add to Home Screen" option automatically
// once the manifest + service worker + HTTPS criteria are met.

if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/sw.js').catch(function () {
      // Non-fatal — the site still works perfectly fine without it,
      // just without the installability benefit.
    });
  });
}
