// assets/notifications.js
//
// Shows a small red count badge on the "التنبيهات" nav pill, pulled from
// /api/notifications. Runs on every page that includes this script and
// has a #notifBadge element in its header.

document.addEventListener('DOMContentLoaded', function () {
  const badge = document.getElementById('notifBadge');
  if (!badge) return;

  const authToken = localStorage.getItem('auth_token');
  if (!authToken) return;

  fetch('/api/notifications', { headers: { Authorization: 'Bearer ' + authToken } })
    .then(function (res) { return res.ok ? res.json() : null; })
    .then(function (body) {
      if (!body || !body.success) return;
      const total = body.data.total;
      if (total > 0) {
        badge.textContent = total > 99 ? '99+' : total;
        badge.style.display = 'flex';
      }
    })
    .catch(function () { /* silent — badge just stays hidden */ });
});
