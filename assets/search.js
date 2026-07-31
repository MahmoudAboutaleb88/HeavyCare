// assets/search.js
//
// Shared global search behavior. Every page that includes this script
// (and has #globalSearchInput / #globalSearchResults elements in its
// header) gets the same search-across-everything box for free.

document.addEventListener('DOMContentLoaded', function () {
  const input = document.getElementById('globalSearchInput');
  const resultsBox = document.getElementById('globalSearchResults');
  if (!input || !resultsBox) return; // page doesn't have the search box (e.g. login page)

  const authToken = localStorage.getItem('auth_token');
  if (!authToken) return;

  let debounceTimer = null;

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : str;
    return div.innerHTML;
  }

  function openResults() { resultsBox.classList.add('open'); }
  function closeResults() { resultsBox.classList.remove('open'); }

  function renderHint(message) {
    resultsBox.innerHTML = '<div class="search-hint">' + message + '</div>';
    openResults();
  }

  function renderResults(data) {
    const groups = [];

    if (data.equipment.length > 0) {
      groups.push(
        '<div class="group-label">المعدات</div>' +
        data.equipment.map(function (e) {
          return '<a class="result-item" href="equipment.html">' +
            '<span class="result-title">' + escapeHtml(e.code) + (e.equipment_type ? ' — ' + escapeHtml(e.equipment_type) : '') + '</span>' +
            '<span class="result-sub">' + escapeHtml(e.department_name) + (e.brand ? ' · ' + escapeHtml(e.brand) : '') + '</span>' +
            '</a>';
        }).join('')
      );
    }

    if (data.workshop_entries.length > 0) {
      groups.push(
        '<div class="group-label">زيارات الورشة</div>' +
        data.workshop_entries.map(function (w) {
          return '<a class="result-item" href="job-card.html?id=' + w.id + '">' +
            '<span class="result-title">' + escapeHtml(w.entry_number) + ' — ' + escapeHtml(w.equipment_code) + '</span>' +
            '<span class="result-sub">' + escapeHtml((w.reported_problem || '').slice(0, 60)) + '</span>' +
            '</a>';
        }).join('')
      );
    }

    if (data.users.length > 0) {
      groups.push(
        '<div class="group-label">المستخدمين</div>' +
        data.users.map(function (u) {
          return '<a class="result-item" href="users.html">' +
            '<span class="result-title">' + escapeHtml(u.full_name) + '</span>' +
            '<span class="result-sub">' + escapeHtml(u.username) + ' · ' + escapeHtml(u.role) + '</span>' +
            '</a>';
        }).join('')
      );
    }

    if (groups.length === 0) {
      resultsBox.innerHTML = '<div class="no-results">مفيش نتائج مطابقة</div>';
    } else {
      resultsBox.innerHTML = groups.join('');
    }
    openResults();
  }

  async function runSearch(q) {
    try {
      const res = await fetch('/api/search?q=' + encodeURIComponent(q), {
        headers: { Authorization: 'Bearer ' + authToken },
      });
      if (!res.ok) {
        renderHint('تعذر البحث دلوقتي');
        return;
      }
      const body = await res.json();
      if (!body.success) {
        renderHint('تعذر البحث دلوقتي');
        return;
      }
      renderResults(body.data);
    } catch (err) {
      renderHint('تعذر الاتصال بالخادم');
    }
  }

  input.addEventListener('input', function () {
    const q = input.value.trim();
    clearTimeout(debounceTimer);

    if (q.length < 2) {
      closeResults();
      return;
    }

    debounceTimer = setTimeout(function () { runSearch(q); }, 300);
  });

  input.addEventListener('focus', function () {
    if (input.value.trim().length >= 2) openResults();
  });

  document.addEventListener('click', function (e) {
    if (!e.target.closest('.global-search')) closeResults();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeResults();
  });
});
