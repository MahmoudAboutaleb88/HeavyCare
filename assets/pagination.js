// assets/pagination.js
//
// Client-side pagination — no backend changes needed. Fine for this
// system's scale (an internal workshop tool, not a platform handling
// tens of thousands of rows). If the data ever grows enough that
// fetching "all rows" becomes slow, this is the first thing to swap
// for real server-side LIMIT/OFFSET pagination.
//
// Usage:
//   const pager = createPaginator(document.getElementById('pagerBox'), 10, function (pageItems) {
//     // render pageItems into your table/grid
//   });
//   pager.setItems(fullArrayOfRows); // call whenever the full dataset changes

function createPaginator(containerEl, pageSize, renderPage) {
  let items = [];
  let page = 1;

  function totalPages() {
    return Math.max(1, Math.ceil(items.length / pageSize));
  }

  function renderControls() {
    const tp = totalPages();

    if (items.length <= pageSize) {
      containerEl.innerHTML = '';
      return;
    }

    const windowSize = 5;
    let startP = Math.max(1, page - Math.floor(windowSize / 2));
    let endP = Math.min(tp, startP + windowSize - 1);
    startP = Math.max(1, endP - windowSize + 1);

    let html = '<div class="pager">';
    html += '<button type="button" class="pager-btn" data-page="prev"' + (page === 1 ? ' disabled' : '') + '><i data-lucide="chevron-right"></i></button>';

    if (startP > 1) {
      html += '<button type="button" class="pager-btn" data-page="1">1</button>';
      if (startP > 2) html += '<span class="pager-ellipsis">…</span>';
    }

    for (let p = startP; p <= endP; p++) {
      html += '<button type="button" class="pager-btn' + (p === page ? ' active' : '') + '" data-page="' + p + '">' + p + '</button>';
    }

    if (endP < tp) {
      if (endP < tp - 1) html += '<span class="pager-ellipsis">…</span>';
      html += '<button type="button" class="pager-btn" data-page="' + tp + '">' + tp + '</button>';
    }

    html += '<button type="button" class="pager-btn" data-page="next"' + (page === tp ? ' disabled' : '') + '><i data-lucide="chevron-left"></i></button>';
    html += '<span class="pager-info">صفحة ' + page + ' من ' + tp + ' · ' + items.length + ' عنصر</span>';
    html += '</div>';

    containerEl.innerHTML = html;
    if (window.lucide) lucide.createIcons();

    containerEl.querySelectorAll('[data-page]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        const val = btn.getAttribute('data-page');
        if (val === 'prev') page = Math.max(1, page - 1);
        else if (val === 'next') page = Math.min(tp, page + 1);
        else page = Number(val);
        renderAll();
        containerEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      });
    });
  }

  function renderAll() {
    const start = (page - 1) * pageSize;
    renderPage(items.slice(start, start + pageSize));
    renderControls();
  }

  return {
    setItems: function (newItems) {
      items = newItems || [];
      page = 1;
      renderAll();
    },
    refresh: renderAll,
  };
}
