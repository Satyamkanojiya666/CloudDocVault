/* CloudDocVault v7 - tiny vanilla JS (CSP-friendly: served from /static, no inline scripts) */
(function () {
  try {
    var t = localStorage.getItem('theme');
    if (t) document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('themeBtn');
    if (btn) btn.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', cur);
      try { localStorage.setItem('theme', cur); } catch (e) {}
    });

    document.querySelectorAll('form[data-confirm]').forEach(function (f) {
      f.addEventListener('submit', function (e) { if (!confirm(f.getAttribute('data-confirm'))) e.preventDefault(); });
    });

    var dz = document.getElementById('dropzone'), inp = document.getElementById('fileInput'),
        names = document.getElementById('fileNames');
    function show() {
      if (!names || !inp) return;
      var list = [];
      for (var i = 0; i < inp.files.length; i++) list.push(inp.files[i].name);
      names.textContent = list.length ? list.join(', ') : '';
    }
    if (dz && inp) {
      ['dragenter', 'dragover'].forEach(function (ev) {
        dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add('drag'); });
      });
      ['dragleave', 'drop'].forEach(function (ev) {
        dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove('drag'); });
      });
      dz.addEventListener('drop', function (e) { inp.files = e.dataTransfer.files; show(); });
      inp.addEventListener('change', show);
    }

    var live = document.getElementById('liveFilter');
    if (live) live.addEventListener('input', function () {
      var q = live.value.toLowerCase();
      document.querySelectorAll('#fileTable tr[data-name]').forEach(function (tr) {
        tr.style.display = tr.getAttribute('data-name').indexOf(q) === -1 ? 'none' : '';
      });
    });

    var cp = document.getElementById('copyBtn'), box = document.getElementById('linkBox');
    if (cp && box) cp.addEventListener('click', function () {
      box.select();
      var done = function () { cp.textContent = 'Copied!'; };
      if (navigator.clipboard) navigator.clipboard.writeText(box.value).then(done, function () { document.execCommand('copy'); done(); });
      else { document.execCommand('copy'); done(); }
    });
  });
})();
