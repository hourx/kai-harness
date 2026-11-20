package serve

// dashboardHTML is a single-file view of the workspace. It keeps no state of its
// own: every panel is filled from the JSON API, so the page cannot disagree with
// what the service returns. No external assets and no build step — it has to work
// on a phone pointed at the port.
//
// One Go raw string, so the script avoids template literals and joins arrays
// instead. Every value from the API goes through esc() before it reaches innerHTML.
const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kai — workspace</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #0d1016; color: #d8dee9;
       font: 15px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
header { position: sticky; top: 0; display: flex; gap: 10px; align-items: baseline;
         padding: 12px 14px; background: #202c44; border-bottom: 1px solid #2e3d5c; }
header strong { color: #e2ecff; letter-spacing: .04em; }
header .meta { color: #8ea0bd; font-size: 12px; }
header .sp { flex: 1; }
button { background: #2b3a58; color: #cfe0ff; border: 1px solid #3f5478;
         border-radius: 6px; padding: 6px 10px; font: inherit; font-size: 13px; }
button:active { background: #35476a; }
main { padding: 14px; display: grid; gap: 14px; max-width: 1100px; }
section { border: 1px solid #23304a; border-radius: 8px; overflow: hidden; }
section > h2 { margin: 0; padding: 8px 12px; font-size: 12px; letter-spacing: .12em;
        text-transform: uppercase; color: #ffc75c; background: #151d2c;
        border-bottom: 1px solid #23304a; }
.body { padding: 10px 12px; }
.card { border: 1px solid #23304a; border-radius: 8px; margin: 0 0 10px; overflow: hidden; }
.card > .head { display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline;
        padding: 9px 12px; background: #131a28; border-bottom: 1px solid #23304a; cursor: pointer; }
.card > .head .name { font-weight: 700; color: #e2ecff; }
.card > .head .plat, .card > .head .verdict { color: #8ea0bd; font-size: 12px; }
.card > .head .counts { margin-left: auto; color: #9fb3d1; font-size: 12px; }
.card .detail { display: none; padding: 10px 12px; border-top: 1px solid #1c2740; }
.card.open .detail { display: block; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #1c2740; vertical-align: top; }
th { color: #7f93b3; font-weight: 500; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
td.num, th.num { text-align: right; }
.sc { color: #7ce286; font-weight: 700; }
.cls { color: #f7cd6c; }
.why { color: #93a4bf; }
.dim { color: #6f7f99; }
.pill { display: inline-block; border: 1px solid #3f5478; border-radius: 999px;
        padding: 1px 8px; margin-right: 6px; font-size: 11px; color: #b7c8e4; }
.todo { display: grid; gap: 6px; }
.todo .row { display: flex; gap: 8px; align-items: baseline; }
.todo .why { color: #93a4bf; font-size: 13px; }
.todo code { background: #131a28; border: 1px solid #23304a; border-radius: 5px;
        padding: 1px 6px; font-size: 12px; color: #cfe0ff; }
input[type=text] { background: #131a28; border: 1px solid #2b3a58; border-radius: 6px;
        color: #d8dee9; padding: 6px 8px; font: inherit; min-width: 200px; }
.err { color: #f07a7a; }
.ok { color: #7ce286; }
</style>
</head>
<body>
<header>
  <strong>kai</strong>
  <span class="meta" id="ver"></span>
  <span class="sp"></span>
  <button id="refresh">refresh</button>
  <button id="forget">token</button>
</header>
<main>
  <section><h2>do today</h2><div class="body" id="todo">…</div></section>
  <section><h2>programs</h2><div class="body" id="programs">…</div></section>
</main>
<script>
var TOKEN_KEY = 'kai.token';

function tok() { return sessionStorage.getItem(TOKEN_KEY) || ''; }

async function api(path) {
  var h = {};
  if (tok()) h.Authorization = 'Bearer ' + tok();
  var r = await fetch(path, { headers: h, cache: 'no-store' });
  if (r.status === 401) {
    var v = prompt('kai serve token');
    if (v) { sessionStorage.setItem(TOKEN_KEY, v); return api(path); }
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error(path + ' -> ' + r.status);
  return r.json();
}

function esc(s) {
  return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function join(a) { return a.join(''); }

function todoHTML(board) {
  if (!board.todo || !board.todo.length) {
    return '<div class="dim">nothing queued — every program is up to date</div>';
  }
  return '<div class="todo">' + join(board.todo.map(function (t) {
    return '<div class="row"><span class="dim">' + t.rank + '.</span>' +
      '<span><span class="name">' + esc(t.program) + '</span> ' +
      '<code>' + esc(t.command) + '</code><br><span class="why">' + esc(t.why) + '</span></span></div>';
  })) + '</div>';
}

function programsHTML(list) {
  if (!list.length) return '<div class="dim">no programs yet — kai init &lt;program&gt;</div>';
  return join(list.map(function (p) {
    var s = p.surface || {};
    var counts = 'hosts ' + (s.hosts || 0) + ' · ends ' + (s.endpoints || 0) +
      ' · queue ' + ((p.queue && p.queue.total) || 0);
    var badges = [];
    if (p.findings && p.findings.total) badges.push('<span class="pill">findings ' + p.findings.total + '</span>');
    if (p.evidence) badges.push('<span class="pill">evidence ' + p.evidence + '</span>');
    if (p.scope && p.scope.in_rules) badges.push('<span class="pill">scope ' + p.scope.in_rules + ' in</span>');
    if (p.scope && p.scope.out_rules) badges.push('<span class="pill">' + p.scope.out_rules + ' out</span>');
    var head = '<div class="head" data-name="' + esc(p.name) + '">' +
      '<span class="name">' + esc(p.name) + '</span>' +
      '<span class="plat">' + esc(p.platform || 'direct') + '</span>' +
      '<span class="verdict">' + esc(p.scope_verdict || '') + '</span>' +
      '<span class="counts">' + esc(counts) + '</span></div>';
    return '<div class="card" data-name="' + esc(p.name) + '">' + head +
      '<div class="detail" id="d-' + esc(p.name) + '"><span class="dim">loading…</span></div></div>' +
      '<div class="dim" style="margin:-4px 0 10px 2px">' + join(badges) + '</div>';
  }));
}

function queueHTML(q) {
  if (!q.items || !q.items.length) return '<div class="dim">queue empty — run: kai recon, then kai map and kai next</div>';
  var rows = join(q.items.map(function (h, i) {
    return '<tr><td class="num">' + (i + 1) + '</td><td>' + esc(h.target) + '</td>' +
      '<td class="cls">' + esc(h.class) + '</td><td class="num sc">' + h.score + '</td>' +
      '<td class="why">' + esc((h.why || []).join('; ')) + '</td></tr>';
  }));
  return '<table><thead><tr><th class="num">#</th><th>target</th><th>class</th>' +
    '<th class="num">score</th><th>why</th></tr></thead><tbody>' + rows + '</tbody></table>' +
    '<div class="dim">showing ' + q.items.length + ' of ' + q.total +
    (q.clusters ? ' · ' + q.clusters + ' clusters' : '') + '</div>';
}

function findingsHTML(f) {
  if (!f.total) return '<div class="dim">no findings recorded yet</div>';
  var rows = join((f.items || []).map(function (x) {
    return '<tr><td>' + esc(x.id) + '</td><td>' + esc(x.target) + '</td>' +
      '<td class="cls">' + esc(x.class || '') + '</td><td>' + esc(x.status) + '</td>' +
      '<td>' + esc(x.note || '') + '</td></tr>';
  }));
  return '<table><thead><tr><th>id</th><th>target</th><th>class</th><th>status</th>' +
    '<th>note</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function planHTML(p) {
  if (!p || !p.waves || !p.waves.length) return '<div class="dim">no waves — the queue is empty</div>';
  var rows = join(p.waves.map(function (w) {
    return '<tr><td class="num">' + w.n + '</td><td>' + esc(w.name) + '</td>' +
      '<td class="num">' + w.count + '</td><td class="why">' + esc(w.needs) + '</td>' +
      '<td class="why">' + esc((w.classes || []).join(', ')) + '</td></tr>';
  }));
  return '<table><thead><tr><th class="num">wave</th><th>name</th><th class="num">count</th>' +
    '<th>needs</th><th>classes</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function scopeHTML(s) {
  return '<div class="dim">rules ' + s.in_rules + ' in / ' + s.out_rules + ' out' +
    (s.note ? ' <span class="err">' + esc(s.note) + '</span>' : '') + '</div>';
}

async function openCard(name) {
  var card = document.querySelector('.card[data-name="' + name + '"]');
  var box = document.getElementById('d-' + name);
  if (!card || !box) return;
  if (card.classList.contains('open')) { card.classList.remove('open'); return; }
  card.classList.add('open');
  try {
    var d = await api('/api/v1/programs/' + encodeURIComponent(name));
    box.innerHTML =
      '<h3 style="margin:2px 0 6px;font-size:12px;letter-spacing:.1em;color:#7f93b3">QUEUE</h3>' + queueHTML(d.queue) +
      '<h3 style="margin:12px 0 6px;font-size:12px;letter-spacing:.1em;color:#7f93b3">PLAN</h3>' + planHTML(d.plan) +
      '<h3 style="margin:12px 0 6px;font-size:12px;letter-spacing:.1em;color:#7f93b3">FINDINGS</h3>' + findingsHTML(d.findings) +
      '<h3 style="margin:12px 0 6px;font-size:12px;letter-spacing:.1em;color:#7f93b3">SCOPE</h3>' + scopeHTML(d.scope) +
      '<div style="margin-top:10px"><input type="text" placeholder="host or ip — check scope" id="q-' + esc(name) + '"> ' +
      '<button data-check="' + esc(name) + '">check</button> <span id="r-' + esc(name) + '"></span></div>' +
      '<div style="margin-top:10px"><a class="dim" href="/api/v1/programs/' + encodeURIComponent(name) + '/brief">brief</a>' +
      ' · <a class="dim" href="/api/v1/programs/' + encodeURIComponent(name) + '/outcomes">outcomes</a>' +
      ' · <a class="dim" href="/api/v1/programs/' + encodeURIComponent(name) + '/evidence">evidence</a></div>';
  } catch (e) {
    box.innerHTML = '<span class="err">' + esc(e.message) + '</span>';
  }
}

async function checkScope(name) {
  var input = document.getElementById('q-' + name);
  var out = document.getElementById('r-' + name);
  if (!input || !input.value) return;
  out.textContent = '…';
  try {
    var s = await api('/api/v1/programs/' + encodeURIComponent(name) + '/scope?host=' + encodeURIComponent(input.value));
    out.innerHTML = '<span class="' + (s.verdict === 'IN' ? 'ok' : 'err') + '">' + esc(s.verdict) + '</span> ' +
      '<span class="dim">' + esc(s.reason || '') + '</span>';
  } catch (e) {
    out.innerHTML = '<span class="err">' + esc(e.message) + '</span>';
  }
}

function wire() {
  document.querySelectorAll('.card > .head').forEach(function (h) {
    h.addEventListener('click', function () { openCard(h.getAttribute('data-name')); });
  });
  document.querySelectorAll('button[data-check]').forEach(function (b) {
    b.addEventListener('click', function () { checkScope(b.getAttribute('data-check')); });
  });
  document.querySelectorAll('input[type=text]').forEach(function (i) {
    i.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') checkScope(i.id.slice(2)); });
  });
}

async function load() {
  document.getElementById('todo').innerHTML = '<span class="dim">loading…</span>';
  try {
    var board = await api('/api/v1/board');
    var progs = await api('/api/v1/programs?limit=5');
    document.getElementById('ver').textContent = board.home;
    document.getElementById('todo').innerHTML = todoHTML(board);
    document.getElementById('programs').innerHTML = programsHTML(progs.programs || []);
    wire();
  } catch (e) {
    document.getElementById('todo').innerHTML = '<span class="err">' + esc(e.message) + '</span>';
    document.getElementById('programs').innerHTML = '';
  }
}

document.getElementById('refresh').addEventListener('click', load);
document.getElementById('forget').addEventListener('click', function () {
  sessionStorage.removeItem(TOKEN_KEY);
  alert('token cleared — the next request asks again');
});
load();
</script>
</body>
</html>
`
