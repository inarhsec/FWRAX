"""
FWRAX single-page HTML GUI.

Rendered as a Python string so the web tier has no static-file dependency
and the app ships as a self-contained package.
"""
from __future__ import annotations

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>FWRAX — Firewall Rule Audit</title>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;
  --accent:#58a6ff;--accent2:#388bfd;--danger:#f85149;--warn:#d29922;
  --ok:#3fb950;--med:#e3b341;--low:#79c0ff;
  --text:#e6edf3;--muted:#8b949e;--radius:8px;
  --critical:#f85149;--high:#e3b341;--medium:#d29922;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
a{color:var(--accent)}

/* ── Header ── */
header{background:var(--surface);border-bottom:1px solid var(--border);padding:1.25rem 2rem;display:flex;align-items:center;gap:1rem}
header .logo{font-size:1.6rem;font-weight:700;letter-spacing:.05em;color:var(--accent)}
header .tagline{color:var(--muted);font-size:.85rem}

/* ── Main layout ── */
main{max-width:1200px;margin:2rem auto;padding:0 1.5rem;display:flex;flex-direction:column;gap:2rem}

/* ── Cards ── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.5rem}
.card-title{font-size:1rem;font-weight:600;color:var(--accent);margin-bottom:1rem;display:flex;align-items:center;gap:.5rem}
.card-title svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2}

/* ── Upload zone ── */
#drop-zone{
  border:2px dashed var(--border);border-radius:var(--radius);padding:3rem 2rem;
  text-align:center;cursor:pointer;transition:.2s;background:var(--surface2)
}
#drop-zone:hover,#drop-zone.drag-over{border-color:var(--accent);background:#1c2331}
#drop-zone svg{width:40px;height:40px;stroke:var(--muted);fill:none;stroke-width:1.5;margin-bottom:.75rem}
#drop-zone .primary{font-size:1rem;font-weight:600;color:var(--text)}
#drop-zone .secondary{color:var(--muted);font-size:.875rem;margin-top:.25rem}
#file-name{margin-top:.75rem;font-size:.875rem;color:var(--ok);font-weight:500}
#file-input{display:none}

/* ── Options grid ── */
.options-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}
.opt-group label{display:flex;align-items:center;gap:.5rem;cursor:pointer;font-size:.9rem;padding:.5rem;border-radius:4px}
.opt-group label:hover{background:var(--surface2)}
.opt-group input[type=checkbox]{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}
.opt-group select,.opt-group input[type=text]{
  background:var(--surface2);border:1px solid var(--border);color:var(--text);
  padding:.45rem .75rem;border-radius:4px;font-size:.9rem;width:100%
}
.opt-group select:focus,.opt-group input[type=text]:focus{outline:none;border-color:var(--accent)}
.field-label{font-size:.8rem;color:var(--muted);margin-bottom:.35rem}

/* ── Run button ── */
#run-btn{
  display:block;width:100%;padding:1rem;background:var(--accent2);color:#fff;
  border:none;border-radius:var(--radius);font-size:1rem;font-weight:700;
  cursor:pointer;letter-spacing:.03em;transition:.15s
}
#run-btn:hover:not(:disabled){background:var(--accent)}
#run-btn:disabled{opacity:.5;cursor:not-allowed}

/* ── Progress ── */
#progress-section{display:none}
.progress-bar{height:4px;background:var(--surface2);border-radius:2px;overflow:hidden;margin-top:.5rem}
.progress-bar .fill{height:100%;background:var(--accent);width:0;transition:width .4s}
.status-msg{font-size:.875rem;color:var(--muted);margin-top:.5rem}

/* ── Error ── */
#error-section{display:none}
.error-box{background:#2d1316;border:1px solid var(--danger);border-radius:var(--radius);padding:1rem 1.25rem;color:var(--danger)}

/* ── Results ── */
#results-section{display:none}

/* Summary tiles */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.75rem;margin-bottom:1.5rem}
.tile{background:var(--surface2);border-radius:var(--radius);padding:1rem;text-align:center;border:1px solid var(--border)}
.tile .val{font-size:1.75rem;font-weight:700;line-height:1.1}
.tile .lbl{font-size:.75rem;color:var(--muted);margin-top:.25rem}
.tile.crit .val{color:var(--critical)}
.tile.high .val{color:var(--high)}
.tile.med .val{color:var(--med)}
.tile.low .val{color:var(--low)}
.tile.ok .val{color:var(--ok)}
.tile.info .val{color:var(--accent)}

/* Severity badges */
.badge{display:inline-block;padding:.2rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600;text-transform:uppercase}
.badge-Critical{background:#3d1515;color:var(--critical);border:1px solid var(--critical)}
.badge-High{background:#2d2210;color:var(--high);border:1px solid var(--high)}
.badge-Medium{background:#2a1f08;color:var(--med);border:1px solid var(--med)}
.badge-Low{background:#0d1f35;color:var(--low);border:1px solid var(--low)}
.badge-ok{background:#0d2616;color:var(--ok);border:1px solid var(--ok)}
.badge-disabled{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}

/* Findings table */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.85rem}
thead th{background:var(--surface2);color:var(--muted);padding:.6rem .75rem;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;font-weight:600}
tbody tr{border-bottom:1px solid var(--border)}
tbody tr:hover{background:var(--surface2)}
tbody td{padding:.6rem .75rem;vertical-align:top}
.rule-name{font-family:monospace;font-size:.8rem;color:var(--accent)}
.issues-cell{font-size:.8rem;color:var(--muted);max-width:380px}
.issues-cell ul{padding-left:1rem}
.issues-cell li{margin-bottom:.2rem}

/* Search */
.search-row{display:flex;gap:.75rem;align-items:center;margin-bottom:1rem;flex-wrap:wrap}
#search-input{flex:1;min-width:220px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:.5rem .75rem;border-radius:4px;font-size:.875rem}
#search-input:focus{outline:none;border-color:var(--accent)}
.filter-btns{display:flex;gap:.4rem;flex-wrap:wrap}
.filter-btn{padding:.35rem .65rem;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);font-size:.8rem;cursor:pointer;transition:.15s}
.filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent)}

/* Downloads */
.dl-buttons{display:flex;gap:.75rem;flex-wrap:wrap}
.dl-btn{
  display:flex;align-items:center;gap:.5rem;padding:.65rem 1.1rem;
  border-radius:var(--radius);border:1px solid var(--border);
  background:var(--surface2);color:var(--text);font-size:.875rem;
  cursor:pointer;text-decoration:none;transition:.15s;font-weight:500
}
.dl-btn:hover{border-color:var(--accent);color:var(--accent)}
.dl-btn svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:2}
.dl-btn.pdf{border-color:var(--danger);color:var(--danger)}
.dl-btn.pdf:hover{background:#2d1316}
.dl-btn.xlsx{border-color:var(--ok);color:var(--ok)}
.dl-btn.xlsx:hover{background:#0d2616}
.dl-btn.json-btn{border-color:var(--accent);color:var(--accent)}
.dl-btn.json-btn:hover{background:#0d1f35}

/* Batch notes */
.batch-notes{display:flex;flex-direction:column;gap:.5rem}
.note-item{background:var(--surface2);border-left:3px solid var(--warn);padding:.6rem .9rem;border-radius:0 4px 4px 0;font-size:.85rem;color:var(--muted)}

/* Shadow findings */
.shadow-item{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:.85rem 1rem;font-size:.85rem}
.shadow-item .sh-kind{font-weight:600;margin-bottom:.3rem}
.shadow-item .sh-rules{font-family:monospace;font-size:.8rem;color:var(--accent)}
.shadow-item .sh-desc{color:var(--muted);margin-top:.3rem}
.shadow-grid{display:flex;flex-direction:column;gap:.6rem}

/* Responsive */
@media(max-width:640px){
  main{padding:0 1rem}
  header{flex-direction:column;align-items:flex-start}
}

/* Pagination */
.pagination{display:flex;gap:.4rem;align-items:center;justify-content:flex-end;margin-top:.75rem;flex-wrap:wrap}
.page-btn{padding:.3rem .6rem;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);cursor:pointer;font-size:.8rem}
.page-btn.active,.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-info{font-size:.8rem;color:var(--muted)}
</style>
</head>
<body>

<header>
  <span class="logo">🔥 FWRAX</span>
  <div>
    <div style="font-size:1rem;font-weight:600">Firewall Rule Review Audit X</div>
    <div class="tagline">Upload your rules → Run audit → Download report</div>
  </div>
</header>

<main>

<!-- ── Upload card ── -->
<div class="card">
  <div class="card-title">
    <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
    Upload Rules File
  </div>
  <div id="drop-zone" onclick="document.getElementById('file-input').click()">
    <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
    <div class="primary">Drag &amp; drop your rules file here</div>
    <div class="secondary">or click to browse — accepts <strong>.json</strong> and <strong>.csv</strong></div>
    <div id="file-name"></div>
  </div>
  <input type="file" id="file-input" accept=".json,.csv"/>
</div>

<!-- ── Audit options ── -->
<div class="card">
  <div class="card-title">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>
    Audit Options
  </div>
  <div class="options-grid">
    <div class="opt-group">
      <div class="field-label">Organization Name</div>
      <input type="text" id="org-input" placeholder="the Organization" value="the Organization"/>
    </div>
    <div class="opt-group">
      <div class="field-label">Audit Mode</div>
      <select id="mode-select">
        <option value="strict">Strict — Full findings</option>
        <option value="relaxed">Relaxed — Downgraded severities</option>
      </select>
    </div>
    <div class="opt-group" style="padding-top:.9rem">
      <label><input type="checkbox" id="opt-shadow" checked/> Enable Shadow Detection</label>
      <label><input type="checkbox" id="opt-batch" checked/> Enable Batch Heuristics</label>
      <label><input type="checkbox" id="opt-fake"/> Fake Compliance Mode</label>
    </div>
  </div>
</div>

<!-- ── Run ── -->
<button id="run-btn" disabled>Run Audit</button>

<!-- ── Progress ── -->
<div id="progress-section" class="card">
  <div class="card-title">Processing…</div>
  <div class="progress-bar"><div class="fill" id="progress-fill"></div></div>
  <div class="status-msg" id="status-msg">Uploading file…</div>
</div>

<!-- ── Error ── -->
<div id="error-section">
  <div class="error-box" id="error-msg"></div>
</div>

<!-- ── Results ── -->
<div id="results-section">

  <!-- Summary tiles -->
  <div class="card">
    <div class="card-title">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      Audit Summary
    </div>
    <div class="tiles" id="summary-tiles"></div>
  </div>

  <!-- Downloads -->
  <div class="card">
    <div class="card-title">
      <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Download Reports
    </div>
    <div class="dl-buttons" id="dl-buttons"></div>
  </div>

  <!-- Batch notes -->
  <div class="card" id="notes-card" style="display:none">
    <div class="card-title">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      Batch Advisory Notes
    </div>
    <div class="batch-notes" id="batch-notes-list"></div>
  </div>

  <!-- Shadow findings -->
  <div class="card" id="shadow-card" style="display:none">
    <div class="card-title">
      <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
      Duplicate &amp; Shadow Rule Findings
    </div>
    <div class="shadow-grid" id="shadow-list"></div>
  </div>

  <!-- Findings table -->
  <div class="card">
    <div class="card-title">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      Rule Findings
    </div>
    <div class="search-row">
      <input type="text" id="search-input" placeholder="Search rule name, severity, issues…"/>
      <div class="filter-btns" id="filter-btns">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="non-compliant">Non-Compliant</button>
        <button class="filter-btn" data-filter="Critical">Critical</button>
        <button class="filter-btn" data-filter="High">High</button>
        <button class="filter-btn" data-filter="Medium">Medium</button>
        <button class="filter-btn" data-filter="compliant">Compliant</button>
        <button class="filter-btn" data-filter="disabled">Disabled</button>
      </div>
    </div>
    <div class="table-wrap">
      <table id="findings-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Rule Name</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Issues</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody id="findings-body"></tbody>
      </table>
    </div>
    <div class="pagination" id="pagination"></div>
    <div class="page-info" id="page-info" style="margin-top:.5rem;text-align:right"></div>
  </div>

</div><!-- /results-section -->
</main>

<script>
(function(){
'use strict';

// ── State ──
let auditId = null;
let allRows = [];
let filteredRows = [];
let currentFilter = 'all';
let searchTerm = '';
const PAGE_SIZE = 50;
let currentPage = 1;

// ── File input ──
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileNameEl = document.getElementById('file-name');
const runBtn = document.getElementById('run-btn');
let selectedFile = null;

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if(f) setFile(f);
});
fileInput.addEventListener('change', () => { if(fileInput.files[0]) setFile(fileInput.files[0]); });

function setFile(f) {
  selectedFile = f;
  fileNameEl.textContent = '📎 ' + f.name + ' (' + (f.size/1024).toFixed(1) + ' KB)';
  runBtn.disabled = false;
}

// ── Run ──
runBtn.addEventListener('click', runAudit);

async function runAudit() {
  if(!selectedFile){ alert('Please select a file first.'); return; }
  setProgress(true);
  hideError();
  hideResults();

  const fd = new FormData();
  fd.append('file', selectedFile);
  fd.append('mode', document.getElementById('mode-select').value);
  fd.append('organization', document.getElementById('org-input').value || 'the Organization');
  fd.append('run_shadow_detection', document.getElementById('opt-shadow').checked ? 'true' : 'false');
  fd.append('run_batch_checks', document.getElementById('opt-batch').checked ? 'true' : 'false');
  fd.append('fake_compliance', document.getElementById('opt-fake').checked ? 'true' : 'false');

  updateStatus('Uploading and parsing rules…', 20);
  try {
    const resp = await fetch('/api/upload', { method:'POST', body: fd });
    updateStatus('Running audit engine…', 55);
    const data = await resp.json();
    if(!resp.ok) {
      showError(data.detail || 'Audit failed. Check file format and try again.');
      setProgress(false);
      return;
    }
    updateStatus('Rendering results…', 85);
    auditId = data.audit_id;
    renderResults(data);
    updateStatus('Done.', 100);
    setTimeout(() => setProgress(false), 600);
  } catch(err) {
    showError('Network error: ' + err.message);
    setProgress(false);
  }
}

// ── Progress ──
function setProgress(show) {
  document.getElementById('progress-section').style.display = show ? '' : 'none';
  runBtn.disabled = show;
  if(!show) document.getElementById('progress-fill').style.width = '0';
}
function updateStatus(msg, pct) {
  document.getElementById('status-msg').textContent = msg;
  document.getElementById('progress-fill').style.width = pct + '%';
}

// ── Error ──
function showError(msg) {
  const s = document.getElementById('error-section');
  document.getElementById('error-msg').textContent = '⚠️ ' + msg;
  s.style.display = '';
}
function hideError() { document.getElementById('error-section').style.display = 'none'; }

// ── Results ──
function hideResults() { document.getElementById('results-section').style.display = 'none'; }

function renderResults(data) {
  renderSummary(data.summary);
  renderDownloads();
  renderBatchNotes(data.batch_notes || []);
  renderShadowFindings(data.shadow_findings || []);
  allRows = data.rule_results || [];
  currentFilter = 'all'; searchTerm = ''; currentPage = 1;
  document.getElementById('search-input').value = '';
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter==='all'));
  applyFilters();
  document.getElementById('results-section').style.display = '';
  document.getElementById('results-section').scrollIntoView({behavior:'smooth', block:'start'});
}

function renderSummary(s) {
  const tiles = [
    {val: s.total_rules,     lbl: 'Total Rules',       cls: 'info'},
    {val: s.non_compliant,   lbl: 'Findings',          cls: s.non_compliant>0?'crit':'ok'},
    {val: s.critical,        lbl: 'Critical',          cls: 'crit'},
    {val: s.high,            lbl: 'High',              cls: 'high'},
    {val: s.medium,          lbl: 'Medium',            cls: 'med'},
    {val: s.low,             lbl: 'Low',               cls: 'low'},
    {val: s.disabled,        lbl: 'Disabled',          cls: 'info'},
    {val: s.duplicates,      lbl: 'Duplicates',        cls: s.duplicates>0?'high':'ok'},
    {val: s.shadows,         lbl: 'Shadow Rules',      cls: s.shadows>0?'high':'ok'},
    {val: s.conflict_shadows,lbl: 'Conflict Shadows',  cls: s.conflict_shadows>0?'crit':'ok'},
    {val: s.stale_rules,     lbl: 'Stale Rules',       cls: s.stale_rules>0?'med':'ok'},
    {val: s.any_any_rules,   lbl: 'Any-to-Any',        cls: s.any_any_rules>0?'crit':'ok'},
  ];
  document.getElementById('summary-tiles').innerHTML = tiles.map(t =>
    `<div class="tile ${t.cls}"><div class="val">${t.val}</div><div class="lbl">${t.lbl}</div></div>`
  ).join('');
}

async function downloadReport(fmt, label) {
  if (!auditId) return;
  try {
    const resp = await fetch('/api/download/' + auditId + '/' + fmt);
    if (!resp.ok) {
      let detail = 'Download failed';
      try {
        const err = await resp.json();
        detail = err.detail || detail;
      } catch (_) {}
      alert(label + ' download failed: ' + detail);
      return;
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'fwrax_report_' + auditId.slice(0, 8) + '.' + fmt;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) {
    alert(label + ' download failed: ' + err.message);
  }
}

function renderDownloads() {
  if(!auditId) return;
  document.getElementById('dl-buttons').innerHTML = `
    <button type="button" class="dl-btn pdf" onclick="downloadReport('pdf','PDF')">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
      Download PDF
    </button>
    <button type="button" class="dl-btn xlsx" onclick="downloadReport('xlsx','Excel')">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="3" x2="9" y2="21"/></svg>
      Download Excel
    </button>
    <button type="button" class="dl-btn json-btn" onclick="downloadReport('json','JSON')">
      <svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
      Download JSON
    </button>
  `;
  downloadReport('pdf', 'PDF');
}

function renderBatchNotes(notes) {
  const card = document.getElementById('notes-card');
  const list = document.getElementById('batch-notes-list');
  if(!notes.length){ card.style.display='none'; return; }
  card.style.display='';
  list.innerHTML = notes.map(n => `<div class="note-item">⚡ ${esc(n)}</div>`).join('');
}

function renderShadowFindings(findings) {
  const card = document.getElementById('shadow-card');
  const list = document.getElementById('shadow-list');
  if(!findings.length){ card.style.display='none'; return; }
  card.style.display='';
  const kindColor = {duplicate:'var(--med)',shadow:'var(--high)',conflict_shadow:'var(--critical)'};
  list.innerHTML = findings.map(f => {
    const col = kindColor[f.kind] || 'var(--accent)';
    return `<div class="shadow-item">
      <div class="sh-kind" style="color:${col}">${fmt(f.kind)} — <span class="badge badge-${f.severity||'Medium'}">${f.severity||'Medium'}</span></div>
      <div class="sh-rules">Rule #${(f.earlier_rule_index||0)+1}: ${esc(f.earlier_rule_name||'')} &rarr; Rule #${(f.later_rule_index||0)+1}: ${esc(f.later_rule_name||'')}</div>
      <div class="sh-desc">${esc(f.description||'')} ${f.recommendation?'<em>Rec: '+esc(f.recommendation)+'</em>':''}</div>
    </div>`;
  }).join('');
}

// ── Filtering & table ──
document.getElementById('search-input').addEventListener('input', function(){
  searchTerm = this.value.toLowerCase();
  currentPage = 1;
  applyFilters();
});

document.getElementById('filter-btns').addEventListener('click', function(e){
  const btn = e.target.closest('.filter-btn');
  if(!btn) return;
  currentFilter = btn.dataset.filter;
  currentPage = 1;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b===btn));
  applyFilters();
});

function applyFilters() {
  filteredRows = allRows.filter(r => {
    const name = (r.rule_name||'').toLowerCase();
    const sev = (r.severity||'').toLowerCase();
    const issues = (r.issues||[]).join(' ').toLowerCase();
    const status = r.status||'';
    const disabled = r.is_disabled || false;

    const matchFilter =
      currentFilter==='all' ? true :
      currentFilter==='non-compliant' ? status==='non-compliant' :
      currentFilter==='compliant' ? (status==='compliant' && !disabled) :
      currentFilter==='disabled' ? disabled :
      sev === currentFilter.toLowerCase();

    const matchSearch = !searchTerm ||
      name.includes(searchTerm) ||
      sev.includes(searchTerm) ||
      issues.includes(searchTerm) ||
      status.includes(searchTerm);

    return matchFilter && matchSearch;
  });
  renderTable();
  renderPagination();
}

function renderTable() {
  const start = (currentPage-1)*PAGE_SIZE;
  const page = filteredRows.slice(start, start+PAGE_SIZE);
  const tbody = document.getElementById('findings-body');

  if(!page.length){
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem">No matching rules found.</td></tr>`;
    return;
  }

  tbody.innerHTML = page.map((r, i) => {
    const idx = start + i + 1;
    const disabled = r.is_disabled;
    const badgeCls = disabled ? 'badge-disabled' : ('badge-'+r.severity);
    const statusBadge = disabled
      ? '<span class="badge badge-disabled">Disabled</span>'
      : (r.status==='compliant'
          ? '<span class="badge badge-ok">✓ Compliant</span>'
          : '<span class="badge badge-'+r.severity+'">✗ Finding</span>');
    const issuesList = (r.issues||[]).length
      ? '<ul>' + (r.issues||[]).map(x=>`<li>${esc(x)}</li>`).join('') + '</ul>'
      : '<span style="color:var(--muted)">—</span>';
    return `<tr>
      <td style="color:var(--muted);font-size:.8rem">${idx}</td>
      <td><span class="rule-name">${esc(r.rule_name||'(unnamed)')}</span></td>
      <td>${statusBadge}</td>
      <td><span class="badge ${badgeCls}">${esc(r.severity||'Low')}</span></td>
      <td class="issues-cell">${issuesList}</td>
      <td style="font-size:.8rem;color:var(--muted);max-width:260px">${esc(r.recommendation||'')}</td>
    </tr>`;
  }).join('');
}

function renderPagination() {
  const totalPages = Math.max(1, Math.ceil(filteredRows.length/PAGE_SIZE));
  const pg = document.getElementById('pagination');
  const info = document.getElementById('page-info');
  info.textContent = `Showing ${Math.min((currentPage-1)*PAGE_SIZE+1, filteredRows.length)}–${Math.min(currentPage*PAGE_SIZE, filteredRows.length)} of ${filteredRows.length} rules`;

  if(totalPages<=1){ pg.innerHTML=''; return; }
  let html = '';
  if(currentPage>1) html+=`<button class="page-btn" data-page="${currentPage-1}">‹</button>`;
  for(let p=1;p<=totalPages;p++){
    if(p===1||p===totalPages||Math.abs(p-currentPage)<=2){
      html+=`<button class="page-btn ${p===currentPage?'active':''}" data-page="${p}">${p}</button>`;
    } else if(Math.abs(p-currentPage)===3){
      html+='<span style="color:var(--muted)">…</span>';
    }
  }
  if(currentPage<totalPages) html+=`<button class="page-btn" data-page="${currentPage+1}">›</button>`;
  pg.innerHTML=html;
  pg.querySelectorAll('.page-btn').forEach(btn => btn.addEventListener('click', function(){
    currentPage=parseInt(this.dataset.page); renderTable(); renderPagination();
    document.getElementById('findings-table').scrollIntoView({behavior:'smooth',block:'nearest'});
  }));
}

// ── Helpers ──
function esc(s){ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }
function fmt(s){ return (s||'').replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase()); }

})();
</script>
</body>
</html>
"""


def render_index() -> str:
    """Return the single-page HTML application."""
    return _HTML
