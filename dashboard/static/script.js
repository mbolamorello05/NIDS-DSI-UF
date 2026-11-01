// Dashboard NIDS (Tailwind + daisyUI) -- routage de pages sans rechargement,
// flux SSE en direct, et chargement a la demande pour Performance/Parametres.

const MAX_FEED_ROWS = 300;
const TIMELINE_MINUTES = 30;
const GROUP_WINDOW_MS = 3000;
const PAGE_TITLES = { dashboard: "Tableau de bord", alerts: "Alertes", performance: "Performance du modèle", settings: "Paramètres" };
const FAMILY_COLOR = { benign: "#16a34a", scan: "#f59e0b", ddos: "#ef4444", brute_force: "#a855f7" };

// ============================================================
// Theme (clair/sombre), memorise par navigateur
// ============================================================
const THEME_KEY = "nids-theme";
function applyTheme(light) {
  document.documentElement.setAttribute("data-theme", light ? "corporate" : "business");
  document.getElementById("theme-toggle").checked = light;
  document.getElementById("theme-toggle-2").checked = light;
  localStorage.setItem(THEME_KEY, light ? "light" : "dark");
}
function initTheme() {
  applyTheme(localStorage.getItem(THEME_KEY) === "light");
  document.getElementById("theme-toggle").addEventListener("change", e => applyTheme(e.target.checked));
  document.getElementById("theme-toggle-2").addEventListener("change", e => applyTheme(e.target.checked));
}

// ============================================================
// Routage de pages
// ============================================================
function showPage(name) {
  document.querySelectorAll(".page").forEach(p => p.classList.add("hidden"));
  document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
  document.getElementById(`page-${name}`).classList.remove("hidden");
  document.querySelectorAll(`.nav-item[data-page="${name}"]`).forEach(b => b.classList.add("active"));
  document.getElementById("page-title").textContent = PAGE_TITLES[name];
  if (name === "performance" && !perfLoaded) loadPerformance();
  if (name === "alerts" && !historyLoaded) loadHistoryPage();
  if (name === "settings") { loadConfig(); loadInterfaces(); }
}
document.querySelectorAll("[data-page]").forEach(btn => btn.addEventListener("click", () => showPage(btn.dataset.page)));

// ============================================================
// Etat + compteurs
// ============================================================
const counters = { total: 0, benign: 0, scan: 0, ddos: 0, brute_force: 0 };
const sources = new Map();
const timeline = new Map();   // "HH:MM" -> {benign,scan,ddos,brute_force}
const feedGroups = new Map();
const bellItems = [];
let bellUnread = 0;

function familyOf(r) { return r.verdict === "benign" ? "benign" : (r.family_label || "ddos"); }
function minuteKey(ts) { return ts.slice(11, 16); }

function applyRecord(record) {
  const fam = familyOf(record);

  counters.total += 1;
  counters[fam] = (counters[fam] || 0) + 1;
  const s = sources.get(record.src_ip) || { total: 0, anomal: 0 };
  s.total += 1;
  if (record.verdict === "anomal") s.anomal += 1;
  sources.set(record.src_ip, s);

  const key = minuteKey(record.timestamp);
  const bucket = timeline.get(key) || { benign: 0, scan: 0, ddos: 0, brute_force: 0 };
  bucket[fam] = (bucket[fam] || 0) + 1;
  timeline.set(key, bucket);
  while (timeline.size > TIMELINE_MINUTES) timeline.delete(timeline.keys().next().value);

  // Perf : on ne touche PAS au DOM ici. Pendant une attaque, des milliers
  // d'enregistrements arrivent par seconde ; redessiner 7 graphiques pour
  // chacun gelait l'onglet. Les donnees sont mises a jour ici, l'affichage
  // est regroupe dans scheduleRender() (au plus 2 fois par seconde).
  liveRecords.unshift(record);
  if (liveRecords.length > 2000) liveRecords.length = 2000;
  if (record.verdict === "anomal") pushBell(record, fam);
  scheduleRender();
}

function renderKpis() {
  ["total", "benign", "scan", "ddos", "brute"].forEach((k, i) => {
    const val = i === 0 ? counters.total : counters[["", "benign", "scan", "ddos", "brute_force"][i]] || 0;
    document.getElementById(`kpi-${k}`).textContent = val.toLocaleString("fr-FR");
  });
}

let renderTimer = null;
function scheduleRender() {
  if (renderTimer) return;
  renderTimer = setTimeout(() => {
    renderTimer = null;
    renderKpis();
    renderTimelineChart();
    renderDonut();
    renderSparklines();
    renderRecentAlerts();
    renderBell();
    const pa = document.getElementById("page-alerts");
    if (pa && !pa.classList.contains("hidden")) renderHistoryTable();
  }, 500);
}

// ============================================================
// Cloche de notifications
// ============================================================
function pushBell(record, fam) {
  bellItems.unshift({ record, fam });
  if (bellItems.length > 8) bellItems.pop();
  bellUnread += 1;
}

function renderBell() {
  if (!bellItems.length) return;
  if (bellUnread > 0) {
    const badge = document.getElementById("bell-badge");
    badge.textContent = bellUnread > 9 ? "9+" : bellUnread;
    badge.classList.remove("hidden");
  }
  document.getElementById("bell-list").innerHTML = bellItems.map(({ record: r, fam: f }) => `
    <li class="py-1.5 border-b border-base-200 last:border-0">
      <div class="flex items-center justify-between">
        <span class="font-medium">${r.src_ip}</span>
        <span class="badge badge-sm" style="background:${FAMILY_COLOR[f]};color:white;border:none;">${f}</span>
      </div>
      <div class="text-xs text-base-content/50">${r.dst_ip}:${r.dst_port} · ${r.fine_label || "?"}</div>
    </li>`).join("");
}
document.getElementById("bell-label").addEventListener("click", () => {
  bellUnread = 0;
  document.getElementById("bell-badge").classList.add("hidden");
});

// ============================================================
// Flux en direct (regroupe l'affichage, jamais les compteurs)
// ============================================================
const feedEl = document.createElement("div"); // flux complet garde en memoire (pour page Alertes)
function groupKey(r, fam) { return `${r.src_ip}|${fam}|${r.fine_label || ""}`; }
const liveRecords = [];

function renderFeedRow(record, fam) {
  liveRecords.unshift(record);
  if (liveRecords.length > 2000) liveRecords.pop();
  renderRecentAlerts();
  if (document.getElementById("page-alerts") && !document.getElementById("page-alerts").classList.contains("hidden")) {
    renderHistoryTable();
  }
}

function renderRecentAlerts() {
  const tbody = document.getElementById("recent-alerts-body");
  const rows = liveRecords.slice(0, 8);
  tbody.innerHTML = rows.map(r => {
    const fam = familyOf(r);
    return `<tr class="fade-in">
      <td class="text-xs">${r.timestamp.slice(11, 19)}</td>
      <td class="text-xs">${r.src_ip}:${r.src_port}</td>
      <td class="text-xs">${r.dst_ip}:${r.dst_port}</td>
      <td><span class="badge badge-sm" style="background:${FAMILY_COLOR[fam]};color:white;border:none;">${fam}</span></td>
      <td class="text-xs">${r.fine_label || "--"}</td>
    </tr>`;
  }).join("");
}

// ============================================================
// Graphiques : timeline, donut, sparklines
// ============================================================
let timelineChart, donutChart;
const sparkCharts = {};

function initCharts() {
  timelineChart = new Chart(document.getElementById("chart-timeline").getContext("2d"), {
    type: "line",
    data: { labels: [], datasets: [
      { label: "scan", data: [], borderColor: FAMILY_COLOR.scan, tension: 0.35, pointRadius: 0 },
      { label: "ddos", data: [], borderColor: FAMILY_COLOR.ddos, tension: 0.35, pointRadius: 0 },
      { label: "brute_force", data: [], borderColor: FAMILY_COLOR.brute_force, tension: 0.35, pointRadius: 0 },
      { label: "benign", data: [], borderColor: FAMILY_COLOR.benign, tension: 0.35, pointRadius: 0 },
    ] },
    options: { responsive: true, maintainAspectRatio: false, interaction: { intersect: false, mode: "index" },
      scales: { x: { grid: { display: false } }, y: { beginAtZero: true } } },
  });

  donutChart = new Chart(document.getElementById("chart-donut").getContext("2d"), {
    type: "doughnut",
    data: { labels: ["benign", "scan", "ddos", "brute_force"],
      datasets: [{ data: [0, 0, 0, 0], backgroundColor: Object.values(FAMILY_COLOR), borderWidth: 2 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } },
  });

  ["total", "benign", "scan", "ddos", "brute"].forEach(k => {
    const color = k === "total" ? "#6366f1" : FAMILY_COLOR[k === "brute" ? "brute_force" : k];
    sparkCharts[k] = new Chart(document.getElementById(`spark-${k}`).getContext("2d"), {
      type: "line",
      data: { labels: [], datasets: [{ data: [], borderColor: color, backgroundColor: color + "22", fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false } } },
    });
  });
}

function renderTimelineChart() {
  const keys = Array.from(timeline.keys());
  timelineChart.data.labels = keys;
  timelineChart.data.datasets[0].data = keys.map(k => timeline.get(k).scan || 0);
  timelineChart.data.datasets[1].data = keys.map(k => timeline.get(k).ddos || 0);
  timelineChart.data.datasets[2].data = keys.map(k => timeline.get(k).brute_force || 0);
  timelineChart.data.datasets[3].data = keys.map(k => timeline.get(k).benign || 0);
  timelineChart.update("none");
}

function renderDonut() {
  const vals = [counters.benign || 0, counters.scan || 0, counters.ddos || 0, counters.brute_force || 0];
  donutChart.data.datasets[0].data = vals;
  donutChart.update("none");
  const total = vals.reduce((a, b) => a + b, 0) || 1;
  const labels = ["benign", "scan", "ddos", "brute_force"];
  document.getElementById("donut-legend").innerHTML = labels.map((l, i) => `
    <li class="flex items-center justify-between">
      <span class="flex items-center gap-2"><span class="w-2.5 h-2.5 rounded-full inline-block" style="background:${FAMILY_COLOR[l]}"></span>${l}</span>
      <span class="text-base-content/60">${((vals[i] / total) * 100).toFixed(1)}% (${vals[i]})</span>
    </li>`).join("");
}

function renderSparklines() {
  const keys = Array.from(timeline.keys());
  const series = {
    total: keys.map(k => { const b = timeline.get(k); return (b.benign || 0) + (b.scan || 0) + (b.ddos || 0) + (b.brute_force || 0); }),
    benign: keys.map(k => timeline.get(k).benign || 0),
    scan: keys.map(k => timeline.get(k).scan || 0),
    ddos: keys.map(k => timeline.get(k).ddos || 0),
    brute: keys.map(k => timeline.get(k).brute_force || 0),
  };
  Object.entries(sparkCharts).forEach(([k, chart]) => {
    chart.data.labels = keys;
    chart.data.datasets[0].data = series[k];
    chart.update("none");
  });
}

// ============================================================
// Connexion / historique
// ============================================================
function setStatus(state) {
  const el = document.getElementById("status");
  const map = { connecting: ["badge-warning", "Connexion..."], live: ["badge-success", "● En direct"], down: ["badge-error", "Connexion perdue"] };
  el.className = `badge gap-1 hidden sm:flex ${map[state][0]}`;
  el.textContent = map[state][1];
}
async function loadInitial() {
  try {
    const res = await fetch("/api/history?limit=300");
    (await res.json()).forEach(applyRecord);
  } catch (e) { console.error(e); }
}
function connectStream() {
  const es = new EventSource("/api/stream");
  es.onopen = () => setStatus("live");
  es.onerror = () => setStatus("down");
  es.onmessage = (ev) => { try { applyRecord(JSON.parse(ev.data)); } catch (e) {} };
}

// ============================================================
// Page Alertes
// ============================================================
let historyLoaded = false;
let historyData = [];
async function loadHistoryPage() {
  historyLoaded = true;
  try {
    const res = await fetch("/api/history?limit=1000");
    historyData = (await res.json()).reverse();
    renderHistoryTable();
  } catch (e) {
    document.getElementById("history-body").innerHTML = `<tr><td colspan="7">Historique indisponible.</td></tr>`;
  }
}
function filteredHistory() {
  const search = document.getElementById("hist-search").value.trim().toLowerCase();
  const famFilter = document.getElementById("hist-family").value;
  const merged = [...liveRecords, ...historyData];
  return merged.filter(r => {
    if (search && !r.src_ip.toLowerCase().includes(search)) return false;
    if (famFilter && familyOf(r) !== famFilter) return false;
    return true;
  }).slice(0, 500);
}
function renderHistoryTable() {
  const rows = filteredHistory();
  const tbody = document.getElementById("history-body");
  if (!rows.length) { tbody.innerHTML = `<tr><td colspan="7" class="text-center text-base-content/50 py-8">Aucun résultat.</td></tr>`; return; }
  tbody.innerHTML = rows.map(r => {
    const fam = familyOf(r);
    const conf = r.verdict === "anomal" && r.family_confidence ? (r.family_confidence * 100).toFixed(1) + "%" : "--";
    const conflict = r.family_fine_conflict ? `<span class="tooltip" data-tip="Désaccord entre modèles">⚠️</span>` : "";
    return `<tr>
      <td class="text-xs">${r.timestamp.slice(11, 19)}</td>
      <td class="text-xs">${r.src_ip}:${r.src_port}</td>
      <td class="text-xs">${r.dst_ip}:${r.dst_port}</td>
      <td><span class="badge badge-sm" style="background:${FAMILY_COLOR[fam]};color:white;border:none;">${fam}</span></td>
      <td class="text-xs">${r.fine_label || "--"}</td>
      <td class="text-xs">${conf}</td>
      <td>${conflict}</td>
    </tr>`;
  }).join("");
}
document.getElementById("hist-search").addEventListener("input", renderHistoryTable);
document.getElementById("hist-family").addEventListener("change", renderHistoryTable);
document.getElementById("hist-refresh").addEventListener("click", loadHistoryPage);
document.getElementById("hist-export").addEventListener("click", () => {
  const rows = filteredHistory();
  const header = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "family", "fine_label", "family_confidence", "fine_confidence"];
  const csv = [header.join(",")].concat(rows.map(r => header.map(h => {
    const v = h === "family" ? familyOf(r) : (r[h] ?? "");
    return `"${String(v).replace(/"/g, '""')}"`;
  }).join(","))).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `alertes_nids_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
  a.click();
  URL.revokeObjectURL(url);
});

// ============================================================
// Page Performance du modele
// ============================================================
let perfLoaded = false, perfData = null, perfGranularity = "fine", perfChart = null;
async function loadPerformance() {
  const container = document.getElementById("perf-content");
  try {
    const res = await fetch("/api/metrics");
    if (!res.ok) {
      const err = await res.json();
      container.innerHTML = `<div class="alert alert-warning"><span>${err.message || "Métriques indisponibles."}</span></div>`;
      return;
    }
    perfData = await res.json();
    perfLoaded = true;
    renderPerformance();
  } catch (e) {
    container.innerHTML = `<div class="alert alert-error"><span>Impossible de charger les métriques.</span></div>`;
  }
}
function renderPerformance() {
  const container = document.getElementById("perf-content");
  const granularities = Object.keys(perfData.model2 || {});
  if (!granularities.includes(perfGranularity)) perfGranularity = granularities[0];
  const trainedDate = new Date(perfData.trained_at).toLocaleString("fr-FR");
  const acc = (perfData.model1_binary.report.accuracy * 100).toFixed(2);

  container.innerHTML = `
    <div class="stats shadow w-full bg-base-100 mb-6">
      <div class="stat"><div class="stat-title">Flux dans le dataset</div><div class="stat-value text-2xl">${perfData.dataset.total_flows.toLocaleString("fr-FR")}</div></div>
      <div class="stat"><div class="stat-title">Précision modèle binaire</div><div class="stat-value text-2xl text-success">${acc}%</div></div>
      <div class="stat"><div class="stat-title">Dernier entraînement</div><div class="stat-value text-base">${trainedDate}</div></div>
    </div>
    <div role="tablist" class="tabs tabs-boxed w-fit mb-4">
      ${granularities.map(g => `<a role="tab" data-g="${g}" class="tab ${g === perfGranularity ? "tab-active" : ""}">${g}</a>`).join("")}
    </div>
    <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <div class="card bg-base-100 shadow fade-in"><div class="card-body">
        <h2 class="card-title text-base">F1-score par classe (chaîne complète)</h2>
        <div class="relative h-72 w-full"><canvas id="chart-perf-f1"></canvas></div>
      </div></div>
      <div class="card bg-base-100 shadow fade-in"><div class="card-body">
        <h2 class="card-title text-base">Détail précision / rappel / support</h2>
        <div class="overflow-x-auto"><table class="table table-sm" id="perf-table"></table></div>
      </div></div>
      <div class="card bg-base-100 shadow fade-in xl:col-span-2"><div class="card-body">
        <h2 class="card-title text-base">Matrice de confusion (modèle 2 seul, sur vraies anomalies)</h2>
        <div id="confusion-matrix" class="overflow-x-auto"></div>
      </div></div>
    </div>`;

  container.querySelectorAll('[data-g]').forEach(tab => tab.addEventListener("click", () => { perfGranularity = tab.dataset.g; renderPerformance(); }));
  renderPerfChartAndTable();
  renderConfusionMatrix();
}
function renderPerfChartAndTable() {
  const chainReport = perfData.full_chain[perfGranularity];
  const classes = Object.keys(chainReport).filter(k => !["accuracy", "macro avg", "weighted avg"].includes(k));
  if (perfChart) perfChart.destroy();
  perfChart = new Chart(document.getElementById("chart-perf-f1").getContext("2d"), {
    type: "bar",
    data: { labels: classes, datasets: [{ label: "F1-score", data: classes.map(c => chainReport[c]["f1-score"]), backgroundColor: "#6366f1", borderRadius: 6 }] },
    options: { responsive: true, maintainAspectRatio: false, scales: { y: { min: 0, max: 1 } }, plugins: { legend: { display: false } } },
  });
  document.getElementById("perf-table").innerHTML = `<thead><tr><th>Classe</th><th>Précision</th><th>Rappel</th><th>F1</th><th>Support</th></tr></thead>
    <tbody>${classes.map(c => { const r = chainReport[c];
      return `<tr><td>${c}</td><td>${r.precision.toFixed(3)}</td><td>${r.recall.toFixed(3)}</td><td>${r["f1-score"].toFixed(3)}</td><td>${r.support}</td></tr>`; }).join("")}</tbody>`;
}
function renderConfusionMatrix() {
  const m2 = perfData.model2[perfGranularity];
  const classes = m2.classes, matrix = m2.confusion_matrix;
  const maxVal = Math.max(...matrix.flat());
  let html = '<table class="table table-sm"><thead><tr><th>Vrai \\ Prédit</th>' + classes.map(c => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
  matrix.forEach((row, i) => {
    html += `<tr><th>${classes[i]}</th>`;
    row.forEach((val, j) => {
      const intensity = maxVal ? val / maxVal : 0;
      const bg = i === j ? `rgba(99,102,241,${0.12 + intensity * 0.5})` : `rgba(239,68,68,${val ? 0.1 + intensity * 0.4 : 0})`;
      html += `<td class="text-center" style="background:${bg}">${val}</td>`;
    });
    html += "</tr>";
  });
  document.getElementById("confusion-matrix").innerHTML = html + "</tbody></table>";
}

// ============================================================
// Page Parametres
// ============================================================
async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    const cfg = await res.json();
    document.getElementById("config-body").innerHTML = `
      <tr><td class="font-medium">Journal surveillé</td><td><code class="text-xs">${cfg.log_path}</code></td></tr>
      <tr><td class="font-medium">Dossier des modèles</td><td><code class="text-xs">${cfg.models_dir}</code></td></tr>
      <tr><td class="font-medium">Utilisateur admin</td><td>${cfg.admin_user}</td></tr>`;
  } catch (e) {
    document.getElementById("config-body").innerHTML = `<tr><td class="text-error">Configuration indisponible.</td></tr>`;
  }
}

// ============================================================
// Interface reseau a surveiller (fichier partage, voir /api/interfaces)
// ============================================================
async function loadInterfaces() {
  const el = document.getElementById("iface-content");
  try {
    const res = await fetch("/api/interfaces");
    if (!res.ok) {
      const err = await res.json();
      el.innerHTML = `<div class="alert alert-warning text-sm"><i data-lucide="alert-triangle" class="w-4 h-4"></i><span>${err.message}</span></div>`;
      lucide.createIcons();
      return;
    }
    const data = await res.json();
    renderInterfaces(data);
  } catch (e) {
    el.innerHTML = `<div class="alert alert-error text-sm"><span>Impossible de charger les interfaces.</span></div>`;
  }
}

function renderInterfaces(data) {
  const el = document.getElementById("iface-content");
  const options = data.available.map(i => {
    const label = `${i.name}${i.addresses.length ? " — " + i.addresses.join(", ") : ""}${i.up === false ? " (inactive)" : ""}`;
    const selected = i.source === data.current ? "selected" : "";
    return `<option value="${i.source}" ${selected}>${label}</option>`;
  }).join("");
  const warnings = data.available.filter(i => i.warning);

  el.innerHTML = `
    <div class="flex flex-wrap gap-3 items-center">
      <select id="iface-select" class="select select-bordered select-sm flex-1 min-w-[260px]">${options}</select>
      <button id="iface-save" class="btn btn-sm btn-primary">Enregistrer</button>
    </div>
    <div id="iface-msg" class="text-sm mt-2"></div>
    ${warnings.length ? `<div class="alert alert-warning text-xs mt-3"><span>${warnings[0].warning}</span></div>` : ""}
    <div class="text-xs text-base-content/50 mt-2">
      Pour rafraîchir cette liste : <code>python realtime_detector_v6.py --list-interfaces</code> sur l'hôte.
    </div>`;

  document.getElementById("iface-save").addEventListener("click", async () => {
    const chosen = document.getElementById("iface-select").value;
    const msg = document.getElementById("iface-msg");
    try {
      const res = await fetch("/api/interfaces", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: chosen }),
      });
      const result = await res.json();
      msg.innerHTML = result.ok
        ? `<span class="text-success">✓ Enregistré. Redémarre le détecteur pour appliquer.</span>`
        : `<span class="text-error">${result.error}</span>`;
    } catch (e) {
      msg.innerHTML = `<span class="text-error">Échec de l'enregistrement.</span>`;
    }
  });
}

// ============================================================
// Etat systeme (CPU/RAM/disque reels, sondage periodique)
// ============================================================
async function pollSystem() {
  try {
    const res = await fetch("/api/system");
    const s = await res.json();
    document.getElementById("sys-cpu").value = s.cpu;
    document.getElementById("sys-cpu-val").textContent = s.cpu.toFixed(0) + "%";
    document.getElementById("sys-mem").value = s.memory;
    document.getElementById("sys-mem-val").textContent = s.memory.toFixed(0) + "%";
    document.getElementById("sys-disk").value = s.disk;
    document.getElementById("sys-disk-val").textContent = s.disk.toFixed(0) + "%";
  } catch (e) { /* ignore */ }
}

// ============================================================
// Init
// ============================================================
async function loadWhoami() {
  try {
    const res = await fetch("/api/whoami");
    const data = await res.json();
    document.getElementById("username").textContent = data.username || "admin";
    document.getElementById("user-avatar").textContent = (data.username || "A")[0].toUpperCase();
  } catch (e) {}
}
document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch("/logout", { method: "POST" });
  window.location.href = "/login";
});

lucide.createIcons();
initTheme();
initCharts();
loadWhoami();
pollSystem();
setInterval(pollSystem, 5000);
loadInitial().then(connectStream);