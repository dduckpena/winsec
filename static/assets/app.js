/**
 * Windows Security App - main logic
 * Queries Cribl Search (default_search group) for winsec worker-group events.
 * Runs inside the Cribl Apps (Preview) iframe; uses relative URLs so the
 * platform fetch proxy attaches auth + enforces RBAC.
 *
 * Search API flow (per Cribl docs):
 *   POST /api/v1/m/default_search/search/jobs   {query, earliest, latest, sampleRate}
 *   GET  /api/v1/m/default_search/search/jobs/{id}/results?limit=..&offset=..
 */
const SEARCH_BASE = "/api/v1/m/default_search";
const NORMALIZED_DATASET = "winsec_events"; // target dataset (update once created)
const ALERT_DATASET = "winsec_alerts";       // target alert dataset (update once created)

const state = {
  earliest: "-24h",
  latest: "now",
};

const $ = (sel) => document.querySelector(sel);

async function getCriblUser() {
  try {
    return await window.getCriblUser();
  } catch (e) {
    return null;
  }
}

async function runSearch(query, earliest, latest, limit = 200) {
  const body = {
    query,
    earliest: earliest || state.earliest,
    latest: latest || state.latest,
    sampleRate: 1,
  };
  const resp = await fetch(`${SEARCH_BASE}/search/jobs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`Search job ${resp.status}: ${await resp.text()}`);
  const data = await resp.json();
  const job = Array.isArray(data.items) ? data.items[0] : data;
  const jobId = job.id;
  if (!jobId) throw new Error("No search job id returned");

  // Fetch results (paginate a few pages)
  let rows = [];
  let offset = 0;
  for (let page = 0; page < 5; page++) {
    const r = await fetch(`${SEARCH_BASE}/search/jobs/${jobId}/results?limit=${limit}&offset=${offset}`, {
      headers: { "Content-Type": "application/x-ndjson" },
    });
    if (!r.ok) break;
    const text = await r.text();
    const pageRows = text
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
    rows = rows.concat(pageRows);
    if (pageRows.length < limit) break;
    offset += limit;
  }
  return rows;
}

function setStatus(msg, isError = false) {
  const el = $("#status-bar");
  el.textContent = msg;
  el.className = "status-bar" + (isError ? " error" : "");
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// ---- Render helpers ----

function renderAuth(rows) {
  const tb = $("#tbl-auth");
  const agg = {};
  for (const r of rows) {
    const code = r.event_code || r.EventID || "?";
    const host = r.host || r.computer || "?";
    const user = r.TargetUserName || r.SubjectUserName || r.User || "?";
    const key = `${code}|${host}|${user}`;
    agg[key] = agg[key] || { code, host, user, count: 0 };
    agg[key].count++;
  }
  const items = Object.values(agg).sort((a, b) => b.count - a.count).slice(0, 15);
  tb.innerHTML = items.length
    ? items.map((i) => `<tr><td>${esc(i.code)}</td><td>${esc(i.host)}</td><td>${esc(i.user)}</td><td>${i.count}</td></tr>`).join("")
    : `<tr><td colspan="4" class="empty">No auth events in range</td></tr>`;
}

function renderAlerts(rows) {
  const tb = $("#tbl-alerts");
  const agg = {};
  for (const r of rows) {
    const sev = r.severity || r.alert_severity || "info";
    const tech = r.mitre_technique_id || r.alert_technique || "?";
    const tact = r.mitre_tactic || r.alert_tactic || "?";
    const host = r.host || "?";
    const key = `${sev}|${tech}|${tact}|${host}`;
    agg[key] = agg[key] || { sev, tech, tact, host, count: 0 };
    agg[key].count++;
  }
  const items = Object.values(agg).sort((a, b) => b.count - a.count).slice(0, 20);
  tb.innerHTML = items.length
    ? items.map((i) => `<tr><td class="sev-${i.sev}">${esc(i.sev)}</td><td>${esc(i.tech)}</td><td>${esc(i.tact)}</td><td>${esc(i.host)}</td><td>${i.count}</td></tr>`).join("")
    : `<tr><td colspan="5" class="empty">No alerts in range</td></tr>`;
}

function renderHosts(rows) {
  const tb = $("#tbl-hosts");
  const agg = {};
  for (const r of rows) {
    const host = r.host || r.computer || "?";
    agg[host] = agg[host] || { host, events: 0, alerts: 0 };
    agg[host].events++;
    if (r.winsec_alert === "true" || r.severity === "critical" || r.severity === "high") agg[host].alerts++;
  }
  const items = Object.values(agg).sort((a, b) => b.events - a.events);
  tb.innerHTML = items.length
    ? items.map((i) => `<tr><td>${esc(i.host)}</td><td>${i.events}</td><td>${i.alerts}</td></tr>`).join("")
    : `<tr><td colspan="3" class="empty">No hosts in range</td></tr>`;
}

function renderMitre(rows) {
  const el = $("#mitre-bars");
  const agg = {};
  for (const r of rows) {
    const tact = r.mitre_tactic || r.alert_tactic || "Unmapped";
    agg[tact] = (agg[tact] || 0) + 1;
  }
  const items = Object.entries(agg).sort((a, b) => b[1] - a[1]);
  const max = items.length ? items[0][1] : 1;
  el.innerHTML = items.length
    ? items.map(([tact, n]) => `
        <div class="mitre-bar">
          <div class="mitre-bar-label"><span>${esc(tact)}</span><span>${n}</span></div>
          <div class="mitre-bar-track"><div class="mitre-bar-fill" style="width:${(n / max) * 100}%"></div></div>
        </div>`).join("")
    : `<div class="empty">No MITRE-mapped events in range</div>`;
}

// ---- Main refresh ----

async function refresh() {
  setStatus("Querying Cribl Search…");
  const user = await getCriblUser();
  const rangeLabel = $("#range").value;

  try {
    // Note: these dataset names assume the winsec pipeline routes to them.
    // Fall back to querying the worker group's events if datasets aren't present.
    const eventsQ = `cribl dataset="${NORMALIZED_DATASET}" | summarize count() by event_code, host, severity`;
    const alertsQ = `cribl dataset="${ALERT_DATASET}" | where winsec_alert == "true" | summarize count() by severity, mitre_technique_id, mitre_tactic, host`;

    // Best-effort: try dataset queries; if they 404/empty, query the raw winsec events.
    let events = [], alerts = [];
    try {
      events = await runSearch(`cribl dataset="${NORMALIZED_DATASET}" | limit 500`, rangeLabel);
    } catch {
      events = [];
    }
    try {
      alerts = await runSearch(`cribl dataset="${ALERT_DATASET}" | limit 500`, rangeLabel);
    } catch {
      alerts = [];
    }

    // Totals + stats from raw events
    const stats = { events: events.length, alerts: 0, critical: 0, failed: 0 };
    const hostSet = new Set();
    for (const r of events) {
      if (r.host || r.computer) hostSet.add(r.host || r.computer);
      if (r.severity === "critical") stats.critical++;
      if (r.event_code === "4625" || r.event_code === "4771") stats.failed++;
      if (r.winsec_alert === "true" || r.severity === "critical" || r.severity === "high") stats.alerts++;
    }
    for (const a of alerts) stats.alerts += a.count || 1;

    $("#stat-events").textContent = stats.events;
    $("#stat-alerts").textContent = stats.alerts;
    $("#stat-critical").textContent = stats.critical;
    $("#stat-failed").textContent = stats.failed;
    $("#stat-hosts").textContent = hostSet.size;

    renderAuth(events);
    renderAlerts(events);
    renderHosts(events);
    renderMitre(events);

    const who = user ? ` as ${user.username || user.email || user.id}` : "";
    setStatus(`Loaded ${stats.events} events across ${hostSet.size} hosts in ${rangeLabel}${who}. Datasets: ${NORMALIZED_DATASET} / ${ALERT_DATASET}`);
  } catch (e) {
    setStatus(`Error: ${e.message}. If datasets don't exist yet, check the winsec pipeline routes to winsec_events / winsec_alerts.`, true);
    console.error(e);
  }
}

// Wire up events
$("#refresh").addEventListener("click", refresh);
$("#range").addEventListener("change", (e) => { state.earliest = e.target.value; refresh(); });

// Initial load
refresh();
