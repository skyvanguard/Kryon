/* KRYON — Dashboard del appliance. Vanilla JS, sin dependencias externas.
   Autentica con X-API-Key (guardada en sessionStorage) contra el FastAPI local.
   Nota: se usa polling en vez de EventSource porque EventSource no permite
   enviar cabeceras custom (X-API-Key); el endpoint de estado ya expone todo
   el progreso, así que polling mantiene la auth limpia. */

"use strict";

const API = "/api/v1";
const KEY_STORE = "kryon_api_key";
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

let apiKey = sessionStorage.getItem(KEY_STORE) || "";
let currentScanId = null;
let pollTimer = null;

/* ----------------------------------------------------------------- helpers */

function $(id) { return document.getElementById(id); }

async function api(path, opts = {}) {
  const headers = Object.assign({ "X-API-Key": apiKey }, opts.headers || {});
  if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const res = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (res.status === 401) { logout(); throw new Error("No autorizado"); }
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = j.detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function normSev(s) {
  const v = String(s || "info").toLowerCase();
  if (v.startsWith("crit")) return "critical";
  if (v.startsWith("high")) return "high";
  if (v.startsWith("med")) return "medium";
  if (v.startsWith("low")) return "low";
  return "info";
}

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Medio", low: "Bajo", info: "Info" };

function sevBadge(sev) {
  const s = normSev(sev);
  return `<span class="sev-badge sev-${s}">${SEV_LABEL[s]}</span>`;
}

function esc(str) {
  const d = document.createElement("div");
  d.textContent = str == null ? "" : String(str);
  return d.innerHTML;
}

function fmtTime(sec) {
  sec = Math.round(sec || 0);
  if (sec < 60) return sec + "s";
  const m = Math.floor(sec / 60), s = sec % 60;
  return m + "m " + (s < 10 ? "0" : "") + s + "s";
}

let toastTimer = null;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 3200);
}

/* -------------------------------------------------------------------- auth */

function showApp() {
  $("login").classList.add("hidden");
  $("app").classList.add("active");
  bootstrap();
}

function logout() {
  apiKey = "";
  sessionStorage.removeItem(KEY_STORE);
  if (pollTimer) clearInterval(pollTimer);
  $("app").classList.remove("active");
  $("login").classList.remove("hidden");
  $("apiKey").value = "";
}

$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const key = $("apiKey").value.trim();
  $("loginErr").textContent = "";
  if (!key) { $("loginErr").textContent = "Ingresá la clave de acceso."; return; }
  apiKey = key;
  try {
    await api("/findings?limit=1"); // valida la clave contra un endpoint autenticado
    sessionStorage.setItem(KEY_STORE, key);
    showApp();
  } catch (err) {
    apiKey = "";
    $("loginErr").textContent = "Clave inválida o servicio no disponible.";
  }
});

$("logoutBtn").addEventListener("click", logout);

/* ------------------------------------------------------------------- theme */

function applyTheme(mode) {
  document.documentElement.setAttribute("data-theme", mode);
  localStorage.setItem("kryon_theme", mode);
}
$("themeBtn").addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme");
  applyTheme(cur === "dark" ? "light" : "dark");
});
(function initTheme() {
  const saved = localStorage.getItem("kryon_theme");
  if (saved) applyTheme(saved);
})();

/* -------------------------------------------------------------------- tabs */

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const view = tab.dataset.view;
    ["panel", "drift", "findings", "schedule", "compliance"].forEach((v) => {
      $("view-" + v).classList.toggle("hidden", v !== view);
    });
    if (view === "drift") loadDrift();
    if (view === "findings") loadFindings(activeSev);
    if (view === "schedule") loadSchedule();
    if (view === "compliance") loadCompliance();
  });
});

/* ------------------------------------------------------------------ health */

async function loadHealth() {
  try {
    const r = await api("/health/ready");
    // El server reporta el LLM bajo checks.ai_provider. 3 estados:
    // healthy → verde; degraded → ámbar (el ping de 5s expira con un modelo
    // reasoning lento pero el motor RESPONDE, no es "no disponible");
    // unhealthy/otro → rojo.
    const provider = String(
      (r.checks && r.checks.ai_provider ? r.checks.ai_provider.status : r.status) || ""
    ).toLowerCase();
    let cls, txt;
    if (["ok", "healthy", "ready"].includes(provider)) {
      cls = "up";
      txt = `Operativo · v${esc(r.version || "")}`;
    } else if (provider === "degraded") {
      cls = "warn";
      txt = "Motor lento (respondiendo)";
    } else {
      cls = "down";
      txt = "Motor no disponible";
    }
    $("healthDot").className = "dot " + cls;
    $("healthText").textContent = txt;
  } catch (_) {
    $("healthDot").className = "dot down";
    $("healthText").textContent = "Sin conexión";
  }
}

/* --------------------------------------------------------------------- KPI */

async function loadKPIs() {
  try {
    const r = await api("/findings?limit=500");
    const items = r.items || [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const hosts = new Set();
    items.forEach((f) => {
      counts[normSev(f.severity)]++;
      const h = f.affected_asset || f.host || f.affected || "";
      if (h) hosts.add(h);
    });
    const total = r.total != null ? r.total : items.length;
    const kpis = [
      { label: "Hallazgos totales", value: total, cls: "" },
      { label: "Críticos", value: counts.critical, cls: "crit" },
      { label: "Altos", value: counts.high, cls: "high" },
      { label: "Equipos afectados", value: hosts.size, cls: "" },
      { label: "Medios / Bajos", value: counts.medium + counts.low, cls: "ok", sub: `${counts.medium} medios · ${counts.low} bajos` },
    ];
    $("kpiGrid").innerHTML = kpis.map((k) => `
      <div class="kpi ${k.cls}">
        <div class="k-label">${esc(k.label)}</div>
        <div class="k-value">${esc(k.value)}</div>
        ${k.sub ? `<div class="k-sub">${esc(k.sub)}</div>` : ""}
      </div>`).join("");
  } catch (err) {
    $("kpiGrid").innerHTML = `<div class="kpi"><div class="k-label">Estado</div><div class="k-value" style="font-size:18px">—</div><div class="k-sub">${esc(err.message)}</div></div>`;
  }
}

/* --------------------------------------------------------- program metrics */

async function loadMetrics() {
  const box = $("metricsBody");
  try {
    const m = await api("/findings/metrics");
    if (!m.total) {
      box.innerHTML = `<div class="empty" style="padding:24px"><div class="big">📊</div>Sin datos todavía. Corré un análisis para ver el funnel de validación.</div>`;
      return;
    }
    const vr = Math.round((m.validated_rate || 0) * 100);
    const fr = Math.round((m.fix_verification_rate || 0) * 100);
    const max = Math.max(1, m.total);
    const funnel = (m.funnel || [])
      .map((s) => {
        const pct = Math.round((s.count / max) * 100);
        return `<div class="funnel-row">
          <span class="funnel-label">${esc(s.stage)}</span>
          <span class="funnel-track"><span class="funnel-fill" style="width:${pct}%"></span></span>
          <b class="funnel-count">${esc(s.count)}</b></div>`;
      })
      .join("");
    const b = m.by_verification || {};
    box.innerHTML = `
      <div style="display:flex;gap:28px;flex-wrap:wrap;margin-bottom:18px">
        <div>
          <div class="k-label">Validados explotables</div>
          <div class="k-value" style="color:var(--sev-critical)">${esc(m.validated_exploitable)}<span style="font-size:15px;color:var(--text-faint);font-weight:600"> / ${esc(m.total)} · ${vr}%</span></div>
        </div>
        <div>
          <div class="k-label">Validados (ground truth)</div>
          <div class="k-value" style="color:var(--ok)">${esc(m.validated || 0)}</div>
        </div>
        <div>
          <div class="k-label">Fixes verificados</div>
          <div class="k-value" style="color:var(--ok)">${fr}%</div>
        </div>
        <div>
          <div class="k-label">Requieren verificación</div>
          <div class="k-value">${esc(m.needs_verification)}</div>
        </div>
      </div>
      ${funnel}
      <div class="funnel-meta">Bandas de validación: <b style="color:var(--ok)">${esc(b.confirmed || 0)}</b> confirmados · <b style="color:var(--sev-high)">${esc(b.judge_confirmed || 0)}</b> adjudicados ⚖ · <b style="color:var(--sev-medium)">${esc(b.heuristic || 0)}</b> heurísticos · <b style="color:var(--text-faint)">${esc(b.inferred || 0)}</b> inferidos</div>`;
  } catch (err) {
    box.innerHTML = `<div class="empty" style="color:var(--sev-critical);padding:20px">${esc(err.message)}</div>`;
  }
}

/* ---------------------------------------------------------------- findings */

let activeSev = "";

document.querySelectorAll("#sevFilters .chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    document.querySelectorAll("#sevFilters .chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    activeSev = chip.dataset.sev;
    loadFindings(activeSev);
  });
});

async function loadFindings(sev) {
  const body = $("findingsBody");
  body.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-faint);padding:32px">Cargando…</td></tr>`;
  try {
    const q = sev ? `?severity=${encodeURIComponent(sev)}&limit=200` : "?limit=200";
    const r = await api("/findings" + q);
    const items = r.items || [];
    $("findingsEmpty").classList.toggle("hidden", items.length > 0);
    if (!items.length) { body.innerHTML = ""; return; }
    body.innerHTML = items.map((f) => {
      const title = f.title || f.name || f.cwe || "Hallazgo";
      const desc = f.description || f.remediation || "";
      const asset = f.affected_asset || f.host || f.affected || "—";
      const cvss = f.cvss_score != null ? f.cvss_score : (f.cvss != null ? f.cvss : "—");
      const src = f.tool_source || f.source || "—";
      return `<tr>
        <td>${sevBadge(f.severity)}</td>
        <td><div class="f-title">${esc(title)}</div>${desc ? `<div class="f-desc">${esc(desc)}</div>` : ""}</td>
        <td class="f-asset">${esc(asset)}</td>
        <td style="font-variant-numeric:tabular-nums">${esc(cvss)}</td>
        <td class="f-asset">${esc(src)}</td>
      </tr>`;
    }).join("");
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--sev-critical);padding:32px">${esc(err.message)}</td></tr>`;
  }
}

/* ------------------------------------------------------------ export report */

// El reporte usa intelligence.models.Finding (title/description/severity/
// affected_asset requeridos). Mapeamos el shape del /findings a eso.
function mapToReportFinding(f) {
  return {
    title: f.title || f.name || f.cwe || "Hallazgo",
    description: f.description || f.remediation || f.evidence || "Sin descripción disponible.",
    severity: normSev(f.severity),
    affected_asset: f.affected_asset || f.host || f.affected || "desconocido",
    evidence: f.evidence || "",
    tool_source: f.tool_source || f.source || "",
    remediation: f.remediation || "",
    cvss_score: f.cvss_score != null ? f.cvss_score : f.cvss != null ? f.cvss : null,
  };
}

async function postReport(findings, format) {
  const framework = $("framework") ? $("framework").value : "";
  return api("/reports", {
    method: "POST",
    body: JSON.stringify({
      findings_json: JSON.stringify(findings),
      report_type: "technical",
      format,
      client_name: "",
      include_compliance: framework ? [framework] : [],
    }),
  });
}

// Descarga con el header X-API-Key (un <a download> normal no lo envía),
// vía fetch → blob → object URL.
async function downloadReport(filename) {
  const res = await fetch(API + "/reports/" + encodeURIComponent(filename) + "/download", {
    headers: { "X-API-Key": apiKey },
  });
  if (!res.ok) throw new Error("No se pudo descargar el reporte");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function exportReport() {
  const btn = $("exportBtn");
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin" style="border-color:rgba(0,0,0,0.2);border-top-color:var(--accent)"></span> Generando…`;
  try {
    const r = await api("/findings?limit=500");
    const findings = (r.items || []).map(mapToReportFinding);
    if (!findings.length) {
      toast("No hay hallazgos para reportar todavía.");
      return;
    }
    let resp;
    try {
      resp = await postReport(findings, "pdf");
    } catch (err) {
      // El equipo puede no tener el motor de PDF (501) → caemos a HTML.
      if (/pdf|501|not available|no disponible/i.test(err.message)) {
        toast("PDF no disponible en este equipo — generando HTML…");
        resp = await postReport(findings, "html");
      } else {
        throw err;
      }
    }
    await downloadReport(resp.filename);
    toast("Reporte generado: " + resp.filename);
  } catch (err) {
    toast("Error al generar el reporte: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = original;
  }
}

const _exportBtn = $("exportBtn");
if (_exportBtn) _exportBtn.addEventListener("click", exportReport);

/* ------------------------------------------------------------------- drift */

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (isNaN(d)) return String(iso);
    return d.toLocaleString("es", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  } catch (_) { return String(iso); }
}

async function loadDrift() {
  const summary = $("driftSummary");
  const body = $("driftBody");
  summary.innerHTML = "";
  body.innerHTML = `<div class="empty">Cargando cambios…</div>`;
  try {
    const d = await api("/findings/drift");
    if (!d.baseline) {
      summary.innerHTML = "";
      body.innerHTML = `<div class="card"><div class="empty"><div class="big">🕓</div>${esc(d.message || "Se necesita un análisis previo para comparar.")}</div></div>`;
      return;
    }
    const s = d.summary || {};
    const cards = [
      { label: "Nuevos", value: s.new || 0, cls: "crit", sub: "Aparecieron desde el último análisis" },
      { label: "Resueltos", value: s.gone || 0, cls: "ok", sub: "Ya no están (remediados)" },
      { label: "Agravados", value: s.changed || 0, cls: "high", sub: "Cambió severidad o evidencia" },
      { label: "Sin cambios", value: s.stable || 0, cls: "", sub: "Piso estable" },
    ];
    summary.innerHTML = cards.map((k) => `
      <div class="kpi ${k.cls}">
        <div class="k-label">${esc(k.label)}</div>
        <div class="k-value">${esc(k.value)}</div>
        <div class="k-sub">${esc(k.sub)}</div>
      </div>`).join("");

    const meta = `<div class="fw-meta" style="margin:2px 0 16px">Comparando <b>${esc(fmtDate(d.current_scan))}</b> vs <b>${esc(fmtDate(d.previous_scan))}</b></div>`;

    const sections = [
      { key: "new", title: "🔴 Nuevos hallazgos", items: d.new || [], color: "var(--sev-critical)" },
      { key: "changed", title: "🟠 Hallazgos agravados", items: d.changed || [], color: "var(--sev-high)" },
      { key: "gone", title: "🟢 Hallazgos resueltos", items: d.gone || [], color: "var(--ok)" },
    ];
    let html = meta;
    let any = false;
    sections.forEach((sec) => {
      if (!sec.items.length) return;
      any = true;
      html += `<div class="card"><h3 class="view-title" style="color:${sec.color}">${sec.title} (${sec.items.length})</h3>`;
      html += `<div class="table-wrap" style="box-shadow:none;border:none"><table><tbody>`;
      sec.items.forEach((it) => {
        // 'changed' viene como {previous, current}; los demás son findings planos.
        const f = it.current || it;
        const prevSev = it.previous ? it.previous.severity : null;
        const title = f.title || f.rule_id || f.cwe || "Hallazgo";
        const host = f.host || f.affected_asset || "—";
        html += `<tr>
          <td style="width:120px">${sevBadge(f.severity)}${prevSev && normSev(prevSev) !== normSev(f.severity) ? `<div class="f-desc" style="margin-top:4px">antes: ${SEV_LABEL[normSev(prevSev)]}</div>` : ""}</td>
          <td><div class="f-title">${esc(title)}</div></td>
          <td class="f-asset" style="width:200px">${esc(host)}</td>
        </tr>`;
      });
      html += `</tbody></table></div></div>`;
    });
    if (!any) {
      html += `<div class="card"><div class="empty"><div class="big">✓</div>Sin cambios respecto al análisis anterior. Tu postura se mantiene estable.</div></div>`;
    }
    body.innerHTML = html;
  } catch (err) {
    summary.innerHTML = "";
    body.innerHTML = `<div class="card"><div class="empty" style="color:var(--sev-critical)">${esc(err.message)}</div></div>`;
  }
}

/* -------------------------------------------------------------- compliance */

let frameworks = [];

async function loadFrameworks() {
  try {
    const r = await api("/compliance/frameworks");
    frameworks = r.frameworks || [];
    ["framework", "schFramework"].forEach((selId) => {
      const sel = $(selId);
      if (!sel) return;
      frameworks.forEach((fw) => {
        const o = document.createElement("option");
        o.value = fw.id;
        o.textContent = fw.name;
        sel.appendChild(o);
      });
    });
  } catch (_) { /* select queda con "Ninguno" */ }
}

/* ---------------------------------------------------------------- schedule */

function populateHourSelect() {
  const sel = $("schHour");
  if (!sel || sel.options.length) return;
  for (let h = 0; h < 24; h++) {
    const o = document.createElement("option");
    o.value = h;
    o.textContent = String(h).padStart(2, "0") + ":00";
    if (h === 2) o.selected = true; // 02:00 por defecto (ventana nocturna)
    sel.appendChild(o);
  }
}

async function loadSchedule() {
  const box = $("scheduleList");
  box.innerHTML = `<div class="empty">Cargando…</div>`;
  try {
    const jobs = await api("/scans?limit=200");
    // Solo análisis reales: un job sin objetivos no hace nada (y filtra ruido).
    const real = (jobs || []).filter((j) => (j.targets || []).length && j.status !== "cancelled");
    if (!real.length) {
      box.innerHTML = `<div class="empty"><div class="big">🌙</div>Sin análisis programados. Creá uno a la izquierda.</div>`;
      return;
    }
    box.innerHTML = real
      .map((j) => {
        const cad = (j.interval_seconds || 0) >= 604800 ? "Semanal" : "Diario";
        const hora = j.start_hour != null ? String(j.start_hour).padStart(2, "0") + ":00" : "—";
        const last = j.last_run ? fmtDate(j.last_run) : "nunca";
        const fws = (j.frameworks || []).join(", ") || "sin marco";
        return `<div class="card" style="margin:0 0 12px;box-shadow:none">
          <div style="display:flex;align-items:flex-start;gap:10px">
            <div style="flex:1;min-width:0">
              <div class="f-title" style="word-break:break-word">${esc((j.targets || []).join(", "))}</div>
              <div class="f-desc">${cad} · ${hora} · ${esc(fws)} · último: ${esc(last)}</div>
            </div>
            <button class="btn ghost" data-cancel="${esc(j.id)}">Cancelar</button>
          </div></div>`;
      })
      .join("");
    box.querySelectorAll("[data-cancel]").forEach((b) =>
      b.addEventListener("click", () => cancelSchedule(b.dataset.cancel))
    );
  } catch (err) {
    box.innerHTML = `<div class="empty" style="color:var(--sev-critical)">${esc(err.message)}</div>`;
  }
}

async function createSchedule() {
  const targets = $("schTargets").value.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean);
  if (!targets.length) {
    toast("Cargá al menos un objetivo.");
    return;
  }
  const fw = $("schFramework").value;
  const btn = $("schCreateBtn");
  btn.disabled = true;
  try {
    await api("/scans", {
      method: "POST",
      body: JSON.stringify({
        client_id: "default",
        profile: "standard",
        targets,
        frameworks: fw ? [fw] : [],
        interval_seconds: parseInt($("schCadence").value, 10),
        start_hour: parseInt($("schHour").value, 10),
      }),
    });
    toast("Análisis programado para las " + $("schHour").value.padStart(2, "0") + ":00.");
    $("schTargets").value = "";
    loadSchedule();
  } catch (err) {
    toast("Error al programar: " + err.message);
  } finally {
    btn.disabled = false;
  }
}

async function cancelSchedule(id) {
  try {
    await api("/scans/" + encodeURIComponent(id), { method: "DELETE" });
    toast("Programación cancelada.");
    loadSchedule();
  } catch (err) {
    toast("Error al cancelar: " + err.message);
  }
}

const _schCreateBtn = $("schCreateBtn");
if (_schCreateBtn) _schCreateBtn.addEventListener("click", createSchedule);

async function loadCompliance() {
  const grid = $("fwGrid");
  if (!frameworks.length) { grid.innerHTML = `<div class="empty">No hay marcos disponibles.</div>`; return; }
  grid.innerHTML = frameworks.map((fw) => `
    <div class="fw-card" data-fw="${esc(fw.id)}">
      <div class="fw-name">${esc(fw.name)}</div>
      <div class="fw-meta">${esc(fw.controls || "?")} controles${fw.safeguards ? ` · ${esc(fw.safeguards)} salvaguardas` : ""}</div>
      <div class="fw-score" id="score-${esc(fw.id)}">—</div>
      <div class="fw-bar"><span id="bar-${esc(fw.id)}" style="width:0%;background:var(--text-faint)"></span></div>
      <div class="fw-meta" style="margin-top:8px">Tocá para evaluar contra los hallazgos actuales</div>
    </div>`).join("");
  grid.querySelectorAll(".fw-card").forEach((card) => {
    card.addEventListener("click", () => assess(card.dataset.fw));
  });
}

async function assess(framework) {
  const scoreEl = $("score-" + framework);
  const barEl = $("bar-" + framework);
  if (scoreEl) scoreEl.textContent = "…";
  try {
    const r = await api("/compliance/assess", { method: "POST", body: JSON.stringify({ framework, client_id: "" }) });
    // Forma tolerante: distintos mappers exponen el score con nombres distintos.
    let score = r.compliance_score;
    if (score == null && r.summary) score = r.summary.compliance_score || r.summary.score;
    if (score == null && r.passed != null && r.total != null) score = r.total ? (r.passed / r.total) * 100 : 0;
    score = score == null ? null : Math.round(score);
    if (score == null) { if (scoreEl) scoreEl.textContent = "N/D"; return; }
    if (scoreEl) scoreEl.textContent = score + "%";
    if (barEl) {
      barEl.style.width = Math.max(0, Math.min(100, score)) + "%";
      barEl.style.background = score >= 80 ? "var(--ok)" : score >= 50 ? "var(--sev-medium)" : "var(--sev-critical)";
    }
  } catch (err) {
    if (scoreEl) scoreEl.textContent = "Error";
    toast("Error al evaluar: " + err.message);
  }
}

/* -------------------------------------------------------------------- scan */

$("scanBtn").addEventListener("click", startScan);

function setScanning(on) {
  const btn = $("scanBtn");
  btn.disabled = on;
  btn.innerHTML = on ? `<span class="spin"></span> Analizando…` : "Iniciar análisis";
}

async function startScan() {
  const raw = $("targets").value.trim();
  const targets = raw.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean);
  if (!targets.length) { toast("Cargá al menos un objetivo."); return; }

  const framework = $("framework").value;
  const stealthMap = { standard: "normal", stealth: "high", thorough: "low" };
  const body = {
    targets,
    profile: $("profile").value,
    stealth_level: stealthMap[$("profile").value] || "normal",
    compliance_frameworks: framework ? [framework] : [],
    output_format: "pdf",
  };

  setScanning(true);
  $("progressIdle").classList.add("hidden");
  $("progressLive").classList.remove("hidden");
  $("scanLog").innerHTML = "";
  resetProgress();

  try {
    const r = await api("/scans/auto", { method: "POST", body: JSON.stringify(body) });
    currentScanId = r.scan_id;
    toast("Análisis iniciado sobre " + targets.length + " objetivo(s).");
    pollScan();
  } catch (err) {
    setScanning(false);
    toast("No se pudo iniciar: " + err.message);
    $("progressLive").classList.add("hidden");
    $("progressIdle").classList.remove("hidden");
  }
}

function resetProgress() {
  $("progFill").style.width = "0%";
  ["mPhase", "mHosts", "mFindings", "mCrit", "mHigh", "mElapsed"].forEach((id) => {
    $(id).textContent = id === "mHosts" ? "0/0" : id === "mElapsed" ? "0s" : "0";
  });
}

let seenLogLines = 0;

function pollScan() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (!currentScanId) { clearInterval(pollTimer); return; }
    try {
      const s = await api("/scans/auto/" + currentScanId);
      const pct = Math.round((s.phase_progress || 0) * (s.phase_progress <= 1 ? 100 : 1));
      $("progFill").style.width = pct + "%";
      $("mPhase").textContent = pct + "%";
      $("mHosts").textContent = `${s.hosts_scanned || 0}/${s.hosts_discovered || 0}`;
      $("mFindings").textContent = s.findings_count || 0;
      $("mCrit").textContent = s.critical_count || 0;
      $("mHigh").textContent = s.high_count || 0;
      $("mElapsed").textContent = fmtTime(s.elapsed_seconds);

      const logs = s.log_messages || [];
      if (logs.length > seenLogLines) {
        const box = $("scanLog");
        for (let i = seenLogLines; i < logs.length; i++) {
          const div = document.createElement("div");
          div.textContent = "› " + logs[i];
          box.appendChild(div);
        }
        box.scrollTop = box.scrollHeight;
        seenLogLines = logs.length;
      }

      const st = String(s.status || "").toLowerCase();
      if (st === "completed" || st === "failed" || st === "cancelled" || st === "error") {
        clearInterval(pollTimer);
        setScanning(false);
        seenLogLines = 0;
        if (st === "completed") {
          toast("Análisis completado. " + (s.findings_count || 0) + " hallazgos.");
          await loadKPIs();
          loadMetrics();
          await loadScanFindings(currentScanId);
        } else {
          toast("Análisis finalizado: " + (s.error || st));
        }
      }
    } catch (err) {
      clearInterval(pollTimer);
      setScanning(false);
      toast("Se perdió el seguimiento del análisis: " + err.message);
    }
  }, 2000);
}

async function loadScanFindings(scanId) {
  try {
    const items = await api("/scans/auto/" + scanId + "/findings");
    if (Array.isArray(items) && items.length) {
      // Salta a la vista de hallazgos para mostrar el resultado.
      document.querySelector('.tab[data-view="findings"]').click();
    }
  } catch (_) { /* los findings consolidados igual se ven en la pestaña */ }
}

/* --------------------------------------------------------------- bootstrap */

function bootstrap() {
  loadHealth();
  loadKPIs();
  loadMetrics();
  loadFrameworks();
  populateHourSelect();
  setInterval(loadHealth, 15000);
}

/* ------------------------------------------------------------------- start */

if (apiKey) { showApp(); } else { $("login").classList.remove("hidden"); }
