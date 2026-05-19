/**
 * popup/popup.js
 * Solicita estado ao background e renderiza o popup.
 */

"use strict";

// -----------------------------------------------------------------------
// Threat Score
// Metodologia:
//   Parte de 100 e desconta penalidades por cada vetor detectado.
//   - Cada dominio de 3a parte:        -2  (max -30)
//   - Cada cookie de 3a parte:         -3  (max -15)
//   - Supercookie detectado:           -10 cada
//   - Cada tecnica de fingerprinting:  -8  (max -24)
//   - Script suspeito / tracker:       -5  (max -20)
//   - Cookie syncing detectado:        -5  (max -10)
//   - Redirecionamento suspeito:       -8 cada
//   Score minimo = 0, maximo = 100.
// -----------------------------------------------------------------------
function calcPrivacyScore(state) {
  let score = 100;

  const thirdPartyCount = Object.keys(state.thirdPartyDomains || {}).length;
  score -= Math.min(thirdPartyCount * 2, 30);

  const cookies3rd = (state.cookies.thirdParty || []).length;
  score -= Math.min(cookies3rd * 3, 15);

  const supercookies = (state.cookies.supercookies || []).length;
  score -= supercookies * 10;

  const fpTypes = ["canvas", "webgl", "audioContext"];
  let fpCount = 0;
  for (const t of fpTypes) {
    if ((state.fingerprinting[t] || []).length > 0) fpCount++;
  }
  score -= Math.min(fpCount * 8, 24);

  const suspiciousScripts = (state.hijacking.suspiciousScripts || []).length;
  score -= Math.min(suspiciousScripts * 5, 20);

  const cookieSyncCount = (state.cookieSyncing || []).length;
  score -= Math.min(cookieSyncCount * 5, 10);

  const redirects = (state.hijacking.redirectAttempts || []).length;
  score -= redirects * 8;

  return Math.max(0, score);
}

// -----------------------------------------------------------------------
// Helpers de renderizacao
// -----------------------------------------------------------------------
const KNOWN_TRACKERS = [
  "doubleclick.net", "googletagmanager.com", "google-analytics.com",
  "facebook.net", "scorecardresearch.com", "quantserve.com",
  "outbrain.com", "taboola.com", "criteo.com", "adnxs.com"
];

function isTracker(domain) {
  return KNOWN_TRACKERS.some(t => domain.endsWith(t));
}

function setCount(id, n, warn = false) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = n;
  if (warn && n > 0) el.classList.add("warn");
  else el.classList.remove("warn");
}

function setList(id, items) {
  const ul = document.getElementById(id);
  if (!ul) return;
  ul.innerHTML = "";
  if (!items.length) {
    ul.innerHTML = '<li class="empty">Nenhum detectado.</li>';
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    li.innerHTML = item;
    ul.appendChild(li);
  }
}

const TYPE_MAP = {
  script:           "script",
  module:           "script",
  image:            "image",
  imageset:         "image",
  img:              "image",
  media:            "media",
  font:             "font",
  stylesheet:       "style",
  sub_frame:        "iframe",
  iframe:           "iframe",
  xmlhttprequest:   "xhr",
  fetch:            "fetch",
  websocket:        "ws",
  ping:             "ping",
  beacon:           "ping",
  object:           "object",
  object_subrequest:"object",
  main_frame:       "page"
};

function tagHtml(type) {
  const t = (type || "other").toLowerCase();
  const mapped = TYPE_MAP[t] || "other";
  return `<span class="tag t-${mapped}">${mapped}</span>`;
}

// -----------------------------------------------------------------------
// Renderizacao principal
// -----------------------------------------------------------------------
function render(state) {
  if (!state) return;

  // Score
  const score = calcPrivacyScore(state);
  const scoreEl = document.getElementById("score-value");
  scoreEl.textContent = score;
  scoreEl.className = score >= 70 ? "good" : score >= 40 ? "mid" : "bad";

  // Third-party domains
  const domains = Object.entries(state.thirdPartyDomains || {});
  setCount("cnt-thirdparty", domains.length, true);
  setList("list-thirdparty", domains.map(([domain, reqs]) => {
    const trackerTag = isTracker(domain)
      ? '<span class="tag tracker">tracker</span>' : "";
    const types = [...new Set(reqs.map(r => r.type))];
    return `${domain}${trackerTag} ${types.map(tagHtml).join("")}`;
  }));

  // Cookies
  const c = state.cookies || {};
  const total = (c.firstParty || []).length + (c.thirdParty || []).length;
  setCount("cnt-cookies", total, (c.thirdParty || []).length > 0);
  document.getElementById("cnt-cookies-1st").textContent = (c.firstParty || []).length;
  document.getElementById("cnt-cookies-3rd").textContent = (c.thirdParty || []).length;
  document.getElementById("cnt-cookies-session").textContent = (c.session || []).length;
  document.getElementById("cnt-cookies-persistent").textContent = (c.persistent || []).length;
  document.getElementById("cnt-supercookies").textContent = (c.supercookies || []).length;
  setList("list-cookies-3rd", (c.thirdParty || []).map(ck =>
    `${ck.name} <span style="color:#999">${ck.domain}</span>${!ck.secure ? ' <span class="tag t-other">insecure</span>' : ""}`
  ));
  setList("list-supercookies", (c.supercookies || []).map(sc => {
    if (sc.type === "etag") {
      return `<span class="tag t-etag">ETag</span> ${sc.domain} <span style="color:#999">${sc.value}</span>`;
    }
    return `<span class="tag t-hsts">HSTS</span> ${sc.domain} <span style="color:#999">(${sc.subdomains} subdominios)</span>`;
  }));

  // Storage
  const stor = state.storage || {};
  const ls = (stor.localStorage || []).length;
  const ss = (stor.sessionStorage || []).length;
  const idb = (stor.indexedDB || []).length;
  setCount("cnt-storage", ls + ss + idb, ls + ss + idb > 0);
  const storItems = [
    ...(stor.localStorage || []).map(e => `<b>localStorage</b> ${e.key} <span style="color:#999">${e.size}B</span>`),
    ...(stor.sessionStorage || []).map(e => `<b>sessionStorage</b> ${e.key} <span style="color:#999">${e.size}B</span>`),
    ...(stor.indexedDB || []).map(e => `<b>IndexedDB</b> ${e.name} v${e.version}`)
  ];
  setList("list-storage", storItems);

  // Fingerprinting
  const fp = state.fingerprinting || {};
  const fpItems = [];
  for (const [type, calls] of Object.entries(fp)) {
    if (calls.length) {
      const methods = [...new Set(calls.map(c => c.method))].join(", ");
      fpItems.push(`<b>${type}</b>: ${methods} <span style="color:#999">(${calls.length}x)</span>`);
    }
  }
  setCount("cnt-fingerprint", fpItems.length, fpItems.length > 0);
  setList("list-fingerprint", fpItems);

  // Hijacking
  const hij = state.hijacking || {};
  const hijItems = [
    ...(hij.suspiciousScripts || []).map(s => `Script suspeito: <span style="color:#d32f2f">${s.domain}</span>`),
    ...(hij.redirectAttempts || []).map(r => `Redirect: ${new URL(r.from).hostname} -> ${new URL(r.to).hostname}`)
  ];
  setCount("cnt-hijack", hijItems.length, hijItems.length > 0);
  setList("list-hijack", hijItems);

  // Cookie Syncing
  const syncItems = (state.cookieSyncing || []).map(s =>
    `${s.domain} <span style="color:#999">?${s.param}=...</span>`
  );
  setCount("cnt-cookiesync", syncItems.length, syncItems.length > 0);
  setList("list-cookiesync", syncItems);
}

// -----------------------------------------------------------------------
// Inicializacao
// -----------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  browser.runtime.sendMessage({ action: "getFullState" }).then(async resp => {
    if (!resp || !resp.ok) return;
    const state = resp.state;

    // Tenta buscar storage direto do content script da aba ativa
    try {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (tabs.length) {
        const pageResp = await browser.tabs.sendMessage(tabs[0].id, { action: "getPageData" });
        if (pageResp && pageResp.ok) {
          state.storage = pageResp.data.storage;
          // Merge fingerprinting do content script tambem
          for (const t of ["canvas", "webgl", "audioContext"]) {
            if (pageResp.data.fingerprinting[t].length > 0) {
              state.fingerprinting[t] = pageResp.data.fingerprinting[t];
            }
          }
        }
      }
    } catch (_) {}

    render(state);
  }).catch(err => console.error("Threat Detection popup error:", err));
});
