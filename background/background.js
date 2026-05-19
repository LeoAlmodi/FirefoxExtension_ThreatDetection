/**
 * background/background.js
 * Background script persistente.
 * Responsavel por: interceptacao de requests (webRequest),
 * monitoramento de cookies, deteccao de hijacking e cookie syncing.
 */

"use strict";

// -----------------------------------------------------------------------
// Estado global por aba
// -----------------------------------------------------------------------
const tabState = {};

function getTabState(tabId) {
  if (!tabState[tabId]) {
    tabState[tabId] = {
      pageHost: null,
      thirdPartyDomains: {},
      cookies: {
        firstParty: [],
        thirdParty: [],
        session: [],
        persistent: [],
        supercookies: []
      },
      hijacking: {
        suspiciousScripts: [],
        redirectAttempts: []
      },
      fingerprinting: {
        canvas: [],
        webgl: [],
        audioContext: []
      },
      cookieSyncing: [],
      storage: {
        localStorage: [],
        sessionStorage: [],
        indexedDB: []
      }
    };
  }
  return tabState[tabId];
}

// -----------------------------------------------------------------------
// Utilitarios
// -----------------------------------------------------------------------
function extractHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function isThirdParty(requestHost, pageHost) {
  if (!requestHost || !pageHost) return false;
  const rParts = requestHost.split(".").slice(-2).join(".");
  const pParts = pageHost.split(".").slice(-2).join(".");
  return rParts !== pParts;
}

// Dominios conhecidos de rastreamento / ads (lista minima de referencia)
const KNOWN_TRACKERS = [
  "doubleclick.net", "googletagmanager.com", "google-analytics.com",
  "facebook.net", "facebook.com", "scorecardresearch.com",
  "quantserve.com", "outbrain.com", "taboola.com", "criteo.com",
  "amazon-adsystem.com", "adnxs.com", "rubiconproject.com"
];

function isSuspiciousScript(url, host, pageHost) {
  if (!isThirdParty(host, pageHost)) return false;
  return KNOWN_TRACKERS.some(t => host.endsWith(t));
}

// -----------------------------------------------------------------------
// webRequest - intercepta todas as requisicoes
// -----------------------------------------------------------------------
browser.webRequest.onBeforeRequest.addListener(
  function (details) {
    const { tabId, url, type, originUrl } = details;
    if (tabId < 0) return;

    const state = getTabState(tabId);
    const requestHost = extractHostname(url);
    const pageHost = state.pageHost || extractHostname(originUrl);

    if (type === "main_frame") {
      // Nova pagina: reseta dados de rede mas preserva estrutura
      tabState[tabId] = {
        pageHost: requestHost,
        thirdPartyDomains: {},
        cookies: {
          firstParty: [],
          thirdParty: [],
          session: [],
          persistent: [],
          supercookies: []
        },
        hijacking: {
          suspiciousScripts: [],
          redirectAttempts: []
        },
        fingerprinting: {
          canvas: [],
          webgl: [],
          audioContext: []
        },
        cookieSyncing: [],
        storage: {
          localStorage: [],
          sessionStorage: [],
          indexedDB: []
        }
      };
      return;
    }

    if (!pageHost || !requestHost) return;

    // Dominios de terceira parte
    if (isThirdParty(requestHost, pageHost)) {
      if (!state.thirdPartyDomains[requestHost]) {
        state.thirdPartyDomains[requestHost] = [];
      }
      state.thirdPartyDomains[requestHost].push({ type, url });

      // Deteccao de cookie syncing:
      // Requisicao 3rd-party com parametros de query que parecem IDs de usuario
      try {
        const params = new URL(url).searchParams;
        const cookieSyncParams = ["uid", "user_id", "uuid", "id", "userid", "gdpr_consent"];
        for (const p of cookieSyncParams) {
          if (params.has(p)) {
            state.cookieSyncing.push({ domain: requestHost, param: p, url });
            break;
          }
        }
      } catch {}

      // Deteccao de scripts suspeitos
      if (type === "script" && isSuspiciousScript(url, requestHost, pageHost)) {
        state.hijacking.suspiciousScripts.push({ url, domain: requestHost });
      }
    }
  },
  { urls: ["<all_urls>"] }
);

// Detecta redirecionamentos nao esperados
browser.webRequest.onBeforeRedirect.addListener(
  function (details) {
    const { tabId, url, redirectUrl, type } = details;
    if (tabId < 0 || type !== "main_frame") return;
    const state = getTabState(tabId);
    state.hijacking.redirectAttempts.push({
      from: url,
      to: redirectUrl,
      ts: Date.now()
    });
  },
  { urls: ["<all_urls>"] }
);

// -----------------------------------------------------------------------
// Supercookies - deteccao de ETag e HSTS
// -----------------------------------------------------------------------

// ETag supercookie: recurso de 3a parte retorna ETag que o browser reenvia
// como If-None-Match em visitas futuras, funcionando como identificador persistente
browser.webRequest.onHeadersReceived.addListener(
  function (details) {
    const { tabId, url, responseHeaders, type } = details;
    if (tabId < 0 || !responseHeaders) return;

    const state = getTabState(tabId);
    const requestHost = extractHostname(url);
    if (!requestHost || !isThirdParty(requestHost, state.pageHost)) return;

    // Ignora tipos que legitimamente usam ETag para cache (imagens, scripts grandes)
    // Foca em recursos pequenos de tracking: pixel, xhr, beacon
    const trackingTypes = ["xmlhttprequest", "ping", "beacon", "image"];
    if (!trackingTypes.includes(type)) return;

    const etagHeader = responseHeaders.find(h => h.name.toLowerCase() === "etag");
    if (!etagHeader || !etagHeader.value) return;

    // ETag de tracking costuma ser longo e parecer um UUID ou hash
    const etag = etagHeader.value.replace(/"/g, "");
    const looksLikeId = etag.length >= 16 && /^[a-zA-Z0-9\-_]+$/.test(etag);
    if (!looksLikeId) return;

    // Evita duplicatas por dominio
    const already = state.cookies.supercookies.some(
      s => s.type === "etag" && s.domain === requestHost
    );
    if (already) return;

    state.cookies.supercookies.push({
      type: "etag",
      domain: requestHost,
      value: etag.substring(0, 32) + (etag.length > 32 ? "..." : "")
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// HSTS supercookie: heuristica baseada em subdomínios numerados/aleatorios
// Sites que usam HSTS supercookies fazem requests para N subdomínios distintos
// do mesmo dominio pai para codificar bits de um ID
const hstsCandidates = {}; // { "dominio.com": Set(subdomains) }

browser.webRequest.onBeforeRequest.addListener(
  function (details) {
    const { tabId, url, type } = details;
    if (tabId < 0 || type === "main_frame") return;

    const state = getTabState(tabId);
    const requestHost = extractHostname(url);
    if (!requestHost || !isThirdParty(requestHost, state.pageHost)) return;

    // Pega dominio pai (ex: "a1.track.com" -> "track.com")
    const parts = requestHost.split(".");
    if (parts.length < 3) return;
    const parent = parts.slice(-2).join(".");
    const subdomain = parts.slice(0, -2).join(".");

    // Subdominio parece aleatorio/numerico?
    const looksRandom = /^[a-z0-9]{2,8}$/.test(subdomain);
    if (!looksRandom) return;

    if (!hstsCandidates[parent]) hstsCandidates[parent] = new Set();
    hstsCandidates[parent].add(subdomain);

    // Se o mesmo dominio pai aparece com 4+ subdomínios aleatorios diferentes,
    // e' um forte indicativo de HSTS supercookie
    if (hstsCandidates[parent].size >= 4) {
      const already = state.cookies.supercookies.some(
        s => s.type === "hsts" && s.domain === parent
      );
      if (!already) {
        state.cookies.supercookies.push({
          type: "hsts",
          domain: parent,
          subdomains: hstsCandidates[parent].size
        });
      }
    }
  },
  { urls: ["<all_urls>"] }
);


browser.cookies.onChanged.addListener(function (changeInfo) {
  const { cookie, removed } = changeInfo;
  if (removed) return;

  // Tenta associar ao tab ativo
  browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
    if (!tabs.length) return;
    const tabId = tabs[0].id;
    const state = getTabState(tabId);
    const pageHost = state.pageHost;

    const cookieHost = cookie.domain.replace(/^\./, "");
    const isThird = isThirdParty(cookieHost, pageHost);
    const isSession = !cookie.expirationDate;

    const entry = {
      name: cookie.name,
      domain: cookie.domain,
      session: isSession,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite
    };

    if (isThird) state.cookies.thirdParty.push(entry);
    else state.cookies.firstParty.push(entry);

    if (isSession) state.cookies.session.push(entry);
    else state.cookies.persistent.push(entry);
  });
});

// -----------------------------------------------------------------------
// Mensagens vindas do content script e do popup
// -----------------------------------------------------------------------
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;

  if (msg.action === "storageData" && tabId !== null) {
    const state = getTabState(tabId);
    state.storage = msg.data;
    return;
  }

  if (msg.action === "fingerprintDetected" && tabId !== null) {
    const state = getTabState(tabId);
    const { type, method } = msg;
    if (state.fingerprinting[type]) {
      state.fingerprinting[type].push({ method, ts: Date.now() });
    }
    return;
  }

  if (msg.action === "getFullState") {
    browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
      if (!tabs.length) { sendResponse({ ok: false }); return; }
      const state = getTabState(tabs[0].id);
      sendResponse({ ok: true, state });
    });
    return true; // async
  }
});

// Limpa estado de abas fechadas
browser.tabs.onRemoved.addListener(tabId => {
  delete tabState[tabId];
});
