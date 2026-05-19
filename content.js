/**
 * content.js
 * Content script principal - injeta no contexto de cada pagina.
 * Responsavel por: Web Storage, IndexedDB, fingerprinting hooks.
 */

(function () {
  "use strict";

  // -----------------------------------------------------------------------
  // Estado local da pagina
  // -----------------------------------------------------------------------
  const pageData = {
    storage: {
      localStorage: [],
      sessionStorage: [],
      indexedDB: []
    },
    fingerprinting: {
      canvas: [],
      webgl: [],
      audioContext: []
    }
  };

  // -----------------------------------------------------------------------
  // Web Storage - leitura de localStorage e sessionStorage
  // -----------------------------------------------------------------------
  function scanWebStorage() {
    const origin = window.location.hostname;

    // localStorage
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        pageData.storage.localStorage.push({
          key,
          size: value ? value.length : 0,
          origin
        });
      }
    } catch (e) {
      // Bloqueado por politica de seguranca - ignorar silenciosamente
    }

    // sessionStorage
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        pageData.storage.sessionStorage.push({
          key,
          size: value ? value.length : 0,
          origin
        });
      }
    } catch (e) {}
  }

  // -----------------------------------------------------------------------
  // IndexedDB - listagem de databases
  // -----------------------------------------------------------------------
  async function scanIndexedDB() {
    if (!window.indexedDB || !indexedDB.databases) return;
    try {
      const dbs = await indexedDB.databases();
      pageData.storage.indexedDB = dbs.map(db => ({
        name: db.name,
        version: db.version,
        origin: window.location.hostname
      }));
    } catch (e) {}
  }

  // -----------------------------------------------------------------------
  // Fingerprinting hooks - injeta fingerprint_hooks.js no contexto da pagina
  // via src para ter acesso ao window real (MV2 page world workaround)
  // -----------------------------------------------------------------------
  function injectFingerprintingHooks() {
    const script = document.createElement("script");
    script.src = browser.runtime.getURL("fingerprint_hooks.js");
    script.onload = () => script.remove();
    (document.head || document.documentElement).prepend(script);
  }

  // Recebe eventos de fingerprinting vindos do contexto da pagina
  window.addEventListener("__pm_fingerprint__", function (e) {
    const { type, method } = e.detail;
    if (pageData.fingerprinting[type]) {
      pageData.fingerprinting[type].push({
        method,
        ts: Date.now()
      });
      // Notifica background
      browser.runtime.sendMessage({
        action: "fingerprintDetected",
        type,
        method,
        origin: window.location.hostname
      }).catch(() => {});
    }
  });

  // -----------------------------------------------------------------------
  // Inicializacao
  // -----------------------------------------------------------------------
  injectFingerprintingHooks();

  function doStorageScan() {
    // Limpa antes de re-escanear para evitar duplicatas
    pageData.storage.localStorage = [];
    pageData.storage.sessionStorage = [];
    scanWebStorage();
    scanIndexedDB().then(sendStorageData);
  }

  // Primeiro scan: espera DOM se necessario
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", doStorageScan);
  } else {
    doStorageScan();
  }

  // Re-scan periodico para pegar storage escrito pos-load
  setTimeout(doStorageScan, 2000);
  setTimeout(doStorageScan, 5000);

  function sendStorageData() {
    browser.runtime.sendMessage({
      action: "storageData",
      data: pageData.storage,
      origin: window.location.hostname
    }).catch(() => {});
  }

  // Responde a pedidos do popup
  browser.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === "getPageData") {
      sendResponse({ ok: true, data: pageData });
    }
    return true;
  });

})();
