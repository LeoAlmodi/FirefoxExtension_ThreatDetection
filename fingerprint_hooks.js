/**
 * fingerprint_hooks.js
 * Executado no contexto real da pagina (page world) via src inject.
 * Hookeia Canvas, WebGL e AudioContext e dispara CustomEvents.
 */
(function () {
  if (window.__pm_hooks_installed__) return;
  window.__pm_hooks_installed__ = true;

  const _send = function (type, method) {
    window.dispatchEvent(new CustomEvent("__pm_fingerprint__", {
      detail: { type, method }
    }));
  };

  // Canvas
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (...args) {
    _send("canvas", "toDataURL");
    return origToDataURL.apply(this, args);
  };

  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (...args) {
    _send("canvas", "getImageData");
    return origGetImageData.apply(this, args);
  };

  // WebGL
  const hookWebGL = (ctx) => {
    if (!ctx) return;
    const origGetParameter = ctx.prototype.getParameter;
    ctx.prototype.getParameter = function (...args) {
      _send("webgl", "getParameter");
      return origGetParameter.apply(this, args);
    };
  };
  hookWebGL(WebGLRenderingContext);
  if (typeof WebGL2RenderingContext !== "undefined") hookWebGL(WebGL2RenderingContext);

  // AudioContext
  const AC = window.AudioContext || window.webkitAudioContext;
  if (AC) {
    const origCreateOscillator = AC.prototype.createOscillator;
    AC.prototype.createOscillator = function (...args) {
      _send("audioContext", "createOscillator");
      return origCreateOscillator.apply(this, args);
    };

    const origCreateDynamicsCompressor = AC.prototype.createDynamicsCompressor;
    AC.prototype.createDynamicsCompressor = function (...args) {
      _send("audioContext", "createDynamicsCompressor");
      return origCreateDynamicsCompressor.apply(this, args);
    };
  }
})();
