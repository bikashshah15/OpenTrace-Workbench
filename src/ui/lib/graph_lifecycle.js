// UIP-13-GRAPH-LIFECYCLE: lifecycle of the Cytoscape instances that live on kept hosts ([data-keep]) across paint() repaints. Pure logic over injected host objects (no globals).
//
// Why this exists (measured, UIP-13 correction): Cytoscape's canvas renderer observes the PARENT of its container (MutationObserver, childList) and destroys the renderer when the
// container leaves that parent - but it does not mark the Core destroyed. paint() replaces a root's innerHTML and re-parents every kept host (ph.replaceWith(old)), which removes the host
// from the parent the renderer observes; one microtask later the renderer is destroyed while cy.destroyed() stays false: laid out and fitted, never painted, not clickable, not recoverable by
// forceRender. The fix keeps ONE instance per host (so pan, zoom, selection, elements and cy.on handlers - all held by the Core - survive) and re-attaches it with the public cy.mount(host)
// synchronously after the re-parent, which builds a fresh renderer observing the host's NEW parent (and disconnects the old observer before it can fire).

export const isLive = (cy) => { try { return !!cy && !cy.destroyed() && !cy.renderer().destroyed; } catch { return false; } };
// A completion that arrives after its instance was replaced, destroyed, or its host retired must not touch anything.
export const isDestroyed = (cy) => typeof cy.destroyed === 'function' && cy.destroyed();
export const isStale = (host, cy) => host._cy !== cy || isDestroyed(cy);

// Re-attach the host's own instance. mount() re-applies the creation-time stylesheet, so the current one is re-applied afterwards (host._restyle(), else a snapshot taken before mount).
// Skipped only when the instance is live and the host still sits in the parent the renderer observes.
export function remountGraph(host, force = false) {
  const cy = host && host._cy; if (!cy || cy.destroyed()) return false;
  if (!force && isLive(cy) && cy.container() === host && host._mountParent === host.parentNode) return false;
  const snapshot = host._restyle ? null : cy.style().json();
  cy.mount(host); cy.style(host._restyle ? host._restyle() : snapshot); cy.resize();
  host._mountParent = host.parentNode;
  return true;
}

// Intentional teardown: navigation away, session change or a graph that is no longer rendered. Leaves nothing behind (instance, observers, callbacks).
export function disposeGraph(host) {
  if (!host) return;
  try { host._cy?.destroy(); } catch { /* already gone */ }
  host._token = (host._token || 0) + 1;   // invalidates a pending dense.js layout completion (R9-04)
  host._themeObs?.disconnect(); host._themeObs = null; host._cy = null; host._sig = null; host._onSelect = null; host._mountParent = null; host._restyle = null;
  stopResizeFit(host);   // S4-FIX-01: the resize observer, its pending debounce timer and the auto-fit state go with the instance
}
export const disposeGraphsIn = (root) => { if (root) root.querySelectorAll('[data-keep]').forEach(disposeGraph); };

// paint() helpers: collect the kept hosts before the root is rewritten, then put each back in the new markup (re-attaching its instance) and retire the ones that did not come back.
export function keepersOf(el) { const m = new Map(); el.querySelectorAll('[data-keep]').forEach((n) => m.set(n.dataset.keep, n)); return m; }
export function restoreKeepers(el, keepers) {
  const reused = new Set();
  el.querySelectorAll('[data-keep]').forEach((ph) => { const old = keepers.get(ph.dataset.keep); if (old) { ph.replaceWith(old); reused.add(ph.dataset.keep); remountGraph(old, true); } });   // forced: replaceWith always removes the host from the parent the old renderer observes (R9-03)
  keepers.forEach((n, k) => { if (!reused.has(k)) disposeGraph(n); });
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// S4-FIX-01 (Stage 4 diagnostic, measured): after a window resize Cytoscape resizes its canvas to the host but leaves the camera, so a graph that was fitted can be clipped.
// Policy: a host is in AUTO-FIT mode after its layout fit and after an explicit Fit. A resize of the host then refits it. A DELIBERATE user camera change (wheel/pinch zoom,
// drag/swipe pan, the toolbar zoom buttons) leaves auto-fit mode: a later resize only tells Cytoscape the new size and never moves the camera. Explicit Fit always fits the current
// host and re-arms auto-fit. User gestures are told apart from programmatic camera changes by Cytoscape's own gesture events (`dragpan`, `scrollzoom`, `pinchzoom`), which the
// library emits only for user input (measured in the vendored build: fit()/zoom()/pan() emit pan/zoom/viewport only), so no timing guard is needed.
export const RESIZE_DEBOUNCE_MS = 120;
export const USER_CAMERA_EVENTS = 'dragpan scrollzoom pinchzoom';
const sizeOf = (host, entries) => {
  const r = entries && entries.length ? entries[entries.length - 1].contentRect : null;
  const w = r ? r.width : host.clientWidth, h = r ? r.height : host.clientHeight;
  return Number.isFinite(w) && Number.isFinite(h) ? { w: Math.round(w), h: Math.round(h) } : null;
};

// Fit the host's graph to the host as it is now and (re)arm auto-fit. Returns false when there is nothing live to fit.
export function fitHost(host, padding = 24) {
  const cy = host && host._cy; if (!cy || isDestroyed(cy)) return false;
  cy.resize(); cy.fit(undefined, padding);
  host._autoFit = true; host._lastSize = sizeOf(host) || host._lastSize || null;
  return true;
}
// A deliberate camera change by the user (toolbar zoom buttons call this; Cytoscape gestures reach it through armUserCamera).
export function noteUserCamera(host) { if (host) host._autoFit = false; }
// Register the user-gesture listeners once per Cytoscape instance (they live on the Core, which is kept across repaints, so repaints add none).
export function armUserCamera(host, cy) { cy.on(USER_CAMERA_EVENTS, () => { if (host._cy === cy) noteUserCamera(host); }); }

// Observe the host's size. Zero sizes (hidden tab, detached host) and unchanged sizes are ignored; changes are debounced into one pass that resizes the renderer and refits
// only in auto-fit mode. Safe when ResizeObserver does not exist (unit tests, old browsers): the graph then keeps the pre-fix behaviour. Idempotent per host.
export function observeResize(host, { ResizeObserverImpl = globalThis.ResizeObserver, setTimer = setTimeout, clearTimer = clearTimeout, delay = RESIZE_DEBOUNCE_MS } = {}) {
  if (!host || host._resizeObs || typeof ResizeObserverImpl !== 'function') return false;
  host._lastSize = sizeOf(host) || host._lastSize || null;
  host._clearTimer = (id) => clearTimer(id);   // an arrow: window.clearTimeout throws "Illegal invocation" when called as a method of the host (found by the Stage 4 browser run)
  host._resizeObs = new ResizeObserverImpl((entries) => {
    const sz = sizeOf(host, entries);
    if (!sz || sz.w <= 0 || sz.h <= 0) return;                       // not laid out (hidden / detached): nothing to fit to
    const last = host._lastSize;
    if (!last) { host._lastSize = sz; return; }                       // first measurement: record only
    if (sz.w === last.w && sz.h === last.h) return;                   // re-parent or repaint without a size change
    if (host._resizeTimer) clearTimer(host._resizeTimer);
    host._resizeTimer = setTimer(() => {
      host._resizeTimer = null;
      const cy = host._cy; if (!cy || isStale(host, cy) || !isLive(cy)) return;
      const now = sizeOf(host); if (!now || now.w <= 0 || now.h <= 0) return;
      host._lastSize = now;
      if (host._autoFit) fitHost(host); else cy.resize();           // a deliberate user camera is never moved
    }, delay);
  });
  host._resizeObs.observe(host);
  return true;
}
// Teardown (called by disposeGraph): observer, pending timer and mode state.
export function stopResizeFit(host) {
  if (!host) return;
  try { host._resizeObs?.disconnect(); } catch { /* already gone */ }
  if (host._resizeTimer && host._clearTimer) host._clearTimer(host._resizeTimer);
  host._resizeObs = null; host._resizeTimer = null; host._clearTimer = null; host._autoFit = null; host._lastSize = null;
}
