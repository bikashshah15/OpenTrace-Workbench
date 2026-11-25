const MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => MAP[c]);
export const $ = (id) => document.getElementById(id);
export const NARROW = '(max-width: 700px)';
export const isNarrow = () => window.matchMedia(NARROW).matches;
export const fmt = (n) => Number(n).toLocaleString('en-US');
