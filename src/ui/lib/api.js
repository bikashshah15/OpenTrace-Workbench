// Same-origin JSON client. Credentials travel only in the HttpOnly session cookie.
export class ApiError extends Error { constructor(status, body) { super(body?.message || body?.error || 'request failed'); this.status = status; this.code = body?.error; this.body = body; } }

export async function api(path, { method = 'GET', body } = {}) {
  const init = { method, credentials: 'same-origin', headers: {} };
  if (method === 'POST') { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body ?? {}); }
  const res = await fetch(path, init);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

export const qs = (o) => Object.entries(o).filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
