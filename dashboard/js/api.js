// API client for the local bridge. Every POST carries the custom header the
// bridge requires (it blocks cross-site requests without it).

async function post(path, body = {}) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-SC-Client': 'dashboard' },
    body: JSON.stringify(body),
  });
  let data;
  try { data = await res.json(); } catch { data = { ok: false, error: `HTTP ${res.status}` }; }
  if (!res.ok && data.ok === undefined) data.ok = false;
  return data;
}

export const api = {
  engine: (cmd, arg) => post('/api/engine', { cmd, arg }),
  run: (what) => post(`/api/run/${what}`),
  tcp: (action, body) => post(`/api/tcp/${action}`, body),
  health: () => fetch('/api/health').then((r) => r.json()),
  stream(onMessage) {
    const es = new EventSource('/api/stream');
    es.onmessage = (e) => {
      try { onMessage(JSON.parse(e.data)); } catch { /* ignore malformed */ }
    };
    return es;
  },
};
