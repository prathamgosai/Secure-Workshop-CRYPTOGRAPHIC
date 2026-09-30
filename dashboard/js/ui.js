// Small rendering helpers shared by all views.

export const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const time = (ts) => ts ? new Date(ts).toLocaleTimeString([], { hour12: false }) : '—';
export const timeMs = (ts) => {
  if (!ts) return '—';
  const d = new Date(ts);
  return `${d.toLocaleTimeString([], { hour12: false })}.${String(d.getMilliseconds()).padStart(3, '0')}`;
};

export const hexGroups = (hex = '', max = 64) => {
  const bytes = hex.match(/../g) || [];
  const shown = bytes.slice(0, max).join(' ');
  return bytes.length > max ? `${shown} … (+${bytes.length - max} B)` : shown;
};

export const shortHex = (hex = '', n = 6) => {
  const b = hex.match(/../g) || [];
  return b.length <= n ? b.join(' ').toUpperCase() : `${b.slice(0, n).join(' ')} …`.toUpperCase();
};

export function $(sel, root = document) { return root.querySelector(sel); }
export function $$(sel, root = document) { return [...root.querySelectorAll(sel)]; }

export function toast(msg, isError = false) {
  const root = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = `toast${isError ? ' err' : ''}`;
  t.textContent = msg;
  root.appendChild(t);
  setTimeout(() => t.remove(), 4200);
}

/* Disables the button and shows a spinner while fn runs. */
export async function busy(btn, fn) {
  if (!btn || btn.disabled) return undefined;
  btn.disabled = true;
  btn.classList.add('busy');
  try { return await fn(); }
  catch (e) { toast(e.message || String(e), true); return undefined; }
  finally { btn.disabled = false; btn.classList.remove('busy'); }
}

export function verdictBadge(verdict, rc) {
  const cls = verdict === 'ACCEPTED' ? 'b-ok' : verdict === 'UNCHANGED' ? 'b-cyan' : 'b-bad';
  const icon = verdict === 'ACCEPTED' || verdict === 'UNCHANGED' ? '✓' : '✕';
  return `<span class="badge ${cls}">${icon} ${esc(verdict)}${rc !== undefined && rc !== null ? ` <span class="faint">rc ${rc}</span>` : ''}</span>`;
}

export function statusBadge(status) {
  const map = {
    VERIFIED: 'b-ok', PASS: 'b-ok', ACTIVE: 'b-cyan', ENABLED: 'b-cyan', BLOCKED: 'b-ok',
    'NOT TESTED': 'b-muted', 'NOT RUN': 'b-muted', LIMITATION: 'b-warn', FAILED: 'b-bad', FAIL: 'b-bad', OFF: 'b-muted',
  };
  return `<span class="badge ${map[status] || 'b-info'}">${esc(status)}</span>`;
}

/* Colour-coded byte map of a captured packet. modified = byte offset the
 * attacker changed (-1 if none). All bytes are public wire data. */
export function byteMap(p) {
  const cells = [];
  const push = (hex, cls, offset) => {
    (hex.match(/../g) || []).forEach((b, i) => {
      const at = offset + i;
      const mod = p.modified >= 0 && at === p.modified;
      cells.push(`<span class="byte ${cls}${mod ? ' mod' : ''}" title="offset ${at}" style="animation-delay:${Math.min(at, 90) * 6}ms">${b}</span>`);
    });
  };
  if (p.raw_hex !== undefined) {
    push(p.raw_hex, 'f-seq', 0);
  } else {
    push(p.seq_hex || '', 'f-seq', 0);
    push(p.nonce_hex || '', 'f-nonce', 8);
    push(p.ct_hex || '', 'f-ct', 20);
    push(p.tag_hex || '', 'f-tag', 20 + (p.ct_len || 0));
  }
  return `<div class="bytemap" aria-label="packet bytes">${cells.join('')}</div>
    <div class="legend">
      <span><i style="background:var(--f-seq)"></i>SEQ 8 B (AAD)</span>
      <span><i style="background:var(--f-nonce)"></i>NONCE 12 B</span>
      <span><i style="background:var(--f-ct)"></i>CIPHERTEXT ${p.ct_len ?? '?'} B</span>
      <span><i style="background:var(--f-tag)"></i>TAG 16 B</span>
      ${p.modified >= 0 ? '<span><i style="background:var(--red)"></i>BYTE CHANGED BY ATTACKER</span>' : ''}
    </div>`;
}

export function packetFormat() {
  return `<div class="fmt">
    <div class="fx-seq"><b>SEQ · 8 B</b><span>big-endian · AAD</span></div>
    <div class="fx-nonce"><b>NONCE · 12 B</b><span>random per packet</span></div>
    <div class="fx-ct"><b>CIPHERTEXT</b><span>ChaCha20 · same length as plaintext</span></div>
    <div class="fx-tag"><b>TAG · 16 B</b><span>Poly1305</span></div>
  </div>`;
}

export const icons = {
  client: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
  server: '<svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/></svg>',
  attacker: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/><path d="M9 8h6"/></svg>',
};

export function emptyState(msg, actionHtml = '') {
  return `<div class="empty"><div>${msg}</div>${actionHtml}</div>`;
}
