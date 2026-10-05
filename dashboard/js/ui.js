// Small rendering helpers and static components shared by all views.
// Nothing here animates: every change is an instant DOM update.

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

export const pad2 = (n) => String(n).padStart(2, '0');
export const seqLabel = (s) => (s === '18446744073709551615' ? '2⁶⁴−1' : s ?? '—');

export function $(sel, root = document) { return root.querySelector(sel); }
export function $$(sel, root = document) { return [...root.querySelectorAll(sel)]; }

export function toast(msg, isError = false) {
  const root = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = `toast${isError ? ' err' : ''}`;
  t.setAttribute('role', isError ? 'alert' : 'status');
  t.textContent = msg;
  root.appendChild(t);
  setTimeout(() => t.remove(), 4200);
}

/* Disables the button and swaps its label for a static "Running…" while fn
 * runs (no spinner). */
export async function busy(btn, fn) {
  if (!btn || btn.disabled) return undefined;
  const label = btn.innerHTML;
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.textContent = 'Running…';
  try { return await fn(); }
  catch (e) { toast(e.message || String(e), true); return undefined; }
  finally {
    if (btn.isConnected) { btn.disabled = false; btn.removeAttribute('aria-busy'); btn.innerHTML = label; }
  }
}

/* ---- status language ------------------------------------------------------
 * Every status pairs a colour with a glyph and a word, so nothing relies on
 * colour alone. */
const TONE = {
  PASS: 'ok', VERIFIED: 'ok', BLOCKED: 'ok', PROTECTED: 'ok', SECURE: 'ok', AUTHENTICATED: 'ok', ACCEPTED: 'ok',
  READY: 'ok', AVAILABLE: 'ok', COMPLETE: 'ok', REJECTED: 'ok', OK: 'ok', DETECTED: 'ok',
  ACTIVE: 'info', ENABLED: 'info', RUNNING: 'info', CONNECTED: 'info', 'IN MEMORY': 'info', CURRENT: 'info',
  'NOT RUN': 'muted', 'NOT TESTED': 'muted', OFF: 'muted', PENDING: 'muted', IDLE: 'muted', STOPPED: 'muted',
  'NOT PRESENT': 'muted', WIPED: 'muted', CLOSED: 'muted', TERMINATED: 'muted', OFFLINE: 'bad', UNKNOWN: 'muted', 'NO SESSION': 'muted',
  LIMITATION: 'warn', LIMITED: 'warn', WARNING: 'warn', PARTIAL: 'warn', EXTENSION: 'violet', SCOPE: 'muted',
  FAILED: 'bad', FAIL: 'bad', UNEXPECTED: 'bad', ERROR: 'bad', MISMATCH: 'bad',
};
const GLYPH = { ok: '✓', info: '●', muted: '○', warn: '!', bad: '✕', violet: '◆' };

export function toneOf(status) { return TONE[String(status).toUpperCase()] || 'info'; }

export function chip(status, { tone, glyph, lg = false, text } = {}) {
  const t = tone || toneOf(status);
  const g = glyph ?? GLYPH[t];
  return `<span class="chip c-${t}${lg ? ' lg' : ''}">${g ? `<span class="g" aria-hidden="true">${g}</span>` : ''}${esc(text ?? status)}</span>`;
}
export const statusBadge = (status) => chip(status);

/* Packet fate: ACCEPTED is good; a rejection is shown as a red ✕ even when it
 * was the expected outcome of an attack (the check column shows PASS). */
export function verdictBadge(verdict, rc) {
  const ok = verdict === 'ACCEPTED' || verdict === 'UNCHANGED';
  const rcTxt = rc !== undefined && rc !== null ? ` · rc ${rc}` : '';
  return `<span class="chip ${ok ? 'c-ok' : 'c-bad'}"><span class="g" aria-hidden="true">${ok ? '✓' : '✕'}</span>${esc(verdict)}${rcTxt}</span>`;
}

export function emptyState(msg, actionHtml = '', title = 'NOT RUN') {
  return `<div class="empty"><div class="empty-title">${esc(title)}</div><div class="empty-msg">${msg}</div>${actionHtml}</div>`;
}

export function errorState(title, lines = []) {
  return `<div class="alert" role="alert"><b>${esc(title)}</b>${lines.map((l) => `<span>${esc(l)}</span>`).join('')}</div>`;
}

export function pageHead(eyebrow, title, desc, actions = '') {
  return `<div class="page-head">
    <div><span class="eyebrow accent">${esc(eyebrow)}</span><h1>${esc(title)}</h1>${desc ? `<p>${desc}</p>` : ''}</div>
    ${actions ? `<div class="actions">${actions}</div>` : ''}
  </div>`;
}

export function panelHead(title, sub = '', right = '') {
  return `<div class="panel-head"><div><div class="panel-title">${title}</div>${sub ? `<div class="panel-sub">${sub}</div>` : ''}</div>${right ? `<div class="actions">${right}</div>` : ''}</div>`;
}

/* ---- packets ---------------------------------------------------------------- */

/* Colour-coded byte map of a captured packet. modified = byte offset the
 * attacker changed (-1 if none). All bytes are public wire data. */
export function byteMap(p) {
  const cells = [];
  const push = (hex, cls, offset) => {
    (hex.match(/../g) || []).forEach((b, i) => {
      const at = offset + i;
      const mod = p.modified >= 0 && at === p.modified;
      cells.push(`<span class="byte ${cls}${mod ? ' mod' : ''}" title="offset ${at}${mod ? ' — changed by attacker' : ''}">${b}</span>`);
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
  return `<div class="bytemap" role="img" aria-label="${p.length} packet bytes, colour-coded by field">${cells.join('')}</div>
    <div class="legend">
      <span><i style="background:var(--f-seq)"></i>SEQ 8 B (AAD)</span>
      <span><i style="background:var(--f-nonce)"></i>NONCE 12 B</span>
      <span><i style="background:var(--f-ct)"></i>CIPHERTEXT ${p.ct_len ?? '?'} B</span>
      <span><i style="background:var(--f-tag)"></i>TAG 16 B</span>
      ${p.modified >= 0 ? '<span><i style="background:var(--danger)"></i>BYTE CHANGED BY ATTACKER</span>' : ''}
    </div>`;
}

/* Static packet anatomy. With a captured packet it shows the real field
 * bytes; without one it shows the format only. */
export function packetAnatomy(p = null, { large = false } = {}) {
  if (p && p.raw_hex !== undefined) {
    return `<div class="pkt short${large ? ' lg' : ''}"><div class="p-seq"><b>TRUNCATED PACKET</b><span class="sz">${p.length} B</span><span class="d">below the 36-byte minimum — rejected before any cryptography runs</span><span class="hx">${esc(hexGroups(p.raw_hex, 16))}</span></div></div>`;
  }
  const hx = (h, n) => (p ? `<span class="hx">${esc(shortHex(h, n))}</span>` : '');
  const ct = p ? `${p.ct_len} B` : 'n B';
  return `<div class="anatomy">
    <div class="anatomy-groups" aria-hidden="true"><div>HEADER · 20 B · SENT IN CLEAR</div><div>PAYLOAD · AUTHENTICATED</div></div>
    <div class="pkt${large ? ' lg' : ''}">
      <div class="p-seq"><b>SEQUENCE</b><span class="sz">8 B</span><span class="d">big-endian · authenticated as AAD</span>${p ? `<span class="hx">${esc(seqLabel(p.seq))}</span>` : ''}</div>
      <div class="p-nonce"><b>NONCE</b><span class="sz">12 B</span><span class="d">random per packet</span>${hx(p?.nonce_hex, 6)}</div>
      <div class="p-ct"><b>CIPHERTEXT</b><span class="sz">${ct}</span><span class="d">ChaCha20 · same length as plaintext</span>${hx(p?.ct_hex, 8)}</div>
      <div class="p-tag"><b>AUTH TAG</b><span class="sz">16 B</span><span class="d">Poly1305 over ciphertext + AAD</span>${hx(p?.tag_hex, 6)}</div>
    </div>
    <div class="anatomy-foot">
      <span>AAD <b>sequence number</b></span>
      <span>CIPHER <b>ChaCha20-Poly1305-IETF</b></span>
      <span>TOTAL <b>${p ? `${p.length} B` : '36 + n B'}</b></span>
    </div>
  </div>`;
}

function miniPacket(p, hostile) {
  if (!p) return '<div class="minipkt idle" aria-hidden="true"><span class="m-seq">SEQ</span><span class="m-nonce">NONCE</span><span class="m-ct">CT</span><span class="m-tag">TAG</span></div>';
  if (p.raw_hex !== undefined) return `<div class="minipkt${hostile ? ' hostile' : ''}"><span class="m-seq">${p.length} B</span></div>`;
  return `<div class="minipkt${hostile ? ' hostile' : ''}"><span class="m-seq">SEQ ${esc(seqLabel(p.seq))}</span><span class="m-nonce">NONCE</span><span class="m-ct">CT ${p.ct_len}</span><span class="m-tag">TAG</span></div>`;
}

/* Static transmission diagram: sender — last packet on the wire — receiver,
 * with the receiver's real verdict. */
export function packetFlow({ from, to, packet = null, verdict = null, rc = null, live = false, label = '', hostile = false }) {
  const v = verdict ? verdictBadge(verdict, rc) : '';
  return `<div class="flow">
    <div class="endpoint${live ? ' live' : ''}${from.hostile ? ' hostile' : ''}">${icons[from.icon]}<b>${esc(from.name)}</b><small>${esc(from.sub)}</small></div>
    <div class="wire${live ? ' live' : ''}">
      <span class="wire-label">${esc(label)}</span>
      ${miniPacket(packet, hostile)}
      <div class="flow-verdict">${v}</div>
    </div>
    <div class="endpoint${live ? ' live' : ''}">${icons[to.icon]}<b>${esc(to.name)}</b><small>${esc(to.sub)}</small></div>
  </div>`;
}

/* ---- icons: one thin geometric family (24px grid, 1.6 stroke) ------------- */
const svg = (d) => `<svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
export const icons = {
  overview: svg('<rect x="3" y="3" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="2"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="2"/>'),
  handshake: svg('<path d="M4 8h13l-3-3"/><path d="M20 16H7l3 3"/>'),
  channel: svg('<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2"/>'),
  inspector: svg('<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M8 6v12M12.5 6v12M17 6v12"/>'),
  attacks: svg('<path d="M9 3h6"/><path d="M10 3v6.5L4.8 18.2A1.8 1.8 0 0 0 6.4 21h11.2a1.8 1.8 0 0 0 1.6-2.8L14 9.5V3"/><path d="M7.5 15h9"/>'),
  tests: svg('<rect x="3.5" y="3.5" width="17" height="17" rx="3"/><path d="M8 12.2l2.7 2.6L16.2 9"/>'),
  vault: svg('<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M21 12v2"/>'),
  wrap: svg('<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.1-7.5 9.5-4.3-1.4-7.5-4.9-7.5-9.5V6z"/><circle cx="12" cy="11" r="2"/><path d="M12 13v3"/>'),
  openssl: svg('<rect x="3" y="4" width="7.5" height="16" rx="2"/><rect x="13.5" y="4" width="7.5" height="16" rx="2"/><path d="M5.5 9h2.5M5.5 12h2.5M16 9h2.5M16 12h2.5"/>'),
  bench: svg('<path d="M4 20V10M10 20V4M16 20v-7M21 20H3"/>'),
  logs: svg('<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M7 9.5l3 2.5-3 2.5M12.5 15H17"/>'),
  limits: svg('<path d="M12 3.5l9 16H3z"/><path d="M12 10v4M12 17h.01"/>'),
  client: svg('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'),
  server: svg('<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>'),
  network: svg('<circle cx="12" cy="12" r="2.5"/><circle cx="4.5" cy="6" r="1.8"/><circle cx="19.5" cy="6" r="1.8"/><circle cx="12" cy="20.5" r="1.8"/><path d="M6 7l4 3.5M18 7l-4 3.5M12 14.5v4.2"/>'),
  shield: svg('<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.1-7.5 9.5-4.3-1.4-7.5-4.9-7.5-9.5V6z"/>'),
  lock: svg('<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>'),
  fingerprint: svg('<path d="M6.5 17.5c1-1.8 1.5-3.6 1.5-5.5a4 4 0 0 1 8 0c0 2.6-.4 5-1.4 7.2"/><path d="M12 12c0 3-.8 5.8-2.3 8"/><path d="M4.5 13.5V12a7.5 7.5 0 0 1 13.8-4"/><path d="M19.3 11.5c.1 2.2-.2 4.4-.8 6.4"/>'),
  clock: svg('<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>'),
  key: svg('<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M21 12v2"/>'),
  file: svg('<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>'),
  memory: svg('<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>'),
  caret: '<svg class="caret" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>',
};

/* ---- Architectural Tiers & Trust Boundary (Rules 39, 40) -------------------
 * Communicates clearly: Untrusted Browser → Controlled Node Bridge → Trusted C Engine */
export function architecturalTiers() {
  return `<div class="arch-tiers" role="region" aria-label="System Architecture and Trust Boundaries">
    <div class="tier tier-untrusted">
      <div class="tier-tag"><span class="chip c-warn"><span class="g">!</span>UNTRUSTED · PRESENTATION LAYER</span></div>
      <div class="tier-card">
        <div class="tier-head">
          <div class="tier-title">Browser Dashboard</div>
          <span class="faint small mono">localhost</span>
        </div>
        <div class="tier-tech">HTML5 · Vanilla CSS · JavaScript Modules</div>
        <p>Interactive control center, packet wire inspection, attack triggering and telemetry display. <b>Zero cryptographic keys or private material are ever loaded into or possessed by the browser.</b></p>
        <div class="tier-badges">
          <span class="tbadge">DOM UI</span>
          <span class="tbadge">Wire Inspector</span>
          <span class="tbadge">Zero Secret Persistence</span>
        </div>
      </div>
    </div>

    <div class="tier-connector" aria-hidden="true">
      <span class="conn-label">JSON over HTTP (127.0.0.1)</span>
      <span class="conn-arrow">↓</span>
    </div>

    <div class="tier tier-controlled">
      <div class="tier-tag"><span class="chip c-info"><span class="g">●</span>CONTROLLED · LOCAL IPC BRIDGE</span></div>
      <div class="tier-card">
        <div class="tier-head">
          <div class="tier-title">Node.js Bridge Runner</div>
          <span class="faint small mono">bridge/server.js</span>
        </div>
        <div class="tier-tech">Node.js HTTP Server · Child Process Controller</div>
        <p>Local validator with strict security controls: DNS rebinding guard (Host header check, 421), CSP headers (<code>script-src 'self'</code>), client header verification (403), command whitelist, and path traversal block.</p>
        <div class="tier-badges">
          <span class="tbadge">DNS Rebinding Guard</span>
          <span class="tbadge">Command Whitelist</span>
          <span class="tbadge">Process Sandbox</span>
        </div>
      </div>
    </div>

    <div class="tier-connector" aria-hidden="true">
      <span class="conn-label">POSIX Standard I/O (JSON Line Stream)</span>
      <span class="conn-arrow">↓</span>
    </div>

    <div class="tier tier-trusted">
      <div class="tier-tag"><span class="chip c-ok"><span class="g">✓</span>TRUSTED · CRYPTOGRAPHIC BOUNDARY</span></div>
      <div class="tier-card">
        <div class="tier-head">
          <div class="tier-title">C Cryptographic Engine (sc_engine) + libsodium</div>
          <span class="faint small mono">POSIX C11 · libsodium</span>
        </div>
        <div class="tier-tech">C11 (GCC) · libsodium 1.0.18+ · WSL2 / Linux Kernel</div>
        <p>All cryptographic operations execute exclusively within this boundary. Ephemeral keys are protected with <code>sodium_malloc()</code> guard pages; secrets are zeroed with <code>sodium_memzero()</code> immediately after use.</p>
        <div class="tier-badges">
          <span class="tbadge">ChaCha20-Poly1305</span>
          <span class="tbadge">crypto_kx (X25519)</span>
          <span class="tbadge">Ed25519 Signatures</span>
          <span class="tbadge">Argon2id + Secretbox</span>
          <span class="tbadge">sodium_memzero()</span>
        </div>
      </div>
    </div>
  </div>`;
}

/* ---- Full Cryptographic Pipeline (Rule 18) --------------------------------
 * Major static visual showing the complete cryptographic lifecycle from
 * message to unseal and release. */
export function fullCryptoPipeline(p, text) {
  const isOk = p?.rc === 0 && (p?.verdict === 'ACCEPTED' || p?.verdict === 'UNCHANGED');
  const hasPacket = !!p;
  const isAttack = hasPacket && p.rc !== 0;
  const seqDisp = p?.seq !== undefined ? (p.seq === '18446744073709551615' ? '2⁶⁴−1' : String(p.seq)) : '0';
  const ptBytes = text ? new TextEncoder().encode(text).length : (p?.ct_len ?? 0);

  const stages = [
    { n: '01', name: 'PLAINTEXT', meta: hasPacket ? `${p.ct_len} B input` : `${ptBytes} B msg`, status: hasPacket ? 'done' : 'ready' },
    { n: '02', name: 'VALIDATE', meta: hasPacket ? 'Length ≤ 256 B' : 'Input validation', status: hasPacket ? 'done' : 'pending' },
    { n: '03', name: 'SEQUENCE #', meta: hasPacket ? `Seq #${seqDisp} (8 B)` : 'Monotonic counter', status: hasPacket ? 'done' : 'pending' },
    { n: '04', name: 'NONCE', meta: hasPacket ? (p.nonce_hex ? shortHex(p.nonce_hex, 2) : '12 B random') : '12 B random', status: hasPacket ? 'done' : 'pending' },
    { n: '05', name: 'AAD BINDING', meta: hasPacket ? 'Seq bound as AAD' : 'Authenticated meta', status: hasPacket ? 'done' : 'pending' },
    { n: '06', name: 'CHACHA20 SEAL', meta: hasPacket ? `${p.ct_len} B ciphertext` : 'Client TX key', status: hasPacket ? 'done' : 'pending' },
    { n: '07', name: 'POLY1305 TAG', meta: hasPacket ? (p.tag_hex ? shortHex(p.tag_hex, 2) : '16 B tag') : '16 B authenticator', status: hasPacket ? 'done' : 'pending' },
    { n: '08', name: 'WIRE PACKET', meta: hasPacket ? `${p.length} B on wire` : '36 + n B datagram', status: hasPacket ? 'done' : 'pending' },
    { n: '09', name: 'AEAD UNSEAL', meta: hasPacket ? (isOk ? 'Tag verified' : `unseal() rc ${p.rc}`) : 'Server RX key', status: hasPacket ? (isOk ? 'done' : 'fail') : 'pending' },
    { n: '10', name: 'PLAINTEXT RELEASE', meta: hasPacket ? (isOk ? 'Plaintext released' : 'RELEASE BLOCKED') : 'Delivered buffer', status: hasPacket ? (isOk ? 'done' : 'fail') : 'pending' }
  ];

  return `<div class="full-pipeline" role="region" aria-label="Cryptographic AEAD Pipeline">
    <div class="pipe-track">
      ${stages.map((st) => `<div class="pipe-node ${st.status}">
        <span class="pipe-num">${st.n}</span>
        <b class="pipe-title">${st.name}</b>
        <small class="pipe-meta">${esc(st.meta)}</small>
      </div>`).join('<div class="pipe-arrow" aria-hidden="true">→</div>')}
    </div>
  </div>`;
}

/* ---- Static Attack Comparison (Rule 22) -----------------------------------
 * Pure static side-by-side comparison: Legitimate Packet vs In-Transit Mutation */
export function staticAttackComparison(attackId = 'tamper') {
  const titles = {
    normal: 'Normal Genuine Packet',
    tamper: 'Ciphertext Tampering (Bit Flip)',
    aad: 'Sequence / AAD Manipulation',
    replay: 'Packet Replay Attack',
    reorder: 'Packet Reordering',
    wrongkey: 'Forged Key Injection',
    forged: 'Forged Sequence Window Poisoning',
    short: 'Malformed / Truncated Datagram'
  };
  const mutations = {
    normal: 'Zero modification (genuine client transmission)',
    tamper: 'Attacker flips 1 bit of ciphertext in transit',
    aad: 'Attacker rewrites clear-text seq in header (+1000)',
    replay: 'Attacker captures and re-sends already accepted packet',
    reorder: 'Attacker delivers newer packet first, older packet second',
    wrongkey: 'Attacker seals packet with forged unauthorized key',
    forged: 'Attacker injects forged seq = 2⁶⁴−1 to poison window',
    short: 'Attacker truncates packet below 36-byte minimum'
  };

  const title = titles[attackId] || 'Injected Attack Scenario';
  const mutation = mutations[attackId] || 'Packet modified by attacker';

  return `<div class="attack-comparison-grid">
    <div class="cmp-flow legit">
      <div class="cmp-head">
        <span class="chip c-ok"><span class="g">✓</span>LEGITIMATE TRANSMISSION</span>
        <b>Genuine Client Packet Flow</b>
      </div>
      <div class="cmp-steps">
        <div class="cmp-step">
          <span class="step-role">CLIENT</span>
          <div class="step-body"><b>seal()</b> with directional key <code>client_tx</code></div>
        </div>
        <div class="cmp-connector"><span>Genuine wire datagram</span><span>↓</span></div>
        <div class="cmp-step">
          <span class="step-role">SERVER</span>
          <div class="step-body"><b>unseal()</b> with matching key <code>server_rx</code></div>
        </div>
        <div class="cmp-connector"><span>Poly1305 tag verified &amp; seq fresh</span><span>↓</span></div>
        <div class="cmp-verdict ok">
          <b>✓ ACCEPTED (rc 0)</b>
          <small>Plaintext released to application · last_seq updated</small>
        </div>
      </div>
    </div>

    <div class="cmp-flow hostile">
      <div class="cmp-head">
        <span class="chip c-bad"><span class="g">✕</span>ATTACK: ${esc(title)}</span>
        <b>Hostile In-Transit Manipulation Flow</b>
      </div>
      <div class="cmp-steps">
        <div class="cmp-step">
          <span class="step-role">CLIENT</span>
          <div class="step-body">Seals genuine packet</div>
        </div>
        <div class="cmp-connector"><span class="bad">Adversary intercepts packet</span><span>↓</span></div>
        <div class="cmp-step hostile-node">
          <span class="step-role hostile">ATTACKER</span>
          <div class="step-body"><b class="bad">${esc(mutation)}</b></div>
        </div>
        <div class="cmp-connector"><span class="bad">Altered datagram forwarded to server</span><span>↓</span></div>
        <div class="cmp-step">
          <span class="step-role">SERVER</span>
          <div class="step-body"><b>unseal()</b> evaluates packet in C</div>
        </div>
        <div class="cmp-connector"><span class="bad">Security invariant triggered</span><span>↓</span></div>
        <div class="cmp-verdict bad">
          <b>✕ ATTACK REJECTED (${attackId === 'replay' || attackId === 'reorder' ? 'rc -3' : attackId === 'short' ? 'rc -1' : 'rc -2'})</b>
          <small>Plaintext buffer WIPED with sodium_memzero() · ZERO data released</small>
        </div>
      </div>
    </div>
  </div>`;
}

/* ---- MITM Centerpiece Comparison (Rule 23) --------------------------------
 * Static comparison of Unauthenticated crypto_kx vs Authenticated Handshake */
export function mitmComparisonDiagram(m) {
  return `<div class="mitm-comparison-grid">
    <div class="mitm-card plain">
      <div class="mitm-card-head">
        <span class="chip c-warn"><span class="g">!</span>WITHOUT AUTHENTICATED IDENTITY</span>
        <h4>Plain crypto_kx Handshake</h4>
        <p class="faint small">Pure X25519 Diffie–Hellman key exchange without peer authentication (as defined in the brief).</p>
      </div>
      <div class="mitm-diagram">
        <div class="entity"><b>CLIENT</b><small>initiator</small></div>
        <div class="wire-channel bad">
          <span class="flow-lbl">Client eph pubkey <code>client_eph</code></span>
          <span class="arr-down">↓ intercepted</span>
        </div>
        <div class="entity hostile"><b>ATTACKER (MALLORY)</b><small>Active Man-in-the-Middle</small></div>
        <div class="wire-channel bad">
          <span class="flow-lbl">Substituted pubkey <code>mallory_eph</code></span>
          <span class="arr-down">↓ forwarded</span>
        </div>
        <div class="entity"><b>SERVER</b><small>responder</small></div>
      </div>
      <div class="mitm-consequences bad">
        <div class="conseq-row"><span>Identity Verification:</span> <b>✕ NOT PROTECTED</b></div>
        <div class="conseq-row"><span>Attacker Capability:</span> <b>Mallory decrypts and alters all messages</b></div>
        <div class="conseq-row"><span>Live Evidence:</span> <code>${m?.plain ? esc(m.plain.read_text) : 'Mallory reads &amp; rewrites traffic'}</code></div>
        <div class="conseq-verdict bad">RESULT: MITM POSSIBLE (Documented Limitation)</div>
      </div>
    </div>

    <div class="mitm-card signed">
      <div class="mitm-card-head">
        <span class="chip c-ok"><span class="g">✓</span>WITH SIGNED HANDSHAKE EXTENSION</span>
        <h4>Ed25519-Signed Identity Handshake</h4>
        <p class="faint small">Server signs the ephemeral exchange with its long-term Ed25519 private key; Client verifies against pinned <code>server_pk.bin</code>.</p>
      </div>
      <div class="mitm-diagram">
        <div class="entity"><b>CLIENT</b><small>has pinned server_pk.bin</small></div>
        <div class="wire-channel ok">
          <span class="flow-lbl">Client eph pubkey <code>client_eph</code></span>
          <span class="arr-down">↓</span>
        </div>
        <div class="entity hostile blocked"><b>MALLORY (BLOCKED)</b><small>Cannot forge server signature</small></div>
        <div class="wire-channel ok">
          <span class="flow-lbl">Server signs: <code>server_eph ‖ client_eph</code></span>
          <span class="arr-down">↓ verified</span>
        </div>
        <div class="entity"><b>SERVER</b><small>signs with server_sk.bin</small></div>
      </div>
      <div class="mitm-consequences ok">
        <div class="conseq-row"><span>Identity Verification:</span> <b>✓ SIGNATURE VERIFIED (Ed25519)</b></div>
        <div class="conseq-row"><span>Server Identity:</span> <b>✓ Pinned to known public key</b></div>
        <div class="conseq-row"><span>Key Swap Attack:</span> <b>✓ REJECTED (Signature invalid)</b></div>
        <div class="conseq-row"><span>Own Signature Attack:</span> <b>✓ REJECTED (Key not pinned)</b></div>
        <div class="conseq-row"><span>Replay Signature:</span> <b>✓ REJECTED (Transcript mismatch)</b></div>
        <div class="conseq-verdict ok">RESULT: ALL MITM ATTACKS BLOCKED</div>
      </div>
    </div>
  </div>`;
}

/* ---- "Why This Matters" Explanations (Rule 29) ----------------------------
 * Rigorous, concise cryptographic justifications */
export function whyThisMatters(topic) {
  const K = {
    aead: {
      title: 'Authenticated Encryption with Associated Data (AEAD)',
      prop: 'Confidentiality + Integrity Together',
      body: 'Traditional ciphers (such as AES-CBC without MAC) provide confidentiality but allow bit-flipping attacks. ChaCha20-Poly1305 guarantees that any modification to the ciphertext or associated data immediately causes unseal() to abort and release zero plaintext.'
    },
    aad: {
      title: 'Associated Authenticated Data (AAD)',
      prop: 'Cleartext Metadata Integrity',
      body: 'AAD allows protocol metadata (such as sequence numbers, version headers, or routing information) to travel in plaintext so receivers can inspect it early, while still binding it cryptographically to the authentication tag so it cannot be altered by an adversary.'
    },
    replay: {
      title: 'Monotonic Sequence Replay Window',
      prop: 'Packet Freshness',
      body: 'Encrypting data does not stop an attacker from recording a legitimate packet and re-transmitting it later (e.g. replaying a payment instruction). Enforcing seq > last_seq rejects duplicates. Updating last_seq ONLY after tag verification prevents window-poisoning denial of service.'
    },
    directional: {
      title: 'Directional Key Separation (crypto_kx)',
      prop: 'Reflection Attack Prevention',
      body: 'If a client and server shared a single symmetric key for both directions, an adversary could reflect a client packet back into the client receiver. Generating complementary pairs (client_tx == server_rx, client_rx == server_tx, client_tx ≠ client_rx) guarantees a sender can never ingest its own traffic.'
    },
    handshake: {
      title: 'Cryptographic Identity Binding',
      prop: 'Man-in-the-Middle Defense',
      body: 'Unauthenticated Diffie-Hellman establishes confidentiality between endpoints, but cannot prove who the peer is. Signing the ephemeral key exchange with a pinned long-term Ed25519 identity binds the session to the authentic server, completely defeating key-substitution MITM attacks.'
    },
    keywrap: {
      title: 'Password-Based Key Wrapping (Argon2id + Secretbox)',
      prop: 'At-Rest Secret Protection',
      body: 'Private keys stored unencrypted on disk are vulnerable to unauthorized access or disk image exfiltration. Argon2id derives a high-entropy key through memory-hard computation (64 MiB), rendering GPU/ASIC offline dictionary attacks computationally infeasible.'
    }
  };

  const item = K[topic];
  if (!item) return '';

  return `<div class="why-matters-card">
    <div class="wm-head">
      <span class="wm-tag">WHY THIS MATTERS</span>
      <span class="wm-prop">${esc(item.prop)}</span>
    </div>
    <h4 class="wm-title">${esc(item.title)}</h4>
    <p class="wm-body">${esc(item.body)}</p>
  </div>`;
}

