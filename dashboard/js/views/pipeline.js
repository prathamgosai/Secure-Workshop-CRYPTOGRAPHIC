// Pipeline View — Cryptographic Decision Pipeline
// Cyberpunk node-graph visualization of the protocol flow with live metrics,
// animated SVG connections, and real-time telemetry panels.

import { store, subscribe } from '../store.js';
import { esc } from '../ui.js';

/* ---- pipeline graph definition ------------------------------------------ */

// Each node: id, label, sublabel, column (0-based), row (0-based), status
const NODES = [
  // Column 0 – Initiation
  { id: 'init',      col: 0, row: 0, label: 'INIT',          sub: 'libsodium ready',       group: 'init' },
  { id: 'keygen',    col: 0, row: 1, label: 'KEYGEN',        sub: 'crypto_kx_keypair',     group: 'init' },
  { id: 'vault',     col: 0, row: 2, label: 'KEY VAULT',     sub: 'Ed25519 identity',      group: 'init' },

  // Column 1 – Handshake / Key exchange
  { id: 'kx-client', col: 1, row: 0, label: 'KX CLIENT',    sub: 'ephemeral kp',          group: 'handshake' },
  { id: 'kx-server', col: 1, row: 1, label: 'KX SERVER',    sub: 'ephemeral kp',          group: 'handshake' },
  { id: 'sign',      col: 1, row: 2, label: 'SIGN',         sub: 'Ed25519 · server_eph',  group: 'handshake' },
  { id: 'verify',    col: 1, row: 3, label: 'VERIFY',       sub: 'detached sig check',    group: 'handshake' },

  // Column 2 – Session derivation
  { id: 'derive',    col: 2, row: 0, label: 'BLAKE2b-KDF',  sub: 'X25519 → 64 B',         group: 'session' },
  { id: 'split',     col: 2, row: 1, label: 'KEY SPLIT',    sub: 'tx / rx directional',   group: 'session' },
  { id: 'wipe',      col: 2, row: 2, label: 'KEY WIPE',     sub: 'sodium_memzero',         group: 'session' },

  // Column 3 – Secure channel
  { id: 'encrypt',   col: 3, row: 0, label: 'AEAD ENCRYPT', sub: 'ChaCha20-Poly1305',     group: 'channel' },
  { id: 'wire',      col: 3, row: 1, label: 'WIRE',         sub: 'SEQ‖NONCE‖CT‖TAG',      group: 'channel' },
  { id: 'decrypt',   col: 3, row: 2, label: 'AEAD DECRYPT', sub: 'tag verify → plaintext', group: 'channel' },

  // Column 4 – Audit / result
  { id: 'seq-check', col: 4, row: 0, label: 'SEQ CHECK',   sub: 'anti-replay guard',      group: 'audit' },
  { id: 'accept',    col: 4, row: 1, label: 'ACCEPT',      sub: 'packet delivered',        group: 'audit' },
  { id: 'reject',    col: 4, row: 2, label: 'REJECT',      sub: 'tamper detected',         group: 'audit', danger: true },
];

// Edges: from → to (node ids)
const EDGES = [
  ['init', 'keygen'], ['init', 'vault'],
  ['keygen', 'kx-client'], ['keygen', 'kx-server'],
  ['vault', 'sign'],
  ['kx-client', 'derive'], ['kx-server', 'derive'],
  ['sign', 'verify'], ['verify', 'derive'],
  ['derive', 'split'], ['split', 'wipe'],
  ['split', 'encrypt'],
  ['encrypt', 'wire'], ['wire', 'decrypt'],
  ['wipe', 'encrypt'],
  ['decrypt', 'seq-check'],
  ['seq-check', 'accept'], ['seq-check', 'reject'],
];

/* ---- layout constants ---------------------------------------------------- */
const COL_W  = 180;   // px per column
const ROW_H  = 110;   // px per row
const NODE_W = 148;
const NODE_H = 62;
const PAD_X  = 32;
const PAD_Y  = 32;

const COLS = 5;
const ROWS = 4;

const CANVAS_W = PAD_X * 2 + COLS * COL_W;
const CANVAS_H = PAD_Y * 2 + ROWS * ROW_H + 20;

function nodeX(n) { return PAD_X + n.col * COL_W; }
function nodeY(n) { return PAD_Y + n.row * ROW_H; }

/* ---- store-to-node status mapping ---------------------------------------- */

function getNodeStatus(id) {
  const s = store.session;
  const hs = store.handshake;
  const vault = store.vault;

  switch (id) {
    case 'init':      return store.engineUp ? 'active' : 'idle';
    case 'keygen':    return vault?.files?.[0]?.exists ? 'done' : (store.engineUp ? 'ready' : 'idle');
    case 'vault':     return vault?.files?.[1]?.exists ? 'done' : (store.engineUp ? 'ready' : 'idle');
    case 'kx-client': return hs?.ok ? 'done' : (hs ? 'running' : 'idle');
    case 'kx-server': return hs?.ok ? 'done' : (hs ? 'running' : 'idle');
    case 'sign':      return hs?.mode === 'signed' ? (hs?.ok ? 'done' : 'running') : 'skip';
    case 'verify':    return hs?.signature === 1 ? 'done' : (hs?.mode === 'signed' ? 'running' : 'skip');
    case 'derive':    return hs?.ok ? 'done' : 'idle';
    case 'split':     return store.session.key_fingerprints ? 'done' : 'idle';
    case 'wipe':      return hs?.ok ? 'done' : 'idle';
    case 'encrypt': {
      const pkts = store.channel?.sent;
      return pkts > 0 ? 'active' : (hs?.ok ? 'ready' : 'idle');
    }
    case 'wire': {
      const pkts = store.channel?.sent;
      return pkts > 0 ? 'active' : (hs?.ok ? 'ready' : 'idle');
    }
    case 'decrypt': {
      const pkts = store.channel?.received;
      return pkts > 0 ? 'active' : (hs?.ok ? 'ready' : 'idle');
    }
    case 'seq-check': {
      const ch = store.channel;
      return ch?.received > 0 ? (ch.ok ? 'done' : 'warn') : 'idle';
    }
    case 'accept': {
      return store.channel?.ok ? 'done' : 'idle';
    }
    case 'reject': {
      const atk = store.attacks;
      return atk && Object.values(atk).some((a) => a.tamper_detected || a.replay_detected) ? 'danger' : 'idle';
    }
    default: return 'idle';
  }
}

/* ---- metrics bar data ---------------------------------------------------- */
function getMetrics() {
  const ch = store.channel || {};
  const hs = store.handshake || {};
  const atks = store.attacks || {};
  const evts = store.events || [];

  const packets = (ch.sent || 0) + (ch.received || 0);
  const elapsed = hs.elapsed_ms != null ? `${Number(hs.elapsed_ms).toFixed(2)} ms` : '—';
  const attacks_blocked = Object.values(atks).filter((a) => a.tamper_detected || a.replay_detected || a.blocked).length;
  const passRate = packets > 0
    ? ((packets - attacks_blocked) / packets * 100).toFixed(1)
    : '—';

  return { packets, elapsed, attacks_blocked, passRate, evts: evts.length };
}

/* ---- waveform sparkline --------------------------------------------------- */
let _waveHistory = Array(40).fill(0);
let _waveIdx = 0;

function updateWave() {
  const ch = store.channel;
  const v = ch ? ((ch.sent || 0) + (ch.received || 0)) % 100 : 0;
  _waveHistory[_waveIdx % 40] = v + Math.random() * 20;
  _waveIdx++;
  return [..._waveHistory.slice(_waveIdx % 40), ..._waveHistory.slice(0, _waveIdx % 40)];
}

function sparklinePath(vals, w, h) {
  const max = Math.max(...vals, 1);
  return vals.map((v, i) => {
    const x = (i / (vals.length - 1)) * w;
    const y = h - (v / max) * h;
    return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

/* ---- SVG node-graph renderer --------------------------------------------- */
function buildSvgGraph(statuses) {
  const nodeMap = Object.fromEntries(NODES.map((n) => [n.id, n]));

  const groupColors = {
    init:      { stroke: '#66e6ff', fill: 'rgba(102,230,255,0.07)', glow: '#66e6ff' },
    handshake: { stroke: '#b8a6ff', fill: 'rgba(184,166,255,0.07)', glow: '#b8a6ff' },
    session:   { stroke: '#45d99a', fill: 'rgba(69,217,154,0.07)',  glow: '#45d99a' },
    channel:   { stroke: '#ffca68', fill: 'rgba(255,202,104,0.07)', glow: '#ffca68' },
    audit:     { stroke: '#aab3c0', fill: 'rgba(170,179,192,0.05)', glow: '#aab3c0' },
  };

  const statusOverride = {
    done:    { stroke: '#45d99a', fill: 'rgba(69,217,154,0.12)',  text: '#45d99a' },
    active:  { stroke: '#66e6ff', fill: 'rgba(102,230,255,0.15)', text: '#66e6ff' },
    running: { stroke: '#ffca68', fill: 'rgba(255,202,104,0.12)', text: '#ffca68' },
    ready:   { stroke: '#7d8796', fill: 'rgba(125,135,150,0.05)', text: '#aab3c0' },
    warn:    { stroke: '#ffca68', fill: 'rgba(255,202,104,0.1)',  text: '#ffca68' },
    danger:  { stroke: '#ff687a', fill: 'rgba(255,104,122,0.12)', text: '#ff687a' },
    skip:    { stroke: '#3d4555', fill: 'rgba(61,69,85,0.05)',    text: '#5b6474' },
    idle:    { stroke: '#2a3040', fill: 'rgba(42,48,64,0.05)',    text: '#5b6474' },
  };

  // Defs
  let defs = `<defs>
    <filter id="glow-cyan" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="4" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-green" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-violet" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <marker id="arrowhead" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#3d4d66"/>
    </marker>
    <marker id="arrowhead-active" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#66e6ff"/>
    </marker>
    <marker id="arrowhead-done" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#45d99a"/>
    </marker>
  </defs>`;

  // Edges (behind nodes)
  let edges = '';
  for (const [fromId, toId] of EDGES) {
    const fn = nodeMap[fromId];
    const tn = nodeMap[toId];
    if (!fn || !tn) continue;

    const x1 = nodeX(fn) + NODE_W;
    const y1 = nodeY(fn) + NODE_H / 2;
    const x2 = nodeX(tn);
    const y2 = nodeY(tn) + NODE_H / 2;

    const fStatus = statuses[fromId] || 'idle';
    const tStatus = statuses[toId] || 'idle';
    const isActive = fStatus === 'active' || fStatus === 'done';
    const isDone   = fStatus === 'done' && tStatus === 'done';

    const stroke = isDone ? '#45d99a' : isActive ? '#66e6ff' : '#2a3040';
    const opacity = isDone ? 0.7 : isActive ? 0.6 : 0.3;
    const marker  = isDone ? 'arrowhead-done' : isActive ? 'arrowhead-active' : 'arrowhead';
    const strokeW = isDone || isActive ? 1.5 : 1;

    // Bezier curve
    const cx1 = x1 + (x2 - x1) * 0.5;
    const cy1 = y1;
    const cx2 = x1 + (x2 - x1) * 0.5;
    const cy2 = y2;

    edges += `<path d="M${x1},${y1} C${cx1},${cy1} ${cx2},${cy2} ${x2},${y2}"
      fill="none" stroke="${stroke}" stroke-width="${strokeW}"
      stroke-opacity="${opacity}" marker-end="url(#${marker})"/>`;
  }

  // Nodes
  let nodes = '';
  for (const n of NODES) {
    const st = statuses[n.id] || 'idle';
    const gc = groupColors[n.group] || groupColors.audit;
    const sc = statusOverride[st] || statusOverride.idle;
    const x = nodeX(n);
    const y = nodeY(n);

    const filterAttr = (st === 'active' || st === 'done') ? ' filter="url(#glow-cyan)"'
      : (st === 'running' ? ' filter="url(#glow-violet)"' : '');

    const statusDot = {
      done:    `<circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="4" fill="#45d99a"/>`,
      active:  `<circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="4" fill="#66e6ff"/>`,
      running: `<circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="4" fill="#ffca68"/>`,
      warn:    `<circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="4" fill="#ffca68"/>`,
      danger:  `<circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="4" fill="#ff687a"/>`,
      ready:   `<circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="3" fill="none" stroke="#7d8796" stroke-width="1.5"/>`,
      skip:    '',
      idle:    `<circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="3" fill="none" stroke="#2a3040" stroke-width="1.5"/>`,
    }[st] || '';

    nodes += `
    <g class="pipe-node" data-id="${n.id}" data-status="${st}"${filterAttr}>
      <rect x="${x}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="8"
        fill="${sc.fill}" stroke="${sc.stroke}" stroke-width="1.2" stroke-opacity="0.85"/>
      <rect x="${x}" y="${y}" width="3" height="${NODE_H}" rx="2"
        fill="${sc.stroke}" opacity="0.9"/>
      <text x="${x + 14}" y="${y + 22}" font-family="'JetBrains Mono','Cascadia Code',monospace"
        font-size="11" font-weight="700" fill="${sc.text}" letter-spacing="0.04em">${esc(n.label)}</text>
      <text x="${x + 14}" y="${y + 39}" font-family="'JetBrains Mono','Cascadia Code',monospace"
        font-size="9.5" fill="#7d8796" letter-spacing="0.02em">${esc(n.sub)}</text>
      <text x="${x + 14}" y="${y + 54}" font-family="'JetBrains Mono','Cascadia Code',monospace"
        font-size="8.5" fill="${sc.text}" opacity="0.8" letter-spacing="0.06em">${st.toUpperCase()}</text>
      ${statusDot}
    </g>`;
  }

  // Column labels
  const colLabels = ['INIT', 'HANDSHAKE', 'SESSION', 'CHANNEL', 'AUDIT'];
  let labels = '';
  for (let c = 0; c < COLS; c++) {
    const lx = PAD_X + c * COL_W + NODE_W / 2;
    labels += `<text x="${lx}" y="${PAD_Y - 10}" text-anchor="middle"
      font-family="'JetBrains Mono','Cascadia Code',monospace" font-size="9" fill="#3d4d66"
      letter-spacing="0.1em" font-weight="600">${colLabels[c]}</text>`;
  }

  return `<svg class="pipe-svg" viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" width="${CANVAS_W}" height="${CANVAS_H}"
    xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Cryptographic protocol pipeline">
    ${defs}
    <rect width="${CANVAS_W}" height="${CANVAS_H}" fill="transparent"/>
    <!-- Grid dots -->
    ${(() => {
      let dots = '';
      for (let gx = 0; gx < CANVAS_W; gx += 24) {
        for (let gy = 0; gy < CANVAS_H; gy += 24) {
          dots += `<circle cx="${gx}" cy="${gy}" r="0.8" fill="#1a2030" opacity="0.6"/>`;
        }
      }
      return dots;
    })()}
    ${labels}
    ${edges}
    ${nodes}
  </svg>`;
}

/* ---- bottom telemetry panels --------------------------------------------- */
function renderTelemetry(wave) {
  const ch  = store.channel  || {};
  const hs  = store.handshake || {};
  const atk = store.attacks  || {};
  const tc  = store.toolchain || {};
  const evts = (store.events || []).slice(-6).reverse();

  const sp = sparklinePath(wave, 160, 36);
  const isMitm = store.mitm;
  const attacks = Object.entries(atk).map(([k, v]) => ({
    name: k.replace(/_/g, ' '), blocked: v.tamper_detected || v.replay_detected || v.blocked || false,
  }));

  return `
  <div class="pipe-telem">
    <!-- Panel 1: Protocol State -->
    <div class="pipe-tel-card">
      <div class="pipe-tel-title">PROTOCOL STATE</div>
      ${['INIT','AUTH','SECURE','TERMINATE'].map((s) => {
        const done = store.session?.state === s || (s === 'INIT' && store.engineUp);
        const cur  = store.session?.state === s;
        return `<div class="pipe-tel-row${cur ? ' cur' : ''}">
          <span class="pipe-tel-dot ${done ? 'done' : 'idle'}"></span>
          <span>${esc(s)}</span>
          ${cur ? '<span class="pipe-tel-badge active">CURRENT</span>' : ''}
        </div>`;
      }).join('')}
      <div class="pipe-tel-divider"></div>
      <div class="pipe-tel-row"><span class="pipe-tel-key">Epoch</span><b>${store.session?.epoch ?? '—'}</b></div>
      <div class="pipe-tel-row"><span class="pipe-tel-key">Mode</span><b>${esc(hs?.mode ?? '—')}</b></div>
    </div>

    <!-- Panel 2: Confidence / Waveform -->
    <div class="pipe-tel-card pipe-tel-wave-card">
      <div class="pipe-tel-title">CHANNEL THROUGHPUT</div>
      <svg viewBox="0 0 160 36" class="pipe-wave-svg" preserveAspectRatio="none">
        <defs>
          <linearGradient id="wg" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#66e6ff" stop-opacity="0.2"/>
            <stop offset="100%" stop-color="#45d99a" stop-opacity="0.9"/>
          </linearGradient>
        </defs>
        <path d="${sp}" fill="none" stroke="url(#wg)" stroke-width="1.5"/>
        <path d="${sp} L160,36 L0,36 Z" fill="url(#wg)" opacity="0.08"/>
      </svg>
      <div class="pipe-tel-stats">
        <div><span class="pipe-tel-key">SENT</span><b>${ch.sent ?? 0}</b></div>
        <div><span class="pipe-tel-key">RECV</span><b>${ch.received ?? 0}</b></div>
        <div><span class="pipe-tel-key">HANDSHAKE</span><b>${hs.elapsed_ms != null ? hs.elapsed_ms.toFixed(2) + ' ms' : '—'}</b></div>
      </div>
    </div>

    <!-- Panel 3: Attack Status -->
    <div class="pipe-tel-card">
      <div class="pipe-tel-title">ATTACK SURFACE</div>
      ${attacks.length === 0
        ? '<div class="pipe-tel-empty">No attacks run yet</div>'
        : attacks.slice(0, 6).map((a) => `
          <div class="pipe-tel-row">
            <span class="pipe-tel-dot ${a.blocked ? 'done' : 'danger'}"></span>
            <span class="pipe-tel-attack-name">${esc(a.name)}</span>
            <span class="pipe-tel-badge ${a.blocked ? 'ok' : 'danger'}">${a.blocked ? 'BLOCKED' : 'OPEN'}</span>
          </div>`).join('')}
      ${isMitm ? `<div class="pipe-tel-row" style="margin-top:6px">
        <span class="pipe-tel-dot done"></span><span>MITM scenario</span>
        <span class="pipe-tel-badge ok">TESTED</span>
      </div>` : ''}
    </div>

    <!-- Panel 4: Live log feed -->
    <div class="pipe-tel-card pipe-tel-log-card">
      <div class="pipe-tel-title">SECURITY LOG</div>
      <div class="pipe-tel-log">
        ${evts.length === 0
          ? '<div class="pipe-tel-empty">Awaiting engine events…</div>'
          : evts.map((e) => `
            <div class="pipe-tel-log-row">
              <span class="pipe-tel-lvl ${(e.level||'').toLowerCase()}">${esc(e.level)}</span>
              <span class="pipe-tel-log-msg">${esc(e.msg)}</span>
            </div>`).join('')}
      </div>
      <div class="pipe-tel-divider"></div>
      <div class="pipe-tel-row">
        <span class="pipe-tel-key">ENGINE</span>
        <b class="${store.engineUp ? 'pipe-ok' : 'pipe-bad'}">${store.engineUp ? '✓ READY' : '✕ OFFLINE'}</b>
      </div>
      <div class="pipe-tel-row"><span class="pipe-tel-key">LIBSODIUM</span><b>${esc(store.libsodium ?? '—')}</b></div>
    </div>
  </div>`;
}

/* ---- tab state ------------------------------------------------------------ */
const TABS = [
  { id: 'full',     label: 'Full Pipeline' },
  { id: 'handshake', label: 'Handshake' },
  { id: 'channel',  label: 'Channel' },
  { id: 'audit',    label: 'Audit' },
];
let activeTab = 'full';

const FILTER_GROUPS = {
  full:      null,
  handshake: ['init', 'handshake', 'session'],
  channel:   ['session', 'channel'],
  audit:     ['channel', 'audit'],
};

/* ---- main render ---------------------------------------------------------- */

function computeStatuses() {
  return Object.fromEntries(NODES.map((n) => [n.id, getNodeStatus(n.id)]));
}

function filterGraph(statuses) {
  const groups = FILTER_GROUPS[activeTab];
  if (!groups) return { nodes: NODES, edges: EDGES, statuses };
  const visIds = new Set(NODES.filter((n) => groups.includes(n.group)).map((n) => n.id));
  const nodes = NODES.filter((n) => visIds.has(n.id));
  const edges = EDGES.filter(([a, b]) => visIds.has(a) && visIds.has(b));
  return { nodes, edges, statuses };
}

function render(root) {
  const statuses = computeStatuses();
  const wave = updateWave();
  const m = getMetrics();

  // Re-layout nodes for filtered view
  const groups = FILTER_GROUPS[activeTab];
  let visNodes = groups ? NODES.filter((n) => groups.includes(n.group)) : NODES;
  let visEdges = groups
    ? EDGES.filter(([a, b]) => visNodes.find((n) => n.id === a) && visNodes.find((n) => n.id === b))
    : EDGES;

  // Re-index columns for filtered views
  let layoutNodes = visNodes;
  if (groups) {
    const colMap = {};
    let ci = 0;
    for (const n of visNodes) {
      if (colMap[n.col] === undefined) colMap[n.col] = ci++;
    }
    layoutNodes = visNodes.map((n) => ({ ...n, col: colMap[n.col] }));
  }

  const origNodeFn = nodeX;
  const origNodeFY = nodeY;
  // Temporarily override for layoutNodes
  const nodeMapLayout = Object.fromEntries(layoutNodes.map((n) => [n.id, n]));

  function lx(n) { return PAD_X + (nodeMapLayout[n.id]?.col ?? n.col) * COL_W; }
  function ly(n) { return PAD_Y + (nodeMapLayout[n.id]?.row ?? n.row) * ROW_H; }

  const nCols = layoutNodes.reduce((m, n) => Math.max(m, (nodeMapLayout[n.id]?.col ?? n.col)), 0) + 1;
  const nRows = layoutNodes.reduce((m, n) => Math.max(m, n.row), 0) + 1;
  const svgW  = PAD_X * 2 + nCols * COL_W;
  const svgH  = PAD_Y * 2 + nRows * ROW_H + 20;

  const nodeMap = Object.fromEntries(NODES.map((n) => [n.id, n]));

  // Build SVG with layout-corrected positions
  const groupColors = {
    init:      { stroke: '#66e6ff', fill: 'rgba(102,230,255,0.07)', glow: '#66e6ff' },
    handshake: { stroke: '#b8a6ff', fill: 'rgba(184,166,255,0.07)', glow: '#b8a6ff' },
    session:   { stroke: '#45d99a', fill: 'rgba(69,217,154,0.07)',  glow: '#45d99a' },
    channel:   { stroke: '#ffca68', fill: 'rgba(255,202,104,0.07)', glow: '#ffca68' },
    audit:     { stroke: '#aab3c0', fill: 'rgba(170,179,192,0.05)', glow: '#aab3c0' },
  };
  const statusOverride = {
    done:    { stroke: '#45d99a', fill: 'rgba(69,217,154,0.12)',  text: '#45d99a' },
    active:  { stroke: '#66e6ff', fill: 'rgba(102,230,255,0.15)', text: '#66e6ff' },
    running: { stroke: '#b8a6ff', fill: 'rgba(184,166,255,0.12)', text: '#b8a6ff' },
    ready:   { stroke: '#7d8796', fill: 'rgba(125,135,150,0.05)', text: '#aab3c0' },
    warn:    { stroke: '#ffca68', fill: 'rgba(255,202,104,0.1)',  text: '#ffca68' },
    danger:  { stroke: '#ff687a', fill: 'rgba(255,104,122,0.12)', text: '#ff687a' },
    skip:    { stroke: '#3d4555', fill: 'rgba(61,69,85,0.05)',    text: '#5b6474' },
    idle:    { stroke: '#2a3040', fill: 'rgba(42,48,64,0.05)',    text: '#5b6474' },
  };

  const colLabels = groups
    ? (groups.map((g) => g.toUpperCase()))
    : ['INIT', 'HANDSHAKE', 'SESSION', 'CHANNEL', 'AUDIT'];

  let svgEdges = '';
  for (const [fromId, toId] of visEdges) {
    const fn = nodeMapLayout[fromId];
    const tn = nodeMapLayout[toId];
    if (!fn || !tn) continue;
    const x1 = lx(fn) + NODE_W;
    const y1 = ly(fn) + NODE_H / 2;
    const x2 = lx(tn);
    const y2 = ly(tn) + NODE_H / 2;
    const fst = statuses[fromId] || 'idle';
    const tst = statuses[toId]   || 'idle';
    const isDone   = fst === 'done' && tst === 'done';
    const isActive = (fst === 'active' || fst === 'done') && !isDone;
    const stroke   = isDone ? '#45d99a' : isActive ? '#66e6ff' : '#1e2a3a';
    const opacity  = isDone ? 0.75 : isActive ? 0.6 : 0.35;
    const marker   = isDone ? 'arrowhead-done' : isActive ? 'arrowhead-active' : 'arrowhead';
    const sw       = isDone || isActive ? 1.5 : 0.8;
    const cx1 = x1 + (x2 - x1) * 0.5;
    const cy1 = y1;
    const cx2 = x1 + (x2 - x1) * 0.5;
    const cy2 = y2;
    svgEdges += `<path d="M${x1},${y1} C${cx1},${cy1} ${cx2},${cy2} ${x2},${y2}"
      fill="none" stroke="${stroke}" stroke-width="${sw}" stroke-opacity="${opacity}"
      marker-end="url(#${marker})"/>`;
  }

  let svgNodes = '';
  for (const n of layoutNodes) {
    const st = statuses[n.id] || 'idle';
    const sc = statusOverride[st] || statusOverride.idle;
    const x  = lx(n);
    const y  = ly(n);
    const fa = (st === 'active' || st === 'done') ? ' filter="url(#glow-cyan)"'
      : st === 'running' ? ' filter="url(#glow-violet)"' : '';
    const dot = {
      done:    `<circle cx="${x+NODE_W-12}" cy="${y+12}" r="4" fill="#45d99a"/>`,
      active:  `<circle cx="${x+NODE_W-12}" cy="${y+12}" r="4" fill="#66e6ff"/>`,
      running: `<circle cx="${x+NODE_W-12}" cy="${y+12}" r="4" fill="#b8a6ff"/>`,
      warn:    `<circle cx="${x+NODE_W-12}" cy="${y+12}" r="4" fill="#ffca68"/>`,
      danger:  `<circle cx="${x+NODE_W-12}" cy="${y+12}" r="4" fill="#ff687a"/>`,
      ready:   `<circle cx="${x+NODE_W-12}" cy="${y+12}" r="3" fill="none" stroke="#7d8796" stroke-width="1.5"/>`,
      skip:    '',
      idle:    `<circle cx="${x+NODE_W-12}" cy="${y+12}" r="3" fill="none" stroke="#1e2a3a" stroke-width="1.5"/>`,
    }[st] || '';
    svgNodes += `
    <g class="pipe-node" data-id="${n.id}" data-status="${st}"${fa}>
      <rect x="${x}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="8"
        fill="${sc.fill}" stroke="${sc.stroke}" stroke-width="1.2" stroke-opacity="0.9"/>
      <rect x="${x}" y="${y}" width="3" height="${NODE_H}" rx="2" fill="${sc.stroke}" opacity="0.95"/>
      <text x="${x+14}" y="${y+22}" font-family="'JetBrains Mono','Cascadia Mono',monospace"
        font-size="10.5" font-weight="700" fill="${sc.text}" letter-spacing="0.05em">${esc(n.label)}</text>
      <text x="${x+14}" y="${y+38}" font-family="'JetBrains Mono','Cascadia Mono',monospace"
        font-size="9" fill="#7d8796" letter-spacing="0.02em">${esc(n.sub)}</text>
      <text x="${x+14}" y="${y+53}" font-family="'JetBrains Mono','Cascadia Mono',monospace"
        font-size="8" fill="${sc.text}" opacity="0.7" letter-spacing="0.08em">${st.toUpperCase()}</text>
      ${dot}
    </g>`;
  }

  // grid dots
  let gridDots = '';
  for (let gx = 0; gx <= svgW; gx += 24) {
    for (let gy = 0; gy <= svgH; gy += 24) {
      gridDots += `<circle cx="${gx}" cy="${gy}" r="0.7" fill="#161f2e" opacity="0.8"/>`;
    }
  }

  // col labels
  let svgLabels = '';
  const uniqueCols = [...new Set(layoutNodes.map((n) => nodeMapLayout[n.id]?.col ?? n.col))].sort();
  for (let ci = 0; ci < uniqueCols.length; ci++) {
    const lxc = PAD_X + ci * COL_W + NODE_W / 2;
    svgLabels += `<text x="${lxc}" y="${PAD_Y - 10}" text-anchor="middle"
      font-family="'JetBrains Mono','Cascadia Mono',monospace" font-size="9" fill="#2d3d55"
      letter-spacing="0.1em" font-weight="600">${esc(colLabels[ci] || '')}</text>`;
  }

  const svgContent = `<svg class="pipe-svg" viewBox="0 0 ${svgW} ${svgH}"
    xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Cryptographic protocol pipeline graph"
    style="min-width:${svgW}px">
    <defs>
      <filter id="glow-cyan" x="-40%" y="-40%" width="180%" height="180%">
        <feGaussianBlur stdDeviation="4" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <filter id="glow-violet" x="-40%" y="-40%" width="180%" height="180%">
        <feGaussianBlur stdDeviation="3.5" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <marker id="arrowhead" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#1e2a3a"/>
      </marker>
      <marker id="arrowhead-active" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#66e6ff"/>
      </marker>
      <marker id="arrowhead-done" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#45d99a"/>
      </marker>
    </defs>
    ${gridDots}
    ${svgLabels}
    ${svgEdges}
    ${svgNodes}
  </svg>`;

  // Metrics
  const passNum = parseFloat(m.passRate);
  const passColor = isNaN(passNum) ? '#7d8796' : passNum > 90 ? '#45d99a' : passNum > 60 ? '#ffca68' : '#ff687a';

  root.innerHTML = `
  <div class="pipe-page">
    <!-- ── Metrics bar ── -->
    <div class="pipe-metrics">
      <div class="pipe-metric-item">
        <span class="pipe-metric-label">PACKETS</span>
        <div class="pipe-metric-val">${m.packets}</div>
        <span class="pipe-metric-sub">total processed</span>
      </div>
      <div class="pipe-metric-sep"></div>
      <div class="pipe-metric-item">
        <span class="pipe-metric-label">HANDSHAKE</span>
        <div class="pipe-metric-val pipe-accent">${m.elapsed}</div>
        <span class="pipe-metric-sub">round-trip latency</span>
      </div>
      <div class="pipe-metric-sep"></div>
      <div class="pipe-metric-item">
        <span class="pipe-metric-label">ATTACKS</span>
        <div class="pipe-metric-val" style="color:#ff687a">${m.attacks_blocked > 0 ? '= ' : ''}${m.attacks_blocked > 0 ? `<span style="color:#ff687a">${m.attacks_blocked}</span>` : '<span style="color:#5b6474">0</span>'}</div>
        <span class="pipe-metric-sub">blocked / detected</span>
      </div>
      <div class="pipe-metric-sep"></div>
      <div class="pipe-metric-item">
        <span class="pipe-metric-label">PASS RATE</span>
        <div class="pipe-metric-val" style="color:${passColor}">${m.passRate}${m.passRate !== '—' ? '<span style="font-size:16px;opacity:0.7">%</span>' : ''}</div>
        <span class="pipe-metric-sub">packet acceptance</span>
      </div>
      <div class="pipe-metric-sep"></div>
      <div class="pipe-metric-item">
        <span class="pipe-metric-label">EVENTS</span>
        <div class="pipe-metric-val pipe-accent">${m.evts}</div>
        <span class="pipe-metric-sub">security log entries</span>
      </div>
      <div class="pipe-metric-grow"></div>
      <div class="pipe-metric-status">
        <span class="pipe-status-dot ${store.engineUp ? 'on' : 'off'}"></span>
        <span class="pipe-status-lbl">${store.engineUp ? 'ENGINE LIVE' : 'ENGINE OFFLINE'}</span>
      </div>
    </div>

    <!-- ── Tab bar ── -->
    <div class="pipe-tabbar" id="pipe-tabs" role="tablist">
      ${TABS.map((t) => `<button class="pipe-tab${t.id === activeTab ? ' active' : ''}"
        role="tab" data-tab="${t.id}" aria-selected="${t.id === activeTab}">${esc(t.label)}</button>`).join('')}
      <div class="pipe-tab-grow"></div>
      <div class="pipe-legend">
        <span class="pipe-leg-item"><span class="pipe-leg-dot done"></span>Done</span>
        <span class="pipe-leg-item"><span class="pipe-leg-dot active"></span>Active</span>
        <span class="pipe-leg-item"><span class="pipe-leg-dot running"></span>Running</span>
        <span class="pipe-leg-item"><span class="pipe-leg-dot idle"></span>Idle</span>
        <span class="pipe-leg-item"><span class="pipe-leg-dot danger"></span>Alert</span>
      </div>
    </div>

    <!-- ── Node graph ── -->
    <div class="pipe-graph-wrap" id="pipe-graph-wrap">
      <div class="pipe-graph-scroll">
        ${svgContent}
      </div>
    </div>

    <!-- ── Telemetry bottom panels ── -->
    ${renderTelemetry(wave)}
  </div>`;

  // Tab clicks
  root.querySelector('#pipe-tabs')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-tab]');
    if (!btn) return;
    activeTab = btn.dataset.tab;
    render(root);
  });
}

/* ---- view export ---------------------------------------------------------- */
export default {
  id:    'pipeline',
  label: 'Pipeline',
  icon:  'pipeline',

  mount(root, _ctx) {
    render(root);
  },

  update(_topic) {
    const root = document.querySelector('#view .view-inner');
    if (root && root.querySelector('.pipe-page')) render(root);
  },
};
