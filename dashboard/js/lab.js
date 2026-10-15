// Live laboratory components: the reusable pieces the 21-stage demo is built
// from (command bar, state timeline, cryptographic workspace, artifacts,
// inspector, decision trace, execution console, presenter notes).
//
// They are pure functions: data in, static markup out. They never invent a
// value: every artifact, flow and gate they draw is handed to them by a stage
// that read it from a real C engine response. Motion classes (mo-*) are only
// emitted when `fresh` is true, i.e. on the first render after a real result
// arrived; they show causality and never stand in for waiting.

import { esc } from './ui.js';

const pad = (n) => String(n).padStart(2, '0');
export const fmtMs = (n) => (typeof n === 'number' ? `${n < 10 ? n.toFixed(2) : Math.round(n)} ms` : '—');
export const clock = (ts) => (ts ? new Date(ts).toLocaleTimeString([], { hour12: false }) + '.' + String(ts % 1000).padStart(3, '0') : '—');

/* ---- StatusBadge: glyph + word, never colour alone -------------------------- */
const STATUS = {
  LOCKED: ['○', 'muted'], READY: ['◌', 'muted'], ACTIVE: ['◉', 'info'], EXECUTING: ['◉', 'info'],
  VERIFIED: ['✓', 'ok'], COMPLETED: ['✓', 'ok'], REJECTED: ['✕', 'rej'], 'ATTACK REJECTED': ['✕', 'rej'],
  FAILED: ['!', 'bad'], ATTENTION: ['!', 'bad'], BLOCKED: ['■', 'warn'], 'NOT RUN': ['○', 'muted'],
  CONNECTED: ['●', 'ok'], OFFLINE: ['●', 'bad'],
};
export function badge(word, tone) {
  const [g, t] = STATUS[word] || ['●', 'info'];
  return `<span class="sb sb-${tone || t}"><span class="g" aria-hidden="true">${g}</span>${esc(word)}</span>`;
}

/* ---- CommandBar -------------------------------------------------------------- */
export function commandBar({ num, total, title, sessionId, state, mode, conn, busy }) {
  const pill = (ok, label, detail) => `<span class="cb-pill ${ok ? 'on' : 'off'}" title="${esc(detail)}"><i aria-hidden="true"></i>${esc(label)}<b class="sr">${ok ? ' connected' : ' not connected'}</b></span>`;
  return `<header class="cb">
    <div class="cb-brand"><span class="cb-mark" aria-hidden="true"></span><div><b>SECURE CHANNEL</b><span>Live cryptographic laboratory</span></div></div>
    <div class="cb-state">
      <span class="cb-k">STATE</span><span class="cb-num">${pad(num)}<small> / ${total}</small></span>
      <span class="cb-title">${esc(title)}</span>
    </div>
    <div class="cb-session">
      <span class="cb-k">SESSION</span><b class="mono">${esc(sessionId || '—')}</b>
      <span class="cb-k">PROTOCOL</span><b class="mono">${esc(state || '—')}</b>
      <span class="cb-k">EXECUTION</span><b>${busy ? 'RUNNING IN C' : 'IDLE'}</b>
    </div>
    <div class="cb-conn" aria-label="Connections">
      ${pill(conn.authority, 'CRYPTO AUTHORITY', conn.authorityDetail)}
      ${pill(conn.bridge, 'NODE BRIDGE', conn.bridgeDetail)}
      ${pill(true, 'BROWSER · VISUALISATION ONLY', 'this page renders evidence; it performs no cryptography')}
    </div>
    <div class="cb-mode" role="group" aria-label="View mode">
      <button class="seg ${mode === 'presentation' ? 'on' : ''}" data-act="mode" data-mode="presentation" aria-pressed="${mode === 'presentation'}">Presentation</button>
      <button class="seg ${mode === 'engineering' ? 'on' : ''}" data-act="mode" data-mode="engineering" aria-pressed="${mode === 'engineering'}">Engineering</button>
    </div>
  </header>`;
}

/* ---- StateTimeline / StateNode ----------------------------------------------- */
export function stateTimeline(items) {
  return `<nav class="tlv" aria-label="21 live execution states"><ol>${items.map((it) => `
    <li class="tn tn-${it.cls}">
      <button data-stage="${it.i}" aria-current="${it.cls === 'active' ? 'step' : 'false'}" title="${esc(it.title)} — ${esc(it.word)}">
        <span class="tn-n">${pad(it.n)}</span>
        <span class="tn-t">${esc(it.short)}</span>
        <span class="tn-s">${badge(it.word)}</span>
      </button>
    </li>`).join('')}</ol></nav>`;
}

/* ---- CryptoArtifact ---------------------------------------------------------- */
export function artifactChip(a, sel, extra = '') {
  if (!a) return '';
  return `<button class="art art-${esc(a.tone || 'info')}${sel === a.id ? ' sel' : ''} ${extra}" data-art="${esc(a.id)}" aria-pressed="${sel === a.id}" title="Inspect ${esc(a.label)}">
    <span class="art-type">${esc(a.type)}</span>
    <span class="art-label">${esc(a.label)}</span>
    ${a.redacted ? '<span class="art-red" aria-label="redacted, never leaves C">████████████</span>' : ''}
    ${a.value ? `<span class="art-val">${esc(a.value)}</span>` : ''}
    ${a.fp ? `<span class="art-fp">${esc(a.fp)}</span>` : ''}
    <span class="art-st">${esc(a.status)}</span>
  </button>`;
}

/* ---- VerificationGate -------------------------------------------------------- */
export function gate(g, fresh) {
  if (!g) return '';
  const cls = g.ok === true ? 'pass' : g.ok === false ? 'fail' : 'idle';
  return `<div class="gate gate-${cls}${fresh ? (g.ok === false ? ' mo-reject' : ' mo-in') : ''}" style="--d:${g.delay || 0}ms">
    <span class="gate-k">${esc(g.label)}</span>
    <b>${g.ok === true ? '✓ ' : g.ok === false ? '✕ ' : ''}${esc(g.word)}</b>
    ${g.note ? `<span class="gate-n">${esc(g.note)}</span>` : ''}
  </div>`;
}

/* ---- CryptoWorkspace --------------------------------------------------------- */
// scene kinds:
//   lanes    { client:[id], server:[id], mallory?:[id], flows:[{from,to,label,art,tone}], gate }
//   chain    { nodes:[{art}|{op:{label,note}}|{gate}] }
//   topology { zones:[{name, sub, ok, detail}] }
//   board    { items:[{label, ok, note}], footer }
export function workspace(scene, arts, sel, fresh) {
  if (!scene) return '<div class="ws-empty">No result yet. Press NEXT to execute this state.</div>';
  const A = (id) => arts.find((x) => x.id === id);
  const mo = (i) => (fresh ? ` mo-in" style="--d:${Math.min(i * 60, 480)}ms` : '');
  if (scene.kind === 'topology') {
    return `<div class="ws ws-topo">${scene.zones.map((z, i) => `
      <div class="zone zone-${z.ok ? 'ok' : 'bad'}${mo(i)}">
        <span class="zone-k">${esc(z.boundary)}</span>
        <div class="zone-node"><i class="lamp" aria-hidden="true"></i><b>${esc(z.name)}</b><span>${esc(z.sub)}</span></div>
        <span class="zone-d">${z.ok ? '✓' : '✕'} ${esc(z.detail)}</span>
      </div>${i < scene.zones.length - 1 ? `<div class="zone-link" aria-hidden="true"><span>${esc(scene.links?.[i] || '')}</span></div>` : ''}`).join('')}</div>`;
  }
  if (scene.kind === 'chain') {
    return `<div class="ws ws-chain">${scene.nodes.map((n, i) => {
      const body = n.art ? artifactChip(A(n.art), sel) : n.gate ? gate({ ...n.gate, delay: Math.min(i * 60, 480) }, fresh)
        : `<div class="op"><b>${esc(n.op.label)}</b>${n.op.note ? `<span>${esc(n.op.note)}</span>` : ''}</div>`;
      return `<div class="cn${mo(i)}">${body}</div>${i < scene.nodes.length - 1 ? '<div class="cn-arrow" aria-hidden="true"></div>' : ''}`;
    }).join('')}</div>`;
  }
  if (scene.kind === 'board') {
    return `<div class="ws-board-wrap">
      <div class="ws ws-board">${scene.items.map((it, i) => `
        <div class="bd bd-${it.ok === true ? 'ok' : it.ok === false ? 'bad' : 'na'}${mo(i)}"><span class="bd-g" aria-hidden="true">${it.ok === true ? '✓' : it.ok === false ? '✕' : '○'}</span><b>${esc(it.label)}</b><span>${esc(it.note || '')}</span></div>`).join('')}
      </div>
      ${scene.footer ? `<div class="bd-foot${fresh ? ' mo-in' : ''}">${scene.footer}</div>` : ''}
    </div>`;
  }
  // lanes
  const side = (who, ids, title, sub) => `<div class="lane lane-${who}">
      <div class="node node-${who}"><b>${title}</b><span>${esc(sub || '')}</span></div>
      <div class="lane-arts">${(ids || []).map((id, i) => `<div class="${fresh ? `mo-in" style="--d:${i * 60}ms` : ''}">${artifactChip(A(id), sel)}</div>`).join('')}</div>
    </div>`;
  const flows = (scene.flows || []).map((f, i) => {
    const dir = (f.from === 'server' || (f.from === 'mallory' && f.to === 'client')) ? 'rtl' : 'ltr';
    const a = f.art ? A(f.art) : null;
    return `<div class="flow-row flow-${f.tone || 'info'} flow-${dir}">
      <div class="flow-head">
        <span class="flow-lab">${esc(f.label)}</span>
        ${f.verdict ? `<span class="flow-v">${esc(f.verdict)}</span>` : ''}
      </div>
      <div class="track"><span class="line" aria-hidden="true"></span>
        ${a ? artifactChip(a, sel, fresh ? `mo-travel-${dir}" style="--d:${i * 120}ms` : '') : ''}
      </div>
    </div>`;
  }).join('');
  return `<div class="ws-lanes-wrap">
    <div class="ws ws-lanes${scene.mallory ? ' with-mal' : ''}">
      ${side('client', scene.client, 'CLIENT', scene.clientSub)}
      <div class="wire">
        <span class="wire-k">${esc(scene.wireTitle || 'NETWORK · UNTRUSTED')}</span>
        ${scene.mallory ? `<div class="node node-mallory"><b>MALLORY</b><span>${esc(scene.mallorySub || 'active attacker on the wire')}</span></div>` : ''}
        ${flows}
      </div>
      ${side('server', scene.server, 'SERVER', scene.serverSub)}
    </div>
    ${scene.gate ? `<div class="lane-gate">${gate(scene.gate, fresh)}</div>` : ''}
  </div>`;
}

/* ---- ArtifactInspector ------------------------------------------------------- */
export function inspector(a) {
  if (!a) return `<section class="insp" aria-label="Artifact inspector"><div class="pk">ARTIFACT INSPECTOR</div><p class="insp-empty">Select any artifact in the workspace to inspect its real metadata.</p></section>`;
  const row = (k, v, mono) => (v === undefined || v === null || v === '' ? '' : `<div><dt>${k}</dt><dd${mono ? ' class="mono"' : ''}>${v}</dd></div>`);
  return `<section class="insp" aria-label="Artifact inspector"><div class="pk">ARTIFACT INSPECTOR</div>
    <h3>${esc(a.label)}</h3>
    <dl>
      ${row('Type', esc(a.type))}
      ${row('Source', esc(a.source), true)}
      ${row('State', esc(a.status))}
      ${row('Value', a.redacted ? 'REDACTED — never leaves the C process' : esc(a.value || ''), !a.redacted)}
      ${row('Fingerprint', esc(a.fp || ''), true)}
      ${row('Algorithm', esc(a.algo || ''))}
      ${row('Created', a.created ? `${esc(clock(a.created))} <span class="faint">(${esc(a.createdBy || 'engine event')})</span>` : '')}
      ${row('Depends on', (a.deps || []).map(esc).join('<br>'))}
      ${row('Proves', esc(a.property || ''))}
      ${(a.extra || []).map(([k, v]) => row(esc(k), esc(v), true)).join('')}
    </dl></section>`;
}

/* ---- SecurityDecisionTrace (horizontal stepper) ------------------------------ */
export function decisionTrace(trace, fresh) {
  if (!trace?.length) return '<div class="dtr-empty">No security decision yet.</div>';
  return `<ol class="dtr">${trace.map((t, i) => `
    <li class="dt dt-${t.m}${fresh ? ' mo-in' : ''}" style="--d:${Math.min(i * 40, 480)}ms">
      <span class="dt-i">${pad(i + 1)}</span><span class="dt-g" aria-hidden="true">${{ ok: '✓', bad: '✕', blocked: '■', skip: '—', warn: '!', info: '●' }[t.m] || ''}</span>
      <b>${esc(t.stage)}</b><span class="dt-n">${esc(t.note)}</span>
    </li>`).join('')}</ol>`;
}

/* ---- ExecutionConsole: real events with real timestamps only ------------------ */
export function executionConsole(lines) {
  if (!lines.length) return '<div class="con-empty">Waiting for the cryptographic authority.</div>';
  return `<ol class="con">${lines.map((l) => `<li class="con-${esc(l.kind)}"><time>${esc(clock(l.ts))}</time><span class="con-src">${esc(l.src)}</span><span class="con-m">${esc(l.msg)}</span></li>`).join('')}</ol>`;
}

/* ---- EvidencePanel ----------------------------------------------------------- */
export function evidencePanel(rows) {
  return `<dl class="evp">${rows.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join('')}</dl>`;
}

/* ---- PresenterNotes ---------------------------------------------------------- */
export function presenterNotes(stage) {
  return `<section class="pnotes" aria-label="Presenter notes">
    <div><span class="pk">WHAT TO SAY</span><p>${esc(stage.notes.say)}</p></div>
    <div><span class="pk">WHAT TO WATCH</span><p>${esc(stage.notes.watch)}</p></div>
    <div><span class="pk">SECURITY PRINCIPLE</span><p>${esc(stage.principle)}</p></div>
    <div><span class="pk">EXPECTED RESULT</span><p>${esc(stage.notes.expected)}</p></div>
  </section>`;
}
