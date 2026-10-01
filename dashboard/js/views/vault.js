import { store, engine, run } from '../store.js';
import { esc, busy, chip, icons, emptyState, pageHead, panelHead, $ } from '../ui.js';

const STAGES = ['GENERATED', 'STORED', 'LOADED', 'USED', 'WIPED'];

function lifecycle(states) {
  // states: 5 values: true (reached), false (not yet), 'na'
  const lastOn = states.lastIndexOf(true);
  return `<div class="life" aria-label="Key lifecycle">${STAGES.map((s, i) => {
    const v = states[i];
    const cls = v === 'na' ? 'na' : v ? (i === lastOn ? 'cur' : 'on') : '';
    return `<div class="${cls}" title="${v === 'na' ? 'not applicable' : v ? 'reached' : 'not yet'}">${v && v !== 'na' ? '✓ ' : ''}${s}</div>`;
  }).join('')}</div>`;
}

function permChip(f) {
  if (!f || !f.exists) return chip('NOT PRESENT');
  if (f.mode_ok) return chip('PASS', { text: f.mode, glyph: '✓' });
  return chip('FAILED', { text: `${f.mode} · expected ${f.expected_mode}` });
}

function fact(k, v) { return `<div class="meta"><span class="k">${k}</span><span class="v">${v}</span></div>`; }

function fileCard(title, subtitle, icon, priv, pub, usedFlag) {
  if (!priv) return '';
  const states = [priv.exists, priv.exists && priv.mode_ok, priv.loaded && priv.pair_ok !== false, !!usedFlag, priv.loaded];
  const secure = priv.exists && priv.mode_ok && (!pub || (pub.exists && pub.mode_ok)) && priv.pair_ok !== false;
  return `<section class="panel vk">
    <div class="vk-head"><div class="t">${icons[icon]}<div><h3>${title}</h3><p>${subtitle}</p></div></div>${priv.exists ? chip(secure ? 'SECURE' : 'WARNING') : chip('NOT PRESENT')}</div>
    <div class="vk-facts">
      ${fact('Algorithm', esc(priv.algorithm))}
      ${fact('Public key', pub ? (pub.exists ? chip('AVAILABLE') : chip('NOT PRESENT')) : '—')}
      ${fact('Private key', priv.exists ? `${chip('PROTECTED', { glyph: '✓' })} <span class="redacted">REDACTED</span>` : chip('NOT PRESENT'))}
      ${fact('Permission', `${permChip(priv)}${pub ? ` <span class="faint small">public ${esc(pub.mode || '—')}</span>` : ''}`)}
      ${fact('Private file', `<span class="mono">${esc(priv.path.replace('keys/', ''))}</span> <span class="faint small">${priv.expected_size} B</span>`)}
      ${fact('Public file', pub ? `<span class="mono">${esc(pub.path.replace('keys/', ''))}</span> <span class="faint small">${pub.expected_size} B</span>` : '—')}
    </div>
    ${fact('Public-key fingerprint', `<span class="fp">${esc(priv.fingerprint || '—')}</span>`)}
    ${priv.pair_ok !== undefined ? fact('Key pair check', priv.pair_ok ? chip('PASS', { text: 'private key matches public file' }) : chip('MISMATCH')) : ''}
    ${lifecycle(states)}
  </section>`;
}

function sessionCard(title, dirLabel, fpA, fpB) {
  const s = store.session;
  const has = !!s.key_fingerprints;
  const used = store.packets.some((p) => p.verdict === 'ACCEPTED');
  const wiped = s.state === 'TERMINATE';
  const everHad = has || wiped;
  const states = [everHad, everHad, 'na', everHad && used, wiped || s.epoch > 1];
  return `<section class="panel vk">
    <div class="vk-head"><div class="t">${icons.memory}<div><h3>${title}</h3><p>${dirLabel}</p></div></div>
      ${has ? chip('IN MEMORY', { text: 'sodium_malloc' }) : wiped ? chip('WIPED') : chip('NO SESSION')}</div>
    <div class="vk-facts">
      ${fact('Algorithm', 'X25519 → BLAKE2b · 32 B')}
      ${fact('Key material', has ? '<span class="redacted">REDACTED</span>' : '—')}
      ${fact('Storage', 'memory only · guard pages · mlock')}
      ${fact('Epoch', `<span class="mono">${has ? s.epoch : '—'}</span>`)}
    </div>
    ${fact('Fingerprint · client = server', `<span class="fp">${has ? `${esc(fpA)} <span class="faint">=</span> ${esc(fpB)}` : '—'}</span>`)}
    ${lifecycle(states)}
  </section>`;
}

function wrappedCard(w) {
  if (!w) return '';
  const lastWrap = store.wrap.correct || store.wrap.wrong;
  const states = [w.exists, w.exists && w.mode_ok, w.loaded, !!store.wrap.correct?.unwrapped, !!lastWrap];
  return `<section class="panel vk">
    <div class="vk-head"><div class="t">${icons.wrap}<div><h3>Wrapped private key</h3><p>Ed25519 secret encrypted at rest</p></div></div>${w.exists ? chip(w.mode_ok ? 'SECURE' : 'WARNING') : chip('NOT PRESENT')}</div>
    <div class="vk-facts">
      ${fact('Algorithm', esc(w.algorithm))}
      ${fact('Permission', permChip(w))}
      ${fact('File', `<span class="mono">${esc(w.path.replace('keys/', ''))}</span> <span class="faint small">${w.expected_size} B</span>`)}
      ${fact('Layout', '<span class="mono small">salt 16 · nonce 24 · MAC 16 · ct 64</span>')}
    </div>
    ${fact('Ciphertext fingerprint', `<span class="fp">${esc(w.fingerprint || '—')}</span>`)}
    ${lifecycle(states)}
  </section>`;
}

export default {
  id: 'vault',
  label: 'Key Vault',
  icon: 'vault',
  mount(root, ctx) {
    root.innerHTML = `
      ${pageHead('Task 1 · Key management', 'Key vault', 'Safe metadata only: algorithms, file permissions, sizes and one-way fingerprints. Private and session key bytes never leave the C engine, and there is no way to reveal them here.',
        '<button class="btn btn-primary" data-a="keygen">Generate keys</button><button class="btn" data-a="scan">Rescan</button><button class="btn btn-ghost" data-a="wrap">Key wrapping</button>')}
      <div class="vault" id="vk-grid"></div>
      <section class="panel section">${panelHead('Last ./keygen run', 'Program output from this session', '<span id="vk-kg-status"></span>')}<div id="vk-keygen"></div></section>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const a = b.dataset.a;
      if (a === 'keygen') busy(b, async () => { await run('keygen'); await engine('vault'); });
      if (a === 'scan') busy(b, () => engine('vault'));
      if (a === 'wrap') ctx.navigate('wrap');
    });
    if (!store.vault) engine('vault');
    this.update();
  },
  update() {
    const v = store.vault;
    const f = (p) => v?.files?.find((x) => x.path === p);
    const fp = store.session.key_fingerprints;
    $('#vk-grid').innerHTML = !v ? emptyState('Scanning key files…', '', 'SCANNING')
      : fileCard('Server signing key', 'Ed25519 long-term identity', 'key', f('keys/server_sk.bin'), f('keys/server_pk.bin'), store.session.authenticated || store.wrap.correct || store.mitm?.signed?.task1_identity)
        + fileCard('Key exchange key', 'X25519 static key pair', 'handshake', f('keys/server_kx_sk.bin'), f('keys/server_kx_pk.bin'), false)
        + wrappedCard(f('keys/server_sk.wrapped'))
        + sessionCard('Session TX key', 'client → server direction', fp?.client_tx, fp?.server_rx)
        + sessionCard('Session RX key', 'server → client direction', fp?.client_rx, fp?.server_tx);
    const kg = store.keygen;
    $('#vk-kg-status').innerHTML = kg ? chip(kg.ok ? 'PASS' : 'FAILED', { text: `exit code ${kg.code}` }) : chip('NOT RUN');
    $('#vk-keygen').innerHTML = kg ? `<pre class="console">${esc(kg.output)}\n$ ls -l keys/\n${esc(kg.listing)}</pre>`
      : '<div class="small faint">Not run from the dashboard yet. The vault above reflects whatever is currently in keys/.</div>';
  },
};
