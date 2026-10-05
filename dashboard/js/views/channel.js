import { store, engine, addEvent, notify } from '../store.js';
import { api } from '../api.js';
import { esc, time, busy, chip, verdictBadge, toast, pad2, seqLabel, hexGroups, packetFlow, pageHead, panelHead, emptyState, fullCryptoPipeline, whyThisMatters, $ } from '../ui.js';
import { securityDecisionTrace } from '../trace.js';

const lastSent = () => store.deliveries.find((p) => p.cmd === 'send') || null;

function pipeline(p, text) {
  const ok = p?.verdict === 'ACCEPTED';
  const bytes = new TextEncoder().encode(text || '').length;
  const steps = [
    ['01', 'Enter message', p ? `${p.ct_len} B plaintext` : `${bytes} B ready`, p ? 'done' : ''],
    ['02', 'Seal · client_tx', p ? `seq ${seqLabel(p.seq)} · fresh nonce` : 'ChaCha20-Poly1305', p ? 'done' : ''],
    ['03', 'Transmit', p ? `${p.length} B on the wire` : '36 + n bytes', p ? 'done' : ''],
    ['04', 'Unseal · server_rx', p ? `${p.verdict} · rc ${p.rc}` : 'verify tag → decrypt', p ? (ok ? 'done' : 'fail') : ''],
  ];
  return `<div class="pipeline">${steps.map(([n, b, s, c]) => `<div class="pstep ${c}"><span class="n">${n}</span><b>${b}</b><small>${esc(s)}</small></div>`).join('')}</div>`;
}

function packetPanel(p) {
  if (!p) return emptyState('Encrypt a message to see the sealed packet: sequence number, nonce, ciphertext and authentication tag.');
  return `<div class="kv">
      <div>Sequence</div><div class="mono">${esc(seqLabel(p.seq))} <span class="faint">· 8 B · AAD</span></div>
      <div>Nonce</div><div class="mono">${esc(hexGroups(p.nonce_hex))} <span class="faint">· 12 B</span></div>
      <div>Ciphertext</div><div class="hex">${esc(hexGroups(p.ct_hex, 32))} <span class="faint">· ${p.ct_len} B</span></div>
      <div>Auth tag</div><div class="mono">${esc(hexGroups(p.tag_hex))} <span class="faint">· 16 B</span></div>
      <div>Total</div><div class="mono">${p.length} B <span class="faint">= 20 header + ${p.ct_len} ciphertext + 16 tag</span></div>
      <div>Server verdict</div><div>${verdictBadge(p.verdict, p.rc)} <span class="faint small">${esc(p.reason)}</span>${p.rekeyed ? ` ${chip('EXTENSION', { tone: 'violet', text: 'Triggered re-key' })}` : ''}</div>
      <div>Delivered</div><div>${p.delivered !== undefined ? `<span class="mono">“${esc(p.delivered)}”</span> <span class="faint small">· recovered by unseal()</span>` : '<span class="faint">nothing — packet rejected</span>'}</div>
    </div>
    <div class="actions" style="margin-top:16px"><button class="btn btn-sm" data-a="inspect" data-id="${p.id}">Inspect packet</button></div>`;
}

function deliveries() {
  const list = store.deliveries.slice(0, 8);
  if (!list.length) return '<div class="small faint">No packets yet.</div>';
  return `<div class="table-wrap"><table class="table"><thead><tr><th>#</th><th>Seq</th><th>Source</th><th>Size</th><th>Verdict</th></tr></thead><tbody>
    ${list.map((p) => `<tr><td class="mono">${p.id}</td><td class="mono">${esc(seqLabel(p.seq))}</td>
      <td>${esc(p.label)}${p.attack ? ` <span class="faint">(${esc(p.attack)})</span>` : ''}${p.rekeyed ? ` ${chip('EXTENSION', { tone: 'violet', text: 'Re-key' })}` : ''}</td>
      <td class="mono">${p.length} B</td><td>${verdictBadge(p.verdict, p.rc)}</td></tr>`).join('')}
  </tbody></table></div>`;
}

function epochs() {
  const s = store.session;
  if (s.state !== 'SECURE' && !store.events.some((e) => /re-key/.test(e.msg))) return '<div class="small faint">Re-keying starts after the handshake.</div>';
  const rekeys = store.events.filter((e) => e.src === 'engine' && /^re-key: epoch/.test(e.msg)).slice(-4);
  const parts = [chip('ACTIVE', { text: 'Epoch 01', glyph: '' })];
  for (const r of rekeys) {
    const m = /epoch (\d+) -> (\d+)/.exec(r.msg);
    if (!m) continue;
    parts.push(`<span class="faint mono small">→ re-key ${time(r.ts)} →</span>`);
    parts.push(chip('ACTIVE', { text: `Epoch ${pad2(m[2])}`, glyph: '' }));
  }
  return `<div class="actions" style="gap:6px">${parts.slice(-7).join('')}</div>
    <p class="note">Each re-key runs <code>crypto_kdf_derive_from_key(new, 32, epoch, "SCREKEY1", old)</code> on all four session keys in place — old key bytes are overwritten, so a key leaked later cannot decrypt earlier epochs.</p>`;
}

function tcpLogs(role) {
  const evs = store.tcp.events.filter((e) => e.src === role).slice(-80);
  if (!evs.length) return `<li><span></span><span></span><span class="faint">no ${role} output yet</span></li>`;
  return evs.map((e) => `<li><time>${time(e.ts)}</time><span><span class="lvl lvl-${esc(e.level)}">${esc(e.level)}</span></span><span>${esc(e.msg)}${e.packet ? ` <span class="faint">[${e.packet.length} B]</span>` : ''}</span></li>`).join('');
}

export default {
  id: 'channel',
  label: 'Secure Channel',
  icon: 'channel',
  mount(root, ctx) {
    this.ctx = ctx;
    root.innerHTML = `
      ${pageHead('Task 3 · AEAD channel', 'Secure message workspace', 'The client seals with <code>client_tx</code>; the server verifies and decrypts with <code>server_rx</code>. Every verdict below is the return code of <code>unseal()</code> in C.', '<span id="ch-state" class="actions"></span>')}
      <div class="grid">
        <section class="panel s5">
          ${panelHead('Plaintext', 'Message composer · 1–256 bytes')}
          <div class="field"><label for="ch-msg">Message</label>
            <textarea id="ch-msg" class="textarea" maxlength="256" autocomplete="off" spellcheck="false">Meet at the library at 10:00</textarea></div>
          <div class="faint small" id="ch-bytes" style="margin-top:6px"></div>
          <div class="actions" style="margin-top:16px">
            <button class="btn btn-primary" data-a="send">Encrypt message</button>
            <button class="btn btn-ghost" data-a="clear">Clear</button>
          </div>
          <div class="hr"></div>
          <div class="actions"><button class="btn btn-sm" data-a="hs">New handshake</button><button class="btn btn-sm btn-danger" data-a="term">Terminate session</button></div>
        </section>
        <section class="panel elevated s7" id="ch-packet-card">
          ${panelHead('Secure packet', 'Latest message sealed by the client and verified by the server')}
          <div id="ch-pipe"></div>
          <div class="hr"></div>
          <div id="ch-packet"></div>
        </section>
        <section class="panel s12">
          ${panelHead('Cryptographic AEAD Pipeline', '10-Stage seal() / unseal() wire lifecycle (ChaCha20-Poly1305)')}
          <div id="ch-full-pipe"></div>
        </section>
        <section class="panel s12">
          ${panelHead('Security Decision Trace', 'Step-by-step cryptographic verdict for the latest message')}
          <div id="ch-trace"></div>
        </section>
        <section class="panel s12">${panelHead('Transmission', 'Static view of the last packet on the wire')}<div id="ch-flow"></div></section>
        <section class="panel s7">${panelHead('Recent deliveries', 'Newest first · includes Attack Lab packets')}<div id="ch-list"></div></section>
        <section class="panel s5">
          ${panelHead('Re-keying · extension')}
          <div class="row">
            <div class="field"><label for="ch-every">Auto re-key every</label>
              <select id="ch-every" class="select"><option value="0">off</option><option value="2">2 messages</option><option value="3">3 messages</option><option value="5">5 messages</option><option value="10">10 messages</option></select></div>
            <button class="btn" data-a="rekey">Re-key now</button>
          </div>
          <div class="hr"></div>
          <div id="ch-epochs"></div>
        </section>
        <section class="panel s6">${whyThisMatters('aead')}</section>
        <section class="panel s6">${whyThisMatters('replay')}</section>
        <section class="panel s12">
          ${panelHead('TCP mode · localhost client / server · extension', 'Real sockets on 127.0.0.1:7700 · 4-byte length prefix · signed handshake · runs <code>sc_server</code> and <code>sc_client</code>', '<span id="tcp-status" class="actions"></span>')}
          <div class="row">
            <div class="field"><label for="tcp-rekey">Server re-key</label><select id="tcp-rekey" class="select"><option value="0">off</option><option value="2">every 2</option><option value="3" selected>every 3</option><option value="5">every 5</option></select></div>
            <button class="btn" data-a="tcp-server">Start server</button>
            <button class="btn" data-a="tcp-connect">Connect client</button>
            <div class="field grow"><label for="tcp-msg">Message</label><input id="tcp-msg" class="input" maxlength="256" value="hello over TCP" autocomplete="off"></div>
            <button class="btn btn-primary" data-a="tcp-send">Send</button>
            <button class="btn btn-danger" data-a="tcp-tamper">Send tampered</button>
            <button class="btn btn-danger" data-a="tcp-replay">Replay</button>
            <button class="btn btn-ghost" data-a="tcp-disconnect">Disconnect</button>
            <button class="btn btn-ghost" data-a="tcp-stop">Stop server</button>
          </div>
          <div class="tcp-cols" style="margin-top:16px">
            <div><div class="term-title"><span class="panel-title">Client</span></div><ol class="term" id="tcp-client" aria-label="TCP client output"></ol></div>
            <div><div class="term-title"><span class="panel-title">Server</span></div><ol class="term" id="tcp-server" aria-label="TCP server output"></ol></div>
          </div>
        </section>
      </div>`;

    const msg = $('#ch-msg', root);
    const count = () => { $('#ch-bytes', root).textContent = `${new TextEncoder().encode(msg.value).length} / 256 bytes · Ctrl+Enter to encrypt`; };
    msg.addEventListener('input', count);
    msg.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $('[data-a="send"]', root).click(); });
    count();
    $('#ch-every', root).addEventListener('change', (e) => engine('config', e.target.value));
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const a = b.dataset.a;
      if (a === 'send') busy(b, () => this.send(msg.value));
      if (a === 'clear') { msg.value = ''; count(); msg.focus(); }
      if (a === 'inspect') { ctx.views.inspector.select(Number(b.dataset.id)); ctx.navigate('inspector'); }
      if (a === 'hs') busy(b, () => engine('handshake', 'plain'));
      if (a === 'term') busy(b, () => engine('terminate'));
      if (a === 'rekey') busy(b, () => engine('rekey'));
      if (a.startsWith('tcp-')) busy(b, () => this.tcp(a.slice(4)));
    });
    this.update();
  },
  async send(text) {
    if (store.session.state !== 'SECURE') {
      toast('Channel is not SECURE — run the handshake first', true);
      return null;
    }
    if (!text || !text.trim()) { toast('Enter a message first', true); return null; }
    const r = await engine('send', text);
    if (!r.ok) toast(r.error || 'send failed', true);
    return r;
  },
  async tcp(action) {
    const body = action === 'server' ? { rekey: Number($('#tcp-rekey').value) }
      : action === 'send' || action === 'tamper' ? { mode: action, text: $('#tcp-msg').value }
        : action === 'replay' ? { mode: 'replay' } : {};
    const route = { server: 'start-server', connect: 'connect', send: 'send', tamper: 'send', replay: 'send', disconnect: 'disconnect', stop: 'stop' }[action];
    const r = await api.tcp(route, body);
    if (!r.ok) toast(r.error || 'TCP action failed', true);
    else addEvent('INFO', `TCP: ${action}${r.note ? ` (${r.note})` : ''}`, 'bridge');
    notify('tcp');
  },
  update() {
    const s = store.session;
    const secure = s.state === 'SECURE';
    $('#ch-state').innerHTML = `${chip(secure ? 'SECURE' : s.state === 'TERMINATE' ? 'TERMINATED' : s.state, { tone: secure ? 'ok' : s.state === 'TERMINATE' ? 'muted' : 'info', lg: true })}
      ${secure ? `${chip('ACTIVE', { text: `Epoch ${pad2(s.epoch)}`, glyph: '', lg: true })}${chip('IDLE', { text: `Next seq ${s.next_seq}`, glyph: '', lg: true })}${chip('IDLE', { text: `Last accepted ${s.has_seq ? s.last_seq : '—'}`, glyph: '', lg: true })}` : ''}`;
    const p = lastSent();
    $('#ch-pipe').innerHTML = pipeline(p, $('#ch-msg')?.value);
    $('#ch-packet').innerHTML = packetPanel(p);
    const fullPipeEl = $('#ch-full-pipe');
    if (fullPipeEl) fullPipeEl.innerHTML = fullCryptoPipeline(p, $('#ch-msg')?.value);
    const traceEl = $('#ch-trace');
    if (traceEl) traceEl.innerHTML = securityDecisionTrace(p);
    const last = store.deliveries[0];
    $('#ch-flow').innerHTML = packetFlow({
      from: last?.role === 'attacker' ? { icon: 'network', name: 'NETWORK', sub: 'attacker in path', hostile: true } : { icon: 'client', name: 'CLIENT', sub: 'seal() · client_tx' },
      to: { icon: 'server', name: 'SERVER', sub: 'unseal() · server_rx' },
      packet: last || null, verdict: last?.verdict, rc: last?.rc, live: secure, hostile: last?.role === 'attacker',
      label: last ? `packet #${last.id} · ${last.length} B` : secure ? 'ChaCha20-Poly1305 · seq as AAD' : s.state === 'TERMINATE' ? 'terminated — keys wiped' : 'not established',
    });
    $('#ch-list').innerHTML = deliveries();
    $('#ch-epochs').innerHTML = epochs();
    const sel = $('#ch-every');
    if (document.activeElement !== sel) sel.value = String([0, 2, 3, 5, 10].includes(s.rekey_every) ? s.rekey_every : 0);
    $('#tcp-status').innerHTML = `${chip(store.tcp.server ? 'RUNNING' : 'STOPPED', { text: `Server ${store.tcp.server ? 'running' : 'stopped'}` })}
      ${chip(store.tcp.client ? 'CONNECTED' : 'IDLE', { text: `Client ${store.tcp.client ? 'connected' : 'idle'}` })}`;
    for (const role of ['client', 'server']) {
      const el = $(`#tcp-${role}`);
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
      el.innerHTML = tcpLogs(role);
      if (atBottom) el.scrollTop = el.scrollHeight;
    }
  },
};
