import { store, engine, addEvent, notify } from '../store.js';
import { api } from '../api.js';
import { esc, time, busy, icons, verdictBadge, toast, $ } from '../ui.js';

function deliveries() {
  const list = store.deliveries.slice(0, 8);
  if (!list.length) return '<div class="small muted">No packets yet.</div>';
  return list.map((p) => `<div class="delivery">
      <span class="mono">#${p.id}</span>
      <span class="mono">seq ${esc(p.seq ?? '—')}</span>
      <span>${esc(p.label)}${p.attack ? ` <span class="faint">(${esc(p.attack)})</span>` : ''}${p.rekeyed ? ' <span class="badge b-violet">REKEY</span>' : ''}</span>
      ${verdictBadge(p.verdict, p.rc)}
    </div>`).join('');
}

function epochs() {
  const s = store.session;
  if (s.state !== 'SECURE' && !store.events.some((e) => /re-key/.test(e.msg))) return '<div class="small muted">Re-keying starts after the handshake.</div>';
  const rekeys = store.events.filter((e) => e.src === 'engine' && /^re-key: epoch/.test(e.msg)).slice(-5);
  const parts = [`<span class="badge b-cyan">EPOCH 01</span>`];
  for (const r of rekeys) {
    const m = /epoch (\d+) -> (\d+)/.exec(r.msg);
    if (!m) continue;
    parts.push(`<span class="faint">→ <span class="badge b-violet">REKEY ${time(r.ts)}</span> →</span>`);
    parts.push(`<span class="badge b-cyan">EPOCH ${m[2].padStart(2, '0')}</span>`);
  }
  return `<div class="actions" style="gap:6px">${parts.slice(-9).join('')}</div>
    <p class="note">Each re-key runs <code>crypto_kdf_derive_from_key(new, 32, epoch, "SCREKEY1", old)</code> on all four session keys in place — the old key bytes are overwritten, so a key leaked later cannot decrypt earlier epochs.</p>`;
}

function tcpLogs(role) {
  const evs = store.tcp.events.filter((e) => e.src === role).slice(-80);
  return evs.map((e) => `<li><time>${time(e.ts)}</time><span class="lvl lvl-${esc(e.level)} st">${esc(e.level)}</span><span>${esc(e.msg)}${e.packet ? ` <span class="faint mono">[${e.packet.length} B]</span>` : ''}</span></li>`).join('');
}

export default {
  id: 'channel',
  label: 'Secure Channel',
  mount(root, ctx) {
    this.ctx = ctx;
    root.innerHTML = `
      <div class="page-head">
        <div><h1>SECURE CHANNEL</h1><p>Messages are sealed by the client with <code>client_tx</code> and verified by the server with <code>server_rx</code>. The animation is decoration; each verdict is the return code of <code>unseal()</code>.</p></div>
        <div class="actions" id="ch-state"></div>
      </div>
      <div class="grid">
        <section class="card s12 glow">
          <div class="lane">
            <div class="endpoint" id="ch-client">${icons.client}<b>CLIENT</b><small>seal() · client_tx</small></div>
            <div class="track" id="ch-track"><span class="track-label" id="ch-label"></span></div>
            <div class="endpoint" id="ch-server">${icons.server}<b>SERVER</b><small>unseal() · server_rx</small></div>
          </div>
          <div class="row" style="margin-top:14px">
            <div class="field grow"><label for="ch-msg">MESSAGE (1–256 BYTES)</label><input id="ch-msg" class="input" maxlength="256" value="Meet at the library at 10:00" autocomplete="off"></div>
            <button class="btn btn-primary" data-a="send">SEND ENCRYPTED ›</button>
            <button class="btn" data-a="hs">NEW HANDSHAKE</button>
            <button class="btn btn-danger" data-a="term">TERMINATE</button>
          </div>
        </section>
        <section class="card s7"><div class="card-head"><div class="card-title">RECENT DELIVERIES</div><span class="card-sub">newest first</span></div><div class="deliveries" id="ch-list"></div></section>
        <section class="card s5">
          <div class="card-head"><div class="card-title">RE-KEYING (EXTENSION)</div></div>
          <div class="row">
            <div class="field"><label for="ch-every">AUTO RE-KEY EVERY</label>
              <select id="ch-every" class="select"><option value="0">off</option><option value="2">2 messages</option><option value="3">3 messages</option><option value="5">5 messages</option><option value="10">10 messages</option></select></div>
            <button class="btn" data-a="rekey">RE-KEY NOW</button>
          </div>
          <div class="hr"></div>
          <div id="ch-epochs"></div>
        </section>
        <section class="card s12">
          <div class="card-head"><div><div class="card-title">TCP MODE — LOCALHOST CLIENT / SERVER (EXTENSION)</div><div class="card-sub">Real sockets on 127.0.0.1:7700 · 4-byte length prefix · signed handshake · re-key every N · runs <code>sc_server</code> and <code>sc_client</code></div></div><div id="tcp-status"></div></div>
          <div class="row">
            <div class="field"><label for="tcp-rekey">SERVER RE-KEY</label><select id="tcp-rekey" class="select"><option value="0">off</option><option value="2">every 2</option><option value="3" selected>every 3</option><option value="5">every 5</option></select></div>
            <button class="btn" data-a="tcp-server">START SERVER</button>
            <button class="btn" data-a="tcp-connect">START CLIENT / CONNECT</button>
            <div class="field grow"><label for="tcp-msg">MESSAGE</label><input id="tcp-msg" class="input" maxlength="256" value="hello over TCP" autocomplete="off"></div>
            <button class="btn btn-primary" data-a="tcp-send">SEND</button>
            <button class="btn btn-danger" data-a="tcp-tamper">SEND TAMPERED</button>
            <button class="btn btn-danger" data-a="tcp-replay">REPLAY</button>
            <button class="btn" data-a="tcp-disconnect">DISCONNECT</button>
            <button class="btn btn-ghost" data-a="tcp-stop">STOP SERVER</button>
          </div>
          <div class="tcp-cols" style="margin-top:14px">
            <div><div class="card-title" style="margin-bottom:6px">CLIENT</div><ol class="tcp-log" id="tcp-client"></ol></div>
            <div><div class="card-title" style="margin-bottom:6px">SERVER</div><ol class="tcp-log" id="tcp-server"></ol></div>
          </div>
        </section>
      </div>`;

    $('#ch-every', root).addEventListener('change', (e) => engine('config', e.target.value));
    $('#ch-msg', root).addEventListener('keydown', (e) => { if (e.key === 'Enter') $('[data-a="send"]', root).click(); });
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const a = b.dataset.a;
      if (a === 'send') busy(b, () => this.send($('#ch-msg').value));
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
    const r = await engine('send', text);
    if (r.ok) this.ctx.animatePacket($('#ch-track'), r);
    else toast(r.error || 'send failed', true);
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
    $('#ch-state').innerHTML = `<span class="badge ${secure ? 'b-ok' : s.state === 'TERMINATE' ? 'b-muted' : 'b-info'}">STATE ${s.state}</span>
      ${secure ? `<span class="badge b-cyan">EPOCH ${String(s.epoch).padStart(2, '0')}</span><span class="badge b-muted">NEXT SEQ ${s.next_seq}</span><span class="badge b-muted">LAST ACCEPTED ${s.has_seq ? s.last_seq : '—'}</span>` : ''}`;
    for (const id of ['#ch-client', '#ch-server']) $(id).classList.toggle('live', secure);
    $('#ch-track').classList.toggle('live', secure);
    $('#ch-label').textContent = secure ? 'ChaCha20-Poly1305 · seq as AAD' : s.state === 'TERMINATE' ? 'terminated — keys wiped' : 'not established';
    $('#ch-list').innerHTML = deliveries();
    $('#ch-epochs').innerHTML = epochs();
    const sel = $('#ch-every');
    if (document.activeElement !== sel) sel.value = String([0, 2, 3, 5, 10].includes(s.rekey_every) ? s.rekey_every : 0);
    $('#tcp-status').innerHTML = `<span class="badge ${store.tcp.server ? 'b-ok' : 'b-muted'}">SERVER ${store.tcp.server ? 'RUNNING' : 'STOPPED'}</span>
      <span class="badge ${store.tcp.client ? 'b-ok' : 'b-muted'}">CLIENT ${store.tcp.client ? 'CONNECTED' : 'IDLE'}</span>`;
    for (const role of ['client', 'server']) {
      const el = $(`#tcp-${role}`);
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
      el.innerHTML = tcpLogs(role);
      if (atBottom) el.scrollTop = el.scrollHeight;
    }
  },
};
