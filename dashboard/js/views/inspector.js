import { store } from '../store.js';
import { esc, timeMs, byteMap, hexGroups, verdictBadge, emptyState, packetFormat, $ } from '../ui.js';

let selected = null;

function list() {
  if (!store.packets.length) return emptyState('No packets captured yet.<br>Send a message or launch an attack.');
  return store.packets.slice(0, 60).map((p) => `
    <button class="pitem${p.id === selected ? ' sel' : ''}" data-id="${p.id}">
      <span class="id">#${p.id}</span>
      <span class="t">${esc(p.label)}<small>seq ${esc(p.seq ?? '—')} · ${p.length} B · ${esc(p.role)}</small></span>
      ${verdictBadge(p.verdict)}
    </button>`).join('');
}

function detail(p) {
  if (!p) return emptyState('Select a packet to inspect it.');
  const short = p.raw_hex !== undefined;
  return `
    <div class="card-head"><div><div class="card-title">PACKET #${p.id} · ${esc(p.label).toUpperCase()}</div><div class="card-sub">captured ${timeMs(p.ts)} · ${esc(p.cmd)}${p.attack ? ` · attack: ${esc(p.attack)}` : ''} · sender: ${esc(p.role)}</div></div>${verdictBadge(p.verdict, p.rc)}</div>
    ${byteMap(p)}
    <div class="hr"></div>
    <div class="kv">
      <div>SEQUENCE NUMBER</div><div class="mono">${esc(p.seq ?? '—')} <span class="faint">(${esc(hexGroups(p.seq_hex || ''))})</span></div>
      <div>NONCE</div><div class="mono">${short ? '<span class="bad">missing — packet truncated</span>' : esc(hexGroups(p.nonce_hex))}</div>
      <div>CIPHERTEXT LENGTH</div><div class="mono">${short ? '—' : `${p.ct_len} B`}</div>
      <div>CIPHERTEXT</div><div class="hex">${short ? '—' : esc(hexGroups(p.ct_hex, 48))}</div>
      <div>AUTHENTICATION TAG</div><div class="mono">${short ? '—' : esc(hexGroups(p.tag_hex))}</div>
      <div>AAD</div><div class="mono">${esc(hexGroups(p.aad_hex || ''))} <span class="faint">= the 8 sequence bytes</span></div>
      <div>TOTAL PACKET SIZE</div><div class="mono">${p.length} B${short ? ' <span class="bad">(below 36 B minimum)</span>' : ` = 20 header + ${p.ct_len} ciphertext + 16 tag`}</div>
      <div>VERIFICATION</div><div>${verdictBadge(p.verdict, p.rc)} <span class="muted small">${esc(p.reason)}</span>${p.rekeyed ? ' <span class="badge b-violet">TRIGGERED RE-KEY</span>' : ''}</div>
      <div>MODIFIED BYTE</div><div class="mono">${p.modified >= 0 ? `<span class="bad">offset ${p.modified}</span> (${p.modified < 8 ? 'sequence / AAD' : p.modified < 20 ? 'nonce' : 'ciphertext'})` : 'none'}</div>
    </div>`;
}

export default {
  id: 'inspector',
  label: 'Packet Inspector',
  mount(root) {
    this.rendered = null;
    root.innerHTML = `
      <div class="page-head"><div><h1>PACKET INSPECTOR</h1><p>Every packet the engine delivered, split into its fields. These are public wire bytes: an eavesdropper sees exactly this, and nothing here reveals a key or plaintext.</p></div></div>
      <div class="grid">
        <section class="card s12"><div class="card-head"><div class="card-title">PACKET FORMAT</div></div>${packetFormat()}</section>
        <section class="card s4"><div class="card-head"><div class="card-title">CAPTURED PACKETS</div><span class="card-sub" id="pi-count"></span></div><div class="plist" id="pi-list"></div></section>
        <section class="card s8" id="pi-detail"></section>
        <section class="card s12"><div class="card-head"><div class="card-title">WHAT EACH FIELD PROTECTS</div></div>
          <div class="explain">
            <div class="ex c-seq"><h5>SEQ</h5><p>Freshness. The receiver accepts only seq &gt; last accepted seq, which stops replay and reordering. Checked before decryption, stored only after the tag verifies.</p></div>
            <div class="ex c-nonce"><h5>NONCE</h5><p>Unique encryption input. Twelve random bytes per packet; reusing a nonce with the same key would leak plaintext XORs and allow forgeries.</p></div>
            <div class="ex c-ct"><h5>CIPHERTEXT</h5><p>Confidentiality. ChaCha20 keystream XOR plaintext: same length as the message, unreadable without the session key.</p></div>
            <div class="ex c-tag"><h5>TAG</h5><p>Integrity + authenticity. Poly1305 over ciphertext and AAD. Any flipped bit, wrong key or rewritten seq makes it fail (rc -2).</p></div>
            <div class="ex c-aad"><h5>AAD</h5><p>Authenticated metadata. The seq travels in clear so it can be checked early, yet it is covered by the tag, so it cannot be renumbered.</p></div>
          </div>
        </section>
      </div>`;
    $('#pi-list', root).addEventListener('click', (e) => {
      const b = e.target.closest('.pitem');
      if (!b) return;
      selected = Number(b.dataset.id);
      this.update('select');
    });
    this.update();
  },
  select(id) { selected = id; },
  update() {
    if (selected === null || !store.packets.some((p) => p.id === selected)) selected = store.packets[0]?.id ?? null;
    const key = `${selected}:${store.packets.length}:${store.packets[0]?.id}`;
    if (key === this.rendered) return;          // nothing new: keep animations and scroll
    this.rendered = key;
    $('#pi-count').textContent = `${store.packets.length} captured`;
    $('#pi-list').innerHTML = list();
    $('#pi-detail').innerHTML = detail(store.packets.find((p) => p.id === selected));
  },
};
