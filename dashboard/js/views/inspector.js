import { store } from '../store.js';
import { esc, timeMs, byteMap, hexGroups, verdictBadge, chip, emptyState, packetAnatomy, pageHead, panelHead, seqLabel, $ } from '../ui.js';

let selected = null;

function list() {
  if (!store.packets.length) return emptyState('No packets captured yet. Send a message or launch an attack.', '', 'EMPTY');
  return store.packets.slice(0, 60).map((p) => `
    <button class="pitem" data-id="${p.id}" aria-pressed="${p.id === selected}">
      <span class="id">#${p.id}</span>
      <span class="t">${esc(p.label)}<small>seq ${esc(seqLabel(p.seq))} · ${p.length} B · ${esc(p.role)}</small></span>
      ${verdictBadge(p.verdict)}
    </button>`).join('');
}

function authState(p) {
  if (p.verdict === 'ACCEPTED') return chip('VALID', { tone: 'ok', glyph: '✓', text: 'Valid · tag verified' });
  if (p.rc === -2) return chip('INVALID', { tone: 'bad', glyph: '✕', text: 'Invalid · tag mismatch' });
  if (p.rc === -3) return chip('NOT RUN', { text: 'Not checked · replay rejected first' });
  if (p.rc === -1) return chip('NOT RUN', { text: 'Not checked · too short' });
  return chip('UNKNOWN');
}

function detail(p) {
  if (!p) return `${panelHead('Packet detail')}${emptyState('Select a packet to inspect it. Each field is public wire data — exactly what an eavesdropper sees.', '', 'NO PACKET SELECTED')}`;
  const short = p.raw_hex !== undefined;
  return `
    ${panelHead(`Packet #${p.id} · ${esc(p.label)}`, `captured ${timeMs(p.ts)} · ${esc(p.cmd)}${p.attack ? ` · attack: ${esc(p.attack)}` : ''} · sender: ${esc(p.role)}`, verdictBadge(p.verdict, p.rc))}
    ${packetAnatomy(p, { large: true })}
    <div class="hr"></div>
    <div class="grid">
      <div class="s7">
        <div class="kv">
          <div>Sequence</div><div class="mono">${esc(seqLabel(p.seq))} <span class="faint">(${esc(hexGroups(p.seq_hex || ''))})</span></div>
          <div>Nonce</div><div class="mono">${short ? '<span class="bad">missing — packet truncated</span>' : esc(hexGroups(p.nonce_hex))}</div>
          <div>Ciphertext</div><div class="hex">${short ? '—' : `${esc(hexGroups(p.ct_hex, 48))} <span class="faint">· ${p.ct_len} B</span>`}</div>
          <div>Auth tag</div><div class="mono">${short ? '—' : esc(hexGroups(p.tag_hex))}</div>
          <div>AAD</div><div class="mono">${esc(hexGroups(p.aad_hex || ''))} <span class="faint">= the 8 sequence bytes</span></div>
          <div>Total size</div><div class="mono">${p.length} B${short ? ' <span class="bad">(below the 36 B minimum)</span>' : ` = 20 header + ${p.ct_len} ciphertext + 16 tag`}</div>
          <div>Modified byte</div><div class="mono">${p.modified >= 0 ? `<span class="bad">offset ${p.modified}</span> (${p.modified < 8 ? 'sequence / AAD' : p.modified < 20 ? 'nonce' : 'ciphertext'})` : 'none'}</div>
        </div>
      </div>
      <div class="s5 stack">
        <div class="tile"><div class="meta"><span class="k">Authentication</span><span class="v">${authState(p)}</span></div></div>
        <div class="tile"><div class="meta"><span class="k">Verdict from unseal()</span><span class="v">${verdictBadge(p.verdict, p.rc)}</span><span class="faint small" style="margin-top:6px">${esc(p.reason)}</span>${p.rekeyed ? `<span style="margin-top:6px">${chip('EXTENSION', { tone: 'violet', text: 'Triggered re-key' })}</span>` : ''}</div></div>
      </div>
    </div>
    <div class="hr"></div>
    <div class="panel-title" style="margin-bottom:10px">Raw bytes</div>
    ${byteMap(p)}`;
}

export default {
  id: 'inspector',
  label: 'Packet Inspector',
  icon: 'inspector',
  mount(root) {
    this.rendered = null;
    root.innerHTML = `
      ${pageHead('Task 3 · Wire format', 'Packet inspector', 'Every packet the engine delivered, split into its fields. These are public wire bytes: nothing here reveals a key or a plaintext secret.')}
      <section class="panel elevated">${panelHead('Packet anatomy', 'ChaCha20-Poly1305-IETF · sequence number authenticated as AAD')}${packetAnatomy(null, { large: true })}</section>
      <div class="grid section">
        <section class="panel s4">${panelHead('Captured packets', '', '<span id="pi-count" class="faint small"></span>')}<div class="plist" id="pi-list"></div></section>
        <section class="panel s8" id="pi-detail"></section>
      </div>
      <section class="panel section">${panelHead('What each field protects')}
        <div class="explain">
          <div class="ex x-seq"><h5>SEQUENCE</h5><p>Freshness. Only seq &gt; last accepted seq is accepted, which stops replay and reordering. Checked before decryption, stored only after the tag verifies.</p></div>
          <div class="ex x-nonce"><h5>NONCE</h5><p>Unique encryption input. Twelve random bytes per packet; reusing a nonce under the same key would leak plaintext XORs and allow forgeries.</p></div>
          <div class="ex x-ct"><h5>CIPHERTEXT</h5><p>Confidentiality. ChaCha20 keystream XOR plaintext: same length as the message, unreadable without the session key.</p></div>
          <div class="ex x-tag"><h5>AUTH TAG</h5><p>Integrity and authenticity. Poly1305 over ciphertext and AAD. A flipped bit, wrong key or rewritten seq makes it fail (rc −2).</p></div>
          <div class="ex x-aad"><h5>AAD</h5><p>Authenticated metadata. The seq travels in clear so it can be checked early, yet it is covered by the tag and cannot be renumbered.</p></div>
        </div>
      </section>`;
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
    if (key === this.rendered) return;          // nothing new: keep scroll position
    this.rendered = key;
    $('#pi-count').textContent = `${store.packets.length} captured`;
    $('#pi-list').innerHTML = list();
    $('#pi-detail').innerHTML = detail(store.packets.find((p) => p.id === selected));
  },
};
