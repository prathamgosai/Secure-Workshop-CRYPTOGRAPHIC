// Workspace models for the 21 live stages: which cryptographic artifacts a
// stage produced, how they relate, and which gate decided. Every field is
// read from the stage's real responses (d = what execute() returned,
// e = what evaluate() concluded). Keys and passphrases are never available
// here; they appear only as REDACTED artifacts with a one-way fingerprint
// when the engine provides one.

const evTs = (r) => r?.events?.[0]?.ts;
const seqTxt = (s) => (s === '18446744073709551615' ? '2⁶⁴−1' : String(s ?? '—'));
const hexShort = (h, n = 4) => (h ? `${h.slice(0, n * 2)}…${h.slice(-n * 2)}` : '');

function packetArt(id, p, r, { label, status, tone = 'info', source, deps = [], property } = {}) {
  if (!p) return null;
  return {
    id, type: 'PACKET', label: label || `Packet #${seqTxt(p.seq)}`, tone, status: status || `${p.length} B`,
    value: `seq ${seqTxt(p.seq)} · ${p.length} B`, fp: `tag ${hexShort(p.tag_hex)}`, source, created: evTs(r),
    algo: 'ChaCha20-Poly1305-IETF, AAD = seq', deps, property: property || 'Confidentiality + integrity',
    extra: [['seq (AAD)', p.seq_hex || ''], ['nonce', p.nonce_hex || ''], ['ciphertext', p.ct_hex ? `${p.ct_len} B ${hexShort(p.ct_hex, 6)}` : ''], ['tag', p.tag_hex || ''], ['modified byte', p.modified >= 0 ? `offset ${p.modified}` : 'none']],
  };
}

const ok = (b) => b === true;

export const SCENES = {
  1: (d, e) => ({
    artifacts: [],
    scene: {
      kind: 'topology',
      links: ['HTTP JSON · localhost only', 'stdin/stdout JSON lines · WSL'],
      zones: [
        { boundary: 'BROWSER BOUNDARY', name: 'Dashboard', sub: 'visualisation only — no keys', ok: e.checks[4].ok, detail: e.checks[4].value },
        { boundary: 'NODE BOUNDARY', name: 'Node bridge', sub: 'whitelists every command', ok: e.checks[0].ok, detail: e.checks[0].value },
        { boundary: 'CRYPTOGRAPHIC AUTHORITY', name: 'sc_engine · C / libsodium', sub: 'all keys live here', ok: e.checks[1].ok && e.checks[2].ok, detail: e.checks[2].value },
      ],
    },
  }),

  2: (d) => {
    const files = d.vault.files || [];
    const f = (p) => files.find((x) => x.path === p);
    const sk = f('keys/server_sk.bin'), pk = f('keys/server_pk.bin'), xs = f('keys/server_kx_sk.bin'), xp = f('keys/server_kx_pk.bin');
    const src = './keygen + vault scan';
    const arts = [
      pk && { id: 'id-pk', type: 'PUBLIC KEY', label: 'Ed25519 identity (public)', tone: 'info', status: `GENERATED · ${pk.mode}`, fp: sk?.fingerprint, source: src, created: evTs(d.vault), algo: 'Ed25519', property: 'Server identity others can pin', extra: [['file', pk.path], ['size', `${pk.expected_size} B`]] },
      sk && { id: 'id-sk', type: 'PRIVATE KEY', label: 'Ed25519 identity (secret)', tone: sk.mode_ok ? 'ok' : 'bad', status: `PROTECTED · ${sk.mode}`, redacted: true, source: src, created: evTs(d.vault), algo: 'Ed25519', deps: ['keygen'], property: 'Only the server can sign handshakes', extra: [['file', sk.path], ['pair matches public key', sk.pair_ok ? 'yes' : 'NO'], ['mode ok', sk.mode_ok ? 'yes (0600)' : 'NO']] },
      xp && { id: 'kx-pk', type: 'PUBLIC KEY', label: 'X25519 static (public)', tone: 'info', status: `GENERATED · ${xp.mode}`, fp: xs?.fingerprint, source: src, algo: 'X25519', extra: [['file', xp.path]] },
      xs && { id: 'kx-sk', type: 'PRIVATE KEY', label: 'X25519 static (secret)', tone: xs.mode_ok ? 'ok' : 'bad', status: `PROTECTED · ${xs.mode}`, redacted: true, source: src, algo: 'X25519', extra: [['file', xs.path]] },
    ].filter(Boolean);
    return { artifacts: arts, focus: 'id-pk', scene: { kind: 'chain', nodes: [
      { op: { label: './keygen', note: `exit ${d.keygen.code}` } },
      ...arts.map((a) => ({ art: a.id })),
      { gate: { label: 'PERMISSIONS', ok: d.vault.permissions_ok === true, word: d.vault.permissions_ok ? 'PROTECTED' : 'NOT AS EXPECTED', note: '0600 private · 0644 public' } },
    ] } };
  },

  3: (d) => {
    const h = d.hs;
    const arts = [
      { id: 'c-eph', type: 'PUBLIC KEY', label: 'Client ephemeral', tone: 'info', status: 'GENERATED', fp: h.client_pk_fp, source: 'hs begin', created: evTs(h), algo: 'X25519 (crypto_kx_keypair)', property: 'Fresh keys per session', extra: [['public key', h.client_pk || '']] },
      { id: 'c-eph-sk', type: 'PRIVATE KEY', label: 'Client ephemeral secret', tone: 'ok', status: 'IN C MEMORY', redacted: true, source: 'hs begin', algo: 'X25519', property: 'Wiped after derivation (state 04)' },
      { id: 's-eph', type: 'PUBLIC KEY', label: 'Server ephemeral', tone: 'info', status: 'GENERATED', fp: h.server_pk_fp, source: 'hs begin', created: evTs(h), algo: 'X25519 (crypto_kx_keypair)', extra: [['public key', h.server_pk || '']] },
      { id: 's-eph-sk', type: 'PRIVATE KEY', label: 'Server ephemeral secret', tone: 'ok', status: 'IN C MEMORY', redacted: true, source: 'hs begin', algo: 'X25519' },
    ];
    return { artifacts: arts, focus: 'c-eph', scene: { kind: 'lanes', client: ['c-eph-sk'], server: ['s-eph-sk'], clientSub: 'state INIT', serverSub: 'state INIT',
      flows: [{ from: 'client', to: 'server', label: 'client ephemeral public key', art: 'c-eph' }, { from: 'server', to: 'client', label: 'server ephemeral public key', art: 's-eph' }],
      gate: { label: 'STATE MACHINE', ok: d.probe.ok === false, word: d.probe.ok === false ? 'seal() REFUSED IN INIT' : 'seal() ALLOWED', note: d.probe.error || '' } } };
  },

  4: (d) => {
    const fp = d.fps || {};
    const mk = (id, label, f, side, pair) => ({ id, type: 'SESSION KEY', label, tone: 'ok', status: 'DERIVED', redacted: true, fp: f, source: 'hs derive', created: evTs(d.hs),
      algo: 'crypto_kx (X25519 + BLAKE2b-512)', deps: ['client ephemeral', 'server ephemeral'], property: `Directional key; must equal ${pair}`, extra: [['side', side]] });
    const arts = [
      { id: 'shared', type: 'SHARED SECRET', label: 'X25519 shared point', tone: 'ok', status: 'DERIVED · NEVER EXPORTED', redacted: true, source: 'hs derive (inside crypto_kx)', algo: 'X25519 ECDH', property: 'Both sides compute it; an eavesdropper cannot', deps: ['ephemeral secrets'] },
      mk('ctx', 'client tx', fp.client_tx, 'client', 'server rx'), mk('crx', 'client rx', fp.client_rx, 'client', 'server tx'),
      mk('srx', 'server rx', fp.server_rx, 'server', 'client tx'), mk('stx', 'server tx', fp.server_tx, 'server', 'client rx'),
    ];
    return { artifacts: arts, focus: 'ctx', scene: { kind: 'lanes', client: ['ctx', 'crx'], server: ['srx', 'stx'], wireTitle: 'NOTHING SECRET CROSSES THE WIRE',
      flows: [{ from: 'client', to: 'server', label: 'derived independently on both sides', art: 'shared', tone: 'ok' }],
      gate: { label: 'KEY AGREEMENT', ok: ok(d.hs.complementary) && ok(d.hs.directional), word: d.hs.complementary ? 'TX = peer RX · TX ≠ RX' : 'MISMATCH', note: d.hs.ephemeral_secrets_wiped ? 'ephemeral secrets wiped' : '' } } };
  },

  5: (d) => {
    const h = d.hs;
    const arts = [
      { id: 'pin', type: 'PUBLIC KEY', label: 'Pinned server identity', tone: 'info', status: 'PINNED', fp: h.identity_fp, source: 'keys/server_pk.bin', algo: 'Ed25519', property: 'Who the client expects' },
      { id: 'sig', type: 'SIGNATURE', label: 'Transcript signature', tone: h.signature === 1 ? 'ok' : 'bad', status: h.signature === 1 ? 'VERIFIED' : 'INVALID', value: h.transcript, source: 'hs auth', created: evTs(h), algo: 'Ed25519 detached signature', deps: ['server identity secret', 'both ephemeral public keys'], property: 'Binds this key exchange to the real server' },
      { id: 'idsk', type: 'PRIVATE KEY', label: 'Server identity secret', tone: 'ok', status: 'USED IN C · WIPED', redacted: true, source: 'keys/server_sk.bin', algo: 'Ed25519' },
    ];
    return { artifacts: arts, focus: 'sig', scene: { kind: 'lanes', server: ['idsk'], client: ['pin'], clientSub: 'verifies', serverSub: 'signs',
      flows: [{ from: 'server', to: 'client', label: 'signature over SC-HANDSHAKE-v1 ‖ server_eph ‖ client_eph', art: 'sig', tone: h.signature === 1 ? 'ok' : 'bad' }],
      gate: { label: 'ED25519 VERIFY', ok: h.signature === 1, word: h.signature === 1 ? 'AUTHENTICATED' : 'REJECTED', note: `rc ${h.rc}` } } };
  },

  6: (d) => {
    const r = d.hs.readiness || {};
    return { artifacts: [], scene: { kind: 'chain', nodes: [
      { gate: { label: 'KEY MATERIAL', ok: !!r.session_keys_present, word: r.session_keys_present ? 'AVAILABLE' : 'MISSING' } },
      { gate: { label: 'KEYS AGREE', ok: !!r.keys_complementary, word: r.keys_complementary ? 'YES' : 'NO' } },
      { gate: { label: 'EPHEMERAL SECRETS', ok: !!r.ephemeral_secrets_wiped, word: r.ephemeral_secrets_wiped ? 'WIPED' : 'PRESENT' } },
      { gate: { label: 'AUTHENTICATION', ok: !!r.authenticated, word: r.authenticated ? 'VALID' : 'MISSING' } },
      { gate: { label: 'CHANNEL', ok: d.hs.state_after === 'SECURE', word: `${d.hs.state_before} → ${d.hs.state_after}`, note: `epoch ${d.hs.session?.epoch ?? '—'} · next_seq ${d.hs.session?.next_seq ?? '—'}` } },
    ] } };
  },

  7: (d) => {
    const r = d.r, p = r.packet;
    if (!r.ok) return { artifacts: [], scene: { kind: 'board', items: [{ label: 'seal()', ok: false, note: r.error }] } };
    const arts = [
      { id: 'pt', type: 'PLAINTEXT', label: 'Demo message', tone: 'info', status: `${r.plaintext_len} B · CLIENT ONLY`, value: `“${d.text}”`, source: 'typed by the presenter', property: 'What must stay confidential' },
      { id: 'k', type: 'SESSION KEY', label: 'client tx', tone: 'ok', status: `EPOCH ${r.epoch}`, redacted: true, fp: r.session?.key_fingerprints?.client_tx, source: 'state 04', algo: '32 B ChaCha20-Poly1305 key' },
      packetArt('pkt', p, r, { label: `Packet #${p.seq}`, status: `SEALED · ${p.length} B`, tone: 'ok', source: 'seal', deps: ['plaintext', 'client tx key', `seq ${p.seq} as AAD`, 'random 96-bit nonce'] }),
    ];
    return { artifacts: arts, focus: 'pkt', scene: { kind: 'chain', nodes: [
      { art: 'pt' }, { art: 'k' },
      { op: { label: 'AEAD ENCRYPT', note: `seq ${p.seq} · nonce ${hexShort(p.nonce_hex, 3)} · ${r.elapsed_ms?.toFixed?.(3) ?? '?'} ms in C` } },
      { art: 'pkt' },
      { gate: { label: 'ON THE WIRE', ok: null, word: 'HELD · NOT DELIVERED', note: 'the next states follow this exact packet' } },
    ] } };
  },

  8: (d) => {
    const p = d.r.packet, c = d.r.checks || {};
    if (!p) return { artifacts: [], scene: { kind: 'board', items: [{ label: 'inspect', ok: false, note: d.r.error }] } };
    const arts = [packetArt('pkt', p, d.r, { label: `Packet #${p.seq} (as seen on the wire)`, status: 'INSPECTED · READ-ONLY', source: 'inspect' })];
    return { artifacts: arts, focus: 'pkt', scene: { kind: 'lanes', client: [], server: [], wireTitle: 'WHAT AN EAVESDROPPER SEES',
      flows: [{ from: 'client', to: 'server', label: `packet #${p.seq} held in transit`, art: 'pkt' }],
      gate: { label: 'STRUCTURE', ok: !!(c.length_ok && c.plaintext_not_visible), word: c.plaintext_not_visible ? 'NO PLAINTEXT VISIBLE' : 'PLAINTEXT VISIBLE', note: `${p.length} B = 20 header + ${p.ct_len} ct + 16 tag` } } };
  },

  9: (d) => {
    const st = d.st;
    if (!st) return { artifacts: [], scene: { kind: 'board', items: [{ label: 'deliver', ok: false, note: d.r.error }] } };
    const arts = [
      packetArt('pkt', st.packet, d.r, { label: `Packet #${st.packet.seq}`, status: st.verdict, tone: st.rc === 0 ? 'ok' : 'bad', source: 'deliver' }),
      st.plaintext !== undefined && { id: 'out', type: 'PLAINTEXT', label: 'Released by the server', tone: 'ok', status: st.plaintext_matches ? 'MATCHES SEALED TEXT' : 'MISMATCH', value: `“${st.plaintext}”`, source: 'unseal() output', created: evTs(d.r), deps: ['tag verified', 'replay window passed'], property: 'Authenticated decryption' },
    ].filter(Boolean);
    return { artifacts: arts, focus: 'out', scene: { kind: 'lanes', client: [], server: st.plaintext !== undefined ? ['out'] : [],
      flows: [{ from: 'client', to: 'server', label: 'delivered to unseal()', art: 'pkt', tone: st.rc === 0 ? 'ok' : 'bad', verdict: `${st.verdict} · rc ${st.rc}` }],
      gate: { label: 'POLY1305 + REPLAY WINDOW', ok: st.rc === 0, word: st.rc === 0 ? 'AUTHENTICATED' : st.verdict, note: `last_seq ${st.last_seq_before} → ${st.last_seq_after}` } } };
  },

  ...Object.fromEntries([10, 11, 12, 13, 14].map((n) => [n, attackScene])),

  15: (d) => {
    const r = d.r;
    const arts = [
      { id: 'pw', type: 'PASSPHRASE', label: 'Test passphrase', tone: 'ok', status: 'INSIDE C ONLY', redacted: true, source: 'compiled-in test value', property: 'Never sent to the browser' },
      { id: 'wk', type: 'WRAPPING KEY', label: 'Argon2id output', tone: 'ok', status: 'DERIVED · WIPED', redacted: true, source: 'wrap correct', created: evTs(r), algo: `Argon2id v1.3 · ${r.memlimit_mib} MiB · ops ${r.opslimit}`, deps: ['passphrase', `salt ${hexShort(r.salt_hex)}`], extra: [['time', `${Math.round(r.wrap_ms || 0)} ms`]] },
      { id: 'wf', type: 'WRAPPED KEY', label: 'keys/server_sk.wrapped', tone: r.file_mode === '0600' ? 'ok' : 'bad', status: `${r.file_size} B · ${r.file_mode}`, fp: `salt ${hexShort(r.salt_hex)}`, source: 'wrap correct', created: evTs(r), algo: 'crypto_secretbox (XSalsa20-Poly1305)', deps: ['wrapping key', 'Ed25519 secret key'], property: 'Key at rest is useless without the passphrase', extra: [['salt', r.salt_hex || ''], ['nonce', r.nonce_hex || '']] },
    ];
    return { artifacts: arts, focus: 'wf', scene: { kind: 'chain', nodes: [
      { art: 'pw' }, { op: { label: 'ARGON2ID', note: `${r.memlimit_mib} MiB · ${Math.round(r.wrap_ms || 0)} ms` } }, { art: 'wk' }, { op: { label: 'SECRETBOX', note: 'encrypt Ed25519 secret' } }, { art: 'wf' },
      { gate: { label: 'ROUND TRIP', ok: !!(r.mac_verified && r.unwrapped), word: r.unwrapped ? 'KEY RECOVERED (compared in C)' : 'FAILED' } },
    ] } };
  },

  16: (d) => {
    const r = d.r;
    const arts = [
      { id: 'wf', type: 'WRAPPED KEY', label: 'keys/server_sk.wrapped', tone: 'info', status: 'FROM STATE 15', fp: `salt ${hexShort(r.salt_hex)}`, source: 'unwrap wrong', algo: 'crypto_secretbox' },
      { id: 'bad', type: 'PASSPHRASE', label: 'Wrong passphrase', tone: 'bad', status: 'INSIDE C ONLY', redacted: true, source: 'compiled-in test value' },
      { id: 'out', type: 'OUTPUT BUFFER', label: 'Unwrap output', tone: r.output_zeroed ? 'ok' : 'bad', status: r.output_zeroed ? 'ZEROED' : 'NOT ZEROED', value: r.output_zeroed ? '64 × 0x00 (was 0xA5 pattern)' : '', source: 'unwrap wrong', created: evTs(r), property: 'No partial key material leaks' },
    ];
    return { artifacts: arts, focus: 'out', scene: { kind: 'chain', nodes: [
      { art: 'wf' }, { art: 'bad' }, { op: { label: 'ARGON2ID', note: `${Math.round(r.unwrap_ms || 0)} ms` } },
      { gate: { label: 'SECRETBOX MAC', ok: r.mac_verified === false ? false : null, word: r.mac_verified === false ? 'AUTHENTICATION FAILED' : 'VERIFIED', note: `rc ${r.rc}` } },
      { art: 'out' },
    ] } };
  },

  17: (d) => {
    const p = d.r.plain || {};
    const arts = [
      { id: 'sent', type: 'PLAINTEXT', label: 'Client sealed', tone: 'info', status: 'SENT', value: p.sent_text ? `“${p.sent_text}”` : '', source: 'mitm plain', created: evTs(d.r), property: 'What the client meant to send' },
      { id: 'read', type: 'INTERCEPTED', label: 'Mallory decrypted', tone: p.mallory_read ? 'bad' : 'ok', status: p.mallory_read ? 'CONFIDENTIALITY BROKEN' : 'NOT READ', value: p.read_text ? `“${p.read_text}”` : '', source: 'mitm plain', created: evTs(d.r), property: 'Plain crypto_kx has no identity' },
      { id: 'forge', type: 'FORGED', label: 'Mallory rewrote', tone: p.mallory_forged ? 'bad' : 'ok', status: p.mallory_forged ? 'ACCEPTED BY SERVER' : 'REJECTED', value: p.forged_text ? `“${p.forged_text}”` : '', source: 'mitm plain', created: evTs(d.r) },
    ];
    return { artifacts: arts, focus: 'forge', scene: { kind: 'lanes', mallory: true, client: ['sent'], server: [], mallorySub: p.keys_substituted ? 'swapped both public keys' : 'key swap failed',
      flows: [{ from: 'client', to: 'mallory', label: 'client → “server” (really Mallory)', art: 'read', tone: 'bad' }, { from: 'mallory', to: 'server', label: 'Mallory → server', art: 'forge', tone: 'bad' }],
      gate: { label: 'NO AUTHENTICATION', ok: d.r.vulnerability_shown ? false : null, word: d.r.vulnerability_shown ? 'MITM SUCCEEDED (documented limitation)' : 'not reproduced' } } };
  },

  18: (d) => {
    const s = d.r.signed || {};
    const g = (label, okv) => ({ gate: { label, ok: okv ? false : null, word: okv ? 'REJECTED' : 'NOT BLOCKED' } });
    return { artifacts: [], scene: { kind: 'chain', nodes: [
      { gate: { label: 'HONEST SESSION', ok: !!s.honest_ok, word: s.honest_ok ? 'IDENTITY VERIFIED' : 'FAILED', note: s.task1_identity ? 'pinned: stage-02 identity' : 'temporary identity' } },
      g('MALLORY SWAPS SERVER KEY', s.blocked_key_swap),
      g('MALLORY SIGNS WITH OWN KEY', s.blocked_own_signature),
      g('SIGNATURE REPLAYED', s.blocked_replayed_signature),
      { gate: { label: 'SESSION', ok: !!d.r.extension_blocks_mitm, word: d.r.extension_blocks_mitm ? 'PROTECTED' : 'EXPOSED' } },
    ] } };
  },

  19: (d) => {
    const b = d.before || {}, a = d.after || {};
    const st = d.del?.steps?.[0];
    const arts = [
      { id: 'old', type: 'SESSION KEY', label: `client tx · epoch ${d.epochBefore}`, tone: 'muted', status: 'OVERWRITTEN', redacted: true, fp: b.client_tx, source: 'before rekey', algo: 'ChaCha20-Poly1305 key' },
      { id: 'new', type: 'SESSION KEY', label: `client tx · epoch ${d.rk.session?.epoch}`, tone: 'ok', status: 'ACTIVE', redacted: true, fp: a.client_tx, source: 'rekey', created: evTs(d.rk), algo: 'crypto_kdf_derive_from_key("SCREKEY1")', deps: [`epoch ${d.epochBefore} key`], property: 'Old traffic stays safe if a later key leaks' },
      st && packetArt('probe', st.packet, d.del, { label: `Packet #${st.packet.seq} · new epoch`, status: st.verdict, tone: st.rc === 0 ? 'ok' : 'bad', source: 'seal + deliver' }),
    ].filter(Boolean);
    return { artifacts: arts, focus: 'new', scene: { kind: 'chain', nodes: [
      { art: 'old' }, { op: { label: 'crypto_kdf', note: 'all four keys replaced in place' } }, { art: 'new' }, ...(st ? [{ art: 'probe' }] : []),
      { gate: { label: 'NEW EPOCH', ok: st?.rc === 0, word: st?.rc === 0 ? 'TRAFFIC ACCEPTED' : 'NOT VERIFIED', note: a.client_tx === a.server_rx ? 'sides agree' : 'SIDES DISAGREE' } },
    ] } };
  },

  20: (d, e) => ({ artifacts: [], scene: { kind: 'board',
    items: [...e.cats.map((c) => ({ label: c.name, ok: c.n ? c.pass : undefined, note: c.n ? `${c.tests.filter((t) => t.ok).length}/${c.n} tests` : 'not covered' })),
      e.osAvail ? { label: 'OPENSSL CBC vs AEAD', ok: e.checks.at(-1).ok, note: `CBC tamper ${d.os.cbc.tamper_undetected ? 'undetected' : 'detected'} · AEAD ${d.os.aead_tamper_rejected ? 'rejects' : '—'}` } : { label: 'OPENSSL', ok: undefined, note: 'NOT AVAILABLE' }],
    footer: `${e.produced}` } }),

  21: (d, e) => ({ artifacts: [], scene: { kind: 'board',
    items: e.props.map((p) => ({ label: p.name, ok: p.ok, note: p.ok ? 'live evidence' : `${p.missing.length ? `not run ${p.missing.join(',')}` : ''} ${p.failed.length ? `failed ${p.failed.join(',')}` : ''}` })),
    footer: `<div class="final-word ${e.ok ? 'ok' : 'bad'}">
      <div class="final-word-body">
        <span class="final-word-tag">${e.ok ? 'ALL INVARIANTS SATISFIED' : 'VERIFICATION INCOMPLETE'}</span>
        <b class="final-word-title">${e.ok ? 'SECURE CHANNEL VERIFIED' : 'NOT VERIFIED'}</b>
        <span class="final-word-sub">${e.ok ? 'All 16 cryptographic properties backed by live evidence from one pass' : 'One or more required cryptographic states failed or were not run'}</span>
      </div>
      <div class="final-word-badge">${e.ok ? '✓ PASS' : '✕ FAIL'}</div>
    </div>` } }),
};

function attackScene(d) {
  const r = d.r, a = r.attack;
  if (!r.ok || !a) return { artifacts: [], scene: { kind: 'board', items: [{ label: 'attack', ok: false, note: r.error }] } };
  const steps = r.steps || [];
  const arts = steps.map((s, i) => packetArt(`s${i}`, s.packet, r, {
    label: s.label, status: `${s.verdict} · rc ${s.rc}`, tone: s.rc === 0 ? (s.packet.role === 'client' ? 'ok' : 'bad') : 'rej', source: `intercept ${a.id}`,
    property: s.packet.role === 'attacker' ? 'Attacker input — must be rejected' : 'Genuine traffic — must still work',
  }));
  const orig = a.source === 'next' ? null : d.held && packetArt('orig', d.held, null, { label: `Original packet #${d.held.seq}`, status: 'FROM STATE 07', source: 'seal (state 07)' });
  if (orig) arts.unshift(orig);
  return { artifacts: arts, focus: arts.find((x) => x.id.startsWith('s'))?.id, scene: { kind: 'lanes', mallory: true, client: orig ? ['orig'] : [], server: [], mallorySub: a.network,
    flows: steps.map((s, i) => ({ from: s.packet.role === 'attacker' ? 'mallory' : 'client', to: 'server', label: s.label, art: `s${i}`, tone: s.rc === 0 ? 'ok' : 'bad', verdict: s.verdict })),
    gate: { label: a.verifier, ok: a.result === 'BLOCKED' ? false : true, word: a.result === 'BLOCKED' ? `${a.verdict} · REJECTED` : 'ACCEPTED', note: a.pass ? 'behaved as expected' : 'UNEXPECTED' } } };
}

export const SHORT = {
  1: 'SYSTEM ONLINE', 2: 'IDENTITY', 3: 'SESSION INIT', 4: 'KEY EXCHANGE', 5: 'AUTHENTICATION', 6: 'SECURE STATE', 7: 'ENCRYPTION',
  8: 'PACKET INSPECTION', 9: 'DECRYPTION', 10: 'TAMPER ATTACK', 11: 'REPLAY ATTACK', 12: 'AAD ATTACK', 13: 'SEQUENCE ATTACK', 14: 'WRONG KEY',
  15: 'KEY WRAPPING', 16: 'WRONG PASSPHRASE', 17: 'MITM (PLAIN)', 18: 'MITM DEFENSE', 19: 'RE-KEYING', 20: 'TEST SUITES', 21: 'FINAL VERDICT',
};
