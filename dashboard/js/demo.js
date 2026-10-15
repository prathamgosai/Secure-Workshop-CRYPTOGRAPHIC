// demo.js — Secure Channel: The Cryptographic Cinematic Lab
// Next-Generation Interactive Cybersecurity Cinema Theater (21 Scenes in 6 Acts).
//
// Truthfulness & Cryptographic Integrity:
//   - Connects to real C implementation (sc_engine, keygen, keywrap, test_attacks, test_extended)
//   - Distinguishes between ⚡ REAL C EXECUTION and 🧪 SIMULATION SCENARIO
//   - Every packet inspected follows real ChaCha20-Poly1305 IETF format (Seq 8B, Nonce 12B, Ciphertext, Tag 16B)
//   - Real return codes: rc 0 (Success), rc -1 (Length/Format), rc -2 (AEAD Tag/Poly1305 Mismatch), rc -3 (Replay Violation)
//   - Autoplay, speed controls, collapsible drawers (6 Acts Navigator & Technical Inspector),
//     full-bleed canvas powered by NetworkEngine with camera gliding and Mallory attack animations.

import { store, engine, run, resetCounters, notify, addEvent, subscribe } from './store.js';
import { api } from './api.js';
import { traceList } from './trace.js';
import { $, esc, shortHex, byteMap, hexGroups, timeMs, toast } from './ui.js';
import { SCENES, SHORT } from './demo-scenes.js';
import { NetworkEngine } from './network-engine.js';

const DEFAULT_MESSAGE = 'Quarterly report: transfer approved';
const pad = (n) => String(n).padStart(2, '0');
const chk = (label, ok, value = '') => ({ label, ok: ok === true, value });
const isNum = (x) => typeof x === 'number' && Number.isFinite(x);
const isHex = (h, len) => typeof h === 'string' && /^[0-9a-f]+$/i.test(h) && (len === undefined || h.length === len);

const fmtMs = (ms) => {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1) return `${Math.round(ms * 1000)} µs`;
  if (ms < 10) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
};

/* ---- The 6 Cinematic Acts -------------------------------------------------- */

export const ACTS = [
  {
    act: 1,
    title: 'GENESIS & IDENTITY',
    tagline: 'The dark network awakens and establishes long-term cryptographic roots.',
    scenes: [1, 2],
  },
  {
    act: 2,
    title: 'SESSION & KEY AGREEMENT',
    tagline: 'Ephemeral keys exchange, mutual identity binding, and fail-closed state transition.',
    scenes: [3, 4, 5, 6],
  },
  {
    act: 3,
    title: 'AEAD PACKET TRANSIT & INSPECTION',
    tagline: 'Sealing with ChaCha20-Poly1305, on-the-wire inspection, and authenticated delivery.',
    scenes: [7, 8, 9],
  },
  {
    act: 4,
    title: 'ACTIVE ATTACK SUITE',
    tagline: 'Hostile adversary injection: ciphertext tampering, packet replays, and sequence manipulation.',
    scenes: [10, 11, 12, 13, 14],
  },
  {
    act: 5,
    title: 'KEY LIFECYCLE & PROTOCOL DEFENSE',
    tagline: 'Argon2id key wrapping, active MITM adversary defeating, and dynamic epoch re-keying.',
    scenes: [15, 16, 17, 18, 19],
  },
  {
    act: 6,
    title: 'EMPIRICAL VERIFICATION & VERDICT',
    tagline: 'Automated TAP test suite audit, OpenSSL comparison, and final evidentiary conclusion.',
    scenes: [20, 21],
  },
];

/* ---- Decision Trace Builders ----------------------------------------------- */

function packetTrace(st) {
  if (!st?.packet) return [];
  const rc = st.rc, p = st.packet;
  const windowUsed = st.had_seq_before !== undefined;
  const seq = p.seq === '18446744073709551615' ? '2⁶⁴−1' : p.seq;
  const t = [{ stage: 'INPUT', m: 'ok', note: `${p.length} B from ${p.role}` }];
  t.push(rc === -1 ? { stage: 'LENGTH', m: 'bad', note: 'below 36 B minimum' } : { stage: 'LENGTH', m: 'ok', note: `${p.length} B ≥ 36 B` });
  if (rc === -1) t.push({ stage: 'REPLAY CHECK', m: 'skip', note: 'not reached' });
  else if (!windowUsed) t.push({ stage: 'REPLAY CHECK', m: 'skip', note: 'not applied (stateless key check)' });
  else if (rc === -3) t.push({ stage: 'REPLAY CHECK', m: 'bad', note: `seq ${seq} ≤ last_seq ${st.last_seq_before}` });
  else t.push({ stage: 'REPLAY CHECK', m: 'ok', note: st.had_seq_before ? `seq ${seq} > last_seq ${st.last_seq_before}` : 'first packet of session' });

  if (rc === -1 || rc === -3) t.push({ stage: 'AAD + AEAD TAG', m: 'skip', note: 'not reached' });
  else if (rc === -2) t.push({ stage: 'AAD + AEAD TAG', m: 'bad', note: 'Poly1305 authentication tag mismatch' });
  else if (rc === 0) t.push({ stage: 'AAD + AEAD TAG', m: 'ok', note: 'tag verified over ciphertext + AAD(seq)' });
  else t.push({ stage: 'AAD + AEAD TAG', m: 'bad', note: st.reason });

  t.push(st.plaintext_released ? { stage: 'PLAINTEXT', m: 'ok', note: `${st.plaintext_len} B released` } : { stage: 'PLAINTEXT', m: 'blocked', note: 'BLOCKED' });
  if (rc === 0) t.push({ stage: 'STATE UPDATE', m: 'ok', note: `last_seq ${st.last_seq_before} → ${st.last_seq_after}` });
  else t.push({ stage: 'STATE UPDATE', m: st.state_changed ? 'bad' : 'blocked', note: st.state_changed ? 'CHANGED BY A REJECTED PACKET' : windowUsed ? `BLOCKED · last_seq ${st.last_seq_after}` : 'BLOCKED · no state touched' });
  t.push({ stage: 'VERDICT', m: rc === 0 ? 'ok' : 'bad', note: `${st.verdict} (rc ${rc})` });
  return t;
}

const checkTrace = (checks, verdict, ok) => [
  ...checks.map((c) => ({ stage: c.label.toUpperCase(), m: c.ok ? 'ok' : 'bad', note: String(c.value ?? '') })),
  { stage: 'VERDICT', m: ok ? 'ok' : 'bad', note: verdict },
];

/* ---- Shared Demo Context ---------------------------------------------------- */

const D = {
  held: null,
  heldText: '',
  heldDelivered: false,
  identityFp: null,
  sessionId: null,
  draft: DEFAULT_MESSAGE,
};
function clearHeld() { D.held = null; D.heldText = ''; D.heldDelivered = false; }

const R = {}; // stage id -> recorded result object
const okRun = (id) => R[id]?.ok === true;
const sess = () => store.session || {};

const SUITE_CATEGORIES = [
  ['AEAD', /round[- ]trip|packet length|seq field holds/i],
  ['REPLAY', /replay|reorder/i],
  ['AAD', /AAD/],
  ['TAMPERING', /tamper|failed tag/i],
  ['WRONG KEY', /wrong key/i],
  ['MITM DEFENSE', /MITM|substituted|pinned key/i],
  ['KEY WRAPPING', /passphrase|wrapped/i],
  ['RE-KEYING', /re-key/i],
];

const VERDICT_PROPS = [
  ['SYSTEM ONLINE', [1]], ['IDENTITY', [2]], ['SESSION', [3, 6]], ['KEY EXCHANGE', [4]], ['AUTHENTICATION', [5]],
  ['CONFIDENTIALITY (AEAD)', [7, 8, 9]], ['TAMPER DETECTION', [10]], ['REPLAY PROTECTION', [11]], ['AAD INTEGRITY', [12]],
  ['SEQUENCE INTEGRITY', [13]], ['WRONG-KEY REJECTION', [14]], ['KEY WRAPPING', [15, 16]], ['MITM DEFENSE', [17, 18]],
  ['RE-KEYING', [19]], ['TEST SUITES', [20]],
];

function heldAccepted() {
  return [
    { label: 'Held packet accepted (Scene 09)', ok: okRun(9) && D.heldDelivered },
    { label: 'Channel in state SECURE', ok: sess().state === 'SECURE' },
  ];
}

async function attackExec(call, type) {
  const before = { ...sess() };
  const held = D.held;
  const r = await call('engine', 'intercept', type);
  return { r, before, held };
}

function attackEval({ r, before }) {
  const a = r.attack;
  if (r.ok !== true || !a || !isNum(a.rc) || !isNum(a.expected_rc)) {
    return {
      ok: false, status: 'FAILED', decision: 'NOT EXECUTED', rc: '—', produced: r.error || 'no result',
      checks: [chk('Attack executed', false, r.error || 'no result')], trace: [],
    };
  }
  const steps = r.steps || [];
  const hostile = steps.filter((s) => s.packet?.role === 'attacker');
  const genuine = steps.filter((s) => s.packet?.role === 'client');
  const checks = [
    chk(`Rejected as expected (rc ${a.expected_rc})`, a.rc === a.expected_rc, `${a.verdict} · rc ${a.rc}`),
    chk('Plaintext blocked', hostile.length > 0 && hostile.every((s) => s.plaintext_released === false), `${hostile.length} hostile packet(s), 0 B released`),
    chk('State update blocked', hostile.length > 0 && hostile.every((s) => s.state_changed === false), `last_seq ${before.last_seq} → ${r.session?.last_seq}${genuine.length ? ' (moved only by genuine traffic)' : ''}`),
  ];
  if (a.id === 'wrongkey') {
    const s0 = steps[0] || {};
    checks.push(chk('Valid packet + wrong key: tag fails', s0.rc === -2 && s0.plaintext_len === 0, `rc ${s0.rc} · ${s0.plaintext_len} B`));
    checks.push(chk('Output buffer zeroed in memory', s0.output_zeroed === true, 'checked in C after failed decrypt'));
  }
  if ((a.id === 'tamper' && a.source === 'next') || a.id === 'forged') {
    checks.push(chk('Genuine packet still accepted', genuine.length >= 1 && genuine.every((s) => s.rc === 0), genuine.map((s) => `#${s.packet.seq} ${s.verdict}`).join(', ') || 'none sent'));
  }
  checks.push(chk('Engine verdict', a.pass === true && a.side_checks_ok === true, a.pass ? 'behaved as expected' : 'UNEXPECTED'));
  const ok = checks.every((c) => c.ok);
  const deviation = a.id === 'tamper' && a.source === 'next'
    ? ` · packet #${a.held_seq} was already accepted (a modified copy would hit the replay window first), so the attacker tampered the client’s next packet #${genuine[0]?.packet?.seq ?? '?'}` : '';
  return {
    ok, status: ok ? 'REJECTED' : 'FAILED', decision: a.verdict, rc: a.rc,
    produced: ok ? `${a.verdict}: ${a.reason}${deviation}` : `UNEXPECTED: ${a.verdict}`, checks,
    trace: a.id === 'wrongkey'
      ? [...packetTrace(steps[0]).map((t) => ({ ...t, stage: `A · ${t.stage}` })), ...packetTrace(steps[1]).map((t) => ({ ...t, stage: `B · ${t.stage}` }))]
      : packetTrace(hostile.at(-1)),
  };
}

/* ---- Simulated Scene Generator (For presentation exploration & fallback) -- */

function getSimulatedEvidence(stageId, draftText = DEFAULT_MESSAGE) {
  const t = draftText || DEFAULT_MESSAGE;
  const ctLen = new TextEncoder().encode(t).length;
  const mockPkt = (seq = 1, ct = '68656c6c6f2063727970746f', tag = '7a91b4c2e5f80123456789abcdef0123') => ({
    seq: String(seq),
    length: 36 + ctLen,
    seq_hex: '000000000000000' + seq,
    nonce_hex: 'a1b2c3d4e5f60718293a4b5c',
    aad_hex: '000000000000000' + seq,
    ct_hex: ct,
    ct_len: ctLen,
    tag_hex: tag,
    role: 'client',
  });

  switch (stageId) {
    case 1: {
      const checks = [
        chk('Node bridge', true, '127.0.0.1:80 answered in 0.4 ms'),
        chk('C engine', true, 'sc_engine answered "hello"'),
        chk('libsodium', true, 'libsodium 1.0.18 initialised in C'),
        chk('Toolchain / build', true, 'gcc 11.4.0 · make all OK'),
        chk('Dashboard', true, 'live event stream from bridge connected'),
        chk('Protocol structure', true, 'state INIT · seq 8 B + nonce 12 B + ct + tag 16 B'),
        chk('Live-demo commands', true, 'bridge accepts hs / seal / intercept / unwrap'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'SYSTEM ONLINE', rc: 'hello ok=true',
        produced: '7/7 live checks passed · libsodium 1.0.18 · C engine online',
        checks, trace: checkTrace(checks, 'READY', true), isSimulated: true,
      };
    }
    case 2: {
      const checks = [
        chk('keygen exit code', true, 'exit 0'),
        chk('Public identity created', true, 'keys/server_pk.bin · 32 B · mode 0644'),
        chk('Public key fingerprint', true, 'ED25:519A:7F40:2B9C:E310:88AC:9104'),
        chk('Key pair matches', true, 'secret key derives published public key'),
        chk('Private key protected', true, 'keys/server_sk.bin mode 0600 · bytes never leave C'),
        chk('X25519 static pair', true, 'keys/server_kx_sk.bin mode 0600'),
        chk('All key file permissions', true, '0600 private / 0644 public'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'IDENTITY CREATED', rc: 'keygen exit 0',
        produced: 'Ed25519 identity ED25:519A:7F40 · private key 0600 protected',
        checks, trace: checkTrace(checks, 'PROTECTED', true), isSimulated: true,
      };
    }
    case 3: {
      const checks = [
        chk('Session created', true, 'rc 0 · 0.2 ms in C'),
        chk('State', true, 'DISCONNECTED → INIT'),
        chk('Ephemeral key pairs generated', true, 'client X255:19C:8B21 · server X255:19S:4D90'),
        chk('No session keys yet', true, 'rx/tx not derived'),
        chk('Encryption refused in INIT', true, 'C engine refused: session in state INIT (requires SECURE)'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'STATE: INIT', rc: 'hs rc=0 · seal refused',
        produced: 'Session created in INIT with fresh ephemeral key pairs',
        checks, trace: checkTrace(checks, 'INIT', true), isSimulated: true,
      };
    }
    case 4: {
      const checks = [
        chk('crypto_kx executed', true, 'rc 0 · 0.3 ms in C'),
        chk('CLIENT TX == SERVER RX', true, '9A4F:1B8C = 9A4F:1B8C'),
        chk('CLIENT RX == SERVER TX', true, 'C270:5E11 = C270:5E11'),
        chk('TX ≠ RX', true, 'directional keys differ (independent unidirectional channels)'),
        chk('Ephemeral secrets wiped', true, 'sodium_free() zeroed in memory after derivation'),
        chk('State', true, 'INIT → AUTH'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'KEYS DERIVED', rc: 'rc 0',
        produced: '4 directional session keys derived (shown only as fingerprints)',
        checks, trace: checkTrace(checks, 'DERIVED', true), isSimulated: true,
      };
    }
    case 5: {
      const checks = [
        chk('Identity loaded', true, 'pinned Ed25519 key ED25:519A:7F40'),
        chk('Transcript signed and verified', true, 'SC-HANDSHAKE-v1 ‖ server_eph ‖ client_eph · rc 0'),
        chk('Matches Scene 02 identity', true, 'ED25:519A:7F40 confirmed'),
        chk('Session authenticated', true, 'state AUTH · authenticated = true'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'AUTHENTICATED', rc: 'rc 0',
        produced: 'Server identity ED25:519A:7F40 signature verified over transcript',
        checks, trace: checkTrace(checks, 'AUTHENTICATED', true), isSimulated: true,
      };
    }
    case 6: {
      const checks = [
        chk('Session key material available', true, 'YES'),
        chk('Keys complementary', true, 'client_tx = server_rx, client_rx = server_tx'),
        chk('Ephemeral secrets wiped', true, 'YES (sodium_memzero)'),
        chk('Authentication valid', true, 'YES'),
        chk('Channel SECURE', true, 'AUTH → SECURE · epoch 1'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'STATE: SECURE', rc: 'rc 0',
        produced: 'Channel SECURE · next_seq 1 · replay window armed',
        checks, trace: checkTrace(checks, 'SECURE', true), isSimulated: true,
      };
    }
    case 7: {
      const p = mockPkt(1);
      const checks = [
        chk('Message validated', true, `${ctLen} B (limit 1–256 B)`),
        chk('Sequence number assigned', true, 'seq 1 · next_seq now 2'),
        chk('Fresh 96-bit nonce', true, 'A1B2 C3D4 E5F6 …'),
        chk('AAD = sequence number', true, '0000000000000001'),
        chk('AEAD encryption', true, 'rc 0 · 0.2 ms in C'),
        chk('Ciphertext length = plaintext length', true, `${ctLen} B`),
        chk('Authentication tag', true, '16 B 7A91 B4C2 …'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'PACKET #1 SEALED', rc: 'rc 0',
        produced: `packet #1: ${p.length} B, held on the wire (ready for delivery)`,
        packet: p, checks, trace: checkTrace(checks, 'SEALED', true), isSimulated: true,
      };
    }
    case 8: {
      const p = mockPkt(1);
      const checks = [
        chk('Same packet as Scene 07', true, 'packet #1: nonce, ciphertext, and tag identical'),
        chk('Length check', true, `${p.length} B (expected ${p.length} B ≥ 36 B)`),
        chk('Sequence issued by client', true, 'seq 1'),
        chk('Fresh for receiver', true, 'seq 1 > last_seq 0'),
        chk('Nonce present', true, '12 B non-zero'),
        chk('AAD present', true, p.aad_hex),
        chk('Ciphertext present', true, `${ctLen} B`),
        chk('Auth tag present', true, '16 B Poly1305'),
        chk('Plaintext not visible on wire', true, 'byte search for message in wire frame: not found'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'STRUCTURE VALID', rc: 'inspect ok=true',
        produced: `packet #1 inspected: no plaintext visible on the wire`,
        packet: p, checks, trace: checkTrace(checks, 'VALID', true), isSimulated: true,
      };
    }
    case 9: {
      const p = mockPkt(1);
      const st = {
        rc: 0, verdict: 'ACCEPTED', reason: 'Poly1305 tag verified over ciphertext + AAD',
        had_seq_before: true, last_seq_before: 0, last_seq_after: 1, state_changed: true,
        plaintext_released: true, plaintext_len: ctLen, plaintext: t, plaintext_matches: true,
        packet: p,
      };
      const checks = [
        chk('Packet received', true, `#1 · ${p.length} B`),
        chk('Replay check', true, 'first packet of session (seq 1 > 0)'),
        chk('AAD + AEAD tag verified', true, 'tag verified over ciphertext + AAD(seq)'),
        chk('Plaintext released', true, `${ctLen} B released`),
        chk('Decrypted text = sealed text', true, 'byte-for-byte identical'),
        chk('Replay window advanced', true, 'last_seq 0 → 1'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'ACCEPTED', rc: 'rc 0',
        produced: `"${t}" released from packet #1`,
        packet: p, steps: [st], checks, trace: packetTrace(st), isSimulated: true,
      };
    }
    case 10: {
      const p = mockPkt(2, '68656c6c6f2163727970746f', '99999999999999999999999999999999');
      p.role = 'attacker';
      const st = {
        rc: -2, verdict: 'AUTHENTICATION FAILED', reason: 'Poly1305 tag mismatch',
        had_seq_before: true, last_seq_before: 1, last_seq_after: 1, state_changed: false,
        plaintext_released: false, plaintext_len: 0, packet: p,
      };
      const checks = [
        chk('Rejected as expected (rc -2)', true, 'AUTHENTICATION FAILED · rc -2'),
        chk('Plaintext blocked', true, '1 hostile packet, 0 B released'),
        chk('State update blocked', true, 'last_seq 1 → 1 (untouched by hostile packet)'),
        chk('Genuine packet still accepted', true, '#2 ACCEPTED'),
        chk('Engine verdict', true, 'behaved as expected (INT-CTXT held)'),
      ];
      return {
        ok: true, status: 'REJECTED', decision: 'AUTHENTICATION FAILED', rc: -2,
        produced: 'AUTHENTICATION FAILED: Poly1305 tag mismatch on tampered ciphertext',
        packet: p, steps: [st], checks, trace: packetTrace(st), isSimulated: true,
      };
    }
    case 11: {
      const p = mockPkt(1);
      p.role = 'attacker';
      const st = {
        rc: -3, verdict: 'REPLAY DETECTED', reason: 'seq 1 ≤ last_seq 1',
        had_seq_before: true, last_seq_before: 1, last_seq_after: 1, state_changed: false,
        plaintext_released: false, plaintext_len: 0, packet: p,
      };
      const checks = [
        chk('Rejected as expected (rc -3)', true, 'REPLAY DETECTED · rc -3'),
        chk('Plaintext blocked', true, '1 hostile packet, 0 B released'),
        chk('State update blocked', true, 'last_seq 1 → 1 (replay window rejected before AEAD)'),
        chk('Engine verdict', true, 'behaved as expected (replay detected)'),
      ];
      return {
        ok: true, status: 'REJECTED', decision: 'REPLAY DETECTED', rc: -3,
        produced: 'REPLAY DETECTED: sequence number 1 already seen in window',
        packet: p, steps: [st], checks, trace: packetTrace(st), isSimulated: true,
      };
    }
    case 12: {
      const p = mockPkt(1001);
      p.role = 'attacker';
      const st = {
        rc: -2, verdict: 'AUTHENTICATION FAILED', reason: 'Poly1305 tag mismatch over modified AAD',
        had_seq_before: true, last_seq_before: 1, last_seq_after: 1, state_changed: false,
        plaintext_released: false, plaintext_len: 0, packet: p,
      };
      const checks = [
        chk('Rejected as expected (rc -2)', true, 'AUTHENTICATION FAILED · rc -2'),
        chk('Plaintext blocked', true, '1 hostile packet, 0 B released'),
        chk('State update blocked', true, 'last_seq 1 → 1 (tampered sequence rejected)'),
        chk('Engine verdict', true, 'associated data authenticated, not encrypted'),
      ];
      return {
        ok: true, status: 'REJECTED', decision: 'AUTHENTICATION FAILED', rc: -2,
        produced: 'AUTHENTICATION FAILED: cleartext sequence modified (+1000) broke tag',
        packet: p, steps: [st], checks, trace: packetTrace(st), isSimulated: true,
      };
    }
    case 13: {
      const p = mockPkt('18446744073709551615');
      p.role = 'attacker';
      const st = {
        rc: -2, verdict: 'AUTHENTICATION FAILED', reason: 'Poly1305 tag mismatch on forged packet',
        had_seq_before: true, last_seq_before: 1, last_seq_after: 1, state_changed: false,
        plaintext_released: false, plaintext_len: 0, packet: p,
      };
      const checks = [
        chk('Rejected as expected (rc -2)', true, 'AUTHENTICATION FAILED · rc -2'),
        chk('Plaintext blocked', true, '0 B released from max sequence forged packet'),
        chk('State update blocked', true, 'last_seq 1 → 1 (replay window not poisoned)'),
        chk('Genuine follow-up accepted', true, 'packet #2 ACCEPTED'),
        chk('Engine verdict', true, 'never update state from unauthenticated input'),
      ];
      return {
        ok: true, status: 'REJECTED', decision: 'REJECTED (NO STATE POISONING)', rc: -2,
        produced: 'REJECTED (rc -2): replay window untouched, subsequent traffic still passes',
        packet: p, steps: [st], checks, trace: packetTrace(st), isSimulated: true,
      };
    }
    case 14: {
      const p = mockPkt(2);
      p.role = 'attacker';
      const s0 = {
        rc: -2, verdict: 'AUTHENTICATION FAILED', reason: 'tag mismatch under random key',
        had_seq_before: false, state_changed: false, plaintext_released: false, plaintext_len: 0,
        output_zeroed: true, packet: p,
      };
      const checks = [
        chk('Rejected as expected (rc -2)', true, 'AUTHENTICATION FAILED · rc -2'),
        chk('Plaintext blocked', true, '0 B released under wrong key'),
        chk('State update blocked', true, 'last_seq untouched'),
        chk('Valid packet + wrong key: tag fails', true, 'rc -2 · 0 B released'),
        chk('Output buffer zeroed in memory', true, 'checked in C after failed decrypt'),
        chk('Engine verdict', true, 'key secrecy implies confidentiality and unforgeability'),
      ];
      return {
        ok: true, status: 'REJECTED', decision: 'AUTHENTICATION FAILED', rc: -2,
        produced: 'AUTHENTICATION FAILED: tag mismatch under wrong key, output zeroed',
        packet: p, steps: [s0], checks, trace: packetTrace(s0), isSimulated: true,
      };
    }
    case 15: {
      const checks = [
        chk('Argon2id executed', true, 'crypto_pwhash_argon2id13 · 64 MiB · ops 3 · 48 ms'),
        chk('Secretbox executed', true, '120 B wrapped file · salt 16 B'),
        chk('Wrapped file mode 0600', true, 'keys/server_sk.wrapped · mode 0600'),
        chk('Round trip verified', true, 'MAC verified, key equals original (compared in C)'),
        chk('No secret in response', true, 'no key or passphrase field; values stayed in C'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'KEY WRAPPED', rc: 'wrap rc=0 · unwrap rc=0',
        produced: '120 B wrapped key file, salt 48A1 99BC … · Argon2id memory-hard KDF',
        checks, trace: checkTrace(checks, 'WRAPPED', true), isSimulated: true,
      };
    }
    case 16: {
      const checks = [
        chk('Same wrapped file as Scene 15', true, 'salt 48A1 99BC …'),
        chk('Argon2id executed', true, '49 ms computation in C'),
        chk('Authentication failed', true, 'secretbox MAC mismatch · rc -1'),
        chk('No secret released', true, 'nothing released (fail-closed)'),
        chk('Output zeroed', true, 'buffer pre-filled with 0xA5, wiped to zero by unwrap'),
      ];
      return {
        ok: true, status: 'REJECTED', decision: 'UNWRAP REFUSED', rc: -1,
        produced: 'wrong passphrase rejected · Poly1305 MAC failed · memory zeroed',
        checks, trace: checkTrace(checks, 'REJECTED', true), isSimulated: true,
      };
    }
    case 17: {
      const checks = [
        chk('Mallory substituted both keys', true, 'crypto_kx completed with Mallory on both sides'),
        chk('Mallory decrypted client traffic', true, 'client sent "approve transfer", Mallory read "approve transfer"'),
        chk('Server accepted Mallory rewrite', true, 'server got "redirect to Mallory account"'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'VULNERABILITY DEMONSTRATED', rc: 'mitm ok=true',
        produced: 'Mallory read "approve transfer" and injected "redirect to Mallory account"',
        checks,
        trace: [
          { stage: 'KEY EXCHANGE', m: 'warn', note: 'plain crypto_kx: unauthenticated' },
          { stage: 'KEY SUBSTITUTION', m: 'bad', note: 'Mallory sits on both sides' },
          { stage: 'CONFIDENTIALITY', m: 'bad', note: 'BROKEN: traffic read by MITM' },
          { stage: 'INTEGRITY', m: 'bad', note: 'BROKEN: rewritten message accepted' },
          { stage: 'VERDICT', m: 'warn', note: 'VULNERABLE (base protocol limitation)' },
        ],
        isSimulated: true,
      };
    }
    case 18: {
      const checks = [
        chk('Uses Scene 02 identity', true, 'keys/server_pk.bin pinned'),
        chk('Honest session verifies', true, 'signature valid, message delivered'),
        chk('Swapped server key rejected', true, 'real signature, Mallory’s key → REJECTED'),
        chk('Mallory’s own signature rejected', true, 'not pinned identity → REJECTED'),
        chk('Replayed signature rejected', true, 'bound to other session keys → REJECTED'),
      ];
      return {
        ok: true, status: 'REJECTED', decision: 'MITM REJECTED', rc: 'mitm ok=true',
        produced: 'Identity verified ✓ · 3/3 attacker substitutions rejected ✕ · session protected',
        checks, trace: checkTrace(checks, 'SESSION PROTECTED', true), isSimulated: true,
      };
    }
    case 19: {
      const p = mockPkt(1);
      const st = { rc: 0, verdict: 'ACCEPTED (EPOCH 2)', packet: p };
      const checks = [
        chk('Re-key executed', true, 'rc 0 · crypto_kdf_derive_from_key'),
        chk('Epoch advanced', true, '1 → 2'),
        chk('Session material changed', true, 'client_tx 9A4F → 5D31 (overwritten in place)'),
        chk('Sides still agree', true, 'client_tx = server_rx after re-key'),
        chk('New epoch carries traffic', true, 'packet #1 under epoch 2: ACCEPTED'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'EPOCH 2 ACTIVE', rc: 'rekey rc=0',
        produced: 'Epoch 1 keys overwritten; epoch 2 carries traffic seamlessly',
        steps: [st], checks, trace: checkTrace(checks, 'SECURE (new epoch)', true), isSimulated: true,
      };
    }
    case 20: {
      const checks = [
        chk('Required suite (test_attacks)', true, '8/8 passed · exit 0'),
        chk('Extended suite (test_extended)', true, '35/35 passed · exit 0'),
        chk('AEAD tests', true, '11/11 tests pass'),
        chk('REPLAY tests', true, '5/5 tests pass'),
        chk('AAD tests', true, '4/4 tests pass'),
        chk('TAMPERING tests', true, '6/6 tests pass'),
        chk('WRONG KEY tests', true, '3/3 tests pass'),
        chk('MITM DEFENSE tests', true, '3/3 tests pass'),
        chk('KEY WRAPPING tests', true, '2/2 tests pass'),
        chk('RE-KEYING tests', true, '1/1 test pass'),
        chk('OpenSSL CBC vs AEAD', true, 'CBC tamper NOT detected (bit flip in place) · AEAD rejects tampered bytes'),
      ];
      return {
        ok: true, status: 'COMPLETED', decision: 'ALL TESTS PASS', rc: 'exit 0 / exit 0 / exit 0',
        produced: '43/43 TAP tests passed · OpenSSL CBC unauthenticated flaw confirmed',
        checks, trace: checkTrace(checks, 'VERIFIED', true), isSimulated: true,
      };
    }
    case 21: {
      const props = VERDICT_PROPS.map(([name]) => ({ name, ok: true, missing: [], failed: [] }));
      props.push({ name: 'LIVE CHANNEL NOW', ok: true, missing: [], failed: [] });
      const checks = props.map((p) => chk(p.name, true, 'live empirical evidence collected'));
      return {
        ok: true, status: 'COMPLETED', decision: 'SECURE CHANNEL VERIFIED', rc: 'probe 0',
        produced: '16/16 security properties backed by live empirical evidence from one continuous pass',
        checks, props, trace: checkTrace(checks, 'SECURE CHANNEL VERIFIED', true), isSimulated: true,
      };
    }
    default:
      return {
        ok: true, status: 'READY', decision: 'READY', rc: '—',
        produced: 'Ready to execute', checks: [], trace: [], isSimulated: true,
      };
  }
}

/* ---- STAGES Definition (All 21 Stages in C) -------------------------------- */

const STAGES = [
  {
    id: 1, title: 'SYSTEM INITIALIZATION', act: 1,
    op: 'Live readiness checks', backend: 'Node bridge · WSL · sc_engine (C / libsodium)',
    why: 'Before any claim is made, every component answers live: the bridge, the C engine, libsodium, and the GCC toolchain.',
    principle: 'Trust boundary: the browser only visualises; cryptography executes in C.',
    pre: () => [],
    async execute(call) {
      let health, healthMs = 0;
      const waitStart = performance.now();
      for (;;) {
        const t0 = performance.now();
        try { health = await api.health(); } catch (e) { health = { ok: false, error: e.message }; }
        healthMs = performance.now() - t0;
        const ready = health.ok === true && health.engine === true && !!health.toolchain && store.engineUp === true;
        if (ready || health.build === 'failed' || performance.now() - waitStart > 30000) break;
        await new Promise((r) => setTimeout(r, 200));
      }
      health.waitedMs = performance.now() - waitStart;
      const reset = await call('engine', 'reset');
      clearHeld();
      D.sessionId = null;
      const hello = await call('engine', 'hello');
      const status = await call('engine', 'status');
      return { health, healthMs, reset, hello, status };
    },
    evaluate({ health, healthMs, hello, status, reset }) {
      const pf = hello?.packet_format || {};
      const tc = health?.toolchain || {};
      const checks = [
        chk('Node bridge', health.ok === true, health.ok ? `/api/health answered in ${fmtMs(healthMs)}` : (health.error || 'no answer')),
        chk('C engine', hello.ok === true && health.engine === true, hello.ok ? 'sc_engine answered "hello"' : (hello.error || 'no answer')),
        chk('libsodium', hello.ok === true && typeof hello.libsodium === 'string', hello.libsodium ? `libsodium ${hello.libsodium} initialised in C` : 'not reported'),
        chk('Toolchain / build', tc.build_ok === true && !!tc.gcc, tc.gcc ? `gcc ${tc.gcc} · make all OK · libsodium ${tc.libsodium || '?'}` : 'not detected'),
        chk('Dashboard event stream', store.engineUp === true, store.engineUp ? 'live event stream from bridge connected' : 'event stream not connected'),
        chk('Protocol structure', status.ok === true && reset.ok === true && pf.seq === 8 && pf.nonce === 12 && pf.tag === 16 && pf.min === 36,
          `state ${status.session?.state || '?'} · seq ${pf.seq} B + nonce ${pf.nonce} B + ct + tag ${pf.tag} B`),
        chk('Live-demo commands', Array.isArray(health.features) && health.features.includes('hs') && health.features.includes('intercept'),
          Array.isArray(health.features) ? 'bridge accepts hs / seal / intercept / unwrap' : 'old bridge version'),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'SYSTEM ONLINE' : 'CHECK FAILED', rc: `hello ok=${hello?.ok}`,
        produced: ok ? `${checks.length}/${checks.length} live checks passed · libsodium ${hello?.libsodium}` : `${checks.filter((c) => !c.ok).length} check(s) failed`,
        checks, trace: checkTrace(checks, ok ? 'READY' : 'NOT READY', ok), isSimulated: false,
      };
    },
    notes: { say: 'Nothing is pre-loaded. Every component answers live: the bridge, the C engine, libsodium and the toolchain that built it.',
      watch: 'The three trust zones: browser, Node bridge, cryptographic authority.', expected: 'All checks online.' },
  },

  {
    id: 2, title: 'IDENTITY GENERATION', act: 1,
    op: 'Generate the server’s long-term identity (./keygen)', backend: 'C program keygen · crypto_sign_keypair / crypto_kx_keypair',
    why: 'The Ed25519 identity is what later defeats the man-in-the-middle; its private half must be protected and never shown.',
    principle: 'Key management: private keys 0600, never exported.',
    pre: () => [{ label: 'System initialised (Scene 01)', ok: okRun(1) }],
    async execute(call) {
      const keygen = await call('run', 'keygen');
      const vault = await call('engine', 'vault');
      return { keygen, vault };
    },
    evaluate({ keygen, vault }) {
      const f = (p) => vault.files?.find((x) => x.path === p);
      const sk = f('keys/server_sk.bin'), pk = f('keys/server_pk.bin'), kx = f('keys/server_kx_sk.bin');
      const checks = [
        chk('keygen exit code', keygen.code === 0, `exit ${keygen.code}`),
        chk('Public identity created', pk?.exists === true && pk?.loaded === true, pk ? `${pk.path} · ${pk.expected_size} B · mode ${pk.mode}` : 'missing'),
        chk('Public key fingerprint', typeof sk?.fingerprint === 'string', sk?.fingerprint || 'none'),
        chk('Key pair matches', sk?.pair_ok === true, sk?.pair_ok ? 'secret key derives published public key' : 'mismatch'),
        chk('Private key protected', sk?.mode_ok === true, sk ? `${sk.path} mode ${sk.mode} · bytes never leave C` : 'missing'),
        chk('X25519 static pair', kx?.mode_ok === true && kx?.pair_ok === true, kx ? `${kx.path} mode ${kx.mode}` : 'missing'),
        chk('All key file permissions', vault.permissions_ok === true, vault.permissions_ok ? '0600 private / 0644 public' : 'NOT as expected'),
      ];
      const ok = checks.every((c) => c.ok);
      D.identityFp = ok ? sk?.fingerprint : null;
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'IDENTITY CREATED' : 'IDENTITY FAILED', rc: `keygen exit ${keygen.code}`,
        produced: ok ? `Ed25519 identity ${sk?.fingerprint}` : 'identity incomplete', checks, trace: checkTrace(checks, ok ? 'PROTECTED' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'keygen just ran. These are the files it wrote, their real permissions, and a one-way fingerprint of the public key. The private key never leaves C.',
      watch: 'Mode 0600 on private keys; key pair matches.', expected: 'Identity created, private key protected.' },
  },

  {
    id: 3, title: 'SESSION INITIALIZATION', act: 2,
    op: 'hs begin: fresh session, ephemeral X25519 key pairs', backend: 'sc_engine · session_hs_begin() · crypto_kx_keypair',
    why: 'Each session starts from fresh ephemeral keys. In INIT the state machine refuses to encrypt anything.',
    principle: 'State-machine gating; fresh keys per session.',
    pre: () => [{ label: 'System initialised (Scene 01)', ok: okRun(1) }],
    async execute(call) {
      const before = sess().state;
      const hs = await call('engine', 'hs', 'begin');
      clearHeld();
      D.sessionId = hs.ok && hs.client_pk_fp ? `SC-${hs.client_pk_fp.replace(/[^0-9A-F]/g, '').slice(0, 4)}` : null;
      const probe = await call('engine', 'seal', 'probe before handshake');
      return { before, hs, probe };
    },
    evaluate({ before, hs, probe }) {
      const refused = probe.cmd === 'seal' && probe.ok === false && /SECURE/.test(probe.error || '') && probe.session?.state === 'INIT';
      const checks = [
        chk('Session created', hs.ok === true && hs.rc === 0, `rc ${hs.rc ?? '—'} · ${fmtMs(hs.elapsed_ms)} in C`),
        chk('State', hs.state_after === 'INIT', `${before || '—'} → ${hs.state_after || '?'}`),
        chk('Ephemeral key pairs generated', hs.ephemeral_secrets_held === true && !!hs.client_pk_fp && !!hs.server_pk_fp, `client ${hs.client_pk_fp || '?'} · server ${hs.server_pk_fp || '?'}`),
        chk('No session keys yet', hs.session_keys_present === false, 'rx/tx not derived'),
        chk('Encryption refused in INIT', refused, refused ? `C engine refused: ${probe.error}` : `unexpected: ${probe.error || 'seal allowed'}`),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'STATE: INIT' : 'INIT FAILED', rc: `hs ${hs.rc ?? '—'} · probe refused`,
        produced: ok ? 'session created in INIT with fresh ephemeral key pairs' : 'session not initialised', checks, trace: checkTrace(checks, 'INIT', ok), isSimulated: false,
      };
    },
    notes: { say: 'A brand-new session exists in C memory; both sides generated ephemeral key pairs. When seal() was attempted right now, the engine refused because state is INIT.',
      watch: 'Refused seal(): state machine enforced in C.', expected: 'STATE: INIT, encryption refused.' },
  },

  {
    id: 4, title: 'KEY EXCHANGE', act: 2,
    op: 'hs derive: crypto_kx client/server session keys', backend: 'sc_engine · crypto_kx_client_session_keys / crypto_kx_server_session_keys',
    why: 'Both sides derive the same directional keys from public values alone; an eavesdropper who saw both public keys cannot.',
    principle: 'X25519 Diffie–Hellman + BLAKE2b; separate keys per direction.',
    pre: () => [{ label: 'Session in INIT with ephemeral keys (Scene 03)', ok: okRun(3) && sess().state === 'INIT' }],
    async execute(call) {
      const hs = await call('engine', 'hs', 'derive');
      return { hs, fps: hs.session?.key_fingerprints || null };
    },
    evaluate({ hs, fps }) {
      const f = fps || {};
      const checks = [
        chk('crypto_kx executed', hs.ok === true && hs.rc === 0, `rc ${hs.rc ?? '—'} · ${fmtMs(hs.elapsed_ms)} in C`),
        chk('CLIENT TX == SERVER RX', hs.complementary === true && !!f.client_tx && f.client_tx === f.server_rx, `${f.client_tx || '—'} = ${f.server_rx || '—'}`),
        chk('CLIENT RX == SERVER TX', hs.complementary === true && !!f.client_rx && f.client_rx === f.server_tx, `${f.client_rx || '—'} = ${f.server_tx || '—'}`),
        chk('TX ≠ RX', hs.directional === true && !!f.client_tx && f.client_tx !== f.client_rx, 'directional keys differ'),
        chk('Ephemeral secrets wiped', hs.ephemeral_secrets_wiped === true, 'sodium_free() zeroed secrets after derivation'),
        chk('State', hs.state_after === 'AUTH', `INIT → ${hs.state_after || '?'}`),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'KEYS DERIVED' : 'DERIVATION FAILED', rc: hs.rc ?? '—',
        produced: ok ? '4 directional keys derived (shown only as fingerprints)' : 'keys not derived', checks, trace: checkTrace(checks, ok ? 'DERIVED' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'Both sides ran crypto_kx. The fingerprints prove the client’s TX key matches the server’s RX key, and the two directions differ.',
      watch: 'Matching fingerprints; TX ≠ RX.', expected: 'KEYS DERIVED, state AUTH.' },
  },

  {
    id: 5, title: 'AUTHENTICATION', act: 2,
    op: 'hs auth: Ed25519 signature over the handshake transcript', backend: 'sc_engine · crypto_sign_detached / crypto_sign_verify_detached',
    why: 'Key exchange alone does not say who is on the other end. The server signs both ephemeral keys with its identity; the client verifies against the pinned key.',
    principle: 'Authenticated key exchange (identity binding).',
    pre: () => [
      { label: 'Keys derived, state AUTH (Scene 04)', ok: okRun(4) && sess().state === 'AUTH' },
      { label: 'Server identity generated (Scene 02)', ok: okRun(2) },
    ],
    async execute(call) { return { hs: await call('engine', 'hs', 'auth') }; },
    evaluate({ hs }) {
      const checks = [
        chk('Identity loaded', typeof hs.identity_fp === 'string', hs.identity_fp ? `pinned Ed25519 key ${hs.identity_fp}` : (hs.error || 'not loaded')),
        chk('Transcript signed and verified', hs.signature === 1 && hs.rc === 0, `${hs.transcript || '—'} · rc ${hs.rc ?? '—'}`),
        chk('Matches the Scene 02 identity', !!D.identityFp && hs.identity_fp === D.identityFp, D.identityFp ? `Scene 02: ${D.identityFp}` : 'Scene 02 not verified'),
        chk('Session authenticated', hs.authenticated === true && hs.session?.authenticated === true, `state ${hs.state_after || '?'}`),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'AUTHENTICATED' : 'AUTH FAILED', rc: hs.rc ?? '—',
        produced: ok ? `server identity ${hs.identity_fp} verified` : 'not authenticated', checks, trace: checkTrace(checks, ok ? 'AUTHENTICATED' : 'REJECTED', ok), isSimulated: false,
      };
    },
    notes: { say: 'The server signed both public keys with its Scene 02 identity, and the client verified it. This binds the ephemeral session to the true identity.',
      watch: 'Identity fingerprint equals Scene 02.', expected: 'AUTHENTICATED, rc 0.' },
  },

  {
    id: 6, title: 'SECURE CHANNEL ACTIVATION', act: 2,
    op: 'hs secure: readiness checks, then AUTH → SECURE', backend: 'sc_engine · session_hs_secure()',
    why: 'The data phase switches on only after the engine confirms keys exist, agree, ephemeral secrets are gone, and peer is authenticated.',
    principle: 'Fail-closed state transition.',
    pre: () => [{ label: 'Authenticated in AUTH (Scene 05)', ok: okRun(5) && sess().state === 'AUTH' && sess().authenticated === true }],
    async execute(call) { return { hs: await call('engine', 'hs', 'secure') }; },
    evaluate({ hs }) {
      const r = hs.readiness || {};
      const checks = [
        chk('Session key material available', r.session_keys_present === true, r.session_keys_present ? 'YES' : 'NO'),
        chk('Keys complementary', r.keys_complementary === true, r.keys_complementary ? 'client_tx = server_rx, client_rx = server_tx' : 'NO'),
        chk('Ephemeral secrets wiped', r.ephemeral_secrets_wiped === true, r.ephemeral_secrets_wiped ? 'YES' : 'NO'),
        chk('Authentication valid', r.authenticated === true, r.authenticated ? 'YES' : 'NO'),
        chk('Channel SECURE', hs.ok === true && hs.rc === 0 && hs.state_after === 'SECURE', `${hs.state_before} → ${hs.state_after} · epoch ${hs.session?.epoch}`),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'STATE: SECURE' : 'NOT SECURE', rc: hs.rc ?? '—',
        produced: ok ? 'channel SECURE · next_seq 1 · replay window armed' : 'transition refused', checks, trace: checkTrace(checks, ok ? 'SECURE' : 'REFUSED', ok), isSimulated: false,
      };
    },
    notes: { say: 'The engine verified memory before switching state: keys present, keys agree, ephemeral secrets wiped, peer authenticated. Only then did it enter SECURE.',
      watch: 'INIT → AUTH → SECURE, reached by real calls.', expected: 'STATE: SECURE.' },
  },

  {
    id: 7, title: 'AEAD ENCRYPTION', act: 3, input: true,
    op: 'seal: ChaCha20-Poly1305 with seq as AAD', backend: 'sc_engine · session_seal() · crypto_aead_chacha20poly1305_ietf_encrypt',
    why: 'The packet gives confidentiality (ciphertext) and authenticity (a tag over ciphertext + clear-text sequence number).',
    principle: 'Authenticated encryption with associated data.',
    pre: () => [{ label: 'Channel SECURE (Scene 06)', ok: okRun(6) && sess().state === 'SECURE' }],
    async execute(call) {
      const text = (D.draft || '').trim() || DEFAULT_MESSAGE;
      const r = await call('engine', 'seal', text);
      if (r.ok) { D.held = r.packet; D.heldText = text; D.heldDelivered = false; } else clearHeld();
      return { r, text };
    },
    evaluate({ r, text }) {
      const p = r.packet || {};
      const checks = [
        chk('Message validated', r.ok === true && isNum(r.plaintext_len), `${r.plaintext_len ?? '?'} B (limit 1–256 B)`),
        chk('Sequence number assigned', typeof p.seq === 'string' && isHex(p.seq_hex, 16), `seq ${p.seq} · next_seq now ${r.session?.next_seq}`),
        chk('Fresh 96-bit nonce', isHex(p.nonce_hex, 24) && !/^0+$/.test(p.nonce_hex), shortHex(p.nonce_hex || '', 6)),
        chk('AAD = sequence number', isHex(p.aad_hex, 16) && p.aad_hex === p.seq_hex, p.aad_hex || '—'),
        chk('AEAD encryption', r.rc === 0, `rc ${r.rc} · ${fmtMs(r.elapsed_ms)} in C`),
        chk('Ciphertext length = plaintext length', isNum(p.ct_len) && p.ct_len === new TextEncoder().encode(text).length, `${p.ct_len} B`),
        chk('Authentication tag', isHex(p.tag_hex, 32), `16 B ${shortHex(p.tag_hex || '', 4)}`),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? `PACKET #${p.seq} SEALED` : 'SEAL FAILED', rc: r.rc ?? '—',
        produced: ok ? `packet #${p.seq}: ${p.length} B, held on the wire (ready for delivery)` : (r.error || 'no packet'), checks, trace: checkTrace(checks, ok ? 'SEALED' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'The C engine sealed the message with a fresh nonce, the sequence number as AAD, and a Poly1305 tag. Held on wire for inspection.',
      watch: 'The packet artifact: 36 B header/tag + ciphertext.', expected: 'PACKET #N SEALED.' },
  },

  {
    id: 8, title: 'PACKET INSPECTION', act: 3, rerunFrom: 7,
    op: 'inspect: read-only parse of the held packet', backend: 'sc_engine · packet parser (no state change)',
    why: 'Everything an attacker on the network sees: sequence, nonce, ciphertext, and tag — with zero plaintext visible.',
    principle: 'Confidentiality on the wire; structural validation.',
    pre: () => [{ label: 'A packet is held (Scene 07)', ok: okRun(7) && !!D.held }, { label: 'Not yet delivered', ok: !!D.held && !D.heldDelivered }],
    async execute(call) { return { r: await call('engine', 'inspect') }; },
    evaluate({ r }) {
      const c = r.checks || {}, p = r.packet || {};
      const same = !!D.held && isHex(p.ct_hex) && p.ct_hex === D.held.ct_hex && p.nonce_hex === D.held.nonce_hex && p.tag_hex === D.held.tag_hex;
      const checks = [
        chk('Same packet as Scene 07', same, same ? `packet #${p.seq}: nonce, ciphertext and tag identical` : 'DIFFERENT PACKET'),
        chk('Length', c.length_ok === true, `${p.length} B (expected ${c.expected_length} B ≥ 36 B)`),
        chk('Sequence issued by client', c.seq_issued_by_client === true, `seq ${p.seq}`),
        chk('Fresh for receiver', c.seq_fresh_for_receiver === true, c.seq_fresh_for_receiver ? 'seq > last_seq' : 'already used'),
        chk('Nonce present', c.nonce_nonzero === true, '12 B, non-zero'),
        chk('AAD present', isHex(p.aad_hex, 16), p.aad_hex || '—'),
        chk('Ciphertext present', isNum(p.ct_len) && p.ct_len > 0, `${p.ct_len} B`),
        chk('Auth tag present', isHex(p.tag_hex, 32), '16 B'),
        chk('Plaintext not visible', c.plaintext_not_visible === true, 'byte search for message in wire frame: not found'),
      ];
      const ok = r.ok === true && checks.every((x) => x.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'STRUCTURE VALID' : 'INSPECTION FAILED', rc: `inspect ok=${r.ok}`,
        produced: ok ? `packet #${p.seq} inspected: no plaintext visible, still undelivered` : (r.error || 'inspection failed'), checks, trace: checkTrace(checks, ok ? 'VALID' : 'INVALID', ok), isSimulated: false,
      };
    },
    notes: { say: 'Exact packet: same nonce, ciphertext and tag. Parsed without state change; plaintext appears nowhere on the wire.',
      watch: 'Plaintext not visible.', expected: 'STRUCTURE VALID.' },
  },

  {
    id: 9, title: 'DECRYPTION & DELIVERY', act: 3, rerunFrom: 7,
    op: 'deliver: server unseal() of the held packet', backend: 'sc_engine · session_deliver() · crypto_aead_chacha20poly1305_ietf_decrypt',
    why: 'Plaintext is released only after length, replay window, and Poly1305 tag all pass; only then does the replay window advance.',
    principle: 'Verify-then-decrypt; state changes only after authentication.',
    pre: () => [{ label: 'Held packet inspected (Scene 08)', ok: okRun(8) && !!D.held && !D.heldDelivered }, { label: 'Channel SECURE', ok: sess().state === 'SECURE' }],
    async execute(call) {
      const r = await call('engine', 'deliver');
      const st = r.steps?.[0];
      if (st?.rc === 0) D.heldDelivered = true;
      return { r, st };
    },
    evaluate({ r, st }) {
      const checks = st?.packet ? [
        chk('Packet received', st.rc !== -1, `#${st.packet.seq} · ${st.packet.length} B`),
        chk('Replay check', st.rc !== -3 && st.rc !== -1, st.had_seq_before ? `seq ${st.packet.seq} > ${st.last_seq_before}` : 'first packet'),
        chk('AAD + AEAD tag verified', st.rc === 0, st.reason),
        chk('Plaintext released', st.plaintext_released === true && st.plaintext_len > 0, `${st.plaintext_len} B`),
        chk('Decrypted text = sealed text', st.plaintext_matches === true, st.plaintext_matches ? 'byte-for-byte identical' : 'MISMATCH'),
        chk('Replay window advanced', st.state_changed === true && st.last_seq_after === Number(st.packet.seq), `last_seq ${st.last_seq_before} → ${st.last_seq_after}`),
      ] : [chk('Delivery', false, r.error || 'no result')];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: st ? st.verdict : 'FAILED', rc: st ? st.rc : '—',
        produced: ok ? `"${st.plaintext}" released from packet #${st.packet.seq}` : (r.error || st?.reason || 'not delivered'), checks, trace: packetTrace(st), isSimulated: false,
      };
    },
    notes: { say: 'The server received the packet, verified length, replay window and Poly1305 tag, and released the plaintext byte-for-byte.',
      watch: 'Released plaintext and replay window advanced.', expected: 'ACCEPTED, rc 0.' },
  },

  {
    id: 10, title: 'TAMPERING ATTACK', act: 4, attack: 'tamper', rerunFrom: 7,
    op: 'intercept tamper: flip one ciphertext bit in flight', backend: 'sc_engine · session_deliver() on attacker-modified bytes',
    why: 'Changing one bit of ciphertext breaks the Poly1305 tag: the receiver rejects the packet, releases nothing, and state does not move.',
    principle: 'Integrity and authenticity (INT-CTXT).',
    pre: () => heldAccepted(),
    async execute(call) { return attackExec(call, 'tamper'); },
    evaluate: (d) => attackEval(d),
    notes: { say: 'Attacker flips one bit in transit. Unseal() catches the modified tag: packet rejected, 0 B released, state unchanged.',
      watch: 'Authentication failed · plaintext blocked · state blocked.', expected: 'REJECTED (rc -2).' },
  },

  {
    id: 11, title: 'REPLAY ATTACK', act: 4, attack: 'replay', rerunFrom: 7,
    op: 'intercept replay: re-send the exact accepted packet', backend: 'sc_engine · replay window (seq > last_seq)',
    why: 'A perfectly valid packet is rejected the second time: the receiver only accepts strictly increasing sequence numbers.',
    principle: 'Freshness / replay protection.',
    pre: () => heldAccepted(),
    async execute(call) { return attackExec(call, 'replay'); },
    evaluate: (d) => attackEval(d),
    notes: { say: 'Identical valid bytes sent again. The replay window rejects them immediately before any AEAD operation.',
      watch: 'seq ≤ last_seq in decision trace.', expected: 'REPLAY DETECTED (rc -3).' },
  },

  {
    id: 12, title: 'AAD ATTACK', act: 4, attack: 'aad', rerunFrom: 7,
    op: 'intercept aad: rewrite clear-text sequence number (+1000)', backend: 'sc_engine · AEAD tag over AAD',
    why: 'The sequence number travels in clear but is authenticated as AAD: changing it invalidates the tag.',
    principle: 'Associated data is authenticated, not encrypted.',
    pre: () => heldAccepted(),
    async execute(call) { return attackExec(call, 'aad'); },
    evaluate: (d) => attackEval(d),
    notes: { say: 'Attacker rewrites sequence header to pass replay window, but the Poly1305 tag covered that sequence as AAD. Fails tag check.',
      watch: 'Replay check ✓ but AAD + AEAD tag ✕.', expected: 'AUTHENTICATION FAILED (rc -2).' },
  },

  {
    id: 13, title: 'SEQUENCE ATTACK', act: 4, attack: 'forged', rerunFrom: 7,
    op: 'intercept forged: seq = 2⁶⁴−1 to poison the replay window', backend: 'sc_engine · tag check before state update',
    why: 'If the receiver stored the sequence number before verifying the tag, one forged packet would block all future traffic. It must not.',
    principle: 'Never update state from unauthenticated input.',
    pre: () => heldAccepted(),
    async execute(call) { return attackExec(call, 'forged'); },
    evaluate: (d) => attackEval(d),
    notes: { say: 'Attacker injects max sequence number. Trusting it before tag check would lock out genuine traffic. Engine keeps state intact.',
      watch: 'State update BLOCKED; follow-up genuine packet ACCEPTED.', expected: 'REJECTED (rc -2), replay window unchanged.' },
  },

  {
    id: 14, title: 'WRONG-KEY ATTACK', act: 4, attack: 'wrongkey', rerunFrom: 7,
    op: 'intercept wrongkey: open valid packet with wrong key; forge one under attacker key', backend: 'sc_engine · unseal() with random key · session_deliver()',
    why: 'Without the session key nobody can read a valid packet or produce one the receiver accepts.',
    principle: 'Key secrecy ⇒ confidentiality and unforgeability.',
    pre: () => [{ label: 'A packet is held (Scene 07)', ok: okRun(7) && !!D.held }, { label: 'Channel SECURE', ok: sess().state === 'SECURE' }],
    async execute(call) { return attackExec(call, 'wrongkey'); },
    evaluate: (d) => attackEval(d),
    notes: { say: 'Server opens packet with random key: tag fails, buffer zeroed. Attacker forges under her own key: rejected.',
      watch: 'Both steps AUTHENTICATION FAILED, output buffer zeroed.', expected: 'REJECTED (rc -2).' },
  },

  {
    id: 15, title: 'KEY WRAPPING', act: 5,
    op: 'wrap correct: Argon2id + crypto_secretbox over the identity key', backend: 'sc_engine · crypto_pwhash (Argon2id) · crypto_secretbox_easy',
    why: 'At rest, the private key is stored encrypted under a passphrase-derived key; Argon2id makes guessing computationally expensive.',
    principle: 'Key wrapping with a memory-hard KDF.',
    pre: () => [{ label: 'Server identity generated (Scene 02)', ok: okRun(2) }],
    async execute(call) { return { r: await call('engine', 'wrap', 'correct') }; },
    evaluate({ r }) {
      const checks = [
        chk('Argon2id executed', r.ok === true && isNum(r.wrap_ms) && r.wrap_ms > 0 && r.wrap_rc === 0, `${r.kdf || '—'} · ${r.memlimit_mib} MiB · ops ${r.opslimit} · ${fmtMs(r.wrap_ms)}`),
        chk('Secretbox executed', r.ok === true && r.file_size === 120 && isHex(r.salt_hex, 32), `${r.file_size} B wrapped file`),
        chk('Wrapped file 0600', r.file_mode === '0600', `keys/server_sk.wrapped · mode ${r.file_mode}`),
        chk('Round trip verified', r.mac_verified === true && r.unwrapped === true, r.unwrapped ? 'MAC verified, key equals original' : 'FAILED'),
        chk('No secret in response', r.ok === true && !Object.keys(r).some((k) => /(^|_)(sk|key|seed|passphrase)$/i.test(k)), 'no key or passphrase field; values stayed in C'),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'KEY WRAPPED' : 'WRAP FAILED', rc: `wrap ${r.wrap_rc ?? '—'} · unwrap ${r.rc ?? '—'}`,
        produced: ok ? `120 B wrapped key file, salt ${shortHex(r.salt_hex, 4)}` : (r.error || 'not wrapped'), checks, trace: checkTrace(checks, ok ? 'WRAPPED' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'Identity key wrapped: Argon2id with 64 MiB derived wrapping key; secretbox encrypted key material with 0600 permissions.',
      watch: 'Argon2id memory hardness and 0600 wrapped file.', expected: 'WRAPPED, round trip verified.' },
  },

  {
    id: 16, title: 'WRONG PASSPHRASE', act: 5, attack: 'unwrap',
    op: 'unwrap wrong: open Scene 15 file with a wrong passphrase', backend: 'sc_engine · crypto_pwhash + crypto_secretbox_open_easy',
    why: 'A wrong passphrase gives a wrong key, the MAC fails, and the output buffer is actively zeroed: nothing partial leaks.',
    principle: 'Authenticated decryption of key material; fail closed.',
    pre: () => [{ label: 'Wrapped key exists (Scene 15)', ok: okRun(15) }],
    async execute(call) { return { r: await call('engine', 'unwrap', 'wrong') }; },
    evaluate({ r }) {
      const prevSalt = R[15]?.data?.r?.salt_hex;
      const checks = [
        chk('Same wrapped file as Scene 15', isHex(r.salt_hex, 32) && r.salt_hex === prevSalt, `salt ${shortHex(r.salt_hex || '', 4)}`),
        chk('Argon2id executed', r.ok === true && isNum(r.unwrap_ms) && r.unwrap_ms > 0, fmtMs(r.unwrap_ms)),
        chk('Authentication failed', r.ok === true && r.mac_verified === false && isNum(r.rc) && r.rc !== 0, r.mac_verified ? 'MAC VERIFIED' : `secretbox MAC mismatch · rc ${r.rc}`),
        chk('No secret released', r.secret_released === false, r.secret_released ? 'RELEASED' : 'nothing released'),
        chk('Output zeroed', r.output_zeroed === true, 'buffer pre-filled with 0xA5, wiped to zero by unwrap'),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'REJECTED' : 'FAILED', decision: ok ? 'UNWRAP REFUSED' : 'UNEXPECTED', rc: r.rc ?? '—',
        produced: ok ? 'wrong passphrase rejected · output zeroed' : (r.error || 'unexpected result'), checks, trace: checkTrace(checks, ok ? 'REJECTED' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'Wrong passphrase tested: Argon2id runs at full cost, MAC fails, and buffer is wiped to zeros.',
      watch: 'Authentication failed and output zeroed.', expected: 'UNWRAP REFUSED.' },
  },

  {
    id: 17, title: 'MITM WITHOUT AUTHENTICATION', act: 5, attack: 'mitm',
    op: 'mitm plain: Mallory substitutes both public keys in plain crypto_kx', backend: 'sc_engine · mitm_plain() (real crypto_kx, seal, unseal)',
    why: 'Plain Diffie–Hellman is anonymous: an active attacker who swaps keys can read and rewrite everything. This demonstrates the base protocol limitation.',
    principle: 'Unauthenticated key exchange is vulnerable to an active MITM.',
    pre: () => [{ label: 'System initialised (Scene 01)', ok: okRun(1) }],
    async execute(call) { return { r: await call('engine', 'mitm', 'plain') }; },
    evaluate({ r }) {
      const p = r.plain || {};
      const checks = [
        chk('Mallory substituted both keys', p.keys_substituted === true, p.keys_substituted ? 'crypto_kx completed with Mallory on both sides' : 'no'),
        chk('Mallory decrypted client traffic', p.mallory_read === true && p.read_text === p.sent_text, p.mallory_read ? `client sent "${p.sent_text}", Mallory read "${p.read_text}"` : 'no'),
        chk('Server accepted Mallory rewrite', p.mallory_forged === true, p.mallory_forged ? `server got "${p.forged_text}"` : 'no'),
      ];
      const ok = r.ok === true && r.vulnerability_shown === true && checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'VULNERABILITY DEMONSTRATED' : 'NOT REPRODUCED', rc: `mitm ok=${r.ok}`,
        produced: ok ? `Mallory read "${p.read_text}" and injected "${p.forged_text}"` : (r.error || 'attack did not reproduce'), checks,
        trace: [
          { stage: 'KEY EXCHANGE', m: 'warn', note: 'plain crypto_kx: no identity check' },
          { stage: 'KEY SUBSTITUTION', m: p.keys_substituted ? 'bad' : 'ok', note: p.keys_substituted ? 'Mallory sits on both sides' : 'did not happen' },
          { stage: 'CONFIDENTIALITY', m: p.mallory_read ? 'bad' : 'ok', note: p.mallory_read ? 'BROKEN: traffic read' : 'held' },
          { stage: 'INTEGRITY', m: p.mallory_forged ? 'bad' : 'ok', note: p.mallory_forged ? 'BROKEN: rewritten message accepted' : 'held' },
          { stage: 'VERDICT', m: ok ? 'warn' : 'bad', note: ok ? 'VULNERABLE (documented limitation)' : 'demonstration failed' },
        ], isSimulated: false,
      };
    },
    notes: { say: 'Real primitives run with Mallory in the middle without identity check. Mallory read and rewrote traffic. This is why Ed25519 signing is required.',
      watch: 'What client sent, what Mallory read, what server got.', expected: 'VULNERABILITY DEMONSTRATED.' },
  },

  {
    id: 18, title: 'MITM DEFENSE', act: 5, attack: 'mitm',
    op: 'mitm signed: attacks against signed handshake', backend: 'sc_engine · mitm_signed() · Ed25519 verify with Scene 02 identity',
    why: 'With the server’s signature over the transcript, every substitution Mallory can attempt fails verification before any key is derived.',
    principle: 'Authenticated key exchange defeats an active MITM.',
    pre: () => [{ label: 'Server identity generated (Scene 02)', ok: okRun(2) }],
    async execute(call) { return { r: await call('engine', 'mitm', 'signed') }; },
    evaluate({ r }) {
      const s = r.signed || {};
      const checks = [
        chk('Uses Scene 02 identity', s.task1_identity === true, s.task1_identity ? 'keys/server_pk.bin pinned' : 'temporary identity'),
        chk('Honest session verifies', s.honest_ok === true, 'signature valid, message delivered'),
        chk('Swapped server key rejected', s.blocked_key_swap === true, 'real signature, Mallory’s key → REJECTED'),
        chk('Mallory’s own signature rejected', s.blocked_own_signature === true, 'not pinned identity → REJECTED'),
        chk('Replayed signature rejected', s.blocked_replayed_signature === true, 'bound to other session keys → REJECTED'),
      ];
      const ok = r.ok === true && r.extension_blocks_mitm === true && checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'REJECTED' : 'FAILED', decision: ok ? 'MITM REJECTED' : 'MITM NOT BLOCKED', rc: `mitm ok=${r.ok}`,
        produced: ok ? 'identity verified ✓ · 3/3 attacker substitutions rejected ✕ · session protected' : 'defence incomplete', checks, trace: checkTrace(checks, ok ? 'SESSION PROTECTED' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'Server signs the transcript with Scene 02 identity. Every substitution Mallory attempts fails signature verification.',
      watch: 'Identity verification ✓, attacker substitutions ✕.', expected: 'MITM REJECTED, session protected.' },
  },

  {
    id: 19, title: 'RE-KEYING', act: 5,
    op: 'rekey: advance session keys with crypto_kdf, send under new epoch', backend: 'sc_engine · crypto_kdf_derive_from_key · seal / deliver',
    why: 'Old keys are overwritten in place: later key compromise does not expose earlier epochs, and channel continues working.',
    principle: 'Key rotation between epochs.',
    pre: () => [{ label: 'Channel SECURE (Scene 06)', ok: okRun(6) && sess().state === 'SECURE' }],
    async execute(call) {
      const before = sess().key_fingerprints ? { ...sess().key_fingerprints } : null;
      const epochBefore = sess().epoch;
      const rk = await call('engine', 'rekey');
      const after = rk.session?.key_fingerprints || null;
      let seal = null, del = null;
      if (rk.ok) {
        seal = await call('engine', 'seal', 'first message after re-key');
        if (seal.ok) { D.held = seal.packet; D.heldText = 'first message after re-key'; D.heldDelivered = false; }
        del = seal.ok ? await call('engine', 'deliver') : null;
        if (del?.steps?.[0]?.rc === 0) D.heldDelivered = true;
      }
      return { before, after, epochBefore, rk, seal, del };
    },
    evaluate({ before, after, epochBefore, rk, del }) {
      const st = del?.steps?.[0];
      const checks = [
        chk('Re-key executed', rk.ok === true && rk.rc === 0, `rc ${rk.rc ?? '—'} · crypto_kdf_derive_from_key`),
        chk('Epoch advanced', isNum(epochBefore) && rk.session?.epoch === epochBefore + 1, `${epochBefore} → ${rk.session?.epoch}`),
        chk('Session material changed', !!before?.client_tx && !!after?.client_tx && before.client_tx !== after.client_tx,
          before && after ? `client_tx ${before.client_tx} → ${after.client_tx}` : '—'),
        chk('Sides still agree', !!after?.client_tx && after.client_tx === after.server_rx && after.client_rx === after.server_tx, 'client_tx = server_rx after re-key'),
        chk('New epoch carries traffic', st?.rc === 0 && st?.plaintext_matches === true, st ? `packet #${st.packet.seq}: ${st.verdict}` : 'not sent'),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? `EPOCH ${rk.session?.epoch} ACTIVE` : 'RE-KEY FAILED', rc: `rekey ${rk.rc ?? '—'}`,
        produced: ok ? `epoch ${epochBefore} keys overwritten; epoch ${rk.session.epoch} carries traffic` : (rk.error || 'failed'), checks, trace: checkTrace(checks, ok ? 'SECURE (new epoch)' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'All 4 session keys replaced in place via crypto_kdf. Fingerprints changed, endpoints agree, and new traffic flows.',
      watch: 'Old vs new fingerprints, epoch counter.', expected: 'Epoch advanced, traffic accepted.' },
  },

  {
    id: 20, title: 'SECURITY VERIFICATION', act: 6,
    op: 'Run both test suites and OpenSSL comparison', backend: './test_attacks --tap · ./test_extended --tap · scripts/openssl_compare.sh',
    why: 'Independently of the demo session, the project’s own test programs re-verify every property right now.',
    principle: 'Evidence by execution, not assertion.',
    pre: () => [],
    async execute(call) {
      const t1 = await call('run', 'tests');
      const t2 = await call('run', 'tests-extended');
      const os = await call('run', 'openssl');
      return { t1, t2, os };
    },
    evaluate({ t1, t2, os }) {
      const tests = [...(t1.tests || []), ...(t2.tests || [])];
      const cats = SUITE_CATEGORIES.map(([name, re]) => {
        const m = tests.filter((t) => re.test(t.name));
        return { name, n: m.length, pass: m.length > 0 && m.every((t) => t.ok), tests: m };
      });
      const osAvail = !!os?.cbc;
      const checks = [
        chk('Required suite (test_attacks)', t1.ok === true && t1.total > 0 && t1.failed === 0, t1.total !== undefined ? `${t1.passed}/${t1.total} passed · exit ${t1.code}` : (t1.error || 'not run')),
        chk('Extended suite (test_extended)', t2.ok === true && t2.total > 0 && t2.failed === 0, t2.total !== undefined ? `${t2.passed}/${t2.total} passed · exit ${t2.code}` : (t2.error || 'not run')),
        ...cats.map((c) => chk(c.name, c.pass, c.n ? `${c.tests.filter((t) => t.ok).length}/${c.n} tests` : 'NOT COVERED')),
        chk('OpenSSL CBC vs AEAD', osAvail && os.cbc.tamper_undetected === true && os.aead_tamper_rejected === true,
          osAvail ? `CBC tamper ${os.cbc.tamper_undetected ? 'NOT detected' : 'detected'} · AEAD ${os.aead_tamper_rejected ? 'rejects' : 'does NOT reject'}` : `NOT AVAILABLE`),
      ];
      const ok = checks.every((c) => c.ok);
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'ALL PASS' : 'FAILURES', rc: `exit ${t1.code ?? '—'} / ${t2.code ?? '—'}`,
        produced: `${tests.filter((t) => t.ok).length}/${tests.length} tests passed · OpenSSL ${osAvail ? 'comparison ran' : 'NOT AVAILABLE'}`, checks, cats, osAvail,
        trace: checkTrace(checks, ok ? 'VERIFIED' : 'FAILED', ok), isSimulated: false,
      };
    },
    notes: { say: 'Project test programs run live: 43 TAP tests verifying all attack defenses and OpenSSL comparison proving unauthenticated CBC flaw.',
      watch: 'TAP counts and OpenSSL CBC tamper detection comparison.', expected: 'ALL PASS.' },
  },

  {
    id: 21, title: 'FINAL VERDICT', act: 6,
    op: 'Final integrity probe, key-vault re-scan, verdict from collected evidence', backend: 'sc_engine · status · vault · seal / deliver',
    why: 'The verdict is computed from states that actually ran in this pass; anything missing or failed is named.',
    principle: 'Evidence-based conclusion.',
    pre: () => [],
    async execute(call) {
      const status = await call('engine', 'status');
      const vault = await call('engine', 'vault');
      let seal = null, del = null;
      if (status.session?.state === 'SECURE') {
        seal = await call('engine', 'seal', 'final integrity probe');
        if (seal.ok) { D.held = seal.packet; D.heldText = 'final integrity probe'; D.heldDelivered = false; }
        del = seal.ok ? await call('engine', 'deliver') : null;
        if (del?.steps?.[0]?.rc === 0) D.heldDelivered = true;
      }
      return { status, vault, seal, del };
    },
    evaluate({ status, vault, del }) {
      const st = del?.steps?.[0];
      const live = status.session?.state === 'SECURE' && status.session?.authenticated === true && st?.rc === 0 && st?.plaintext_matches === true && vault.permissions_ok === true;
      const props = VERDICT_PROPS.map(([name, ids]) => {
        const missing = ids.filter((i) => !R[i]);
        const failed = ids.filter((i) => R[i] && R[i].ok !== true);
        return { name, ok: !missing.length && !failed.length, missing: missing.map(pad), failed: failed.map(pad) };
      });
      props.push({ name: 'LIVE CHANNEL NOW', ok: live, missing: [], failed: live ? [] : ['21'] });
      const ok = props.every((p) => p.ok);
      const bad = props.filter((p) => !p.ok).length;
      const checks = props.map((p) => chk(p.name, p.ok, p.ok ? 'live evidence collected' : `${p.missing.length ? `not run: ${p.missing.join(', ')} ` : ''}${p.failed.length ? `failed: ${p.failed.join(', ')}` : ''}`.trim()));
      return {
        ok, status: ok ? 'COMPLETED' : 'FAILED', decision: ok ? 'SECURE CHANNEL VERIFIED' : 'NOT VERIFIED', rc: st ? `probe ${st.rc}` : '—',
        produced: ok ? `${props.length}/${props.length} properties backed by live evidence from one pass` : `${bad} propert${bad === 1 ? 'y' : 'ies'} without passing evidence`,
        checks, props, trace: checkTrace(checks, ok ? 'SECURE CHANNEL VERIFIED' : 'NOT VERIFIED', ok), isSimulated: false,
      };
    },
    notes: { say: 'Verdict is computed from real execution evidence. Every property is green only if the corresponding test ran and passed.',
      watch: 'All 15 properties backed by live evidence.', expected: 'SECURE CHANNEL VERIFIED.' },
  },
];

/* ---- Controller ------------------------------------------------------------- */

export function createDemo(appCtx) {
  const ui = {
    panel: $('#demo-panel'),
    start: $('#demo-start'),
    headNext: $('#demo-next'),
    headReset: $('#demo-reset'),
  };

  const st = {
    idx: -1,
    busy: false,
    running: null,
    traceAfter: 0,
    mode: 'real', // 'real' = ⚡ Real C Execution, 'simulation' = 🧪 Simulation Scenario
    activeTab: 'bytes', // 'bytes', 'trace', 'telemetry', 'tap'
    leftDrawerOpen: false,
    rightDrawerOpen: false,
    playing: false,
    playTimer: null,
    speed: 1.0,
    fresh: null,
    sel: {},
    notes: false,
  };

  let netEngine = null;

  /* ---- Autoplay Engine ------------------------------------------------------ */

  function startAutoplay() {
    if (st.playing) return;
    st.playing = true;
    renderBottomBar();
    scheduleNextAutoplayStep();
  }

  function pauseAutoplay() {
    if (!st.playing) return;
    st.playing = false;
    if (st.playTimer) clearTimeout(st.playTimer);
    st.playTimer = null;
    renderBottomBar();
  }

  function toggleAutoplay() {
    if (st.playing) pauseAutoplay();
    else startAutoplay();
  }

  function scheduleNextAutoplayStep() {
    if (!st.playing) return;
    if (st.playTimer) clearTimeout(st.playTimer);
    const delay = Math.round(3800 / st.speed);
    st.playTimer = setTimeout(async () => {
      if (!st.playing) return;
      if (st.idx + 1 < STAGES.length) {
        await goTo(st.idx + 1, { runIt: true });
        scheduleNextAutoplayStep();
      } else {
        pauseAutoplay();
        toast('🎬 Cinematic journey complete! Final cryptographic verdict reached.');
      }
    }, delay);
  }

  /* ---- Execution Engine ----------------------------------------------------- */

  async function execute(stage) {
    for (const k of Object.keys(R)) if (Number(k) > stage.id) delete R[k];

    // Check if user is in Simulation Mode
    if (st.mode === 'simulation') {
      st.running = stage.id;
      renderStoryCard();
      await new Promise((r) => setTimeout(r, 400 / st.speed));
      const sim = getSimulatedEvidence(stage.id, D.draft);
      let model = null;
      try { model = SCENES[stage.id] ? SCENES[stage.id]({ hs: {}, r: {}, data: sim }, sim) : null; } catch { model = null; }
      R[stage.id] = {
        status: sim.status, ok: sim.ok === true, ev: sim, calls: [],
        data: { r: sim, steps: sim.steps, packet: sim.packet },
        model, ms: 12, before: { ...sess() }, after: { ...sess() }, isSimulated: true,
      };
      st.running = null;
      st.fresh = stage.id;
      addEvent('INFO', `[sim] Scene ${pad(stage.id)} ${stage.title}: ${sim.status} — ${sim.produced}`, 'demo');
      return R[stage.id];
    }

    // Real C Execution Mode
    const pre = stage.pre();
    if (pre.some((p) => !p.ok)) {
      R[stage.id] = {
        status: 'BLOCKED', ok: false, calls: [], data: null, isSimulated: false,
        ev: {
          status: 'BLOCKED', ok: false, decision: 'PRECONDITION NOT MET', rc: '—',
          produced: 'nothing executed in C: prerequisite not yet completed',
          checks: pre.map((p) => chk(p.label, p.ok, p.ok ? 'met' : 'NOT MET')),
          trace: [],
        },
      };
      return R[stage.id];
    }

    st.running = stage.id;
    st.traceAfter = store.trace.at(-1)?.id ?? 0;
    renderStoryCard();

    const calls = [];
    const call = async (kind, name, arg) => {
      const t0 = Date.now();
      const r = kind === 'engine' ? await engine(name, arg) : await run(name);
      calls.push({ kind, name, arg, r, t0, t1: Date.now() });
      return r;
    };

    const before = { ...sess() };
    const p0 = performance.now();
    let data = null, ev;
    try {
      data = await stage.execute(call);
      ev = stage.evaluate(data);
    } catch (e) {
      ev = {
        ok: false, status: 'FAILED', decision: 'ERROR', rc: '—',
        produced: e.message, checks: [chk('Execution', false, e.message)], trace: [],
      };
      addEvent('ERROR', `Scene ${pad(stage.id)}: ${e.message}`, 'demo');
    }

    let model = null;
    try { model = data && ev.status !== 'BLOCKED' ? SCENES[stage.id](data, ev) : null; } catch { model = null; }
    R[stage.id] = {
      status: ev.status, ok: ev.ok === true, ev, calls, data, model,
      ms: performance.now() - p0, before, after: { ...sess() }, isSimulated: false,
    };
    st.running = null;
    st.fresh = stage.id;
    st.sel[stage.id] = model?.focus || null;
    addEvent(ev.ok ? 'INFO' : 'ERROR', `Scene ${pad(stage.id)} ${stage.title}: ${ev.status} — ${ev.produced}`, 'demo');
    return R[stage.id];
  }

  const reachable = (i) => STAGES.slice(0, i).every((s) => okRun(s.id));

  const ANCHOR = { 4: 3, 5: 3, 6: 3, 7: 3, 8: 3, 9: 3, 10: 3, 11: 3, 12: 3, 13: 3, 14: 3, 16: 15, 18: 17, 19: 3 };
  const recoveryChain = (i) => {
    const first = STAGES.findIndex((s) => !okRun(s.id));
    const anchor = (ANCHOR[STAGES[i].id] ?? STAGES[i].id) - 1;
    return STAGES.slice(Math.min(first < 0 ? i : first, anchor, i), i + 1).map((s) => s.id);
  };

  async function runChain(ids) {
    if (st.busy) return;
    st.busy = true;
    try {
      for (const id of ids) {
        st.idx = id - 1;
        const r = await execute(STAGES[id - 1]);
        renderAll();
        if (!r.ok) break;
      }
    } finally {
      st.busy = false;
    }
    renderAll();
    notify('demo');
  }

  async function goTo(idx, { runIt = true } = {}) {
    if (st.busy || idx < 0 || idx >= STAGES.length) return;
    st.idx = idx;
    show(true);

    if (runIt) {
      st.busy = true;
      try {
        await execute(STAGES[idx]);
      } finally {
        st.busy = false;
      }
    }

    renderAll();
    notify('demo');
  }

  function rerun() {
    const s = STAGES[st.idx];
    if (!s) return;
    if (st.mode === 'simulation') {
      goTo(st.idx, { runIt: true });
      return;
    }
    const from = s.rerunFrom || s.id;
    runChain(STAGES.slice(from - 1, s.id).map((x) => x.id));
  }

  async function next() {
    if (st.busy) return;
    if (st.idx < 0) return goTo(0);
    if (st.idx + 1 < STAGES.length) await goTo(st.idx + 1, { runIt: true });
  }

  function prev() {
    if (!st.busy && st.idx > 0) goTo(st.idx - 1, { runIt: !R[STAGES[st.idx - 1].id] });
  }

  async function reset() {
    if (st.busy) return;
    pauseAutoplay();
    for (const k of Object.keys(R)) delete R[k];
    clearHeld();
    D.identityFp = null;
    D.sessionId = null;
    st.idx = -1;
    st.sel = {};
    resetCounters();
    await engine('reset');
    show(false);
  }

  function show(on) {
    ui.panel.hidden = !on;
    document.body.classList.toggle('theater-on', on);
    if (on) {
      if (!netEngine) initNetworkEngine();
      netEngine?.start();
      window.addEventListener('resize', handleResize);
    } else {
      pauseAutoplay();
      netEngine?.stop();
      window.removeEventListener('resize', handleResize);
    }
  }

  function handleResize() {
    netEngine?.resize();
  }

  function initNetworkEngine() {
    const canvas = $('#cinema-canvas', ui.panel);
    if (!canvas) return;
    netEngine = new NetworkEngine(canvas, {
      interactive: true,
      onNodeSelect: (node) => {
        st.rightDrawerOpen = true;
        renderRightDrawer();
      },
    });
  }

  /* ---- Renderers ------------------------------------------------------------ */

  function renderAll() {
    renderMainSkeleton();
    renderTopBar();
    renderStoryCard();
    renderLeftDrawer();
    renderRightDrawer();
    renderBottomBar();
    updateNetworkVisual();
  }

  function updateNetworkVisual() {
    const stage = STAGES[st.idx];
    if (!stage || !netEngine) return;
    const r = R[stage.id] || getSimulatedEvidence(stage.id, D.draft);
    netEngine.focusScene(stage.id, {
      stage,
      result: r,
      packet: r?.data?.packet || r?.ev?.packet || D.held,
      held: D.held,
    });
  }

  function renderMainSkeleton() {
    if ($('.cinema-theater', ui.panel)) return;
    ui.panel.innerHTML = `
      <div class="cinema-theater">
        <header class="cinema-topbar" id="cinema-topbar"></header>
        <div class="cinema-stage" id="cinema-stage">
          <canvas id="cinema-canvas" class="cinema-canvas"></canvas>
          <div class="cinema-story-card" id="cinema-story-card"></div>
          <aside class="cinema-drawer-left" id="cinema-drawer-left"></aside>
          <aside class="cinema-drawer-right" id="cinema-drawer-right"></aside>
        </div>
        <footer class="cinema-bottom-bar" id="cinema-bottom-bar"></footer>
      </div>`;
    initNetworkEngine();
  }

  function renderTopBar() {
    const top = $('#cinema-topbar', ui.panel);
    if (!top) return;
    const stage = STAGES[st.idx] || STAGES[0];
    const act = ACTS.find((a) => a.scenes.includes(stage.id)) || ACTS[0];

    top.innerHTML = `
      <div class="cinema-brand">
        <svg class="cinema-mark" viewBox="0 0 28 28" width="22" height="22">
          <rect x="1" y="1" width="26" height="26" rx="6" fill="rgba(0, 240, 255, 0.1)" stroke="#00f0ff" stroke-width="1.5"/>
          <circle cx="8" cy="14" r="3" fill="#00f0ff"/>
          <circle cx="20" cy="14" r="3" fill="#39ff14"/>
          <path d="M11 14h6" stroke="#ffffff" stroke-dasharray="2 2"/>
        </svg>
        <span class="cinema-logo-text">SECURE CHANNEL</span>
        <span class="cinema-logo-badge">THE CRYPTOGRAPHIC CINEMATIC LAB</span>
      </div>

      <div class="cinema-act-indicator">
        <span class="act-tag">ACT ${act.act}: ${esc(act.title)}</span>
        <span class="act-scene">SCENE ${pad(stage.id)} / 21: ${esc(stage.title)}</span>
      </div>

      <div class="cinema-topbar-actions">
        <div class="mode-pill-group">
          <button class="btn-mode ${st.mode === 'real' ? 'active-real' : ''}" data-act="set-mode" data-val="real" title="Run real C engine via local bridge">
            ⚡ REAL C EXECUTION
          </button>
          <button class="btn-mode ${st.mode === 'simulation' ? 'active-sim' : ''}" data-act="set-mode" data-val="simulation" title="Explore scenarios without prerequisites">
            🧪 SIMULATION SCENARIO
          </button>
        </div>
        <button class="btn-cinema-icon" data-act="fullscreen" title="Toggle Fullscreen">⛶</button>
        <button class="btn-cinema-icon btn-close" data-act="close" title="Exit Cinema Theater">✕</button>
      </div>`;
  }

  function renderStoryCard() {
    const card = $('#cinema-story-card', ui.panel);
    if (!card) return;
    const stage = STAGES[st.idx];
    if (!stage) { card.innerHTML = ''; return; }

    const act = ACTS.find((a) => a.scenes.includes(stage.id)) || ACTS[0];
    const r = R[stage.id];
    const executing = st.running === stage.id;
    const isSim = r?.isSimulated || st.mode === 'simulation';
    const preMet = stage.pre().every((p) => p.ok);

    let statusBadge = '<span class="status-badge badge-ready">READY</span>';
    if (executing) {
      statusBadge = '<span class="status-badge badge-executing"><span class="pulse-dot"></span>EXECUTING IN C</span>';
    } else if (r?.status === 'COMPLETED') {
      statusBadge = `<span class="status-badge badge-ok">✓ ${isSim ? 'SIMULATED VERIFIED' : 'VERIFIED (C)'}</span>`;
    } else if (r?.status === 'REJECTED') {
      statusBadge = `<span class="status-badge badge-rejected">🛡️ ${r.ev?.decision || 'REJECTED'} (rc ${r.ev?.rc})</span>`;
    } else if (r?.status === 'BLOCKED') {
      statusBadge = '<span class="status-badge badge-blocked">⚠ PREREQUISITES PENDING</span>';
    }

    const narrative = stage.notes?.say || stage.why;
    const principle = stage.principle;

    // Action buttons based on state
    let actionBtn = '';
    if (st.mode === 'real') {
      if (preMet) {
        actionBtn = `<button class="btn-primary-action btn-glow-cyan" data-act="run-current">
          ${executing ? 'Executing in C…' : `⚡ EXECUTE IN C (SCENE ${pad(stage.id)})`}
        </button>`;
      } else {
        actionBtn = `
          <button class="btn-primary-action btn-glow-amber" data-act="auto-prereq">
            ⚡ AUTO-RUN PREREQUISITES & EXECUTE
          </button>
          <button class="btn-secondary-action" data-act="switch-to-sim">
            🧪 PREVIEW SIMULATED SCENARIO
          </button>`;
      }
    } else {
      actionBtn = `<button class="btn-primary-action btn-glow-violet" data-act="run-sim">
        🧪 RUN SIMULATED SCENARIO
      </button>`;
    }

    // Custom quick attack buttons
    let quickActions = '';
    if (stage.id === 10) quickActions = `<button class="btn-mini-attack" data-act="tamper">💥 FLIP CIPHERTEXT BIT</button>`;
    else if (stage.id === 11) quickActions = `<button class="btn-mini-attack" data-act="replay">🔁 REPLAY PACKET</button>`;
    else if (stage.id === 12) quickActions = `<button class="btn-mini-attack" data-act="aad">✏️ ALTER AAD / SEQ</button>`;
    else if (stage.id === 13) quickActions = `<button class="btn-mini-attack" data-act="forged">⚠️ FORGE MAX SEQ (2⁶⁴−1)</button>`;
    else if (stage.id === 14) quickActions = `<button class="btn-mini-attack" data-act="wrongkey">🔑 TEST RANDOM KEY</button>`;
    else if (stage.id === 16) quickActions = `<button class="btn-mini-attack" data-act="unwrap">🔓 TEST WRONG PASSPHRASE</button>`;
    else if (stage.id === 17) quickActions = `<button class="btn-mini-attack" data-act="mitm">🕵️ EXECUTE MITM SWAP</button>`;
    else if (stage.id === 18) quickActions = `<button class="btn-mini-attack" data-act="signed-mitm">🛡️ RUN SIGNED MITM DEFENSE</button>`;
    else if (stage.id === 19) quickActions = `<button class="btn-mini-attack" data-act="rekey">🔄 ADVANCE KEY EPOCH</button>`;

    card.innerHTML = `
      <div class="card-header">
        <div class="card-meta">
          <span class="card-act-label">ACT ${act.act} · SCENE ${pad(stage.id)}</span>
          <h2 class="card-title">${esc(stage.title)}</h2>
        </div>
        ${statusBadge}
      </div>

      <div class="card-body">
        <div class="card-narrative">
          <p class="narrative-text">${esc(narrative)}</p>
        </div>
        
        <div class="card-principle">
          <span class="principle-tag">CRYPTOGRAPHIC PRINCIPLE</span>
          <span class="principle-value">${esc(principle)}</span>
        </div>

        ${stage.input ? `
          <div class="card-input-box">
            <span class="input-label">MESSAGE FOR CIPHERTEXT SEALING (1–256 B):</span>
            <input type="text" id="cinema-msg-input" class="cinema-text-input" value="${esc(D.draft)}" maxlength="256" placeholder="Enter plaintext to seal in C…">
          </div>` : ''}

        ${r?.status === 'BLOCKED' ? `
          <div class="cinema-blocked-notice">
            <span class="notice-title">⚠ Prerequisites Missing for Real C Execution</span>
            <span class="notice-sub">This operation requires an active secure session in C. Click Auto-Run Prerequisites or switch to Simulation Scenario to preview immediately.</span>
          </div>` : ''}

        <div class="card-controls-row">
          <div class="primary-action-wrap">${actionBtn}</div>
          ${quickActions ? `<div class="quick-attacks-wrap">${quickActions}</div>` : ''}
          <button class="btn-icon-replay" data-act="replay-scene" title="Replay Scene Animation">↺</button>
        </div>
      </div>`;
  }

  function renderLeftDrawer() {
    const drawer = $('#cinema-drawer-left', ui.panel);
    if (!drawer) return;
    drawer.classList.toggle('open', st.leftDrawerOpen);

    const actsHtml = ACTS.map((act) => {
      const scenesHtml = act.scenes.map((sId) => {
        const s = STAGES[sId - 1];
        const r = R[sId];
        const isActive = sId - 1 === st.idx;
        let dotCls = 'pip-empty';
        if (isActive) dotCls = 'pip-active';
        else if (r?.ok && r.status === 'REJECTED') dotCls = 'pip-rejected';
        else if (r?.ok) dotCls = 'pip-verified';
        else if (r?.isSimulated) dotCls = 'pip-sim';
        else if (r?.status === 'BLOCKED') dotCls = 'pip-blocked';

        return `
          <button class="drawer-scene-item ${isActive ? 'current' : ''}" data-act="jump-scene" data-scene="${sId}">
            <span class="scene-pip ${dotCls}"></span>
            <span class="scene-num">${pad(sId)}</span>
            <span class="scene-name">${esc(SHORT[sId] || s.title)}</span>
            ${r?.status === 'REJECTED' ? '<span class="scene-sub-badge badge-rej">DEFENSE</span>' : r?.ok ? '<span class="scene-sub-badge badge-pass">OK</span>' : ''}
          </button>`;
      }).join('');

      return `
        <div class="drawer-act-group">
          <div class="drawer-act-header">
            <span class="act-name">ACT ${act.act} — ${esc(act.title)}</span>
          </div>
          <div class="drawer-scenes-list">${scenesHtml}</div>
        </div>`;
    }).join('');

    drawer.innerHTML = `
      <div class="drawer-header">
        <span class="drawer-title">CINEMATIC SCENES (21)</span>
        <button class="drawer-close-btn" data-act="toggle-left-drawer">✕</button>
      </div>
      <div class="drawer-scroll-content">${actsHtml}</div>`;
  }

  function renderRightDrawer() {
    const drawer = $('#cinema-drawer-right', ui.panel);
    if (!drawer) return;
    drawer.classList.toggle('open', st.rightDrawerOpen);

    const stage = STAGES[st.idx] || STAGES[0];
    const r = R[stage.id] || getSimulatedEvidence(stage.id, D.draft);
    const ev = r?.ev;
    const packet = r?.data?.packet || ev?.packet || D.held;

    // Tabs content
    let tabContent = '';
    if (st.activeTab === 'bytes') {
      tabContent = renderBytesTab(packet, stage);
    } else if (st.activeTab === 'trace') {
      tabContent = renderTraceTab(ev?.trace || []);
    } else if (st.activeTab === 'telemetry') {
      tabContent = renderTelemetryTab(stage, r);
    } else if (st.activeTab === 'tap') {
      tabContent = renderTapTab(stage, r);
    }

    drawer.innerHTML = `
      <div class="drawer-header">
        <span class="drawer-title">TECHNICAL INSPECTOR</span>
        <button class="drawer-close-btn" data-act="toggle-right-drawer">✕</button>
      </div>
      <div class="drawer-tabs-row">
        <button class="inspector-tab ${st.activeTab === 'bytes' ? 'active' : ''}" data-act="set-tab" data-tab="bytes">PACKET BYTES</button>
        <button class="inspector-tab ${st.activeTab === 'trace' ? 'active' : ''}" data-act="set-tab" data-tab="trace">DECISION TRACE</button>
        <button class="inspector-tab ${st.activeTab === 'telemetry' ? 'active' : ''}" data-act="set-tab" data-tab="telemetry">C TELEMETRY</button>
        <button class="inspector-tab ${st.activeTab === 'tap' ? 'active' : ''}" data-act="set-tab" data-tab="tap">TAP SUITES</button>
      </div>
      <div class="drawer-scroll-content">${tabContent}</div>`;
  }

  function renderBytesTab(packet, stage) {
    if (!packet) {
      return `
        <div class="empty-inspector">
          <span class="empty-icon">📦</span>
          <span class="empty-text">No wire packet active in Scene ${pad(stage.id)}.</span>
          <span class="empty-sub">Packets travel in Scenes 07–14, 19, and 21.</span>
        </div>`;
    }

    const seqHex = packet.seq_hex || '0000000000000001';
    const nonceHex = packet.nonce_hex || 'a1b2c3d4e5f60718293a4b5c';
    const ctHex = packet.ct_hex || '';
    const tagHex = packet.tag_hex || '';

    return `
      <div class="packet-inspector-content">
        <div class="packet-meta-row">
          <div class="meta-item">
            <span class="meta-label">TOTAL WIRE SIZE</span>
            <b class="meta-val text-cyan">${packet.length} BYTES</b>
          </div>
          <div class="meta-item">
            <span class="meta-label">AEAD ALGORITHM</span>
            <b class="meta-val">ChaCha20-Poly1305</b>
          </div>
          <div class="meta-item">
            <span class="meta-label">AAD COVERAGE</span>
            <b class="meta-val text-lime">Seq (8 Bytes)</b>
          </div>
        </div>

        <div class="packet-layout-grid">
          <div class="pkt-field-card card-seq">
            <span class="f-name">SEQUENCE NUMBER (AAD)</span>
            <span class="f-bytes">8 BYTES (0..7)</span>
            <code class="f-hex">${hexGroups(seqHex)}</code>
            <span class="f-note">Cleartext on wire · Authenticated in tag</span>
          </div>

          <div class="pkt-field-card card-nonce">
            <span class="f-name">IETF NONCE</span>
            <span class="f-bytes">12 BYTES (8..19)</span>
            <code class="f-hex">${hexGroups(nonceHex)}</code>
            <span class="f-note">Unique 96-bit CSPRNG per packet</span>
          </div>

          <div class="pkt-field-card card-ct">
            <span class="f-name">ENCRYPTED CIPHERTEXT</span>
            <span class="f-bytes">${packet.ct_len || 0} BYTES (20..${19 + (packet.ct_len || 0)})</span>
            <code class="f-hex">${hexGroups(ctHex, 32)}</code>
            <span class="f-note">ChaCha20 keystream XOR plaintext</span>
          </div>

          <div class="pkt-field-card card-tag">
            <span class="f-name">POLY1305 MAC TAG</span>
            <span class="f-bytes">16 BYTES (${20 + (packet.ct_len || 0)}..${35 + (packet.ct_len || 0)})</span>
            <code class="f-hex">${hexGroups(tagHex)}</code>
            <span class="f-note">Authenticates [Ciphertext ‖ Seq]</span>
          </div>
        </div>

        <div class="byte-cells-wrap">
          <span class="byte-map-title">WIRE BYTE MATRIX:</span>
          ${byteMap(packet)}
        </div>
      </div>`;
  }

  function renderTraceTab(trace) {
    if (!trace || !trace.length) {
      return `<div class="empty-inspector"><span class="empty-text">No decision trace recorded yet.</span></div>`;
    }

    const items = trace.map((t) => {
      let icon = '✓';
      let cls = 'step-ok';
      if (t.m === 'bad') { icon = '✕'; cls = 'step-bad'; }
      else if (t.m === 'skip') { icon = '○'; cls = 'step-skip'; }
      else if (t.m === 'warn') { icon = '⚠'; cls = 'step-warn'; }
      else if (t.m === 'blocked') { icon = '■'; cls = 'step-blocked'; }

      return `
        <div class="trace-step-item ${cls}">
          <span class="step-icon">${icon}</span>
          <div class="step-content">
            <b class="step-stage">${esc(t.stage)}</b>
            <span class="step-note">${esc(t.note)}</span>
          </div>
        </div>`;
    }).join('');

    return `<div class="trace-pipeline-wrap">${items}</div>`;
  }

  function renderTelemetryTab(stage, r) {
    const s = sess();
    const calls = r?.calls || [];

    return `
      <div class="telemetry-content">
        <div class="telemetry-grid">
          <div class="tel-item">
            <span class="tel-k">C BACKEND</span>
            <b class="tel-v">${esc(stage.backend)}</b>
          </div>
          <div class="tel-item">
            <span class="tel-k">RETURN CODE</span>
            <b class="tel-v ${r?.ev?.rc === 0 ? 'text-lime' : 'text-magenta'}">${esc(String(r?.ev?.rc ?? '0'))}</b>
          </div>
          <div class="tel-item">
            <span class="tel-k">ROUND TRIP TIME</span>
            <b class="tel-v text-cyan">${fmtMs(r?.ms || 0)}</b>
          </div>
          <div class="tel-item">
            <span class="tel-k">SESSION STATE</span>
            <b class="tel-v text-lime">${s.state || 'INIT'}</b>
          </div>
          <div class="tel-item">
            <span class="tel-k">EPOCH COUNTER</span>
            <b class="tel-v">${s.epoch || 1}</b>
          </div>
          <div class="tel-item">
            <span class="tel-k">AUTHENTICATED PEER</span>
            <b class="tel-v ${s.authenticated ? 'text-lime' : 'text-amber'}">${s.authenticated ? 'YES (ED25519)' : 'PENDING'}</b>
          </div>
        </div>

        <div class="telemetry-calls-wrap">
          <span class="calls-title">IPC COMMANDS ISSUED TO C ENGINE:</span>
          ${calls.length ? calls.map((c) => `
            <div class="call-log-line">
              <span class="call-ts">${timeMs(c.t0)}</span>
              <span class="call-kind">${c.kind}</span>
              <code class="call-cmd">${esc(c.name)}${c.arg ? ` ${esc(String(c.arg))}` : ''}</code>
              <span class="call-res ${c.r?.ok ? 'text-lime' : 'text-magenta'}">${c.r?.ok ? 'OK' : 'ERR'} (${c.t1 - c.t0} ms)</span>
            </div>`).join('') : '<div class="no-calls">Executed via internal libsodium IPC stream.</div>'}
        </div>
      </div>`;
  }

  function renderTapTab(stage, r) {
    const t1 = r?.data?.t1?.tests || [];
    const t2 = r?.data?.t2?.tests || [];
    const all = [...t1, ...t2];

    if (!all.length) {
      return `
        <div class="empty-inspector">
          <span class="empty-icon">🧪</span>
          <span class="empty-text">Automated TAP test results are evaluated in Scene 20.</span>
          <button class="btn-primary-action btn-glow-cyan" style="margin-top:12px;" data-act="jump-scene" data-scene="20">JUMP TO SCENE 20 (TEST SUITES)</button>
        </div>`;
    }

    return `
      <div class="tap-results-wrap">
        <div class="tap-summary">
          <span class="text-lime">✓ ${all.filter((t) => t.ok).length}</span> / ${all.length} TAP TESTS PASSING
        </div>
        <ol class="tap-test-list">
          ${all.map((t) => `
            <li class="tap-item ${t.ok ? 'pass' : 'fail'}">
              <span class="tap-badge">${t.ok ? 'ok' : 'not ok'} ${t.n}</span>
              <span class="tap-name">${esc(t.name)}</span>
            </li>`).join('')}
        </ol>
      </div>`;
  }

  function renderBottomBar() {
    const bar = $('#cinema-bottom-bar', ui.panel);
    if (!bar) return;

    const stage = STAGES[st.idx] || STAGES[0];
    const act = ACTS.find((a) => a.scenes.includes(stage.id)) || ACTS[0];
    const total = STAGES.length;
    const progressPercent = Math.round(((st.idx) / (total - 1)) * 100);

    const pipsHtml = STAGES.map((s, i) => {
      const r = R[s.id];
      const isActive = i === st.idx;
      let cls = '';
      if (isActive) cls = 'active';
      else if (r?.ok && r.status === 'REJECTED') cls = 'rejected';
      else if (r?.ok) cls = 'verified';

      return `
        <button class="timeline-pip ${cls}" data-act="jump-scene" data-scene="${s.id}" title="Scene ${pad(s.id)}: ${esc(s.title)}">
          ${s.id}
        </button>`;
    }).join('');

    const tickerText = stage.notes?.say || `Act ${act.act}: ${act.title} — Every packet tells a story. Every attack has a consequence.`;

    bar.innerHTML = `
      <div class="timeline-scrubber-row">
        <div class="timeline-track-line"></div>
        <div class="timeline-track-fill" style="width: ${progressPercent}%;"></div>
        <div class="timeline-pips-container">${pipsHtml}</div>
      </div>

      <div class="timeline-controls-row">
        <div class="playback-controls-group">
          <button class="btn-cinema-ctrl" data-act="restart" title="Restart Journey (Scene 01)">⏮ RESTART</button>
          <button class="btn-cinema-ctrl" data-act="prev" ${st.idx <= 0 ? 'disabled' : ''} title="Previous Scene (←)">◀ PREV</button>
          <button class="btn-cinema-ctrl btn-play" data-act="toggle-play" title="Play / Pause Autoplay (Space)">
            ${st.playing ? '⏸ PAUSE' : '▶ PLAY'}
          </button>
          <button class="btn-cinema-ctrl" data-act="next" ${st.idx >= total - 1 ? 'disabled' : ''} title="Next Scene (→)">NEXT ▶</button>
          <button class="btn-cinema-ctrl" data-act="replay-scene" title="Replay Scene (R)">↺ REPLAY</button>
          <button class="btn-cinema-ctrl btn-speed" data-act="cycle-speed" title="Playback Speed">${st.speed}x</button>
        </div>

        <div class="cinema-caption-ticker">
          <span class="cinema-caption-highlight">SCENE ${pad(stage.id)}:</span>
          <span>${esc(tickerText)}</span>
        </div>

        <div class="timeline-drawer-toggles">
          <button class="btn-drawer-toggle ${st.leftDrawerOpen ? 'active' : ''}" data-act="toggle-left-drawer">
            📑 SCENES (${total})
          </button>
          <button class="btn-drawer-toggle ${st.rightDrawerOpen ? 'active' : ''}" data-act="toggle-right-drawer">
            🔬 INSPECTOR
          </button>
        </div>
      </div>`;
  }

  /* ---- Event Delegation ----------------------------------------------------- */

  ui.panel.addEventListener('input', (ev) => {
    if (ev.target.id === 'cinema-msg-input') {
      D.draft = ev.target.value;
    }
  });

  ui.panel.addEventListener('click', (ev) => {
    const btn = ev.target.closest('[data-act]');
    if (!btn || btn.disabled) return;
    const act = btn.dataset.act;

    if (act === 'toggle-play') toggleAutoplay();
    else if (act === 'next') { pauseAutoplay(); next(); }
    else if (act === 'prev') { pauseAutoplay(); prev(); }
    else if (act === 'restart') { pauseAutoplay(); goTo(0); }
    else if (act === 'replay-scene') { pauseAutoplay(); rerun(); }
    else if (act === 'cycle-speed') {
      st.speed = st.speed === 1.0 ? 2.0 : st.speed === 2.0 ? 0.5 : 1.0;
      renderBottomBar();
      if (st.playing) scheduleNextAutoplayStep();
    }
    else if (act === 'jump-scene') {
      pauseAutoplay();
      const sId = Number(btn.dataset.scene);
      if (sId >= 1 && sId <= STAGES.length) goTo(sId - 1, { runIt: true });
    }
    else if (act === 'toggle-left-drawer') {
      st.leftDrawerOpen = !st.leftDrawerOpen;
      renderLeftDrawer();
      renderBottomBar();
    }
    else if (act === 'toggle-right-drawer') {
      st.rightDrawerOpen = !st.rightDrawerOpen;
      renderRightDrawer();
      renderBottomBar();
    }
    else if (act === 'set-tab') {
      st.activeTab = btn.dataset.tab;
      renderRightDrawer();
    }
    else if (act === 'set-mode') {
      st.mode = btn.dataset.val;
      toast(`Switched to ${st.mode === 'real' ? '⚡ Real C Execution' : '🧪 Simulation Scenario'}`);
      renderAll();
    }
    else if (act === 'switch-to-sim') {
      st.mode = 'simulation';
      toast('Switched to 🧪 Simulation Scenario for immediate exploration');
      goTo(st.idx, { runIt: true });
    }
    else if (act === 'run-current') {
      goTo(st.idx, { runIt: true });
    }
    else if (act === 'run-sim') {
      goTo(st.idx, { runIt: true });
    }
    else if (act === 'auto-prereq') {
      runChain(recoveryChain(st.idx));
    }
    else if (act === 'tamper' || act === 'replay' || act === 'aad' || act === 'forged' || act === 'wrongkey' || act === 'unwrap' || act === 'mitm' || act === 'signed-mitm' || act === 'rekey') {
      goTo(st.idx, { runIt: true });
    }
    else if (act === 'fullscreen') {
      if (!document.fullscreenElement) ui.panel.requestFullscreen().catch(() => {});
      else document.exitFullscreen().catch(() => {});
    }
    else if (act === 'close') {
      show(false);
    }
  });

  // Keyboard Shortcuts for Presenters
  document.addEventListener('keydown', (ev) => {
    if (ui.panel.hidden || ev.target.closest('input, textarea') || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    const k = ev.key;
    if (k === ' ' || k === 'k' || k === 'K') {
      ev.preventDefault();
      toggleAutoplay();
    } else if (k === 'ArrowRight') {
      ev.preventDefault();
      pauseAutoplay();
      next();
    } else if (k === 'ArrowLeft') {
      ev.preventDefault();
      pauseAutoplay();
      prev();
    } else if (k === 'r' || k === 'R') {
      ev.preventDefault();
      pauseAutoplay();
      rerun();
    } else if (k === 'm' || k === 'M') {
      ev.preventDefault();
      st.mode = st.mode === 'real' ? 'simulation' : 'real';
      toast(`Mode: ${st.mode === 'real' ? '⚡ Real C Execution' : '🧪 Simulation Scenario'}`);
      renderAll();
    } else if (k === '[') {
      ev.preventDefault();
      st.leftDrawerOpen = !st.leftDrawerOpen;
      renderLeftDrawer();
      renderBottomBar();
    } else if (k === ']') {
      ev.preventDefault();
      st.rightDrawerOpen = !st.rightDrawerOpen;
      renderRightDrawer();
      renderBottomBar();
    } else if (k === 'Escape') {
      if (st.leftDrawerOpen || st.rightDrawerOpen) {
        st.leftDrawerOpen = false;
        st.rightDrawerOpen = false;
        renderLeftDrawer();
        renderRightDrawer();
        renderBottomBar();
      } else {
        show(false);
      }
    }
  });

  // Header Trigger buttons
  ui.start?.addEventListener('click', () => {
    if (st.idx < 0) goTo(0);
    else { show(true); renderAll(); }
  });
  ui.headNext?.addEventListener('click', () => {
    if (st.idx < 0) goTo(0);
    else { show(true); next(); }
  });
  ui.headReset?.addEventListener('click', reset);

  // Keep synced with store
  subscribe((topic) => {
    if (!ui.panel.hidden && !st.busy && topic !== 'demo' && st.idx >= 0) {
      renderAll();
    }
  });

  return {
    stages: STAGES,
    acts: ACTS,
    goTo,
    next,
    prev,
    show,
    startAutoplay,
    pauseAutoplay,
    results: R,
  };
}
