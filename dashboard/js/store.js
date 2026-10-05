// Central state. Only data returned by the real C programs is stored here;
// nothing in the UI invents a result.
import { api } from './api.js';

const listeners = new Set();
let packetId = 0;

export const store = {
  engineUp: false,
  platform: '',
  libsodium: '',
  toolchain: null,       // versions detected by the bridge at start-up
  bridgeBuild: null,     // result of the make run the bridge did before starting the engine
  session: { state: 'INIT', epoch: 0, next_seq: 0, has_seq: false, last_seq: 0, authenticated: false, rekey_every: 0, key_fingerprints: null },
  stateLog: { INIT: null, AUTH: null, SECURE: null, TERMINATE: null },
  events: [],             // {ts, level, msg, src}
  packets: [],            // captured packets (public bytes only)
  deliveries: [],         // client->server results for the channel view
  attacks: { executed: 0, passed: 0, blocked: 0, failed: 0, history: [], last: null },
  handshake: null,
  mitm: null,
  vault: null,
  keygen: null,
  wrap: { correct: null, wrong: null, last: null },
  tests: null,
  testsExtended: null,
  build: null,
  openssl: null,
  bench: null,
  tcp: { server: false, client: false, events: [] },
  errors: [],
  trace: [],             // background activity: one entry per bridge call (see traceStart)
};

export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export function notify(topic) { for (const fn of listeners) fn(topic); }

export function addEvent(level, msg, src = 'dashboard', ts = Date.now()) {
  store.events.push({ ts, level, msg, src });
  if (store.events.length > 800) store.events.splice(0, store.events.length - 800);
}

function recordState(resp) {
  const s = resp.session;
  if (!s) return;
  const prev = store.session.state;
  store.session = s;
  const evs = resp.events || [];
  const first = (lvl) => evs.find((e) => e.level === lvl);
  if (resp.cmd === 'handshake' && resp.ok) {
    const init = evs[0];
    store.stateLog.INIT = store.stateLog.INIT || { ts: init?.ts || Date.now(), msg: 'libsodium ready · ephemeral X25519 key pairs generated' };
    const auth = first('AUTH');
    store.stateLog.AUTH = { ts: auth?.ts || Date.now(), msg: resp.mode === 'signed' ? 'public keys exchanged · Ed25519 signature verified · rx/tx derived' : 'public keys exchanged · rx/tx session keys derived' };
    const sec = first('SECURE');
    store.stateLog.SECURE = { ts: sec?.ts || Date.now(), msg: 'AEAD packets active · replay window active · epoch 1' };
    store.stateLog.TERMINATE = null;
  }
  if (s.state === 'TERMINATE' && prev !== 'TERMINATE') {
    const w = first('WIPE');
    store.stateLog.TERMINATE = { ts: w?.ts || Date.now(), msg: w?.msg || 'secrets wiped · session closed' };
  }
  if (resp.cmd === 'reset') {
    store.stateLog = { INIT: { ts: evs[0]?.ts || Date.now(), msg: 'session reset · awaiting handshake' }, AUTH: null, SECURE: null, TERMINATE: null };
  }
}

function capturePackets(resp) {
  for (const st of resp.steps || []) {
    if (!st.packet) continue;
    const p = {
      id: ++packetId, ts: Date.now(), cmd: resp.cmd, attack: resp.attack?.id || null,
      label: st.label, rc: st.rc, verdict: st.verdict, reason: st.reason, rekeyed: st.rekeyed,
      // the user's own message, echoed by the engine only when unseal() returned 0
      delivered: resp.cmd === 'send' && st.rc === 0 ? resp.delivered_text : undefined,
      ...st.packet,
    };
    store.packets.unshift(p);
    if (resp.cmd === 'send' || resp.cmd === 'attack') store.deliveries.unshift(p);
  }
  if (store.packets.length > 200) store.packets.length = 200;
  if (store.deliveries.length > 50) store.deliveries.length = 50;
}

/* ---- background activity trace ---------------------------------------------
 * One entry per call the dashboard makes: what was requested, what the bridge
 * actually executed (from resp.bridge), how long it took, the C engine's own
 * events and a summary built from the real response. Public data only. */
let traceId = 0;

function traceStart(kind, name, arg) {
  const t = { id: ++traceId, ts: Date.now(), t0: performance.now(), kind, name, arg, pending: true, before: store.session.state };
  store.trace.push(t);
  if (store.trace.length > 400) store.trace.splice(0, store.trace.length - 400);
  notify('trace');
  return t;
}

function traceEnd(t, resp) {
  Object.assign(t, {
    pending: false,
    ms: Math.round(performance.now() - t.t0),
    ok: resp.ok !== false,
    error: resp.error || null,
    bridge: resp.bridge || null,
    after: store.session.state,
    // engine calls: the C engine's events; test programs: each TAP line they printed
    events: resp.tests
      ? resp.tests.map((x) => ({ level: x.ok ? 'PASS' : 'FAIL', msg: `${x.ok ? 'ok' : 'not ok'} ${x.n} - ${x.name}` }))
      : (resp.events || []).map((e) => ({ level: e.level, msg: e.msg })),
    summary: summarize(t.kind, t.name, resp),
  });
}

const fx = (n, d = 2) => (typeof n === 'number' ? n.toFixed(d) : '?');
function summarize(kind, name, r) {
  if (r.ok === false && r.error) return `error: ${r.error}`;
  if (kind === 'run') {
    if (name === 'tests' || name === 'tests-extended') return r.total !== undefined ? `${r.passed}/${r.total} tests passed · exit code ${r.code}` : `exit code ${r.code}`;
    if (name === 'keygen') return `exit code ${r.code} · key files written to keys/`;
    if (name === 'openssl') return r.cbc ? `CBC tamper ${r.cbc.tamper_undetected ? 'NOT detected' : 'detected'} (openssl exit ${r.cbc.openssl_exit}) · same change under AEAD ${r.aead_tamper_rejected ? 'rejected' : 'not checked'}` : 'no result';
    if (name === 'bench') return r.results ? `${r.results.length} data points measured · libsodium ${r.libsodium}` : 'no result';
    if (name === 'build') return `make exit code ${r.code}`;
    return `exit code ${r.code}`;
  }
  const s = r.session;
  switch (name) {
    case 'hello': return `libsodium ${r.libsodium} initialised`;
    case 'vault': return `${r.files?.filter((f) => f.exists).length ?? 0} key files scanned · permissions ${r.permissions_ok ? 'OK (0600 private / 0644 public)' : 'NOT as expected'}`;
    case 'handshake': return `${r.mode} handshake · client_tx == server_rx: ${r.complementary ? 'yes' : 'no'} · tx ≠ rx: ${r.directional ? 'yes' : 'no'}${r.mode === 'signed' ? ` · Ed25519 signature ${r.signature === 1 ? 'valid' : 'invalid'}` : ''} · ${fx(r.elapsed_ms)} ms inside C`;
    case 'send': { const st = r.steps?.[0]; return st ? `seal(): ${st.packet.length} B packet, seq ${st.packet.seq} → unseal(): ${st.verdict} (rc ${st.rc})` : 'no packet'; }
    case 'attack': { const a = r.attack; return a ? `${a.title}: ${a.verdict} · rc ${a.rc} (expected ${a.expected_rc}) · ${a.pass ? 'behaved as expected' : 'UNEXPECTED'}` : 'no result'; }
    case 'wrap': return `${r.password?.startsWith('correct') ? 'correct' : 'wrong'} test passphrase · Argon2id ${r.memlimit_mib} MiB · ${r.password?.startsWith('correct') ? (r.unwrapped ? 'MAC verified, key unwrapped' : 'unwrap FAILED') : (r.secret_released ? 'secret RELEASED' : 'MAC failed, nothing released')}`;
    case 'mitm': return `plain crypto_kx: MITM ${r.vulnerability_shown ? 'read and rewrote traffic (known limitation)' : 'did not succeed'} · signed handshake: ${r.extension_blocks_mitm ? 'all MITM variants blocked' : 'NOT all blocked'}`;
    default: return s ? `state ${s.state} · epoch ${s.epoch}` : 'done';
  }
}

/* Calls the engine and folds the real response into the store. */
export async function engine(cmd, arg) {
  const t = traceStart('engine', cmd, arg);
  let resp;
  try { resp = await api.engine(cmd, arg); }
  catch (e) { resp = { ok: false, error: e.message }; }
  for (const e of resp.events || []) addEvent(e.level, e.msg, 'engine', e.ts);
  if (!resp.ok && resp.error) addEvent('ERROR', `${cmd}: ${resp.error}`, 'engine');
  recordState(resp);
  capturePackets(resp);

  if (resp.cmd === 'hello' && resp.ok) store.libsodium = resp.libsodium;
  if (resp.cmd === 'handshake') store.handshake = resp;
  if (resp.cmd === 'vault' && resp.ok) store.vault = resp;
  if (resp.cmd === 'mitm' && resp.ok) store.mitm = resp;
  if (resp.cmd === 'wrap' && resp.ok) {
    const which = resp.password.startsWith('correct') ? 'correct' : 'wrong';
    store.wrap[which] = resp;
    store.wrap.last = which;
  }
  if (resp.cmd === 'attack' && resp.ok && resp.attack) {
    const a = resp.attack;
    const at = store.attacks;
    at.executed++;
    if (a.pass) at.passed++; else at.failed++;
    if (a.result === 'BLOCKED') at.blocked++;
    at.last = resp;
    at.history.unshift({ ts: Date.now(), ...a });
  }
  if (resp.cmd === 'terminate' || resp.cmd === 'reset') store.handshake = resp.cmd === 'reset' ? null : store.handshake;
  traceEnd(t, resp);
  notify(cmd);
  return resp;
}

export async function run(what) {
  addEvent('INFO', `running ${labelFor(what)}…`, 'bridge');
  const t = traceStart('run', what);
  notify('events');
  let r;
  try { r = await api.run(what); }
  catch (e) { r = { ok: false, error: e.message }; }
  traceEnd(t, r);
  if (what === 'tests') store.tests = r;
  if (what === 'tests-extended') store.testsExtended = r;
  if (what === 'openssl') store.openssl = r;
  if (what === 'bench') store.bench = r;
  if (what === 'keygen') store.keygen = r;
  if (what === 'build') store.build = r;
  const detail = r.total !== undefined ? ` — ${r.passed}/${r.total} passed` : '';
  addEvent(r.ok ? 'INFO' : 'ERROR', `${labelFor(what)} ${r.ok ? 'completed' : 'FAILED'}${detail}`, 'bridge');
  notify(what);
  return r;
}

function labelFor(what) {
  return {
    keygen: './keygen', tests: './test_attacks (required suite)', 'tests-extended': './test_extended',
    openssl: 'scripts/openssl_compare.sh', bench: './aead_bench', build: 'make', 'make-test': 'make test',
  }[what] || what;
}

/* Overall system status, derived only from real results. */
export function systemStatus() {
  if (!store.engineUp) return { tone: 'bad', text: 'OFFLINE', detail: 'engine not running' };
  const problems = [];
  if (store.attacks.failed) problems.push(`${store.attacks.failed} attack check(s) unexpected`);
  if (store.tests && store.tests.failed) problems.push(`${store.tests.failed} required test(s) failed`);
  if (store.testsExtended && store.testsExtended.failed) problems.push('extended tests failed');
  if (store.vault && !store.vault.permissions_ok) problems.push('key permissions not 0600/0644');
  if (store.openssl && store.openssl.ok === false) problems.push('OpenSSL comparison failed');
  if (problems.length) return { tone: 'warn', text: 'WARNING', detail: problems[0] };
  const s = store.session.state;
  if (s === 'SECURE') return { tone: 'ok', text: 'SECURE', detail: `epoch ${store.session.epoch} · ${store.session.authenticated ? 'signed handshake' : 'plain crypto_kx'}` };
  if (s === 'TERMINATE') return { tone: 'muted', text: 'TERMINATED', detail: 'secrets wiped' };
  return { tone: 'info', text: 'READY', detail: `libsodium ${store.libsodium || ''} · no session` };
}

export function resetCounters() {
  store.attacks = { executed: 0, passed: 0, blocked: 0, failed: 0, history: [], last: null };
  store.packets = [];
  store.deliveries = [];
  store.handshake = null;
  store.mitm = null;
  store.wrap = { correct: null, wrong: null, last: null };
  store.tests = null;
  store.testsExtended = null;
}
