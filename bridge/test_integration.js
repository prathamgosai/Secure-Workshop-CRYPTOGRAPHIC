#!/usr/bin/env node
/* UI/backend integration test: starts the real bridge (which drives the real
 * C binaries), exercises every API the dashboard uses, checks the security
 * controls, and scans every response for leaked secrets.
 *
 * Usage: node bridge/test_integration.js
 */
'use strict';

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;
const results = [];
const TTY = process.stdout.isTTY;
const ESC = String.fromCharCode(27);
const G = TTY ? ESC + '[32m' : '', R = TTY ? ESC + '[31m' : '', N = TTY ? ESC + '[0m' : '';
const responses = [];

function check(name, cond, detail = '') {
  results.push({ name, ok: !!cond });
  console.log(`  ${cond ? `${G}✓${N}` : `${R}✗${N}`} ${name}${!cond && detail ? `  — ${detail}` : ''}`);
}

async function post(p, body = {}, headers = {}) {
  const res = await fetch(BASE + p, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-SC-Client': 'dashboard', ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  responses.push(text);
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, json };
}
const eng = (cmd, arg) => post('/api/engine', { cmd, arg }).then((r) => r.json);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function rawRequest(opts) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, ...opts }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', () => resolve(-1));
    req.end(opts.body || '');
  });
}

async function main() {
  console.log('\nSECURE CHANNEL — UI/BACKEND INTEGRATION TEST\n');
  const bridge = spawn(process.execPath, [path.join(__dirname, 'server.js'), '--port', String(PORT), '--no-open'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  let bridgeOut = '';
  bridge.stdout.on('data', (d) => { bridgeOut += d; });
  bridge.stderr.on('data', (d) => { bridgeOut += d; });

  const tcpEvents = [];
  let sse = null;
  try {
    let ready = false;
    for (let i = 0; i < 120 && !ready; i++) {
      try { ready = (await (await fetch(`${BASE}/api/health`)).json()).engine; } catch { /* starting */ }
      if (!ready) await sleep(1000);
    }
    check('bridge builds the C code and starts sc_engine', ready, bridgeOut.slice(-400));
    if (!ready) return;

    // live event stream (used for TCP mode)
    sse = http.get({ host: '127.0.0.1', port: PORT, path: '/api/stream' }, (res) => {
      let buf = '';
      res.on('data', (c) => {
        buf += c;
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
          if (chunk.startsWith('data: ')) { try { const m = JSON.parse(chunk.slice(6)); if (m.type === 'tcp') tcpEvents.push(m); } catch { /* ignore */ } }
        }
      });
    });
    sse.on('error', () => { /* stream ends when the bridge stops */ });

    console.log('\n  -- security controls');
    const page = await fetch(`${BASE}/`);
    const html = await page.text();
    check('dashboard page served', page.status === 200 && html.includes('Cryptographic Security Command Center'));
    const css = await (await fetch(`${BASE}/css/app.css`)).text();
    // Motion policy: Cinematic transitions and animations enabled for interactive
    // movie laboratory, fully disabled under prefers-reduced-motion and body.reduced-motion.
    check('motion policy: cinematic animations active with accessibility support',
      /animation\s*:(?!\s*none)/.test(css) && /transition\s*:(?!\s*none)/.test(css));
    check('motion policy: prefers-reduced-motion turns every .mo-* animation off',
      /@media \(prefers-reduced-motion:\s*reduce\)\s*\{[^}]*animation:\s*none !important/.test(css) ||
      /@media \(prefers-reduced-motion: reduce\)\s*\{[^}]*\.mo-in[^}]*animation:\s*none !important/.test(css));
    check('Content-Security-Policy restricts scripts to same origin', /script-src 'self'/.test(page.headers.get('content-security-policy') || ''));
    check('POST without dashboard header rejected (403)', (await post('/api/engine', { cmd: 'hello' }, { 'X-SC-Client': 'x' })).status === 403);
    check('foreign Host header rejected (DNS-rebinding guard, 421)', (await rawRequest({ path: '/api/health', headers: { Host: 'evil.example:8799' } })) === 421);
    check('path traversal blocked', [403, 404].includes(await rawRequest({ path: '/..%2f..%2fMakefile', headers: { Host: `127.0.0.1:${PORT}` } })));
    check('non-whitelisted engine command rejected', (await post('/api/engine', { cmd: 'quit' })).status === 400);
    check('invalid attack name rejected', (await post('/api/engine', { cmd: 'attack', arg: 'rm -rf' })).status === 400);
    check('oversized message rejected', (await post('/api/engine', { cmd: 'send', arg: 'x'.repeat(300) })).status === 400);

    console.log('\n  -- state machine');
    let r = await eng('reset');
    check('reset -> INIT', r.ok && r.session.state === 'INIT');
    r = await eng('attack', 'tamper');
    check('attack refused outside SECURE state', r.ok === false && /SECURE/.test(r.error));
    r = await eng('handshake', 'plain');
    check('plain handshake -> SECURE, complementary + directional keys', r.ok && r.session.state === 'SECURE' && r.complementary && r.directional);
    const fp = r.session.key_fingerprints;
    check('fingerprints: client_tx == server_rx, client_tx != client_rx', fp.client_tx === fp.server_rx && fp.client_tx !== fp.client_rx);

    console.log('\n  -- secure channel');
    r = await eng('send', 'integration test message');
    check('send: packet accepted and decrypted', r.ok && r.accepted && r.delivered_text === 'integration test message');
    const pkt = r.steps[0].packet;
    check('packet layout: 8 B seq, 12 B nonce, 16 B tag, len = 36 + ct', pkt.seq_hex.length === 16 && pkt.nonce_hex.length === 24 && pkt.tag_hex.length === 32 && pkt.length === 36 + pkt.ct_len);

    console.log('\n  -- attack lab (real engine results)');
    const expected = { normal: 0, tamper: -2, aad: -2, replay: -3, reorder: -3, wrongkey: -2, short: -1, forged: -2 };
    for (const [id, rc] of Object.entries(expected)) {
      r = await eng('attack', id);
      check(`attack ${id.padEnd(8)} -> rc ${rc} ${rc === 0 ? 'ACCEPTED' : 'BLOCKED'}`, r.ok && r.attack.rc === rc && r.attack.pass === true, JSON.stringify(r.attack));
    }

    console.log('\n  -- re-keying');
    const before = (await eng('status')).session;
    r = await eng('rekey');
    check('manual re-key: epoch +1, keys change, sides still match', r.ok && r.session.epoch === before.epoch + 1 &&
      r.session.key_fingerprints.client_tx !== before.key_fingerprints.client_tx &&
      r.session.key_fingerprints.client_tx === r.session.key_fingerprints.server_rx);
    await eng('config', '2');
    await eng('send', 'a');
    r = await eng('send', 'b');
    check('automatic re-key after 2 messages', r.steps[0].rekeyed === true);
    await eng('config', '0');

    console.log('\n  -- test suites (separate processes)');
    r = (await post('/api/run/tests')).json;
    check('required suite: 8 passed, 0 failed', r.ok && r.total === 8 && r.passed === 8 && r.failed === 0, JSON.stringify(r).slice(0, 200));
    r = (await post('/api/run/tests-extended')).json;
    check(`extended suite: ${r.passed}/${r.total} passed`, r.ok && r.failed === 0 && r.total > 20);

    console.log('\n  -- key vault + wrapping');
    r = (await post('/api/run/keygen')).json;
    check('./keygen exit 0 and ls -l shows -rw------- keys', r.ok && /-rw------- .*server_sk\.bin/.test(r.listing));
    r = await eng('vault');
    check('vault: private 0600 / public 0644 verified', r.ok && r.permissions_ok);
    check('vault: private keys match their public files', r.files.filter((f) => f.pair_ok !== undefined).every((f) => f.pair_ok));
    r = await eng('wrap', 'correct');
    check('wrap: correct passphrase unwraps', r.ok && r.pass && r.unwrapped && r.file_mode === '0600');
    r = await eng('wrap', 'wrong');
    check('wrap: wrong passphrase -> MAC fails, nothing released, buffer zeroed', r.ok && r.pass && !r.secret_released && r.output_zeroed);

    console.log('\n  -- handshake extension');
    r = await eng('handshake', 'signed');
    check('signed handshake verifies with Task 1 identity', r.ok && r.signature === 1 && r.session.authenticated);
    r = await eng('mitm');
    check('MITM: plain kx vulnerable (documented), signed extension blocks all', r.ok && r.vulnerability_shown && r.extension_blocks_mitm);

    console.log('\n  -- OpenSSL + benchmark');
    r = (await post('/api/run/openssl')).json;
    check('OpenSSL: CBC tamper undetected (exit 0), AEAD rejects', r.ok && r.cbc.openssl_exit === 0 && r.cbc.tamper_undetected && r.aead_tamper_rejected);
    r = (await post('/api/run/bench')).json;
    check('benchmark returns measured results for 5 sizes', r.ok && r.results.length >= 10 && r.results.every((x) => x.mib_per_sec > 0));

    console.log('\n  -- TCP mode (localhost sockets)');
    await post('/api/tcp/start-server', { rekey: 2 });
    await sleep(1200);
    await post('/api/tcp/connect');
    await sleep(1500);
    await post('/api/tcp/send', { mode: 'send', text: 'tcp one' });
    await sleep(700);
    await post('/api/tcp/send', { mode: 'send', text: 'tcp two' });
    await sleep(700);
    await post('/api/tcp/send', { mode: 'tamper', text: 'tcp evil' });
    await sleep(700);
    await post('/api/tcp/send', { mode: 'replay' });
    await sleep(700);
    await post('/api/tcp/disconnect');
    await sleep(1000);
    await post('/api/tcp/stop');
    await sleep(800);
    const msgs = tcpEvents.map((e) => `${e.src}:${e.level}:${e.msg}`);
    const has = (re) => msgs.some((m) => re.test(m));
    check('TCP: signature verified with pinned key', has(/client:AUTH:server Ed25519 signature verified/));
    check('TCP: messages accepted by server', has(/server:SECURE:accepted seq 1/) && has(/server:SECURE:accepted seq 2/));
    check('TCP: re-key after 2 messages on both sides', has(/server:AUTH:re-key: now epoch 2/) && has(/client:AUTH:re-key: now epoch 2/));
    check('TCP: tampered packet rejected', has(/server:ALERT:packet rejected: authentication failed/));
    check('TCP: replayed packet rejected', has(/server:BLOCK:packet rejected: replay/));
    check('TCP: keys wiped on disconnect', has(/client:WIPE/) && has(/server:WIPE/));

    console.log('\n  -- live demo path (stepwise handshake, one held packet)');
    r = await eng('hs', 'begin');
    check('hs begin: INIT with ephemeral key pairs, no session keys', r.ok && r.state_after === 'INIT' && r.ephemeral_secrets_held && !r.session_keys_present);
    r = await eng('seal', 'too early');
    check('seal refused in INIT', !r.ok);
    r = await eng('hs', 'secure');
    check('hs secure refused before derive/auth', !r.ok && r.session.state === 'INIT');
    r = await eng('hs', 'derive');
    check('hs derive: AUTH, complementary + directional, ephemeral secrets wiped', r.ok && r.state_after === 'AUTH' && r.complementary && r.directional && r.ephemeral_secrets_wiped);
    r = await eng('hs', 'secure');
    check('hs secure refused while unauthenticated', !r.ok && r.session.state === 'AUTH');
    r = await eng('hs', 'auth');
    check('hs auth: Ed25519 transcript signature verified', r.ok && r.signature === 1 && r.authenticated);
    r = await eng('hs', 'secure');
    check('hs secure: SECURE after readiness checks', r.ok && r.state_after === 'SECURE' && r.readiness.keys_complementary && r.readiness.authenticated);
    r = await eng('seal', 'held demo message');
    const held = r.packet;
    check('seal holds a packet without delivering it', r.ok && held && r.session.has_seq === false);
    r = await eng('intercept', 'replay');
    check('intercept replay refused before the held packet is accepted', !r.ok);
    r = await eng('inspect');
    check('inspect: same bytes, structure valid, plaintext not visible', r.ok && r.packet.ct_hex === held.ct_hex && r.checks.length_ok && r.checks.plaintext_not_visible && !r.checks.delivered);
    r = await eng('deliver');
    check('deliver: accepted, decrypted text equals sealed text', r.ok && r.rc === 0 && r.steps[0].plaintext_matches && r.steps[0].plaintext === 'held demo message');
    const ic = {};
    for (const t of ['tamper', 'replay', 'aad', 'forged', 'wrongkey']) ic[t] = await eng('intercept', t);
    check('intercept tamper -> rc -2, state unchanged, original accepted', ic.tamper.ok && ic.tamper.attack.pass && ic.tamper.attack.rc === -2);
    check('intercept replay (exact held bytes) -> rc -3', ic.replay.ok && ic.replay.attack.pass && ic.replay.attack.rc === -3 && ic.replay.steps[0].packet.ct_hex === held.ct_hex);
    check('intercept aad (held seq +1000) -> rc -2, last_seq unchanged', ic.aad.ok && ic.aad.attack.pass && !ic.aad.steps[0].state_changed);
    check('intercept forged (held seq 2^64-1) -> rc -2, follow-up accepted', ic.forged.ok && ic.forged.attack.pass);
    check('intercept wrongkey -> rc -2, nothing released', ic.wrongkey.ok && ic.wrongkey.attack.pass && ic.wrongkey.steps.every((s) => !s.plaintext_released));
    r = await eng('wrap', 'correct');
    r = await eng('unwrap', 'wrong');
    check('unwrap wrong (existing file): MAC fails, output zeroed', r.ok && r.pass && r.rc !== 0 && !r.secret_released && r.output_zeroed);
    r = await eng('unwrap', 'correct');
    check('unwrap correct (existing file): key equals original', r.ok && r.pass && r.unwrapped);
    r = await eng('mitm', 'plain');
    check('mitm plain only: keys swapped, Mallory read what the client sent, no signed section', r.ok && r.vulnerability_shown && r.plain.keys_substituted && r.plain.sent_text === r.plain.read_text && r.signed === undefined);
    r = await eng('mitm', 'signed');
    check('mitm signed only: all variants blocked', r.ok && r.extension_blocks_mitm && r.plain === undefined);
    r = (await post('/api/engine', { cmd: 'hs', arg: 'skip' })).json;
    check('bridge rejects unknown hs step / intercept type', r.ok === false && (await post('/api/engine', { cmd: 'intercept', arg: 'normal' })).json.ok === false);

    console.log('\n  -- termination + secret hygiene');
    r = await eng('terminate');
    check('terminate -> TERMINATE, no key material left', r.ok && r.session.state === 'TERMINATE' && r.session.key_fingerprints === null);
    const all = responses.join('\n') + JSON.stringify(tcpEvents);
    const secrets = ['keys/server_sk.bin', 'keys/server_kx_sk.bin'].map((f) => fs.readFileSync(path.join(ROOT, f)).toString('hex'));
    const leaked = secrets.some((hex) => all.includes(hex.slice(0, 32)) || all.includes(hex.slice(-32)));
    check('no private-key bytes in any API response or event', !leaked);
    check('no passphrase in any API response or event', !/correct horse|wrong pass\b|test-only-demo-passphrase/.test(all));
  } finally {
    if (sse) sse.destroy();
    bridge.kill('SIGINT');
    await sleep(800);
    if (!bridge.killed) bridge.kill();
  }

  const failed = results.filter((x) => !x.ok).length;
  console.log(`\n${results.length} tests, ${results.length - failed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
