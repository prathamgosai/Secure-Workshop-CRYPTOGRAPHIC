#!/usr/bin/env node
/* Local bridge between the dashboard and the real C binaries.
 *
 * - Serves dashboard/ and a small JSON API on 127.0.0.1 only.
 * - Keeps one sc_engine process alive (it holds the live session in
 *   sodium_malloc memory); every command is whitelisted and validated here.
 * - Runs the other binaries (keygen, test suites, benchmark, OpenSSL script)
 *   on demand and returns their real output.
 * - On Windows everything runs inside WSL (`wsl -d <distro> -- ...`).
 *
 * No secrets pass through this process: the C programs only emit public
 * values, return codes and one-way fingerprints.
 *
 * Usage: node bridge/server.js [--port 8787] [--no-open]
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const readline = require('readline');

const ROOT = path.resolve(__dirname, '..');
const STATIC = path.join(ROOT, 'dashboard');
const args = process.argv.slice(2);
const PORT = Number(argValue('--port') || process.env.SC_PORT || 8787);
const OPEN_BROWSER = !args.includes('--no-open') && !process.env.SC_NO_OPEN;
const DISTRO = process.env.SC_WSL_DISTRO || 'Ubuntu';
const IS_WIN = process.platform === 'win32';
const TCP_PORT = 7700;
const MAX_BODY = 4096;

function argValue(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

/* ---- running the C programs --------------------------------------------- */

function spawnC(cmd, cmdArgs = []) {
  // NO_COLOR keeps terminal colour codes out of captured output.
  const full = ['env', 'NO_COLOR=1', cmd, ...cmdArgs];
  return IS_WIN
    ? spawn('wsl', ['-d', DISTRO, '--', ...full], { cwd: ROOT, windowsHide: true })
    : spawn(full[0], full.slice(1), { cwd: ROOT });
}

/* On Windows every `wsl -d ... -- cmd` costs ~1 s just to start. One-shot
 * programs therefore run through a single persistent WSL bash ("worker"),
 * one at a time; each job's stdout/stderr come back base64-encoded on one
 * marker line together with the real exit code. The engine and the TCP
 * processes keep their own long-running processes. */
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const worker = { proc: null, buf: '', jobs: new Map(), queue: Promise.resolve(), seq: 0 };

function startWorker() {
  const proc = spawn('wsl', ['-d', DISTRO, '--', 'bash', '--noprofile', '--norc'], { cwd: ROOT, windowsHide: true });
  worker.proc = proc;
  worker.buf = '';
  proc.stdout.on('data', (d) => {
    worker.buf += d;
    let i;
    while ((i = worker.buf.indexOf('\n')) >= 0) {
      const line = worker.buf.slice(0, i);
      worker.buf = worker.buf.slice(i + 1);
      // fields are prefixed with '=' so an empty output still matches
      const m = /^__SC__ (\d+) (-?\d+) =(\S*) =(\S*)$/.exec(line.trim());
      if (!m) continue;
      const job = worker.jobs.get(Number(m[1]));
      if (!job) continue;
      worker.jobs.delete(Number(m[1]));
      job.done({ code: Number(m[2]), stdout: Buffer.from(m[3], 'base64').toString('utf8'), stderr: Buffer.from(m[4], 'base64').toString('utf8') });
    }
  });
  proc.stderr.on('data', () => { /* job stderr is captured per job */ });
  proc.on('close', () => {
    if (worker.proc === proc) worker.proc = null;
    for (const [, job] of worker.jobs) job.done({ code: -1, stdout: '', stderr: 'WSL worker exited' });
    worker.jobs.clear();
  });
  return proc;
}

function runInWorker(cmd, cmdArgs, timeoutMs) {
  const exec = () => new Promise((resolve) => {
    const proc = worker.proc || startWorker();
    const id = ++worker.seq;
    const timer = setTimeout(() => {          // a hung job: kill the worker, a fresh one starts on demand
      if (worker.jobs.has(id)) { worker.jobs.delete(id); proc.kill(); resolve({ code: -1, stdout: '', stderr: 'timeout' }); }
    }, timeoutMs);
    worker.jobs.set(id, { done: (r) => { clearTimeout(timer); resolve(r); } });
    const line = [cmd, ...cmdArgs].map(shq).join(' ');
    proc.stdin.write(`env NO_COLOR=1 ${line} </dev/null >/tmp/.sc_out_$$ 2>/tmp/.sc_err_$$; ` +
      `printf '__SC__ %s %s %s %s\\n' ${id} $? "=$(base64 -w0 /tmp/.sc_out_$$)" "=$(base64 -w0 /tmp/.sc_err_$$)"\n`);
  });
  const p = worker.queue.then(exec, exec);
  worker.queue = p.catch(() => {});
  return p;
}

function runC(cmd, cmdArgs = [], timeoutMs = 120000) {
  if (IS_WIN) return runInWorker(cmd, cmdArgs, timeoutMs);
  return new Promise((resolve) => {
    const child = spawnC(cmd, cmdArgs);
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, stdout, stderr: String(e) }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

/* ---- sc_engine: one long-running process, one JSON line per command ------ */

const engine = { proc: null, ready: false, queue: [], info: null, busy: Promise.resolve() };

function startEngine() {
  const proc = spawnC('./sc_engine');
  engine.proc = proc;
  engine.ready = false;
  const rl = readline.createInterface({ input: proc.stdout });
  rl.on('line', (line) => {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (msg.cmd === 'ready') {
      engine.ready = true;
      engine.info = msg;
      broadcast({ type: 'engine', status: 'ready', libsodium: msg.libsodium });
      return;
    }
    const waiter = engine.queue.shift();
    if (waiter) waiter(msg);
  });
  proc.stderr.on('data', (d) => log('engine stderr: ' + String(d).trim()));
  proc.on('close', (code) => {
    engine.ready = false;
    while (engine.queue.length) engine.queue.shift()({ ok: false, error: 'engine exited' });
    broadcast({ type: 'engine', status: 'stopped', code });
    if (!shuttingDown) {
      log(`sc_engine exited (${code}); restarting in 1 s`);
      setTimeout(startEngine, 1000);
    }
  });
}

/* Commands are serialised: the engine answers strictly in order. */
function engineCall(line) {
  const run = () => new Promise((resolve) => {
    if (!engine.proc || !engine.ready) return resolve({ ok: false, error: 'engine not ready' });
    const timer = setTimeout(() => resolve({ ok: false, error: 'engine timeout' }), 30000);
    engine.queue.push((msg) => { clearTimeout(timer); resolve(msg); });
    engine.proc.stdin.write(line + '\n');
  });
  const p = engine.busy.then(run, run);
  engine.busy = p.catch(() => {});
  return p;
}

const ATTACKS = ['normal', 'tamper', 'aad', 'replay', 'reorder', 'wrongkey', 'short', 'forged'];
const INTERCEPTS = ['tamper', 'replay', 'aad', 'forged', 'wrongkey'];

/* Whitelist + validation. Returns the engine line or throws. */
function engineLine(cmd, arg) {
  const simple = ['hello', 'status', 'vault', 'rekey', 'terminate', 'reset', 'inspect', 'deliver'];
  if (simple.includes(cmd)) return cmd;
  if (cmd === 'mitm') {
    if (!['', 'plain', 'signed'].includes(arg)) throw new Error('mitm part must be plain or signed');
    return arg ? `mitm ${arg}` : 'mitm';
  }
  if (cmd === 'hs') {
    if (!['begin', 'derive', 'auth', 'secure'].includes(arg)) throw new Error('hs step must be begin, derive, auth or secure');
    return `hs ${arg}`;
  }
  if (cmd === 'intercept') {
    if (!INTERCEPTS.includes(arg)) throw new Error('unknown intercept');
    return `intercept ${arg}`;
  }
  if (cmd === 'unwrap') {
    if (!['correct', 'wrong'].includes(arg)) throw new Error('unwrap must be correct or wrong');
    return `unwrap ${arg}`;
  }
  if (cmd === 'seal') return `seal ${cleanText(arg)}`;
  if (cmd === 'handshake') {
    if (!['plain', 'signed'].includes(arg)) throw new Error('handshake mode must be plain or signed');
    return `handshake ${arg}`;
  }
  if (cmd === 'attack') {
    if (!ATTACKS.includes(arg)) throw new Error('unknown attack');
    return `attack ${arg}`;
  }
  if (cmd === 'wrap') {
    if (!['correct', 'wrong'].includes(arg)) throw new Error('wrap must be correct or wrong');
    return `wrap ${arg}`;
  }
  if (cmd === 'config') {
    const n = Number(arg);
    if (!Number.isInteger(n) || n < 0 || n > 1000) throw new Error('rekey_every must be 0..1000');
    return `config rekey_every ${n}`;
  }
  if (cmd === 'send') return `send ${cleanText(arg)}`;
  throw new Error('command not allowed');
}

function cleanText(t) {
  if (typeof t !== 'string') throw new Error('text required');
  const s = t.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  const bytes = Buffer.byteLength(s, 'utf8');
  if (bytes < 1 || bytes > 256) throw new Error('message must be 1-256 bytes');
  return s;
}

/* ---- TCP mode (sc_server / sc_client) ------------------------------------- */

const tcp = { server: null, client: null, rekey: 0 };
let toolchain = null;   // detected at start-up, after the build succeeds

function pipeTcp(proc, role) {
  const rl = readline.createInterface({ input: proc.stdout });
  rl.on('line', (line) => {
    try { broadcast({ type: 'tcp', ...JSON.parse(line) }); }
    catch { broadcast({ type: 'tcp', src: role, level: 'INFO', state: '', msg: line, ts: Date.now() }); }
  });
  proc.stderr.on('data', (d) => broadcast({ type: 'tcp', src: role, level: 'ERROR', state: '', msg: String(d).trim(), ts: Date.now() }));
  proc.on('close', (code) => {
    tcp[role] = null;
    broadcast({ type: 'tcp-status', role, running: false, code });
  });
}

async function tcpAction(action, body) {
  if (action === 'start-server') {
    if (tcp.server) return { ok: true, note: 'server already running' };
    const n = Number(body.rekey ?? 3);
    if (!Number.isInteger(n) || n < 0 || n > 1000) throw new Error('rekey must be 0..1000');
    await runC('pkill', ['-f', `sc_server --port ${TCP_PORT}`]);   // stale copy from a previous run
    tcp.rekey = n;
    tcp.server = spawnC('./sc_server', ['--port', String(TCP_PORT), '--rekey', String(n)]);
    pipeTcp(tcp.server, 'server');
    broadcast({ type: 'tcp-status', role: 'server', running: true });
    return { ok: true };
  }
  if (action === 'connect') {
    if (!tcp.server) throw new Error('start the server first');
    if (tcp.client) return { ok: true, note: 'client already connected' };
    tcp.client = spawnC('./sc_client', ['--port', String(TCP_PORT)]);
    pipeTcp(tcp.client, 'client');
    broadcast({ type: 'tcp-status', role: 'client', running: true });
    return { ok: true };
  }
  if (action === 'send') {
    if (!tcp.client) throw new Error('client not connected');
    const mode = body.mode || 'send';
    if (mode === 'replay') tcp.client.stdin.write('replay\n');
    else if (mode === 'send' || mode === 'tamper') tcp.client.stdin.write(`${mode} ${cleanText(body.text)}\n`);
    else throw new Error('mode must be send, tamper or replay');
    return { ok: true };
  }
  if (action === 'disconnect') {
    if (tcp.client) tcp.client.stdin.end('quit\n');
    return { ok: true };
  }
  if (action === 'stop') {
    if (tcp.client) tcp.client.stdin.end('quit\n');
    await runC('pkill', ['-TERM', '-f', `sc_server --port ${TCP_PORT}`]);
    return { ok: true };
  }
  throw new Error('unknown tcp action');
}

/* ---- one-shot runs --------------------------------------------------------- */

function parseTap(text) {
  const tests = [];
  for (const line of text.split('\n')) {
    const m = /^(not )?ok (\d+) - (.*)$/.exec(line.trim());
    if (m) tests.push({ n: Number(m[2]), ok: !m[1], name: m[3] });
  }
  const passed = tests.filter((t) => t.ok).length;
  return { tests, total: tests.length, passed, failed: tests.length - passed };
}

/* Shown in the dashboard's background-activity trace: the exact command
 * lines this bridge executed for an action (no secrets are ever arguments). */
const execLabel = (cmd, args) => [IS_WIN ? `wsl -d ${DISTRO} --` : null, 'env NO_COLOR=1', cmd, ...args].filter(Boolean).join(' ');

async function runAction(what) {
  const execs = [];
  const t0 = Date.now();
  const recorder = (cmd, args = [], ms) => { execs.push(execLabel(cmd, args)); return runC(cmd, args, ms); };
  const out = await runActionInner(what, recorder);
  out.bridge = { exec: execs, ms: Date.now() - t0 };
  return out;
}

// runC is shadowed by the recording wrapper passed in by runAction.
async function runActionInner(what, runC) {
  const started = Date.now();
  if (what === 'build') {
    const r = await runC('make', ['-s', 'all'], 300000);
    return { ok: r.code === 0, code: r.code, output: (r.stdout + r.stderr).slice(-4000) };
  }
  if (what === 'keygen') {
    const r = await runC('./keygen');
    const ls = await runC('ls', ['-l', 'keys/']);
    return { ok: r.code === 0, code: r.code, output: r.stdout.slice(-6000), listing: ls.stdout };
  }
  if (what === 'tests') {
    const r = await runC('./test_attacks', ['--tap']);
    return { ok: r.code === 0, code: r.code, suite: 'tests/test_attacks.c', ...parseTap(r.stdout), ms: Date.now() - started };
  }
  if (what === 'tests-extended') {
    const r = await runC('./test_extended', ['--tap']);
    return { ok: r.code === 0, code: r.code, suite: 'tests/test_extended.c', ...parseTap(r.stdout), ms: Date.now() - started };
  }
  if (what === 'make-test') {
    const r = await runC('make', ['-s', 'test'], 300000);
    const m = /(\d+) passed, (\d+) failed/.exec(r.stdout);
    return { ok: r.code === 0, code: r.code, passed: m ? Number(m[1]) : null, failed: m ? Number(m[2]) : null, output: r.stdout.slice(-12000) };
  }
  if (what === 'openssl') {
    const r = await runC('bash', ['scripts/openssl_compare.sh', '--json']);
    try { return { ...JSON.parse(r.stdout.trim().split('\n').pop()), code: r.code }; }
    catch { return { ok: false, code: r.code, error: 'could not parse OpenSSL script output', output: r.stderr.slice(-2000) }; }
  }
  if (what === 'bench') {
    const r = await runC('./aead_bench', ['--json', '120'], 180000);
    try { return { ...JSON.parse(r.stdout), code: r.code }; }
    catch { return { ok: false, code: r.code, error: 'could not parse benchmark output' }; }
  }
  throw new Error('unknown action');
}

/* ---- HTTP ------------------------------------------------------------------ */

const sseClients = new Set();
function broadcast(obj) {
  const data = `data: ${JSON.stringify(obj)}\n\n`;
  for (const res of sseClients) res.write(data);
}
function log(msg) {
  console.log(`[bridge] ${msg}`);
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.json': 'application/json', '.ico': 'image/x-icon',
};

const SECURITY_HEADERS = {
  // style-src-attr allows style="" attributes (layout/animation delays only);
  // scripts stay restricted to same-origin files.
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store',
};

function send(res, status, body, type = 'application/json') {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type });
  res.end(type === 'application/json' ? JSON.stringify(body) : body);
}

/* DNS-rebinding guard: only accept requests addressed to this local server. */
function hostAllowed(req) {
  const host = String(req.headers.host || '');
  return host === `127.0.0.1:${PORT}` || host === `localhost:${PORT}` || host === `[::1]:${PORT}`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new Error('invalid JSON')); }
    });
  });
}

function serveStatic(req, res) {
  const url = new URL(req.url, 'http://localhost');
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(STATIC, rel));
  if (!file.startsWith(STATIC + path.sep)) return send(res, 403, { error: 'forbidden' });
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'not found', 'text/plain');
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

async function handle(req, res) {
  if (!hostAllowed(req)) return send(res, 421, { error: 'unexpected Host header' });
  const url = new URL(req.url, 'http://localhost');

  if (!url.pathname.startsWith('/api/')) {
    if (req.method !== 'GET') return send(res, 405, { error: 'method not allowed' });
    return serveStatic(req, res);
  }

  if (url.pathname === '/api/stream' && req.method === 'GET') {
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/event-stream', Connection: 'keep-alive' });
    res.write(`data: ${JSON.stringify({ type: 'hello', engine: engine.ready })}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }
  if (url.pathname === '/api/health' && req.method === 'GET') {
    return send(res, 200, {
      ok: true, engine: engine.ready, libsodium: engine.info?.libsodium || null,
      platform: IS_WIN ? `Windows → WSL (${DISTRO})` : process.platform,
      tcp: { server: !!tcp.server, client: !!tcp.client, port: TCP_PORT },
      toolchain,
      build: buildState.status,
      build_output: buildState.status === 'failed' ? buildState.output : undefined,
      // live-demo engine commands this bridge accepts (a stale bridge lacks them)
      features: ['hs', 'seal', 'inspect', 'deliver', 'intercept', 'unwrap', 'mitm-parts'],
    });
  }

  /* Every state-changing call must be a JSON POST carrying our custom header.
   * Browsers cannot send that header cross-origin without a CORS preflight,
   * which this server never approves - so other websites cannot drive it. */
  if (req.method !== 'POST' || req.headers['x-sc-client'] !== 'dashboard' ||
      !String(req.headers['content-type'] || '').startsWith('application/json')) {
    return send(res, 403, { error: 'forbidden' });
  }

  try {
    const body = await readBody(req);
    if (url.pathname === '/api/engine') {
      const line = engineLine(String(body.cmd || ''), body.arg === undefined ? '' : String(body.arg));
      const t0 = Date.now();
      const resp = await engineCall(line);
      resp.bridge = { stdin: line, process: IS_WIN ? `wsl -d ${DISTRO} -- ./sc_engine` : './sc_engine', ms: Date.now() - t0 };
      return send(res, 200, resp);
    }
    const run = /^\/api\/run\/([a-z-]+)$/.exec(url.pathname);
    if (run) {
      const out = await runAction(run[1]);
      broadcast({ type: 'run', what: run[1], ok: out.ok, ts: Date.now() });
      return send(res, 200, out);
    }
    const t = /^\/api\/tcp\/([a-z-]+)$/.exec(url.pathname);
    if (t) return send(res, 200, await tcpAction(t[1], body));
    return send(res, 404, { error: 'not found' });
  } catch (e) {
    return send(res, 400, { ok: false, error: e.message });
  }
}
const server = http.createServer(handle);

/* ---- startup / shutdown ---------------------------------------------------- */

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  log('shutting down: engine quit, TCP processes stopped');
  try { engine.proc?.stdin.write('quit\n'); } catch { /* already gone */ }
  if (tcp.client) tcp.client.stdin.end('quit\n');
  if (tcp.server) await runC('pkill', ['-TERM', '-f', `sc_server --port ${TCP_PORT}`], 5000);
  try { worker.proc?.stdin.end('exit\n'); } catch { /* already gone */ }
  setTimeout(() => process.exit(0), 300);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

/* The page is served immediately; build, engine start-up and toolchain
 * detection follow and are reported through /api/health and the event stream. */
let buildState = { status: 'building', output: '' };
(async () => {
  log(IS_WIN ? `running C binaries through WSL (${DISTRO})` : 'running C binaries natively');
  server.on('error', (e) => {
    console.error(`[bridge] cannot listen on 127.0.0.1:${PORT}: ${e.message}`);
    process.exit(1);
  });
  // Also listen on ::1: browsers resolve "localhost" to ::1 first, and a refused
  // IPv6 connection costs ~200 ms per request before falling back to IPv4.
  const server6 = http.createServer(handle);
  server6.on('error', () => { /* no IPv6 loopback: IPv4 alone still works */ });
  server6.listen(PORT, '::1');
  server.listen(PORT, '127.0.0.1', () => {
    const url = `http://localhost:${PORT}`;
    console.log(`\n  SECURE CHANNEL // CRYPTOGRAPHIC COMMAND CENTER\n  ${url}\n  (Ctrl+C to stop)\n`);
    if (OPEN_BROWSER && IS_WIN) spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  });
  log('building (make -s all)...');
  const t0 = Date.now();
  const b = await runC('make', ['-s', 'all'], 300000);
  if (b.code !== 0) {
    buildState = { status: 'failed', output: (b.stdout + b.stderr).slice(-4000) };
    console.error(b.stdout + b.stderr);
    console.error('[bridge] build failed - fix the errors above and restart; the dashboard shows the failure');
    broadcast({ type: 'engine', status: 'build-failed' });
    return;
  }
  buildState = { status: 'ok', output: '', ms: Date.now() - t0 };
  startEngine();
  // Versions shown in the dashboard: detected (one worker job), never assumed.
  const v = await runC('sh', ['-c', 'gcc -dumpfullversion; echo ---; pkg-config --modversion libsodium; echo ---; openssl version'], 15000);
  const [gcc, sodium, ossl] = v.stdout.split('---').map((x) => x.trim().split('\n')[0] || null);
  toolchain = { gcc, libsodium: sodium, openssl: ossl, build_ok: true, build_ts: Date.now() };
  broadcast({ type: 'toolchain', toolchain });
  log(`ready in ${Date.now() - t0} ms`);
})();
