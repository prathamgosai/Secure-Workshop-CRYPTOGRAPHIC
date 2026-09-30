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

function runC(cmd, cmdArgs = [], timeoutMs = 120000) {
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

/* Whitelist + validation. Returns the engine line or throws. */
function engineLine(cmd, arg) {
  const simple = ['hello', 'status', 'vault', 'rekey', 'mitm', 'terminate', 'reset'];
  if (simple.includes(cmd)) return cmd;
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

async function runAction(what) {
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
  return host === `127.0.0.1:${PORT}` || host === `localhost:${PORT}`;
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

const server = http.createServer(async (req, res) => {
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
      return send(res, 200, await engineCall(line));
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
});

/* ---- startup / shutdown ---------------------------------------------------- */

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  log('shutting down: engine quit, TCP processes stopped');
  try { engine.proc?.stdin.write('quit\n'); } catch { /* already gone */ }
  if (tcp.client) tcp.client.stdin.end('quit\n');
  if (tcp.server) await runC('pkill', ['-TERM', '-f', `sc_server --port ${TCP_PORT}`], 5000);
  setTimeout(() => process.exit(0), 300);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

(async () => {
  log(IS_WIN ? `running C binaries through WSL (${DISTRO})` : 'running C binaries natively');
  log('building (make -s all)...');
  const b = await runC('make', ['-s', 'all'], 300000);
  if (b.code !== 0) {
    console.error(b.stdout + b.stderr);
    console.error('[bridge] build failed - fix the errors above and retry');
    process.exit(1);
  }
  startEngine();
  server.on('error', (e) => {
    console.error(`[bridge] cannot listen on 127.0.0.1:${PORT}: ${e.message}`);
    process.exit(1);
  });
  server.listen(PORT, '127.0.0.1', () => {
    const url = `http://localhost:${PORT}`;
    console.log(`\n  SECURE CHANNEL // CRYPTOGRAPHIC COMMAND CENTER\n  ${url}\n  (Ctrl+C to stop)\n`);
    if (OPEN_BROWSER && IS_WIN) spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  });
})();

