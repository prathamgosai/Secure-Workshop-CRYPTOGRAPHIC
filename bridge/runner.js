// runner.js - runs the project's C binaries (inside WSL when on Windows).
//
// Nothing here implements cryptography: every result comes from the C
// programs. The engine (sc_engine) is a long-running process that answers one
// JSON line per command; jobs (tests, keygen, openssl, benchmark) are one-shot.
'use strict';

const { spawn } = require('node:child_process');
const path = require('node:path');
const readline = require('node:readline');

const ROOT = path.resolve(__dirname, '..');
const IS_WIN = process.platform === 'win32';
const DISTRO = process.env.SC_WSL_DISTRO || 'Ubuntu';

function command(args) {
  // On Windows, wsl.exe starts in the Linux path of the current directory.
  if (IS_WIN) return { cmd: 'wsl', args: ['-d', DISTRO, '--', ...args] };
  return { cmd: args[0], args: args.slice(1) };
}

function spawnProject(args) {
  const c = command(args);
  return spawn(c.cmd, c.args, { cwd: ROOT, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
}

// One-shot job: resolves with exit code and captured output (never rejects).
function runJob(args, { timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    let stdout = '';
    let stderr = '';
    let done = false;
    const child = spawnProject(args);
    const finish = (code, error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr, ms: Date.now() - started, error });
    };
    const timer = setTimeout(() => { child.kill(); finish(-1, 'timeout'); }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => finish(-1, e.message));
    child.on('close', (code) => finish(code));
    child.stdin.end();
  });
}

// Parses TAP ("ok N - name" / "not ok N - name") into a result list.
function parseTap(text) {
  const tests = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^(not )?ok (\d+) - (.*)$/.exec(line);
    if (m) tests.push({ n: Number(m[2]), name: m[3], ok: !m[1] });
  }
  return { tests, passed: tests.filter((t) => t.ok).length, failed: tests.filter((t) => !t.ok).length };
}

function lastJsonLine(text) {
  const lines = text.trim().split(/\r?\n/).reverse();
  for (const l of lines) {
    try { return JSON.parse(l); } catch { /* keep looking */ }
  }
  return null;
}

// Long-running sc_engine with a FIFO of pending commands.
class Engine {
  constructor(onExit) {
    this.child = null;
    this.pending = [];
    this.ready = null;
    this.onExit = onExit;
  }

  start() {
    if (this.child) return this.ready;
    const child = spawnProject(['./sc_engine']);
    this.child = child;
    const rl = readline.createInterface({ input: child.stdout });
    this.ready = new Promise((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    rl.on('line', (line) => {
      let msg;
      try { msg = JSON.parse(line); } catch { return; }
      if (msg.cmd === 'ready') { this.readyResolve(msg); return; }
      const p = this.pending.shift();
      if (p) p.resolve(msg);
    });
    child.stderr.on('data', () => { /* engine never writes secrets; ignore noise */ });
    child.on('close', (code) => {
      this.child = null;
      this.readyReject?.(new Error('engine exited'));
      for (const p of this.pending.splice(0)) p.reject(new Error('engine exited'));
      this.onExit?.(code);
    });
    child.on('error', (e) => this.readyReject?.(e));
    return this.ready;
  }

  async send(line) {
    await this.start();
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.child.stdin.write(line + '\n');
    });
  }

  stop() {
    if (this.child) this.child.stdin.end('quit\n');
  }
}

// A streaming process (TCP server/client) whose JSON lines go to onEvent.
function startStream(args, onEvent, onExit) {
  const child = spawnProject(args);
  readline.createInterface({ input: child.stdout }).on('line', (line) => {
    try { onEvent(JSON.parse(line)); } catch { onEvent({ level: 'INFO', msg: line }); }
  });
  child.stderr.on('data', (d) => onEvent({ level: 'ERROR', msg: String(d).trim() }));
  child.on('close', (code) => onExit?.(code));
  return child;
}

module.exports = { ROOT, IS_WIN, DISTRO, runJob, parseTap, lastJsonLine, Engine, startStream };
