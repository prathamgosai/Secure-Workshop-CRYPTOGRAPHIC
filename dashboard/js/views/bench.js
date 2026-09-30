import { store, run } from '../store.js';
import { esc, busy, emptyState, $ } from '../ui.js';

const COLORS = { 'ChaCha20-Poly1305': 'var(--cyan)', 'AES-256-GCM': 'var(--violet)', 'seal() + nonce': 'var(--green)' };
const fmtSize = (n) => (n >= 1024 ? `${n / 1024} KiB` : `${n} B`);

function barChart(b) {
  const algs = [...new Set(b.results.map((r) => r.algorithm))];
  const sizes = [...new Set(b.results.map((r) => r.size))];
  const W = 760, H = 300, L = 56, B = 34, T = 14, R = 10;
  const max = Math.max(...b.results.map((r) => r.mib_per_sec)) * 1.1;
  const gw = (W - L - R) / sizes.length;
  const bw = Math.min(26, (gw - 18) / algs.length);
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const ticks = 5;
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Throughput by message size">`;
  for (let i = 0; i <= ticks; i++) {
    const v = (max / ticks) * i;
    s += `<line class="grid-l" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text x="${L - 8}" y="${y(v) + 3}" text-anchor="end">${Math.round(v)}</text>`;
  }
  sizes.forEach((sz, gi) => {
    const gx = L + gi * gw + (gw - bw * algs.length) / 2;
    algs.forEach((a, ai) => {
      const r = b.results.find((x) => x.algorithm === a && x.size === sz);
      if (!r) return;
      const x = gx + ai * bw;
      s += `<rect class="bar" x="${x + 2}" y="${y(r.mib_per_sec)}" width="${bw - 4}" height="${H - B - y(r.mib_per_sec)}" rx="3" fill="${COLORS[a]}" opacity=".85" style="animation-delay:${(gi * algs.length + ai) * 45}ms"><title>${esc(a)} · ${fmtSize(sz)}: ${r.mib_per_sec.toFixed(1)} MiB/s</title></rect>`;
    });
    s += `<text x="${L + gi * gw + gw / 2}" y="${H - 12}" text-anchor="middle">${fmtSize(sz)}</text>`;
  });
  s += `<text x="12" y="${T + 4}" transform="rotate(-90 12 ${T + 4})" text-anchor="end">MiB/s</text>`;
  return `${s}<line class="axis" x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}"/></svg>`;
}

function latencyChart(b) {
  const algs = [...new Set(b.results.map((r) => r.algorithm))];
  const sizes = [...new Set(b.results.map((r) => r.size))];
  const W = 760, H = 260, L = 56, B = 34, T = 14, R = 16;
  const vals = b.results.map((r) => r.latency_us);
  const lo = Math.log10(Math.min(...vals) * 0.8), hi = Math.log10(Math.max(...vals) * 1.25);
  const x = (i) => L + (W - L - R) * (i / (sizes.length - 1));
  const y = (v) => T + (H - T - B) * (1 - (Math.log10(v) - lo) / (hi - lo));
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Latency per operation (log scale)">`;
  for (const v of [0.1, 0.3, 1, 3, 10, 30, 100]) {
    if (Math.log10(v) < lo || Math.log10(v) > hi) continue;
    s += `<line class="grid-l" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text x="${L - 8}" y="${y(v) + 3}" text-anchor="end">${v}</text>`;
  }
  sizes.forEach((sz, i) => { s += `<text x="${x(i)}" y="${H - 12}" text-anchor="middle">${fmtSize(sz)}</text>`; });
  algs.forEach((a) => {
    const pts = sizes.map((sz, i) => [x(i), y(b.results.find((r) => r.algorithm === a && r.size === sz).latency_us)]);
    s += `<path class="line" d="M${pts.map((p) => p.join(',')).join(' L')}" stroke="${COLORS[a]}"/>`;
    pts.forEach(([px, py], i) => {
      const r = b.results.find((q) => q.algorithm === a && q.size === sizes[i]);
      s += `<circle class="pt" cx="${px}" cy="${py}" r="3.5" fill="${COLORS[a]}" style="animation-delay:${600 + i * 80}ms"><title>${esc(a)} · ${fmtSize(sizes[i])}: ${r.latency_us.toFixed(2)} µs/op</title></circle>`;
    });
  });
  s += `<text x="12" y="${T + 4}" transform="rotate(-90 12 ${T + 4})" text-anchor="end">µs / op (log)</text>`;
  return `${s}<line class="axis" x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}"/></svg>`;
}

function table(b) {
  return `<table class="table"><thead><tr><th>ALGORITHM</th><th>MESSAGE</th><th>ITERATIONS</th><th>OPS / S</th><th>AVG LATENCY</th><th>THROUGHPUT</th></tr></thead><tbody>
    ${b.results.map((r) => `<tr><td><i style="display:inline-block;width:9px;height:9px;border-radius:2px;background:${COLORS[r.algorithm]};margin-right:8px"></i>${esc(r.algorithm)}</td>
      <td class="mono">${fmtSize(r.size)}</td><td class="mono">${r.iterations.toLocaleString()}</td>
      <td class="mono">${Math.round(r.ops_per_sec).toLocaleString()}</td><td class="mono">${r.latency_us.toFixed(2)} µs</td><td class="mono">${r.mib_per_sec.toFixed(1)} MiB/s</td></tr>`).join('')}
  </tbody></table>`;
}

export default {
  id: 'bench',
  label: 'Benchmarks',
  mount(root) {
    this.rendered = null;
    root.innerHTML = `
      <div class="page-head">
        <div><h1>PERFORMANCE BENCHMARKS</h1><p>Runs <code>./aead_bench --json</code>: encrypts 64 B – 16 KiB messages for about 120 ms per data point, timed with <code>CLOCK_MONOTONIC</code>. Every number is measured on this machine at run time.</p></div>
        <div class="actions"><button class="btn btn-primary" data-a="run">RUN BENCHMARK</button></div>
      </div>
      <div id="bn-body"></div>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a="run"]');
      if (b) busy(b, async () => { $('#bn-body').innerHTML = emptyState('Measuring… (about 2 seconds)'); await run('bench'); });
    });
    this.update();
  },
  update() {
    const b = store.bench;
    const body = $('#bn-body');
    if (!b) { if (!body.innerHTML) body.innerHTML = emptyState('No measurements yet. Results are never pre-filled or estimated.'); return; }
    if (!b.results) { body.innerHTML = `<div class="bad">${esc(b.error || 'benchmark failed')}</div>`; return; }
    const key = b.checksum + ':' + b.results.length;
    if (key === this.rendered) return;
    this.rendered = key;
    const series = [...new Set(b.results.map((r) => r.algorithm))];
    body.innerHTML = `
      <div class="grid">
        <section class="card s12"><div class="card-head"><div><div class="card-title">THROUGHPUT BY MESSAGE SIZE</div><div class="card-sub">higher is better</div></div>
          <div class="series">${series.map((a) => `<span><i style="background:${COLORS[a]}"></i>${esc(a)}</span>`).join('')}
          ${b.aes256gcm_available ? '' : '<span class="badge b-warn">AES-256-GCM: NOT AVAILABLE ON THIS PLATFORM</span>'}</div></div>
          ${barChart(b)}</section>
        <section class="card s7"><div class="card-head"><div class="card-title">AVERAGE LATENCY PER OPERATION</div><span class="card-sub">lower is better · log scale</span></div>${latencyChart(b)}</section>
        <section class="card s5"><div class="card-head"><div class="card-title">READING THE RESULTS</div></div>
          <div class="explain" style="grid-template-columns:1fr">
            <div class="ex"><h5>AES-GCM ${b.aes256gcm_available ? 'IS AVAILABLE' : 'IS UNAVAILABLE'}</h5><p>${b.aes256gcm_available ? 'This CPU has AES-NI/PCLMUL, so libsodium can use hardware AES-GCM, which is typically faster here.' : 'libsodium only enables AES-256-GCM with hardware support; it is not available on this CPU.'}</p></div>
            <div class="ex"><h5>WHY CHACHA20 ANYWAY</h5><p>ChaCha20-Poly1305 is fast and constant-time in pure software on any CPU — phones, small ARM boards — with no special instructions.</p></div>
            <div class="ex"><h5>seal() OVERHEAD</h5><p>The seal() series includes building the header and a fresh random nonce, so the gap to raw ChaCha20 is the cost of the packet format.</p></div>
          </div></section>
        <section class="card s12"><div class="card-head"><div class="card-title">RAW MEASUREMENTS</div><span class="card-sub">libsodium ${esc(b.libsodium)} · ${b.budget_ms} ms per data point</span></div>${table(b)}</section>
      </div>`;
  },
};
