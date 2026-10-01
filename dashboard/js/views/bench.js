import { store, run } from '../store.js';
import { esc, busy, chip, emptyState, pageHead, panelHead, $ } from '../ui.js';

const COLORS = { 'ChaCha20-Poly1305': 'var(--accent)', 'AES-256-GCM': 'var(--violet)', 'seal() + nonce': 'var(--success)' };
const fmtSize = (n) => (n >= 1024 ? `${n / 1024} KiB` : `${n} B`);

function barChart(b) {
  const algs = [...new Set(b.results.map((r) => r.algorithm))];
  const sizes = [...new Set(b.results.map((r) => r.size))];
  const W = 1160, H = 320, L = 56, B = 34, T = 14, R = 10;
  const max = Math.max(...b.results.map((r) => r.mib_per_sec)) * 1.1;
  const gw = (W - L - R) / sizes.length;
  const bw = Math.min(26, (gw - 18) / algs.length);
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const ticks = 5;
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Throughput in MiB per second by message size">`;
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
      s += `<rect x="${x + 2}" y="${y(r.mib_per_sec)}" width="${bw - 4}" height="${H - B - y(r.mib_per_sec)}" rx="3" fill="${COLORS[a]}" opacity=".85"><title>${esc(a)} · ${fmtSize(sz)}: ${r.mib_per_sec.toFixed(1)} MiB/s</title></rect>`;
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
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Average latency per operation in microseconds, log scale">`;
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
      s += `<circle cx="${px}" cy="${py}" r="3.5" fill="${COLORS[a]}"><title>${esc(a)} · ${fmtSize(sizes[i])}: ${r.latency_us.toFixed(2)} µs/op</title></circle>`;
    });
  });
  s += `<text x="12" y="${T + 4}" transform="rotate(-90 12 ${T + 4})" text-anchor="end">µs / op (log)</text>`;
  return `${s}<line class="axis" x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}"/></svg>`;
}

function headline(b) {
  const at = (alg, size) => b.results.find((r) => r.algorithm === alg && r.size === size);
  const algs = ['ChaCha20-Poly1305', 'AES-256-GCM', 'seal() + nonce'];
  return `<div class="summary-strip">${algs.map((a) => {
    const r = at(a, 1024);
    return `<div class="metric"><span><i style="display:inline-block;width:10px;height:3px;border-radius:2px;background:${COLORS[a]};margin-right:6px;vertical-align:3px"></i>${esc(a)} · 1 KiB</span>
      <b>${r ? `${r.mib_per_sec.toFixed(0)}<small> MiB/s · ${r.latency_us.toFixed(2)} µs</small>` : '<span class="faint">n/a</span>'}</b></div>`;
  }).join('')}</div>`;
}

function table(b) {
  return `<div class="table-wrap"><table class="table"><thead><tr><th>Algorithm</th><th>Message</th><th>Iterations</th><th>Ops / s</th><th>Avg latency</th><th>Throughput</th></tr></thead><tbody>
    ${b.results.map((r) => `<tr><td><i style="display:inline-block;width:10px;height:3px;border-radius:2px;background:${COLORS[r.algorithm]};margin-right:8px;vertical-align:3px"></i>${esc(r.algorithm)}</td>
      <td class="mono">${fmtSize(r.size)}</td><td class="mono">${r.iterations.toLocaleString()}</td>
      <td class="mono">${Math.round(r.ops_per_sec).toLocaleString()}</td><td class="mono">${r.latency_us.toFixed(2)} µs</td><td class="mono">${r.mib_per_sec.toFixed(1)} MiB/s</td></tr>`).join('')}
  </tbody></table></div>`;
}

export default {
  id: 'bench',
  label: 'Benchmarks',
  icon: 'bench',
  mount(root) {
    this.rendered = null;
    root.innerHTML = `
      ${pageHead('Extension · Performance', 'Benchmark lab', 'Runs <code>./aead_bench --json</code>: encrypts 64 B – 16 KiB messages for about 120 ms per data point, timed with <code>CLOCK_MONOTONIC</code>. Every number is measured on this machine at run time — never pre-filled or estimated.',
        '<button class="btn btn-primary" data-a="run">Run benchmark</button>')}
      <div id="bn-body"></div>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a="run"]');
      if (b) busy(b, async () => { this.rendered = null; $('#bn-body').innerHTML = emptyState('Measuring on this machine… about 2 seconds.', '', 'RUNNING'); await run('bench'); });
    });
    this.update();
  },
  update() {
    const b = store.bench;
    const body = $('#bn-body');
    if (!b) { if (!body.innerHTML) body.innerHTML = emptyState('No measurements yet. Run the benchmark to measure ChaCha20-Poly1305, AES-256-GCM and the full seal() path on this machine.'); return; }
    if (!b.results) { body.innerHTML = `<div class="alert" role="alert"><b>BENCHMARK FAILED</b><span>${esc(b.error || 'no results')}</span></div>`; return; }
    const key = `${b.checksum}:${b.results.length}`;
    if (key === this.rendered) return;
    this.rendered = key;
    const series = [...new Set(b.results.map((r) => r.algorithm))];
    body.innerHTML = `
      <section class="panel hero" style="padding:28px 32px">${panelHead('Measured now', `libsodium ${esc(b.libsodium)} · ${b.budget_ms} ms per data point`,
        b.aes256gcm_available ? chip('AVAILABLE', { text: 'AES-256-GCM available' }) : chip('WARNING', { text: 'AES-256-GCM not available on this CPU' }))}${headline(b)}</section>
      <div class="grid section">
        <section class="panel s12">${panelHead('Throughput by message size', 'higher is better',
          `<div class="series">${series.map((a) => `<span><i style="background:${COLORS[a]}"></i>${esc(a)}</span>`).join('')}</div>`)}${barChart(b)}</section>
        <section class="panel s7">${panelHead('Average latency per operation', 'lower is better · log scale')}${latencyChart(b)}</section>
        <section class="panel s5">${panelHead('Reading the results')}
          <div class="explain" style="grid-template-columns:1fr">
            <div class="ex"><h5>AES-GCM ${b.aes256gcm_available ? 'IS AVAILABLE' : 'IS UNAVAILABLE'}</h5><p>${b.aes256gcm_available ? 'This CPU has AES-NI / PCLMUL, so libsodium can use hardware AES-GCM, which is typically faster here.' : 'libsodium only enables AES-256-GCM with hardware support; it is not available on this CPU.'}</p></div>
            <div class="ex"><h5>WHY CHACHA20</h5><p>ChaCha20-Poly1305 is fast and constant-time in pure software on any CPU — phones and small ARM boards included — with no special instructions.</p></div>
            <div class="ex"><h5>SEAL() OVERHEAD</h5><p>The seal() series includes building the header and a fresh random nonce, so the gap to raw ChaCha20 is the cost of the packet format.</p></div>
          </div></section>
        <section class="panel s12">${panelHead('Raw measurements')}${table(b)}</section>
      </div>`;
  },
};
