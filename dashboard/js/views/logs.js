import { store } from '../store.js';
import { esc, timeMs, $ } from '../ui.js';

const LEVELS = ['ALL', 'INFO', 'AUTH', 'SECURE', 'ALERT', 'BLOCK', 'WIPE', 'ERROR'];
let filter = 'ALL';
let query = '';

export function setLogFilter(level) { filter = LEVELS.includes(level) ? level : 'ALL'; }

export default {
  id: 'logs',
  label: 'Logs',
  mount(root) {
    root.innerHTML = `
      <div class="page-head">
        <div><h1>SECURITY EVENT LOG</h1><p>Timestamps come from the C engine and the TCP programs (CLOCK_REALTIME) or from the bridge. Messages are built from public data only — no keys, passphrases or plaintext secrets.</p></div>
        <div class="actions"><button class="btn" data-a="export">EXPORT JSON</button></div>
      </div>
      <section class="card">
        <div class="row" style="margin-bottom:12px">
          <div class="filters" id="lg-filters">${LEVELS.map((l) => `<button class="chipf${l === filter ? ' on' : ''}" data-l="${l}">${l}</button>`).join('')}</div>
          <div class="field grow"><input id="lg-q" class="input" placeholder="filter text…" value="${esc(query)}"></div>
        </div>
        <div id="lg-table"></div>
      </section>`;
    $('#lg-filters', root).addEventListener('click', (e) => {
      const b = e.target.closest('[data-l]');
      if (!b) return;
      filter = b.dataset.l;
      root.querySelectorAll('.chipf').forEach((c) => c.classList.toggle('on', c === b));
      this.update();
    });
    $('#lg-q', root).addEventListener('input', (e) => { query = e.target.value.toLowerCase(); this.update(); });
    root.addEventListener('click', (e) => {
      if (!e.target.closest('[data-a="export"]')) return;
      const blob = new Blob([JSON.stringify(store.events, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `secure-channel-events-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });
    this.update();
  },
  update() {
    const rows = store.events.filter((e) => (filter === 'ALL' || e.level === filter) &&
      (!query || e.msg.toLowerCase().includes(query) || e.src.includes(query))).slice().reverse();
    $('#lg-table').innerHTML = rows.length ? `<table class="table"><thead><tr><th>TIME</th><th>LEVEL</th><th>SOURCE</th><th>EVENT</th></tr></thead><tbody>
      ${rows.slice(0, 400).map((e) => `<tr><td class="mono">${timeMs(e.ts)}</td><td><span class="lvl lvl-${esc(e.level)} badge" style="border:0">${esc(e.level)}</span></td><td class="mono faint">${esc(e.src)}</td><td>${esc(e.msg)}</td></tr>`).join('')}
      </tbody></table>` : '<div class="small muted">No events match.</div>';
  },
};
