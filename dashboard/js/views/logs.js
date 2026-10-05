import { store, notify } from '../store.js';
import { esc, timeMs, toast, pageHead, $ } from '../ui.js';
import { traceList } from '../trace.js';

const LEVELS = ['ALL', 'INFO', 'AUTH', 'SECURE', 'ALERT', 'BLOCK', 'WIPE', 'ERROR'];
let filter = 'ALL';
let query = '';
let mode = 'events';   // 'events' = security events, 'trace' = every backend call

export function setLogFilter(level) { filter = LEVELS.includes(level) ? level : 'ALL'; }

const visible = () => store.events.filter((e) => (filter === 'ALL' || e.level === filter) &&
  (!query || e.msg.toLowerCase().includes(query) || e.src.includes(query))).slice().reverse();

export default {
  id: 'logs',
  label: 'Logs',
  icon: 'logs',
  mount(root) {
    root.innerHTML = `
      ${pageHead('Analysis · Event console', 'Security event log', 'Timestamps come from the C engine and the TCP programs (CLOCK_REALTIME) or from the bridge. Messages are built from public data only — no keys, passphrases or plaintext secrets.',
        '<button class="btn" data-a="copy">Copy log</button><button class="btn" data-a="export">Export JSON</button><button class="btn btn-ghost" data-a="clear">Clear log</button>')}
      <section class="panel">
        <div class="console-toolbar">
          <div class="seg" id="lg-mode" role="group" aria-label="Log view"><button data-m="events" aria-pressed="${mode === 'events'}">Security events</button><button data-m="trace" aria-pressed="${mode === 'trace'}">Backend trace</button></div>
          <div class="filters" id="lg-filters" role="group" aria-label="Filter by level">${LEVELS.map((l) => `<button class="chipf" data-l="${l}" aria-pressed="${l === filter}">${l}</button>`).join('')}</div>
          <div class="grow"><label class="sr-only" for="lg-q">Filter text</label><input id="lg-q" class="input" placeholder="Filter text…" value="${esc(query)}"></div>
          <span class="faint small mono" id="lg-count"></span>
        </div>
        <div class="logcon" id="lg-table" role="log" aria-label="Security events"></div>
      </section>`;
    $('#lg-mode', root).addEventListener('click', (e) => {
      const b = e.target.closest('[data-m]');
      if (!b) return;
      mode = b.dataset.m;
      root.querySelectorAll('#lg-mode button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      this.update();
    });
    $('#lg-filters', root).addEventListener('click', (e) => {
      const b = e.target.closest('[data-l]');
      if (!b) return;
      filter = b.dataset.l;
      root.querySelectorAll('.chipf').forEach((c) => c.setAttribute('aria-pressed', String(c === b)));
      this.update();
    });
    $('#lg-q', root).addEventListener('input', (e) => { query = e.target.value.toLowerCase(); this.update(); });
    root.addEventListener('click', async (e) => {
      const a = e.target.closest('button[data-a]')?.dataset.a;
      if (a === 'export') {
        const trace = store.trace.map(({ t0, ...rest }) => rest);
        const blob = new Blob([JSON.stringify({ events: store.events, trace }, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `secure-channel-events-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.json`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
      }
      if (a === 'copy') {
        const text = visible().map((ev) => `${timeMs(ev.ts)}  ${ev.level.padEnd(6)}  ${ev.src.padEnd(10)}  ${ev.msg}`).join('\n');
        try { await navigator.clipboard.writeText(text); toast(`Copied ${visible().length} events`); }
        catch { toast('Clipboard not available in this browser context', true); }
      }
      if (a === 'clear') {
        // Clears the dashboard's copy only; the engine keeps no history.
        store.events.length = 0;
        store.trace.length = 0;
        notify('events');
      }
    });
    this.update();
  },
  update() {
    const isTrace = mode === 'trace';
    $('#lg-filters').hidden = isTrace;
    $('#lg-q').parentElement.hidden = isTrace;
    if (isTrace) {
      $('#lg-count').textContent = `${store.trace.length} backend calls`;
      $('#lg-table').innerHTML = `<div style="padding:8px 16px">${traceList(store.trace.slice().reverse(), 'No backend calls yet. Run anything — or start the demo — to see the full browser → bridge → C chain.')}</div>`;
      return;
    }
    const rows = visible();
    $('#lg-count').textContent = `${rows.length} of ${store.events.length} events`;
    $('#lg-table').innerHTML = rows.length
      ? rows.slice(0, 400).map((e) => `<div class="logline"><time>${timeMs(e.ts)}</time><span class="lvl-cell"><span class="lvl lvl-${esc(e.level)}">${esc(e.level)}</span></span><span class="src">${esc(e.src)}</span><span class="m">${esc(e.msg)}</span></div>`).join('')
      : '<div class="small faint" style="padding:16px">No events match.</div>';
  },
};
