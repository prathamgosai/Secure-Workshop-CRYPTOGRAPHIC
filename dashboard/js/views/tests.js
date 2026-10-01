import { store, run } from '../store.js';
import { esc, time, busy, chip, emptyState, pageHead, panelHead, $ } from '../ui.js';
import { ATTACKS } from './attacks.js';

/* Every number here comes from a run in this session (or, for the build,
 * from the make the bridge ran before starting the engine). Nothing is
 * copied from the README. */

function suiteResult(r) {
  if (!r) return { st: 'NOT RUN', res: '—', sub: 'not run in this session' };
  if (!r.tests) return { st: 'FAILED', res: 'error', sub: r.error || 'no TAP output' };
  return { st: r.failed ? 'FAILED' : 'PASS', res: `${r.passed}<small> / ${r.total}</small>`, sub: `exit ${r.code} · ${r.ms} ms` };
}

function liveAttacks() {
  const latest = ATTACKS.map((a) => store.attacks.history.find((h) => h.id === a.id)).filter(Boolean);
  if (!latest.length) return { st: 'NOT RUN', res: '—', sub: 'no live attacks yet' };
  const ok = latest.filter((h) => h.pass).length;
  return { st: ok === latest.length ? (latest.length === ATTACKS.length ? 'PASS' : 'PARTIAL') : 'FAILED', res: `${ok}<small> / ${latest.length}${latest.length < ATTACKS.length ? ` of ${ATTACKS.length}` : ''}</small>`, sub: 'latest result per attack' };
}

function validation() {
  const tc = store.toolchain;
  const b = store.build;
  const build = b ? { st: b.ok ? 'PASS' : 'FAILED', res: b.ok ? 'OK' : `exit ${b.code}`, sub: 'make -s all · run from dashboard' }
    : tc?.build_ok ? { st: 'PASS', res: 'OK', sub: `make -s all · bridge start ${time(tc.build_ts)}` }
      : { st: 'NOT RUN', res: '—', sub: 'build status unknown' };
  const o = store.openssl;
  const ossl = o ? { st: o.ok ? 'PASS' : 'FAILED', res: o.ok ? 'OK' : `${o.failures ?? '?'} unexpected`, sub: o.openssl_version || 'scripts/openssl_compare.sh' }
    : { st: 'NOT RUN', res: '—', sub: 'not run in this session' };
  const rows = [
    ['Build', 'make · gcc -Wall -Wextra -Wpedantic', build, '<button class="btn btn-sm btn-ghost" data-a="build">Rebuild</button>'],
    ['Required security tests', 'tests/test_attacks.c · Task 4', suiteResult(store.tests), '<button class="btn btn-sm btn-primary" data-a="tests">Run</button>'],
    ['Extended tests', 'tests/test_extended.c', suiteResult(store.testsExtended), '<button class="btn btn-sm" data-a="ext">Run</button>'],
    ['Live attack checks', 'Attack Lab · sc_engine', liveAttacks(), '<button class="btn btn-sm btn-ghost" data-a="lab">Open lab</button>'],
    ['OpenSSL comparison', 'Task 6 · scripts/openssl_compare.sh', ossl, '<button class="btn btn-sm btn-ghost" data-a="openssl">Run</button>'],
    ['UI / bridge integration', 'bridge/test_integration.js', { st: 'NOT RUN', res: '—', sub: 'run from a terminal: npm run test:ui' }, ''],
  ];
  return `<div class="posture">${rows.map(([name, src, r, btn]) => `
    <div class="val-row">
      <div class="nm"><b>${name}</b><small>${esc(src)}</small></div>
      <div class="res ${r.st === 'PASS' ? 'ok' : r.st === 'FAILED' ? 'bad' : 'faint'}">${r.res}</div>
      <div>${chip(r.st)}<div class="faint small mono" style="margin-top:4px">${esc(r.sub)}</div></div>
      <div class="actions">${btn}</div>
    </div>`).join('')}</div>`;
}

function testCards(r, what, btnLabel) {
  if (!r) return emptyState(`Run the ${what} to populate verified results. Test names and outcomes come from the program&rsquo;s TAP output.`, `<button class="btn btn-primary" data-a="${what === 'required suite' ? 'tests' : 'ext'}">${btnLabel}</button>`);
  if (!r.tests) return `<div class="alert" role="alert"><b>SUITE FAILED TO RUN</b><span>${esc(r.error || 'no TAP output')}</span><span>No results were recorded.</span></div>`;
  return `<div class="suite-head">
      <div><div class="score ${r.failed ? 'bad' : 'ok'}">${r.passed}<small> / ${r.total}</small></div></div>
      <div class="actions">${chip(r.failed ? 'FAILED' : 'PASS', { lg: true, text: `${r.passed} passed · ${r.failed} failed` })}<span class="faint small mono">${esc(r.suite)} · exit ${r.code}</span></div>
    </div>
    <div class="tests">${r.tests.map((t, i) => `<div class="test${t.ok ? '' : ' fail'}"><span class="n">${String(i + 1).padStart(2, '0')}</span><span class="nm">${esc(t.name)}</span>${chip(t.ok ? 'PASS' : 'FAIL')}</div>`).join('')}</div>`;
}

export default {
  id: 'tests',
  label: 'Test Center',
  icon: 'tests',
  mount(root, ctx) {
    root.innerHTML = `
      ${pageHead('Verification', 'Test center', 'Security validation for the whole project. Results appear only after the real programs run; anything not executed in this session is shown as NOT RUN.',
        '<button class="btn btn-primary" data-a="tests">Run security tests</button><button class="btn" data-a="ext">Run extended tests</button>')}
      <section aria-label="Security validation">${'<div class="section-head"><div><span class="eyebrow">Summary</span><h2>Security validation</h2></div></div>'}<div id="tc-val"></div></section>
      <section class="panel elevated section" id="atk-suite">${panelHead('Required tests', 'tests/test_attacks.c — the 8 tests from the brief, run as a separate process')}<div id="tc-req"></div></section>
      <section class="panel section">${panelHead('Extended tests', 'tests/test_extended.c — packets, key files, wrapping, state machine, re-key, handshake')}<div id="tc-ext"></div></section>
      <section class="panel section" id="tc-build-card" hidden>${panelHead('Build output', 'make -s all')}<pre class="console" id="tc-build"></pre></section>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const a = b.dataset.a;
      if (a === 'tests') busy(b, () => run('tests'));
      if (a === 'ext') busy(b, () => run('tests-extended'));
      if (a === 'build') busy(b, () => run('build'));
      if (a === 'openssl') busy(b, () => run('openssl'));
      if (a === 'lab') ctx.navigate('attacks');
    });
    this.update();
  },
  update() {
    $('#tc-val').innerHTML = validation();
    $('#tc-req').innerHTML = testCards(store.tests, 'required suite', 'Run security tests');
    $('#tc-ext').innerHTML = testCards(store.testsExtended, 'extended suite', 'Run extended tests');
    const b = store.build;
    $('#tc-build-card').hidden = !b;
    if (b) $('#tc-build').textContent = b.output?.trim() || (b.ok ? '(no output — build is up to date)' : 'build failed');
  },
};
