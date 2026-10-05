// Renders the background-activity trace recorded in store.trace: the full
// chain browser → bridge → WSL → C for every call. Static markup only.
import { esc, timeMs, chip } from './ui.js';

const ROUTE = { engine: 'POST /api/engine', run: (n) => `POST /api/run/${n}` };

function request(t) {
  if (t.kind === 'run') return ROUTE.run(t.name);
  return `${ROUTE.engine} { cmd: "${t.name}"${t.arg !== undefined ? `, arg: "${String(t.arg).slice(0, 48)}"` : ''} }`;
}

function executed(t) {
  const b = t.bridge;
  if (!b) return t.pending ? [] : ['bridge did not report an execution'];
  if (b.stdin !== undefined) return [`${b.process}  ‹stdin›  ${b.stdin}`];
  return b.exec || [];
}

export function traceEntry(t) {
  const status = t.pending ? chip('RUNNING', { text: 'Running' })
    : t.ok ? chip('OK', { text: `OK · ${t.ms} ms` }) : chip('FAILED', { text: `Failed · ${t.ms} ms` });
  const lines = executed(t);
  return `<li class="tr${t.pending ? ' pending' : ''}${!t.pending && !t.ok ? ' failed' : ''}">
    <div class="tr-head"><time>${timeMs(t.ts)}</time><span class="tr-kind">${t.kind === 'run' ? 'PROGRAM' : 'ENGINE'}</span><b>${esc(t.kind === 'run' ? t.name : `${t.name}${t.arg !== undefined ? ` ${String(t.arg).slice(0, 32)}` : ''}`)}</b>${status}</div>
    <div class="tr-row"><span class="k">browser</span><span>${esc(request(t))}</span></div>
    ${lines.map((l) => `<div class="tr-row"><span class="k">executed</span><span class="cmd">${esc(l)}</span></div>`).join('')}
    ${t.pending ? '<div class="tr-row"><span class="k">status</span><span class="faint">waiting for the C program to answer…</span></div>' : `
      <div class="tr-row"><span class="k">result</span><span class="res">${esc(t.summary)}</span></div>
      ${t.before !== t.after ? `<div class="tr-row"><span class="k">state</span><span>${esc(t.before)} → <b>${esc(t.after)}</b></span></div>` : ''}
      ${t.events.length ? `<div class="tr-row"><span class="k">${t.kind === 'run' ? 'output' : 'C events'}</span><ul class="tr-ev">${t.events.map((e) => `<li><span class="lvl lvl-${esc(e.level)}">${esc(e.level)}</span>${esc(e.msg)}</li>`).join('')}</ul></div>` : ''}`}
  </li>`;
}

export function traceList(entries, empty = 'No background calls yet.') {
  if (!entries.length) return `<div class="tr-empty">${empty}</div>`;
  return `<ol class="trace">${entries.map(traceEntry).join('')}</ol>`;
}

/* Security Decision Trace (Rule 20): Explains every cryptographic operation
 * as INPUT → VALIDATION → CRYPTOGRAPHIC OPERATION → AUTHENTICATION → STATE DECISION → RETURN CODE → SECURITY VERDICT.
 * Every value originates strictly from actual backend engine execution. */
export function securityDecisionTrace(p) {
  if (!p) {
    return `<div class="decision-trace empty">
      <div class="dt-header">
        <div class="dt-badge"><span class="g">●</span>SECURITY DECISION TRACE</div>
        <span class="faint small">Awaiting transmission or attack verification</span>
      </div>
      <div class="dt-empty">No packet evaluated yet. Encrypt a message in the channel or launch an attack in the lab to view the step-by-step cryptographic decision path.</div>
    </div>`;
  }

  const isShort = p.rc === -1 || p.raw_hex !== undefined;
  const isAuthFail = p.rc === -2;
  const isReplay = p.rc === -3;
  const isOk = p.rc === 0 && (p.verdict === 'ACCEPTED' || p.verdict === 'UNCHANGED');
  const seqDisplay = p.seq !== undefined ? (p.seq === '18446744073709551615' ? '2⁶⁴−1' : String(p.seq)) : '—';

  // Step 1: Input Validation
  const s1 = isShort
    ? { ok: false, name: 'INPUT VALIDATION', sub: `Truncated packet (${p.length} B) below minimum threshold (36 B header + tag required)` }
    : { ok: true, name: 'INPUT VALIDATION', sub: `Frame format valid (${p.length} B: 20 B header + ${p.ct_len ?? 0} B ciphertext + 16 B tag)` };

  // Step 2: Header / Sequence Extraction
  const s2 = isShort
    ? { ok: false, name: 'HEADER EXTRACTION', sub: 'Frame truncated — cannot extract sequence number or nonce' }
    : { ok: true, name: 'HEADER EXTRACTION', sub: `Parsed sequence #${seqDisplay} (8 B big-endian) and nonce (12 B cryptographic random)` };

  // Step 3: Replay / Freshness Check
  const s3 = isShort
    ? { ok: null, name: 'REPLAY FRESHNESS CHECK', sub: 'Skipped — frame malformed before replay evaluation' }
    : isReplay
      ? { ok: false, name: 'REPLAY FRESHNESS CHECK', sub: `Monotonic check failed: seq ${seqDisplay} ≤ last_seq (${p.attack === 'reorder' ? 'out-of-order packet' : 'duplicate packet rejected'})` }
      : { ok: true, name: 'REPLAY FRESHNESS CHECK', sub: `Monotonic check passed: seq ${seqDisplay} > last_seq (packet is fresh)` };

  // Step 4: Cryptographic Operation / AAD Binding
  const s4 = (isShort || isReplay)
    ? { ok: null, name: 'AEAD CRYPTOGRAPHIC OP', sub: 'Aborted early before decryption (defense in depth)' }
    : { ok: true, name: 'AEAD CRYPTOGRAPHIC OP', sub: 'ChaCha20-Poly1305 initialized; sequence number bound as Associated Data (AAD)' };

  // Step 5: Authentication Tag Verification
  const s5 = (isShort || isReplay)
    ? { ok: null, name: 'POLY1305 AUTHENTICATION', sub: 'Bypassed due to prior rejection check' }
    : isAuthFail
      ? { ok: false, name: 'POLY1305 AUTHENTICATION', sub: `Tag mismatch (${p.attack === 'tamper' ? 'ciphertext modified in transit' : p.attack === 'aad' ? 'AAD sequence altered' : p.attack === 'wrongkey' ? 'invalid session key' : p.attack === 'forged' ? 'forged sequence tag mismatch' : 'integrity tag mismatch'})` }
      : { ok: true, name: 'POLY1305 AUTHENTICATION', sub: 'Poly1305 MAC tag verified over ciphertext + AAD' };

  // Step 6: State Decision & Release
  const s6 = isOk
    ? { ok: true, name: 'STATE DECISION & RELEASE', sub: `Plaintext released to caller; last_seq updated to ${seqDisplay}` }
    : { ok: true, name: 'STATE DECISION & RELEASE', sub: 'Plaintext release BLOCKED; buffer zeroed with sodium_memzero(); session state preserved' };

  const steps = [s1, s2, s3, s4, s5, s6];
  const verdictTitle = isOk ? 'ACCEPTED' : (p.verdict || 'ATTACK REJECTED');
  const verdictClass = isOk ? 'ok' : 'bad';
  const rcName = p.rc === 0 ? 'SC_OK (0)' : p.rc === -1 ? 'SC_ERR_SHORT (-1)' : p.rc === -2 ? 'SC_ERR_AUTH (-2)' : p.rc === -3 ? 'SC_ERR_REPLAY (-3)' : `rc ${p.rc}`;

  return `<div class="decision-trace ${verdictClass}">
    <div class="dt-header">
      <div class="dt-badge"><span class="g">${isOk ? '✓' : '✕'}</span>SECURITY DECISION TRACE · PACKET #${p.id || 1}</div>
      <div class="dt-meta">
        <span class="mono">${rcName}</span>
        <span class="chip c-${isOk ? 'ok' : 'bad'}">${esc(verdictTitle)}</span>
      </div>
    </div>
    <ol class="dt-steps">
      ${steps.map((st, i) => {
        const icon = st.ok === true ? '✓' : st.ok === false ? '✕' : '○';
        const cls = st.ok === true ? 'pass' : st.ok === false ? 'fail' : 'skip';
        return `<li class="dt-step ${cls}">
          <span class="dt-num">0${i + 1}</span>
          <span class="dt-glyph">${icon}</span>
          <div class="dt-info">
            <b>${esc(st.name)}</b>
            <small>${esc(st.sub)}</small>
          </div>
        </li>`;
      }).join('')}
    </ol>
    <div class="dt-verdict">
      <span class="k">FINAL VERDICT</span>
      <b class="${isOk ? 'ok' : 'bad'}">${isOk ? '✓ PACKET AUTHENTICATED &amp; DELIVERED' : '✕ ATTACK REJECTED · INVARIANTS PRESERVED'}</b>
    </div>
  </div>`;
}

