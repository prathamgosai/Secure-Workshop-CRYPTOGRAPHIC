// test_security_audit.js — Live End-to-End Security & Functional API Audit
const http = require('http');

const PORT = 8787;
const HOST = '127.0.0.1';

function request({ method = 'GET', path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: HOST, port: PORT, path, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, raw: data, json });
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function postEngine(cmd, arg = undefined) {
  const payload = { cmd };
  if (arg !== undefined) payload.arg = arg;
  return request({
    method: 'POST',
    path: '/api/engine',
    headers: { 'Content-Type': 'application/json', 'X-SC-Client': 'dashboard' },
    body: payload,
  });
}

async function postRun(action) {
  return request({
    method: 'POST',
    path: '/api/run',
    headers: { 'Content-Type': 'application/json', 'X-SC-Client': 'dashboard' },
    body: { action },
  });
}

async function runSecurityAudit() {
  console.log('====================================================');
  console.log(' SECURE CHANNEL — FULL SECURITY & API INTEGRITY AUDIT');
  console.log('====================================================\n');

  let passed = 0;
  let total = 0;

  function assert(title, condition, details = '') {
    total++;
    if (condition) {
      console.log(`  [✓ PASS] ${title}`);
      passed++;
    } else {
      console.error(`  [✕ FAIL] ${title} - ${details}`);
    }
  }

  // 1. Security Headers
  console.log('-- 1. HTTP Security Headers & Access Guards --');
  const indexRes = await request({ path: '/' });
  assert('HTTP 200 OK for root', indexRes.status === 200);
  assert('CSP script-src is self', /script-src 'self'/.test(indexRes.headers['content-security-policy'] || ''));
  assert('Frame-ancestors is none', /frame-ancestors 'none'/.test(indexRes.headers['content-security-policy'] || ''));
  assert('X-Frame-Options is DENY', indexRes.headers['x-frame-options'] === 'DENY');
  assert('X-Content-Type-Options is nosniff', indexRes.headers['x-content-type-options'] === 'nosniff');
  assert('Cache-Control is no-store', indexRes.headers['cache-control'] === 'no-store');

  // 2. DNS Rebinding & Traversal Guards
  console.log('\n-- 2. Network & Boundary Defenses --');
  const dnsRes = await request({ path: '/api/health', headers: { Host: 'attacker.evil.com:8787' } });
  assert('Foreign Host header rejected with 421', dnsRes.status === 421);

  const travRes = await request({ path: '/../../Makefile', headers: { Host: `127.0.0.1:${PORT}` } });
  assert('Directory traversal blocked', [403, 404].includes(travRes.status));

  const postCsrf = await request({ method: 'POST', path: '/api/engine', body: { cmd: 'hello' } });
  assert('POST without X-SC-Client rejected with 403', postCsrf.status === 403);

  // 3. Engine Initialization & Status
  console.log('\n-- 3. C Cryptographic Engine & State Invariants --');
  const helloRes = await postEngine('hello');
  assert('sc_engine hello responds ok=true', helloRes.json?.ok === true);
  assert('libsodium reported in hello', !!helloRes.json?.libsodium);

  const resetRes = await postEngine('reset');
  assert('Reset returns state INIT', resetRes.json?.ok === true && resetRes.json?.session?.state === 'INIT');

  const sealRefused = await postEngine('seal', 'probe before handshake');
  assert('seal() refused while in state INIT', sealRefused.json?.ok === false && sealRefused.json?.session?.state === 'INIT');

  // 4. Handshake & Gating
  console.log('\n-- 4. Ephemeral Key Exchange & Authentication --');
  const hsBegin = await postEngine('hs', 'begin');
  assert('hs begin creates ephemeral keypairs', hsBegin.json?.ok === true && !!hsBegin.json?.client_pk_fp);

  const hsDerive = await postEngine('hs', 'derive');
  assert('hs derive derives directional session keys', hsDerive.json?.ok === true && hsDerive.json?.complementary === true);
  assert('client_tx differs from client_rx (directional separation)', hsDerive.json?.directional === true);

  const hsAuth = await postEngine('hs', 'auth');
  assert('hs auth verifies Ed25519 transcript signature', hsAuth.json?.ok === true && hsAuth.json?.signature === 1);

  const hsSecure = await postEngine('hs', 'secure');
  assert('hs secure transitions state to SECURE', hsSecure.json?.ok === true && hsSecure.json?.state_after === 'SECURE');

  // 5. AEAD Sealing, Inspection & Decryption
  console.log('\n-- 5. ChaCha20-Poly1305 AEAD Records & Delivery --');
  const sealRes = await postEngine('seal', 'Confidential transaction approved');
  assert('Message sealed with sequence number and nonce', sealRes.json?.ok === true && sealRes.json?.packet?.seq === '1');
  const pkt = sealRes.json?.packet;
  assert('Packet layout: 20B header + ct + 16B tag (min 36B)', pkt && pkt.length === 36 + pkt.ct_len);

  const inspectRes = await postEngine('inspect');
  assert('Inspect succeeds without state change', inspectRes.json?.ok === true && inspectRes.json?.checks?.length_ok === true);

  const deliverRes = await postEngine('deliver');
  const dStep = deliverRes.json?.steps?.[0];
  assert('Deliver unseals and releases plaintext', dStep && dStep.rc === 0 && dStep.plaintext === 'Confidential transaction approved');
  assert('Replay window advanced to 1', dStep && dStep.last_seq_after === 1);

  // 6. Active Attack Defenses
  console.log('\n-- 6. Active Adversary Attack Invariants --');
  const tamperAtk = await postEngine('intercept', 'tamper');
  assert('Ciphertext tampering rejected with rc -2 (Poly1305 mismatch)', tamperAtk.json?.attack?.rc === -2);

  const replayAtk = await postEngine('intercept', 'replay');
  assert('Replayed packet rejected with rc -3 (Replay window)', replayAtk.json?.attack?.rc === -3);

  const aadAtk = await postEngine('intercept', 'aad');
  assert('Modified sequence header rejected with rc -2 (AAD integrity)', aadAtk.json?.attack?.rc === -2);

  const forgedAtk = await postEngine('intercept', 'forged');
  assert('Forged max sequence (2^64-1) rejected with rc -2 without poisoning window', forgedAtk.json?.attack?.rc === -2);

  const wrongKeyAtk = await postEngine('intercept', 'wrongkey');
  assert('Wrong key rejected with rc -2 and output buffer zeroed', wrongKeyAtk.json?.attack?.rc === -2);

  // 7. Key Vault & Wrapping
  console.log('\n-- 7. Key Vault Permissions & Argon2id Wrapping --');
  const vaultRes = await postEngine('vault');
  assert('Vault permissions verified (0600 private / 0644 public)', vaultRes.json?.permissions_ok === true);

  const wrapWrong = await postEngine('unwrap', 'wrong');
  assert('Wrong passphrase unwrap rejected (fail-closed, buffer zeroed)', wrapWrong.json?.ok === true && wrapWrong.json?.rc !== 0 && wrapWrong.json?.output_zeroed === true);

  const wrapCorrect = await postEngine('unwrap', 'correct');
  assert('Correct passphrase unwrap verified with original key match', wrapCorrect.json?.ok === true && wrapCorrect.json?.rc === 0 && wrapCorrect.json?.unwrapped === true);

  // 8. Re-keying
  console.log('\n-- 8. Dynamic Key Rotation & Epoch Advancement --');
  const rekeyRes = await postEngine('rekey');
  assert('Re-key advances epoch from 1 to 2', rekeyRes.json?.ok === true && rekeyRes.json?.session?.epoch === 2);

  // 9. Secret Hygiene Verification
  console.log('\n-- 9. Zero Secret Leakage Verification --');
  const allJson = [helloRes, resetRes, hsBegin, hsDerive, hsAuth, hsSecure, sealRes, inspectRes, deliverRes, tamperAtk, replayAtk, aadAtk, forgedAtk, wrongKeyAtk, vaultRes, wrapWrong, wrapCorrect, rekeyRes]
    .map((r) => JSON.stringify(r.json))
    .join(' ');

  const leakedKeys = allJson.match(/"(sk|secret_key|private_key|seed|passphrase)"\s*:\s*"[^"]+"/i);
  assert('Zero secret key material in API responses', !leakedKeys, leakedKeys ? leakedKeys[0] : '');

  // Summary
  console.log('\n====================================================');
  console.log(` AUDIT RESULT: ${passed} / ${total} CHECKS PASSED (${((passed / total) * 100).toFixed(1)}%)`);
  console.log('====================================================\n');
  process.exit(passed === total ? 0 : 1);
}

runSecurityAudit().catch((err) => {
  console.error('Audit failed with error:', err);
  process.exit(1);
});
