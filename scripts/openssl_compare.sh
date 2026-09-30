#!/usr/bin/env bash
# Task 6 - OpenSSL CLI comparison.
# Run from the project root:  bash scripts/openssl_compare.sh [--quiet | --json]
# --json prints one JSON object with the observed values (used by the dashboard).
# All files are created in openssl_demo/ (git-ignored).
set -euo pipefail

QUIET=0; JSON=0
case "${1:-}" in --quiet) QUIET=1 ;; --json) QUIET=1; JSON=1 ;; esac
keygen_ok=false; roundtrip_ok=false; cbc_undetected=false; aead_rejected=false
block1=""; garbage=""; cbc_exit=-1

ROOT="$(pwd)"
OUT="$ROOT/openssl_demo"

# TEST-ONLY passphrase for this automated demo. Passed through the
# environment (-pass env:) so it never appears in the process list.
export OSSL_DEMO_PASS="test-only-demo-passphrase"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ $QUIET -eq 0 ]; then
  B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
else
  B=; D=; G=; R=; Y=; C=; N=
fi

failures=0
say()     { [ $QUIET -eq 1 ] || printf '%s\n' "$*"; }
section() { say ""; say "${B}${C}▶ $*${N}"; say "${D}──────────────────────────────────────────────────────────────────${N}"; }
pass()    { say "  ${G}[✓ PASS]${N} $*"; }
fail()    { say "  ${R}[✗ FAIL]${N} $*"; failures=$((failures + 1)); }
info()    { say "  ${C}[ info ]${N} $*"; }
warn()    { say "  ${Y}[! WARN]${N} $*"; }
run()     { say "  ${D}\$ $*${N}"; }

say ""
say "${C}╔════════════════════════════════════════════════════════════════╗${N}"
say "${C}║${N}${B}              TASK 6 - OPENSSL CLI COMPARISON                   ${N}${C}║${N}"
say "${C}║${N}${D}      Ed25519 / X25519 PEM keys  ·  aes-256-cbc vs AEAD         ${N}${C}║${N}"
say "${C}╚════════════════════════════════════════════════════════════════╝${N}"

rm -rf "$OUT"
mkdir -m 700 "$OUT"
cd "$OUT"

section "1. Tool version"
say "  $(openssl version)"

section "2. Generate Ed25519 and X25519 keys"
run "openssl genpkey -algorithm ED25519 -out ed_priv.pem"
openssl genpkey -algorithm ED25519 -out ed_priv.pem
run "openssl pkey -in ed_priv.pem -pubout -out ed_pub.pem"
openssl pkey -in ed_priv.pem -pubout -out ed_pub.pem
run "openssl genpkey -algorithm X25519 -out x_priv.pem"
openssl genpkey -algorithm X25519 -out x_priv.pem
openssl pkey -in x_priv.pem -pubout -out x_pub.pem
if [ -s ed_priv.pem ] && [ -s ed_pub.pem ] && [ -s x_priv.pem ]; then
  pass "Ed25519 and X25519 key pairs created"; keygen_ok=true
else
  fail "key generation"
fi

section "3. PEM format (Base64 DER between BEGIN/END lines)"
run "cat ed_pub.pem"
while IFS= read -r line; do say "    $line"; done < ed_pub.pem
run "cat ed_priv.pem   (body redacted - it is private key material)"
while IFS= read -r line; do
  case "$line" in -----*) say "    $line" ;; *) say "    ${D}<base64 body hidden>${N}" ;; esac
done < ed_priv.pem
priv_der=$(openssl pkey -in ed_priv.pem -outform DER | wc -c | tr -d ' ')
pub_der=$(openssl pkey -in ed_priv.pem -pubout -outform DER | wc -c | tr -d ' ')
info "OpenSSL Ed25519 private key: ${priv_der} B PKCS#8 DER (ASN.1 wrapping a 32 B seed)"
info "OpenSSL Ed25519 public key : ${pub_der} B SubjectPublicKeyInfo DER"
info "libsodium stores raw bytes : 64 B secret (seed || public key), 32 B public, no headers"

section "4. File permissions"
run "ls -l *.pem"
ls -l ./*.pem | while IFS= read -r line; do say "    $line"; done
priv_mode=$(stat -c '%a' ed_priv.pem)
if [ "$priv_mode" = "600" ]; then
  pass "ed_priv.pem is 0600 (OpenSSL 3 creates private key files owner-only)"
else
  warn "ed_priv.pem is ${priv_mode}: permissions depend on OpenSSL version, umask and filesystem"
fi

section "5. aes-256-cbc encrypt / decrypt (commands from the brief)"
echo "hello" > message.txt
run "openssl enc -aes-256-cbc -salt -pbkdf2 -in message.txt -out message.enc"
openssl enc -aes-256-cbc -salt -pbkdf2 -in message.txt -out message.enc -pass env:OSSL_DEMO_PASS
run "openssl enc -d -aes-256-cbc -pbkdf2 -in message.enc"
decrypted=$(openssl enc -d -aes-256-cbc -pbkdf2 -in message.enc -pass env:OSSL_DEMO_PASS)
say "    $decrypted"
if [ "$decrypted" = "hello" ]; then pass "Encrypt/decrypt round-trip works"; roundtrip_ok=true; else fail "round-trip"; fi
info "File layout: 'Salted__' (8 B) | salt (8 B) | CBC ciphertext - no authentication tag"

section "6. Tamper attack on aes-256-cbc (bit-flipping)"
# Block 0 = "FROM=Pratham;TO="  Block 1 = "Bob;AMOUNT=00100"  Block 2 = "\n" + padding
printf 'FROM=Pratham;TO=Bob;AMOUNT=00100\n' > payment.txt
openssl enc -aes-256-cbc -salt -pbkdf2 -in payment.txt -out payment.enc -pass env:OSSL_DEMO_PASS
info "Original plaintext : $(cat payment.txt)"
# In CBC, P1 = D(C1) XOR C0. Flipping bits in ciphertext block C0 flips the
# SAME bits in plaintext block P1. Byte 11 of P1 is the first digit of the
# amount ('0'); XOR with ('0' ^ '9') = 0x09 turns it into '9'.
# File offset = 16 (Salted__ + salt) + 11 = 27.
off=27
orig=$(od -An -tu1 -j "$off" -N1 payment.enc | tr -d ' ')
new=$(( orig ^ 0x09 ))
printf "$(printf '\\%03o' "$new")" | dd of=payment.enc bs=1 seek="$off" count=1 conv=notrunc status=none
run "flip one bit pattern in ciphertext byte ${off}; decrypt with the correct passphrase"
if openssl enc -d -aes-256-cbc -pbkdf2 -in payment.enc -out tampered.txt -pass env:OSSL_DEMO_PASS 2>/dev/null; then
  cbc_exit=0
  block1=$(tail -c +17 tampered.txt | tr -d '\n')
  garbage=$(head -c 16 tampered.txt | od -An -tx1 | tr -d ' \n' | cut -c1-24)
  info "Decrypted block 0 : ${garbage}…  (16 random-looking bytes)"
  info "Decrypted block 1 : ${block1}"
  if [ "$block1" = "Bob;AMOUNT=90100" ]; then
    pass "Attack demonstrated: openssl exited 0 and the amount changed 00100 -> 90100"; cbc_undetected=true
    say "         ${Y}aes-256-cbc gave NO error: confidentiality only, no integrity.${N}"
  else
    fail "unexpected tampered output"
  fi
else
  fail "decryption failed unexpectedly (expected silent success)"
fi

section "7. The same kind of attack against this project's AEAD"
if [ -x "$ROOT/test_attacks" ]; then
  if "$ROOT/test_attacks" --tap | grep '^ok 2 ' >/dev/null; then
    pass "libsodium ChaCha20-Poly1305: flipped ciphertext byte -> rejected (rc -2)"; aead_rejected=true
  else
    fail "test_attacks tamper test did not pass"
  fi
else
  warn "Build the project (make) to run the libsodium comparison"
fi

section "8. Comparison"
say "  ┌────────────────────┬──────────────────────────────┬──────────────────────────────┐"
say "  │ Property           │ libsodium (this project)     │ OpenSSL CLI (as used here)   │"
say "  ├────────────────────┼──────────────────────────────┼──────────────────────────────┤"
say "  │ Key format         │ raw bytes (32 B pk, 64 B sk) │ PKCS#8 / SPKI (ASN.1 DER)    │"
say "  │ Encoding           │ binary .bin, no headers      │ PEM: Base64 + BEGIN/END      │"
say "  │ Private-key files  │ 0600 via open()+fchmod       │ 0600 in OpenSSL 3, plaintext │"
say "  │ Key-at-rest crypto │ optional Argon2id wrap       │ optional -aes256 passphrase  │"
say "  │ Message encryption │ ChaCha20-Poly1305 (AEAD)     │ aes-256-cbc (no tag)         │"
say "  │ Tamper detection   │ yes: 16 B Poly1305 tag       │ no (bit-flip succeeded)      │"
say "  │ Password KDF       │ Argon2id (memory-hard)       │ PBKDF2 (CPU-hard only)       │"
say "  │ Misuse resistance  │ high: few, safe choices      │ lower: many modes to choose  │"
say "  └────────────────────┴──────────────────────────────┴──────────────────────────────┘"
say ""
say "  aes-256-cbc fails the INTEGRITY / AUTHENTICITY requirement. Use an AEAD"
say "  (ChaCha20-Poly1305 or AES-256-GCM) or encrypt-then-MAC. 'openssl enc'"
say "  does not support AEAD modes; the OpenSSL C API does."

say ""
if [ $failures -eq 0 ]; then
  say "${G}${B}OpenSSL comparison complete: all steps behaved as expected.${N}"
else
  say "${R}${B}OpenSSL comparison: ${failures} step(s) did not behave as expected.${N}"
fi

if [ $JSON -eq 1 ]; then
  esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037'; }
  pem=$(sed ':a;N;$!ba;s/\n/\\n/g' ed_pub.pem)
  printf '{"ok":%s,"failures":%d,"openssl_version":"%s","keygen_ok":%s,' \
    "$([ $failures -eq 0 ] && echo true || echo false)" "$failures" "$(esc "$(openssl version)")" "$keygen_ok"
  printf '"ed25519_pub_pem":"%s","ed25519_priv_der_bytes":%s,"ed25519_pub_der_bytes":%s,"priv_pem_mode":"0%s",' \
    "$pem" "$priv_der" "$pub_der" "$priv_mode"
  printf '"roundtrip_ok":%s,"cbc":{"original":"%s","tampered_block1":"%s","garbled_block0_hex":"%s","byte_offset":%d,"xor":"0x09","openssl_exit":%d,"tamper_undetected":%s},' \
    "$roundtrip_ok" "FROM=Pratham;TO=Bob;AMOUNT=00100" "$(esc "$block1")" "$(esc "$garbage")" "$off" "$cbc_exit" "$cbc_undetected"
  printf '"aead_tamper_rejected":%s}\n' "$aead_rejected"
fi
exit $(( failures > 0 ))
