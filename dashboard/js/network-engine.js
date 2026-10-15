// network-engine.js — Cinematic Cryptographic Protocol Network Engine
// High-performance HTML5 Canvas renderer inspired by the reference video:
// connected graph, luminous spline curves, moving data blocks, glowing focal radar
// rings, particle trails, event-driven color-shifting (cyan/lime/magenta/violet/amber),
// and shockwave rejection particle bursts.

import { store } from './store.js';

export class NetworkEngine {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.options = {
      interactive: true,
      showControls: true,
      ambientParticles: true,
      maxDPR: 2,
      onNodeSelect: null,
      ...options,
    };

    // Camera transform
    this.panX = 0;
    this.panY = 0;
    this.zoom = 1;
    this.targetPanX = 0;
    this.targetPanY = 0;
    this.targetZoom = 1;
    this.isDragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;
    this.paused = false;
    this.speed = 1.0;

    // Cinematic Director & Scene State
    this.activeScene = 1;
    this.mallory = { active: false, x: 740, y: 395, w: 148, h: 54, alpha: 0, label: 'MALLORY (MITM)', action: 'IDLE', sub: 'active wire intercept' };
    this.rekeyWave = { active: false, x: 500, y: 200, radius: 0, maxRadius: 600, alpha: 0 };
    this.sceneLaser = { active: false, x1: 0, y1: 0, x2: 0, y2: 0, color: '#ff0055', alpha: 0 };

    // Animation state
    this.rafId = null;
    this.lastTime = performance.now();
    this.particles = [];
    this.packets = [];
    this.radarRings = [];
    this.sparks = [];
    this.badges = [];
    this.hoveredNode = null;
    this.selectedNode = null;

    // Build graph
    this.initGraph();
    this.initParticles(50);

    // Event listeners
    if (this.options.interactive) {
      this.bindEvents();
    }
    this.resize();
  }

  /* ---- Graph Topology ---------------------------------------------------- */
  initGraph() {
    // Columns:
    // 0: Client Core & Identity
    // 1: Ephemeral Key Exchange (X25519)
    // 2: Session Derivation (BLAKE2b KDF)
    // 3: Record Layer (ChaCha20-Poly1305)
    // 4: Wire Transport & Verification
    // 5: Server Core & Key Vault

    this.columns = [
      { id: 'client', label: 'CLIENT CORE', x: 105 },
      { id: 'kx',     label: 'KEY EXCHANGE (X25519)', x: 290 },
      { id: 'kdf',    label: 'DERIVATION (BLAKE2B)', x: 475 },
      { id: 'record', label: 'RECORD LAYER (AEAD)', x: 660 },
      { id: 'guard',  label: 'WIRE & VALIDATION', x: 845 },
      { id: 'server', label: 'SERVER & VAULT', x: 1030 },
    ];

    const cardW = 152;
    const cardH = 56;

    this.nodes = [
      // Col 0: Client Core
      {
        id: 'client_core', col: 0, row: 0, y: 52, w: cardW, h: cardH,
        label: 'CLIENT CORE', sub: 'ephemeral session state', role: 'endpoint',
        details: 'Initialises sodium_init(), manages local session memory, handles client-side TX/RX buffers.',
        codeRef: 'src/session.c:session_init()', status: 'ready',
      },
      {
        id: 'key_loader', col: 0, row: 1, y: 187, w: cardW, h: cardH,
        label: 'IDENTITY STORE', sub: '0600 mode · atomic open', role: 'vault',
        details: 'Atomic key file creation with open(..., O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600). Checks exact 32/64 byte lengths.',
        codeRef: 'src/keyio.c:write_file_0600()', status: 'ready',
      },
      {
        id: 'client_tx', col: 0, row: 2, y: 322, w: cardW, h: cardH,
        label: 'CLIENT TX', sub: 'outgoing packet queue', role: 'endpoint',
        details: 'Directional transmit channel. Holds next_seq counter starting at 1.',
        codeRef: 'src/session.c:next_seq', status: 'ready',
      },

      // Col 1: Key Exchange
      {
        id: 'eph_kp', col: 1, row: 0, y: 52, w: cardW, h: cardH,
        label: 'EPHEMERAL KP', sub: 'X25519 · CSPRNG', role: 'kx',
        details: 'Generates fresh throwaway X25519 keypair for each handshake using randombytes_buf.',
        codeRef: 'src/handshake.c:crypto_kx_keypair()', status: 'idle',
      },
      {
        id: 'kx_exchange', col: 1, row: 1, y: 142, w: cardW, h: cardH,
        label: 'X25519 ECDH', sub: 'Curve25519 public exchange', role: 'kx',
        details: 'Only public keys cross the wire. Plain exchange is unauthenticated unless signed extension is enabled.',
        codeRef: 'src/handshake.c:session_handshake()', status: 'idle',
      },
      {
        id: 'hs_sign', col: 1, row: 2, y: 232, w: cardW, h: cardH,
        label: 'ED25519 SIGN', sub: 'transcript sig extension', role: 'auth',
        details: 'Signs "SC-HANDSHAKE-v1" ‖ server_eph ‖ client_eph with long-term server_sk.bin to defeat MITM attacks.',
        codeRef: 'src/handshake.c:hs_sign()', status: 'idle',
      },
      {
        id: 'hs_verify', col: 1, row: 3, y: 322, w: cardW, h: cardH,
        label: 'PINNED VERIFY', sub: 'checks pinned server_pk', role: 'auth',
        details: 'Client verifies server signature against pinned server_pk.bin. Aborts handshake if signature is invalid.',
        codeRef: 'src/handshake.c:hs_verify()', status: 'idle',
      },

      // Col 2: Session Derivation
      {
        id: 'blake2b_kdf', col: 2, row: 0, y: 72, w: cardW, h: cardH,
        label: 'BLAKE2B KDF', sub: 'crypto_kx KDF split', role: 'session',
        details: 'Computes BLAKE2b-512 over X25519 shared point and both public keys, deriving 64 bytes of key material.',
        codeRef: 'src/handshake.c:crypto_kx_*_session_keys()', status: 'idle',
      },
      {
        id: 'key_split', col: 2, row: 1, y: 187, w: cardW, h: cardH,
        label: 'KEY SPLIT', sub: 'client_tx == server_rx', role: 'session',
        details: 'Separates 64 bytes into directional 32-byte keys. Enforces client_tx == server_rx, client_tx != client_rx.',
        codeRef: 'src/session.c:c_tx, c_rx', status: 'idle',
      },
      {
        id: 'key_wipe', col: 2, row: 2, y: 302, w: cardW, h: cardH,
        label: 'MEMZERO WIPE', sub: 'forward secrecy zeroing', role: 'session',
        details: 'Calls sodium_memzero() on ephemeral secret keys immediately after session key derivation.',
        codeRef: 'src/session.c:sodium_memzero()', status: 'idle',
      },

      // Col 3: Record Layer
      {
        id: 'nonce_gen', col: 3, row: 0, y: 52, w: cardW, h: cardH,
        label: 'NONCE GEN', sub: '12-byte CSPRNG nonce', role: 'record',
        details: 'Generates fresh 12-byte random nonce for every packet via randombytes_buf. Never reuse nonces.',
        codeRef: 'src/aead.c:randombytes_buf(nonce, 12)', status: 'ready',
      },
      {
        id: 'aad_bind', col: 3, row: 1, y: 142, w: cardW, h: cardH,
        label: 'SEQ AAD BIND', sub: '64-bit BE seq as AAD', role: 'record',
        details: 'Encodes 64-bit sequence number in big-endian format. Sent in clear but bound to authentication tag as AAD.',
        codeRef: 'src/aead.c:store_be64(seqb, seq)', status: 'ready',
      },
      {
        id: 'chacha20_enc', col: 3, row: 2, y: 232, w: cardW, h: cardH,
        label: 'CHACHA20 AEAD', sub: 'IETF RFC 8439 cipher', role: 'record',
        details: 'Constant-time 256-bit stream cipher encryption with authenticated additional data.',
        codeRef: 'src/aead.c:crypto_aead_chacha20poly1305_ietf_encrypt()', status: 'ready',
      },
      {
        id: 'poly1305_mac', col: 3, row: 3, y: 322, w: cardW, h: cardH,
        label: 'POLY1305 TAG', sub: '16-byte MAC tag', role: 'record',
        details: 'Produces 16-byte cryptographic tag covering both ciphertext and sequence number AAD.',
        codeRef: 'src/aead.c:tag (16 B)', status: 'ready',
      },

      // Col 4: Wire & Verification
      {
        id: 'wire_frame', col: 4, row: 0, y: 52, w: cardW, h: cardH,
        label: 'WIRE FRAME', sub: '[SEQ 8][NONCE 12][CT][TAG 16]', role: 'wire',
        details: 'Wire format: 20-byte clear header (8B seq + 12B nonce) followed by n-byte ciphertext and 16-byte tag. Min 36B.',
        codeRef: 'src/common.h:HEADER_LEN, MIN_PACKET_LEN', status: 'ready',
      },
      {
        id: 'len_guard', col: 4, row: 1, y: 142, w: cardW, h: cardH,
        label: 'LENGTH GUARD', sub: 'reject <36B or >64KiB', role: 'guard',
        details: 'Immediate short/malformed packet rejection (rc -1) before performing any cryptographic operations.',
        codeRef: 'src/aead.c:SC_ERR_SHORT (-1)', status: 'ready',
      },
      {
        id: 'replay_guard', col: 4, row: 2, y: 232, w: cardW, h: cardH,
        label: 'REPLAY GUARD', sub: 'seq > last_seq check', role: 'guard',
        details: 'Read-only replay check: rejects seq ≤ last_seq with rc -3. IMPORTANT: last_seq is updated ONLY AFTER tag verifies!',
        codeRef: 'src/aead.c:SC_ERR_REPLAY (-3)', status: 'ready',
      },
      {
        id: 'aead_verify', col: 4, row: 3, y: 322, w: cardW, h: cardH,
        label: 'AEAD VERIFY', sub: 'Poly1305 tag check', role: 'guard',
        details: 'Recomputes tag over ciphertext + seq. If mismatch: wipes output buffer and returns rc -2 (tamper / wrong key / forged).',
        codeRef: 'src/aead.c:SC_ERR_AUTH (-2)', status: 'ready',
      },

      // Col 5: Server Core & Vault
      {
        id: 'server_core', col: 5, row: 0, y: 72, w: cardW, h: cardH,
        label: 'SERVER CORE', sub: 'authenticated delivery', role: 'endpoint',
        details: 'Delivers decrypted plaintext to server application. Updates replay state and triggers auto re-key if configured.',
        codeRef: 'src/session.c:session_deliver()', status: 'ready',
      },
      {
        id: 'key_vault', col: 5, row: 1, y: 187, w: cardW, h: cardH,
        label: 'KEY VAULT', sub: 'server_sk.bin (0600)', role: 'vault',
        details: 'Stores long-term Ed25519 and X25519 secret keys. Verifies POSIX file modes using stat() on every scan.',
        codeRef: 'src/keyio.c:file_mode()', status: 'ready',
      },
      {
        id: 'argon2_wrap', col: 5, row: 2, y: 302, w: cardW, h: cardH,
        label: 'ARGON2ID WRAP', sub: '64 MiB RAM · Secretbox', role: 'vault',
        details: 'Key protection at rest: Argon2id derives 32B key from passphrase, encrypts secret key with XSalsa20-Poly1305 into 120B file.',
        codeRef: 'src/wrap.c:wrap_key()', status: 'ready',
      },
    ];

    // Compute canonical node coordinates with safe bounds
    for (const node of this.nodes) {
      node.x = this.columns[node.col].x - node.w / 2;
    }

    this.nodeMap = new Map(this.nodes.map((n) => [n.id, n]));

    // Edges
    this.edges = [
      // Client -> Key Exchange
      { from: 'client_core', to: 'eph_kp', role: 'kx' },
      { from: 'key_loader',  to: 'hs_sign', role: 'auth' },
      { from: 'eph_kp',      to: 'kx_exchange', role: 'kx' },
      { from: 'hs_sign',     to: 'hs_verify', role: 'auth' },

      // Key Exchange -> Derivation
      { from: 'kx_exchange', to: 'blake2b_kdf', role: 'session' },
      { from: 'hs_verify',   to: 'blake2b_kdf', role: 'session' },
      { from: 'blake2b_kdf', to: 'key_split', role: 'session' },
      { from: 'key_split',   to: 'key_wipe', role: 'session' },

      // Derivation -> Record Layer
      { from: 'key_split',   to: 'chacha20_enc', role: 'record' },
      { from: 'client_tx',   to: 'aad_bind', role: 'record' },
      { from: 'nonce_gen',   to: 'chacha20_enc', role: 'record' },
      { from: 'aad_bind',    to: 'poly1305_mac', role: 'record' },
      { from: 'chacha20_enc',to: 'poly1305_mac', role: 'record' },

      // Record Layer -> Wire
      { from: 'chacha20_enc',to: 'wire_frame', role: 'wire' },
      { from: 'poly1305_mac',to: 'wire_frame', role: 'wire' },

      // Wire -> Validation Pipeline
      { from: 'wire_frame',  to: 'len_guard', role: 'guard' },
      { from: 'len_guard',   to: 'replay_guard', role: 'guard' },
      { from: 'replay_guard',to: 'aead_verify', role: 'guard' },

      // Validation -> Server
      { from: 'aead_verify', to: 'server_core', role: 'endpoint' },

      // Server & Vault
      { from: 'server_core', to: 'key_vault', role: 'vault' },
      { from: 'key_vault',   to: 'argon2_wrap', role: 'vault' },
    ];
  }

  /* ---- Particle Pool ----------------------------------------------------- */
  initParticles(count) {
    this.particles = [];
    for (let i = 0; i < count; i++) {
      const edge = this.edges[Math.floor(Math.random() * this.edges.length)];
      this.particles.push({
        edge,
        t: Math.random(),
        speed: 0.15 + Math.random() * 0.25,
        size: 1.2 + Math.random() * 1.5,
        alpha: 0.3 + Math.random() * 0.5,
      });
    }
  }

  /* ---- Triggers: Real Cryptographic Events -------------------------------- */

  // Triggered when a packet is sent/delivered
  triggerPacket({ seq = 1, nonceHex = '', ctHex = '', tagHex = '', verdict = 'ACCEPTED', rc = 0, attack = null }) {
    const isAttack = attack !== null && rc !== 0;
    const isReplay = rc === -3;
    const isTamper = rc === -2;
    const isShort  = rc === -1;

    // Define path of edges
    let pathEdges = [];
    if (!isAttack) {
      pathEdges = ['client_tx', 'chacha20_enc', 'wire_frame', 'len_guard', 'replay_guard', 'aead_verify', 'server_core'];
    } else {
      pathEdges = ['client_tx', 'chacha20_enc', 'wire_frame', 'len_guard', 'replay_guard', 'aead_verify'];
    }

    // Spawn animated packet capsule
    const packet = {
      id: Math.random().toString(36).slice(2),
      seq,
      nonceHex: nonceHex ? nonceHex.slice(0, 8) : 'rnd',
      tagHex: tagHex ? tagHex.slice(0, 8) : 'mac',
      verdict,
      rc,
      isAttack,
      attack,
      path: pathEdges,
      edgeIndex: 0,
      t: 0,
      color: isAttack ? '#ff0055' : '#00f0ff',
      glowColor: isAttack ? 'rgba(255, 0, 85, 0.8)' : 'rgba(0, 240, 255, 0.8)',
      trail: [],
    };
    this.packets.push(packet);

    // Spawn radar pulse at client
    this.spawnRadar('client_tx', isAttack ? '#ff0055' : '#00f0ff');
  }

  // Triggered during handshake
  triggerHandshake({ mode = 'plain', ok = true, authenticated = false }) {
    const color = authenticated ? '#b8a6ff' : '#00f0ff';
    this.spawnRadar('eph_kp', color);
    this.spawnRadar('kx_exchange', color);
    if (mode === 'signed') {
      setTimeout(() => this.spawnRadar('hs_sign', '#b8a6ff'), 150);
      setTimeout(() => this.spawnRadar('hs_verify', ok ? '#39ff14' : '#ff0055'), 300);
    }
    setTimeout(() => {
      this.spawnRadar('blake2b_kdf', '#00f0ff');
      this.spawnRadar('key_split', '#39ff14');
      this.spawnRadar('key_wipe', '#b8a6ff');
    }, 450);
  }

  // Spawn expanding radar/sonar wave
  spawnRadar(nodeId, color = '#00f0ff') {
    const node = this.nodeMap.get(nodeId);
    if (!node) return;
    this.radarRings.push({
      x: node.x + node.w / 2,
      y: node.y + node.h / 2,
      radius: 10,
      maxRadius: Math.max(node.w, node.h) * 1.8,
      color,
      alpha: 0.9,
    });
  }

  // Spawn rejection shockwave particles
  spawnRejectionExplosion(x, y, rc, reason = 'BLOCKED') {
    const count = 32;
    for (let i = 0; i < count; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 1.5 + Math.random() * 4.5;
      this.sparks.push({
        x, y,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        size: 1.5 + Math.random() * 2.5,
        alpha: 1.0,
        decay: 0.015 + Math.random() * 0.02,
        color: Math.random() > 0.3 ? '#ff0055' : '#ff2a6d',
      });
    }

    // Add temporary HUD badge
    this.badges.push({
      x, y: y - 35,
      text: `${reason} (rc ${rc})`,
      alpha: 1.0,
      color: '#ff0055',
      rise: 0,
    });
  }

  // Spawn acceptance pulse
  spawnAcceptanceFeedback(x, y) {
    for (let i = 0; i < 20; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 1.0 + Math.random() * 3.0;
      this.sparks.push({
        x, y,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        size: 1.5 + Math.random() * 2.0,
        alpha: 1.0,
        decay: 0.02 + Math.random() * 0.02,
        color: '#39ff14',
      });
    }
    this.badges.push({
      x, y: y - 35,
      text: 'ACCEPTED · rc 0',
      alpha: 1.0,
      color: '#39ff14',
      rise: 0,
    });
  }

  /* ---- Interactive Controls & Camera ------------------------------------- */
  bindEvents() {
    this.canvas.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      this.dragStartX = e.clientX - this.panX;
      this.dragStartY = e.clientY - this.panY;
    });

    window.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        this.panX = e.clientX - this.dragStartX;
        this.panY = e.clientY - this.dragStartY;
      }
      this.checkHover(e);
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = this.canvas.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
      this.zoomBy(zoomFactor, cx, cy);
    }, { passive: false });

    this.canvas.addEventListener('click', (e) => {
      const pos = this.screenToWorld(e.clientX, e.clientY);
      for (const node of this.nodes) {
        if (pos.x >= node.x && pos.x <= node.x + node.w &&
            pos.y >= node.y && pos.y <= node.y + node.h) {
          this.selectedNode = node;
          this.spawnRadar(node.id, '#00f0ff');
          if (this.options.onNodeSelect) {
            this.options.onNodeSelect(node);
          }
          return;
        }
      }
      this.selectedNode = null;
    });

    window.addEventListener('resize', () => this.resize());
  }

  screenToWorld(clientX, clientY) {
    const rect = this.canvas.getBoundingClientRect();
    const x = (clientX - rect.left - this.panX) / this.zoom;
    const y = (clientY - rect.top - this.panY) / this.zoom;
    return { x, y };
  }

  checkHover(e) {
    const pos = this.screenToWorld(e.clientX, e.clientY);
    let found = null;
    for (const node of this.nodes) {
      if (pos.x >= node.x && pos.x <= node.x + node.w &&
          pos.y >= node.y && pos.y <= node.y + node.h) {
        found = node;
        break;
      }
    }
    if (this.hoveredNode !== found) {
      this.hoveredNode = found;
      this.canvas.style.cursor = found ? 'pointer' : 'default';
    }
  }

  zoomBy(factor, centerX, centerY) {
    const prevZoom = this.zoom;
    const newZoom = Math.min(Math.max(this.zoom * factor, 0.35), 3.0);
    if (newZoom === prevZoom) return;

    const cx = centerX !== undefined ? centerX : this.width / 2;
    const cy = centerY !== undefined ? centerY : this.height / 2;

    this.panX = cx - (cx - this.panX) * (newZoom / prevZoom);
    this.panY = cy - (cy - this.panY) * (newZoom / prevZoom);
    this.zoom = newZoom;
  }

  autoFit() {
    const padX = 24;
    const padY = 16;
    const availW = Math.max(this.width - padX * 2, 300);
    const availH = Math.max(this.height - padY * 2, 200);

    const fitScale = Math.min(availW / 1140, availH / 430);
    this.zoom = fitScale;
    this.panX = (this.width - 1140 * fitScale) / 2;
    this.panY = (this.height - 430 * fitScale) / 2;
  }

  resize() {
    const rect = this.canvas.parentElement ? this.canvas.parentElement.getBoundingClientRect() : { width: 1200, height: 600 };
    const dpr = Math.min(window.devicePixelRatio || 1, this.options.maxDPR);
    this.width = rect.width || 1200;
    this.height = rect.height || 600;

    this.canvas.width = Math.floor(this.width * dpr);
    this.canvas.height = Math.floor(this.height * dpr);
    this.canvas.style.width = `${this.width}px`;
    this.canvas.style.height = `${this.height}px`;

    this.ctx.setTransform(1, 0, 0, 1, 0, 0);
    this.ctx.scale(dpr, dpr);

    // Frame graph perfectly with breathing room
    this.autoFit();
  }

  /* ---- Render Loop ------------------------------------------------------- */
  start() {
    if (this.rafId) return;
    this.lastTime = performance.now();
    const loop = (time) => {
      const dt = Math.min((time - this.lastTime) / 1000, 0.1) * this.speed;
      this.lastTime = time;

      if (!this.paused) {
        this.update(dt);
      }
      this.render();
      this.rafId = requestAnimationFrame(loop);
    };
    this.rafId = requestAnimationFrame(loop);
  }

  stop() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
  }

  /* ---- Physics & State Updates ------------------------------------------- */
  update(dt) {
    // Smooth cinematic camera lerp
    if (!this.isDragging) {
      this.panX += (this.targetPanX - this.panX) * Math.min(dt * 4.5, 1);
      this.panY += (this.targetPanY - this.panY) * Math.min(dt * 4.5, 1);
      this.zoom += (this.targetZoom - this.zoom) * Math.min(dt * 4.5, 1);
    }

    // Update Mallory actor alpha & laser
    if (this.mallory.active) {
      this.mallory.alpha = Math.min(this.mallory.alpha + dt * 2.5, 1);
    } else {
      this.mallory.alpha = Math.max(this.mallory.alpha - dt * 2.5, 0);
    }

    // Update Rekey radial shockwave
    if (this.rekeyWave.active) {
      this.rekeyWave.radius += dt * 380;
      this.rekeyWave.alpha = Math.max(0, 1 - this.rekeyWave.radius / this.rekeyWave.maxRadius);
      if (this.rekeyWave.alpha <= 0) this.rekeyWave.active = false;
    }

    // Update Laser beam
    if (this.sceneLaser.active) {
      this.sceneLaser.alpha -= dt * 1.5;
      if (this.sceneLaser.alpha <= 0) this.sceneLaser.active = false;
    }

    // Update ambient particles
    if (this.options.ambientParticles) {
      for (const p of this.particles) {
        p.t += p.speed * dt * 0.4;
        if (p.t > 1) {
          p.t = 0;
          p.edge = this.edges[Math.floor(Math.random() * this.edges.length)];
        }
      }
    }

    // Update active packet capsules
    for (let i = this.packets.length - 1; i >= 0; i--) {
      const pkt = this.packets[i];
      pkt.t += dt * 1.6;

      // Current segment
      const fromId = pkt.path[pkt.edgeIndex];
      const toId   = pkt.path[pkt.edgeIndex + 1];

      if (pkt.t >= 1) {
        pkt.t = 0;
        pkt.edgeIndex++;

        // If reached next node, trigger node radar
        if (pkt.edgeIndex < pkt.path.length) {
          const currNodeId = pkt.path[pkt.edgeIndex];
          this.spawnRadar(currNodeId, pkt.color);

          // Check for attack block point
          if (pkt.isAttack) {
            if (currNodeId === 'replay_guard' && pkt.rc === -3) {
              const node = this.nodeMap.get(currNodeId);
              this.spawnRejectionExplosion(node.x + node.w / 2, node.y + node.h / 2, pkt.rc, 'REPLAY REJECTED');
              this.packets.splice(i, 1);
              continue;
            } else if (currNodeId === 'len_guard' && pkt.rc === -1) {
              const node = this.nodeMap.get(currNodeId);
              this.spawnRejectionExplosion(node.x + node.w / 2, node.y + node.h / 2, pkt.rc, 'SHORT PACKET');
              this.packets.splice(i, 1);
              continue;
            } else if (currNodeId === 'aead_verify' && pkt.rc === -2) {
              const node = this.nodeMap.get(currNodeId);
              this.spawnRejectionExplosion(node.x + node.w / 2, node.y + node.h / 2, pkt.rc, 'AUTH FAILED');
              this.packets.splice(i, 1);
              continue;
            }
          }
        } else {
          // Packet reached destination successfully
          const lastNode = this.nodeMap.get(pkt.path[pkt.path.length - 1]);
          this.spawnAcceptanceFeedback(lastNode.x + lastNode.w / 2, lastNode.y + lastNode.h / 2);
          this.packets.splice(i, 1);
          continue;
        }
      }
    }

    // Update radar rings
    for (let i = this.radarRings.length - 1; i >= 0; i--) {
      const ring = this.radarRings[i];
      ring.radius += dt * 50;
      ring.alpha = Math.max(0, 1 - ring.radius / ring.maxRadius);
      if (ring.alpha <= 0) {
        this.radarRings.splice(i, 1);
      }
    }

    // Update spark particles
    for (let i = this.sparks.length - 1; i >= 0; i--) {
      const sp = this.sparks[i];
      sp.x += sp.vx;
      sp.y += sp.vy;
      sp.vx *= 0.96;
      sp.vy *= 0.96;
      sp.alpha -= sp.decay;
      if (sp.alpha <= 0) {
        this.sparks.splice(i, 1);
      }
    }

    // Update floating badges
    for (let i = this.badges.length - 1; i >= 0; i--) {
      const b = this.badges[i];
      b.rise += dt * 15;
      b.alpha -= dt * 0.45;
      if (b.alpha <= 0) {
        this.badges.splice(i, 1);
      }
    }
  }

  /* ---- Rendering Methods ------------------------------------------------- */
  render() {
    const ctx = this.ctx;
    ctx.save();

    // Deep canvas background (near-black charcoal navy)
    ctx.fillStyle = '#05070c';
    ctx.fillRect(0, 0, this.width, this.height);

    // Apply camera Pan & Zoom
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.zoom, this.zoom);

    // 1. Technical background grid & guides
    this.drawGrid();

    // 2. Column headers & architecture rails
    this.drawColumns();

    // 3. Curved spline edges
    this.drawEdges();

    // 4. Ambient particles
    this.drawParticles();

    // 5. Radar rings
    this.drawRadarRings();

    // 6. Nodes (cards)
    this.drawNodes();

    // 6b. Dynamic Mallory Attacker Actor
    this.drawMallory();

    // 6c. Dynamic Rekey Shockwave
    this.drawRekeyWave();

    // 6d. Targeted Scene Laser Beam
    this.drawLaser();

    // 7. Active packet capsules
    this.drawPackets();

    // 8. Explosion sparks & badges
    this.drawSparksAndBadges();

    ctx.restore();

    // 9. Static UI HUD overlays (camera controls, status indicators)
    if (this.options.showControls) {
      this.drawHUD();
    }
  }

  /* ---- Sub-renderers ----------------------------------------------------- */

  drawGrid() {
    const ctx = this.ctx;
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
    ctx.lineWidth = 1;

    const step = 32;
    const startX = -400;
    const endX = 1600;
    const startY = -200;
    const endY = 800;

    ctx.beginPath();
    for (let x = startX; x < endX; x += step) {
      ctx.moveTo(x, startY);
      ctx.lineTo(x, endY);
    }
    for (let y = startY; y < endY; y += step) {
      ctx.moveTo(startX, y);
      ctx.lineTo(endX, y);
    }
    ctx.stroke();

    // Draw subtle vertical rail lines for columns
    for (const col of this.columns) {
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.035)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(col.x, 15);
      ctx.lineTo(col.x, 395);
      ctx.stroke();
    }
  }

  drawColumns() {
    const ctx = this.ctx;
    ctx.font = '600 10.5px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillStyle = 'rgba(102, 230, 255, 0.5)';

    for (let i = 0; i < this.columns.length; i++) {
      const col = this.columns[i];
      const tag = `TIER 0${i + 1} // ${col.label}`;
      ctx.fillText(tag, col.x, 26);

      // Accent bar beneath label
      ctx.fillStyle = '#00f0ff';
      ctx.fillRect(col.x - 14, 33, 28, 1.5);
      ctx.fillStyle = 'rgba(102, 230, 255, 0.5)';
    }
  }

  getEdgeEndpoints(fn, tn) {
    if (fn.col === tn.col) {
      // Clean vertical intra-tier progression
      const p1 = { x: fn.x + fn.w / 2, y: fn.y + fn.h };
      const p2 = { x: tn.x + tn.w / 2, y: tn.y };
      const dy = (p2.y - p1.y) * 0.5;
      const cp1 = { x: p1.x, y: p1.y + dy };
      const cp2 = { x: p2.x, y: p2.y - dy };
      return { p1, p2, cp1, cp2 };
    } else {
      // Fluid horizontal cross-tier spline
      const p1 = { x: fn.x + fn.w, y: fn.y + fn.h / 2 };
      const p2 = { x: tn.x, y: tn.y + tn.h / 2 };
      const dx = Math.abs(p2.x - p1.x) * 0.5;
      const cp1 = { x: p1.x + dx, y: p1.y };
      const cp2 = { x: p2.x - dx, y: p2.y };
      return { p1, p2, cp1, cp2 };
    }
  }

  drawEdges() {
    const ctx = this.ctx;

    for (const edge of this.edges) {
      const fn = this.nodeMap.get(edge.from);
      const tn = this.nodeMap.get(edge.to);
      if (!fn || !tn) continue;

      const { p1, p2, cp1, cp2 } = this.getEdgeEndpoints(fn, tn);

      const isHovered = this.hoveredNode && (this.hoveredNode.id === fn.id || this.hoveredNode.id === tn.id);
      const isSelected = this.selectedNode && (this.selectedNode.id === fn.id || this.selectedNode.id === tn.id);

      // Determine edge glow color
      let strokeColor = 'rgba(255, 255, 255, 0.08)';
      let glowColor = 'transparent';
      let strokeWidth = 1.2;

      if (isHovered || isSelected) {
        strokeColor = 'rgba(0, 240, 255, 0.7)';
        glowColor = 'rgba(0, 240, 255, 0.3)';
        strokeWidth = 2.0;
      } else if (edge.role === 'auth') {
        strokeColor = 'rgba(184, 166, 255, 0.22)';
      } else if (edge.role === 'guard') {
        strokeColor = 'rgba(69, 217, 154, 0.22)';
      } else if (edge.role === 'wire') {
        strokeColor = 'rgba(0, 240, 255, 0.25)';
      }

      // Draw glow if highlighted
      if (glowColor !== 'transparent') {
        ctx.save();
        ctx.shadowColor = glowColor;
        ctx.shadowBlur = 8;
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = strokeWidth + 2;
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.bezierCurveTo(cp1.x, cp1.y, cp2.x, cp2.y, p2.x, p2.y);
        ctx.stroke();
        ctx.restore();
      }

      // Draw primary spline
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = strokeWidth;
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.bezierCurveTo(cp1.x, cp1.y, cp2.x, cp2.y, p2.x, p2.y);
      ctx.stroke();
    }
  }

  getBezierPoint(p1, cp1, cp2, p2, t) {
    const mt = 1 - t;
    const mt2 = mt * mt;
    const mt3 = mt2 * mt;
    const t2 = t * t;
    const t3 = t2 * t;

    return {
      x: mt3 * p1.x + 3 * mt2 * t * cp1.x + 3 * mt * t2 * cp2.x + t3 * p2.x,
      y: mt3 * p1.y + 3 * mt2 * t * cp1.y + 3 * mt * t2 * cp2.y + t3 * p2.y,
    };
  }

  drawParticles() {
    const ctx = this.ctx;

    for (const p of this.particles) {
      const fn = this.nodeMap.get(p.edge.from);
      const tn = this.nodeMap.get(p.edge.to);
      if (!fn || !tn) continue;

      const { p1, p2, cp1, cp2 } = this.getEdgeEndpoints(fn, tn);
      const pos = this.getBezierPoint(p1, cp1, cp2, p2, p.t);

      ctx.fillStyle = `rgba(0, 240, 255, ${p.alpha})`;
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 4;
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, p.size, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.shadowBlur = 0;
  }

  drawRadarRings() {
    const ctx = this.ctx;

    for (const ring of this.radarRings) {
      ctx.save();
      ctx.strokeStyle = ring.color;
      ctx.globalAlpha = ring.alpha;
      ctx.lineWidth = 1.8;
      ctx.shadowColor = ring.color;
      ctx.shadowBlur = 12;

      ctx.beginPath();
      ctx.arc(ring.x, ring.y, ring.radius, 0, Math.PI * 2);
      ctx.stroke();

      // Outer faint ring
      ctx.globalAlpha = ring.alpha * 0.4;
      ctx.beginPath();
      ctx.arc(ring.x, ring.y, ring.radius * 1.3, 0, Math.PI * 2);
      ctx.stroke();

      ctx.restore();
    }
  }

  drawNodes() {
    const ctx = this.ctx;

    for (const node of this.nodes) {
      const isHovered = this.hoveredNode && this.hoveredNode.id === node.id;
      const isSelected = this.selectedNode && this.selectedNode.id === node.id;

      // Card Box Styles
      const r = 8;
      const x = node.x;
      const y = node.y;
      const w = node.w;
      const h = node.h;

      ctx.save();

      // Determine glow & border color
      let borderColor = 'rgba(255, 255, 255, 0.12)';
      let shadowGlow = 'transparent';
      let titleColor = '#f5f7fa';

      if (isSelected) {
        borderColor = '#00f0ff';
        shadowGlow = 'rgba(0, 240, 255, 0.55)';
        titleColor = '#66e6ff';
      } else if (isHovered) {
        borderColor = 'rgba(102, 230, 255, 0.7)';
        shadowGlow = 'rgba(102, 230, 255, 0.35)';
      } else if (node.role === 'auth') {
        borderColor = 'rgba(184, 166, 255, 0.35)';
      } else if (node.role === 'guard') {
        borderColor = 'rgba(69, 217, 154, 0.35)';
      }

      // Background with subtle glass gradient
      ctx.fillStyle = isSelected ? 'rgba(13, 24, 38, 0.94)' : 'rgba(8, 14, 22, 0.88)';
      if (shadowGlow !== 'transparent') {
        ctx.shadowColor = shadowGlow;
        ctx.shadowBlur = 14;
      }

      // Rounded rectangle
      ctx.beginPath();
      ctx.roundRect(x, y, w, h, r);
      ctx.fill();

      // Border stroke
      ctx.strokeStyle = borderColor;
      ctx.lineWidth = isSelected ? 2 : 1;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Status indicator dot (top-right)
      let dotColor = '#45d99a'; // green
      if (node.role === 'auth') dotColor = '#b8a6ff';
      if (node.id === 'len_guard' || node.id === 'replay_guard' || node.id === 'aead_verify') dotColor = '#ffca68';
      if (node.id === 'key_wipe') dotColor = '#ff687a';

      ctx.fillStyle = dotColor;
      ctx.beginPath();
      ctx.arc(x + w - 14, y + 14, 3.5, 0, Math.PI * 2);
      ctx.fill();

      // Node Label (Header)
      ctx.font = '700 11.5px "Inter", "Segoe UI", sans-serif';
      ctx.textAlign = 'left';
      ctx.fillStyle = titleColor;
      ctx.fillText(node.label, x + 12, y + 23);

      // Node Subtitle (Technical spec)
      ctx.font = '500 9.5px "JetBrains Mono", monospace';
      ctx.fillStyle = 'rgba(170, 179, 192, 0.75)';
      ctx.fillText(node.sub, x + 12, y + 42);

      ctx.restore();
    }
  }

  drawPackets() {
    const ctx = this.ctx;

    for (const pkt of this.packets) {
      const fromId = pkt.path[pkt.edgeIndex];
      const toId   = pkt.path[pkt.edgeIndex + 1];
      const fn = this.nodeMap.get(fromId);
      const tn = this.nodeMap.get(toId);
      if (!fn || !tn) continue;

      const { p1, p2, cp1, cp2 } = this.getEdgeEndpoints(fn, tn);
      const pos = this.getBezierPoint(p1, cp1, cp2, p2, pkt.t);

      // Record trail
      pkt.trail.push({ x: pos.x, y: pos.y, alpha: 1.0 });
      if (pkt.trail.length > 12) pkt.trail.shift();

      // Draw packet tail
      for (let i = 0; i < pkt.trail.length; i++) {
        const pt = pkt.trail[i];
        const a = (i / pkt.trail.length) * 0.6;
        ctx.fillStyle = pkt.isAttack ? `rgba(255, 0, 85, ${a})` : `rgba(0, 240, 255, ${a})`;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 2 + i * 0.3, 0, Math.PI * 2);
        ctx.fill();
      }

      // Draw Packet Capsule Block
      ctx.save();
      ctx.translate(pos.x, pos.y);

      // Capsule Background & Glow
      ctx.shadowColor = pkt.glowColor;
      ctx.shadowBlur = 16;
      ctx.fillStyle = '#0a101d';
      ctx.strokeStyle = pkt.color;
      ctx.lineWidth = 1.5;

      const capW = 54;
      const capH = 22;
      ctx.beginPath();
      ctx.roundRect(-capW / 2, -capH / 2, capW, capH, 6);
      ctx.fill();
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Micro Badges inside capsule: [SEQ][TAG]
      ctx.font = '700 8.5px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';

      if (pkt.isAttack) {
        ctx.fillStyle = '#ff0055';
        ctx.fillText(`ATK! #${pkt.seq}`, 0, 3);
      } else {
        ctx.fillStyle = '#00f0ff';
        ctx.fillText(`PKT #${pkt.seq}`, 0, 3);
      }

      ctx.restore();
    }
  }

  drawSparksAndBadges() {
    const ctx = this.ctx;

    // Sparks
    for (const sp of this.sparks) {
      ctx.fillStyle = sp.color;
      ctx.globalAlpha = sp.alpha;
      ctx.shadowColor = sp.color;
      ctx.shadowBlur = 6;
      ctx.beginPath();
      ctx.arc(sp.x, sp.y, sp.size, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1.0;
    ctx.shadowBlur = 0;

    // Floating outcome badges
    for (const b of this.badges) {
      ctx.save();
      ctx.translate(b.x, b.y - b.rise);
      ctx.globalAlpha = Math.max(0, b.alpha);

      ctx.fillStyle = 'rgba(7, 10, 16, 0.92)';
      ctx.strokeStyle = b.color;
      ctx.lineWidth = 1.2;
      ctx.shadowColor = b.color;
      ctx.shadowBlur = 10;

      const padX = 14;
      ctx.font = '700 11px "JetBrains Mono", monospace';
      const textW = ctx.measureText(b.text).width;

      ctx.beginPath();
      ctx.roundRect(-textW / 2 - padX, -12, textW + padX * 2, 24, 6);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = b.color;
      ctx.textAlign = 'center';
      ctx.fillText(b.text, 0, 4);

      ctx.restore();
    }
  }

  drawHUD() {
    const ctx = this.ctx;

    // Bottom-left info pill
    ctx.save();
    ctx.font = '500 10.5px "JetBrains Mono", monospace';
    ctx.fillStyle = 'rgba(170, 179, 192, 0.65)';
    ctx.textAlign = 'left';
    ctx.fillText('Interactive Canvas: Drag to Pan · Scroll to Zoom · Click Node to Inspect', 18, this.height - 12);

    // If node is selected, show selected indicator
    if (this.selectedNode) {
      ctx.fillStyle = '#00f0ff';
      ctx.fillText(`SELECTED: [${this.selectedNode.label}] — ${this.selectedNode.sub}`, 18, this.height - 28);
    }
    ctx.restore();
  }

  drawMallory() {
    if (this.mallory.alpha <= 0) return;
    const ctx = this.ctx;
    const m = this.mallory;
    ctx.save();
    ctx.globalAlpha = m.alpha;
    ctx.translate(m.x, m.y);

    // Glowing border & background
    ctx.shadowColor = 'rgba(255, 0, 85, 0.85)';
    ctx.shadowBlur = 18;
    ctx.fillStyle = 'rgba(22, 6, 14, 0.94)';
    ctx.strokeStyle = '#ff0055';
    ctx.lineWidth = 2;

    ctx.beginPath();
    ctx.roundRect(-m.w / 2, -m.h / 2, m.w, m.h, 10);
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Header label
    ctx.font = '800 11px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillStyle = '#ff0055';
    ctx.fillText('⚡ ' + m.label, 0, -8);

    // Action / subtitle
    ctx.font = '600 9px "Inter", sans-serif';
    ctx.fillStyle = '#ff8fa3';
    ctx.fillText(m.action !== 'IDLE' ? m.action : m.sub, 0, 12);

    ctx.restore();
  }

  drawRekeyWave() {
    if (!this.rekeyWave.active) return;
    const ctx = this.ctx;
    const rw = this.rekeyWave;
    ctx.save();
    ctx.strokeStyle = '#b8a6ff';
    ctx.lineWidth = 2.5;
    ctx.globalAlpha = rw.alpha;
    ctx.shadowColor = '#b8a6ff';
    ctx.shadowBlur = 20;

    ctx.beginPath();
    ctx.arc(rw.x, rw.y, rw.radius, 0, Math.PI * 2);
    ctx.stroke();

    ctx.strokeStyle = '#00f0ff';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(rw.x, rw.y, rw.radius * 0.85, 0, Math.PI * 2);
    ctx.stroke();

    ctx.restore();
  }

  drawLaser() {
    if (!this.sceneLaser.active || this.sceneLaser.alpha <= 0) return;
    const ctx = this.ctx;
    const l = this.sceneLaser;
    ctx.save();
    ctx.strokeStyle = l.color;
    ctx.lineWidth = 2;
    ctx.globalAlpha = l.alpha;
    ctx.shadowColor = l.color;
    ctx.shadowBlur = 14;
    ctx.setLineDash([4, 4]);

    ctx.beginPath();
    ctx.moveTo(l.x1, l.y1);
    ctx.lineTo(l.x2, l.y2);
    ctx.stroke();

    ctx.restore();
  }

  /* ---- External API for Dashboard View ------------------------------------ */
  resetView() {
    this.autoFit();
  }

  setSpeed(s) {
    this.speed = s;
  }

  togglePause() {
    this.paused = !this.paused;
    return this.paused;
  }

  focusScene(sceneId, info = {}) {
    this.activeScene = sceneId;
    this.mallory.active = false;
    this.mallory.action = 'IDLE';

    const availW = Math.max(this.width, 300);
    const availH = Math.max(this.height, 200);

    switch (sceneId) {
      case 1: // System Online
        this.targetZoom = Math.min(availW / 1140, availH / 430);
        this.targetPanX = (this.width - 1140 * this.targetZoom) / 2;
        this.targetPanY = (this.height - 430 * this.targetZoom) / 2;
        this.spawnRadar('client_core', '#00f0ff');
        this.spawnRadar('server_core', '#39ff14');
        break;

      case 2: // Identity
        this.targetZoom = Math.min(availW / 850, availH / 380);
        this.targetPanX = this.width / 2 - 580 * this.targetZoom;
        this.targetPanY = this.height / 2 - 200 * this.targetZoom;
        this.spawnRadar('key_vault', '#b8a6ff');
        this.spawnRadar('key_loader', '#b8a6ff');
        break;

      case 3: // Session Init
        this.targetZoom = Math.min(availW / 900, availH / 380);
        this.targetPanX = this.width / 2 - 320 * this.targetZoom;
        this.targetPanY = this.height / 2 - 180 * this.targetZoom;
        this.spawnRadar('client_core', '#00f0ff');
        this.spawnRadar('eph_kp', '#00f0ff');
        break;

      case 4: // Key Exchange
        this.targetZoom = Math.min(availW / 920, availH / 400);
        this.targetPanX = this.width / 2 - 380 * this.targetZoom;
        this.targetPanY = this.height / 2 - 200 * this.targetZoom;
        this.spawnRadar('kx_exchange', '#b8a6ff');
        this.spawnRadar('blake2b_kdf', '#b8a6ff');
        this.spawnRadar('key_split', '#39ff14');
        break;

      case 5: // Authentication
        this.targetZoom = Math.min(availW / 880, availH / 380);
        this.targetPanX = this.width / 2 - 320 * this.targetZoom;
        this.targetPanY = this.height / 2 - 220 * this.targetZoom;
        this.spawnRadar('hs_sign', '#b8a6ff');
        this.spawnRadar('hs_verify', '#39ff14');
        break;

      case 6: // Secure State
        this.targetZoom = Math.min(availW / 1120, availH / 420);
        this.targetPanX = (this.width - 1120 * this.targetZoom) / 2;
        this.targetPanY = (this.height - 420 * this.targetZoom) / 2;
        this.spawnRadar('key_split', '#39ff14');
        this.spawnRadar('chacha20_enc', '#00f0ff');
        this.spawnRadar('wire_frame', '#39ff14');
        break;

      case 7: // Encryption
        this.targetZoom = Math.min(availW / 860, availH / 380);
        this.targetPanX = this.width / 2 - 380 * this.targetZoom;
        this.targetPanY = this.height / 2 - 180 * this.targetZoom;
        this.spawnRadar('client_tx', '#00f0ff');
        this.spawnRadar('chacha20_enc', '#00f0ff');
        this.spawnRadar('poly1305_mac', '#39ff14');
        this.triggerPacket({ seq: 1, nonceHex: 'e14f2b88', ctHex: '38d9f410', tagHex: '9c5f11a2', verdict: 'HELD ON WIRE', rc: 0 });
        break;

      case 8: // Packet Inspection
        this.targetZoom = Math.min(availW / 680, availH / 340);
        this.targetPanX = this.width / 2 - 800 * this.targetZoom;
        this.targetPanY = this.height / 2 - 140 * this.targetZoom;
        this.spawnRadar('wire_frame', '#00f0ff');
        break;

      case 9: // Decryption
        this.targetZoom = Math.min(availW / 820, availH / 380);
        this.targetPanX = this.width / 2 - 850 * this.targetZoom;
        this.targetPanY = this.height / 2 - 220 * this.targetZoom;
        this.spawnRadar('aead_verify', '#39ff14');
        this.spawnRadar('server_core', '#39ff14');
        this.spawnAcceptanceFeedback(1030, 100);
        break;

      case 10: // Tamper Attack
        this.mallory.active = true;
        this.mallory.action = 'FLIPPING CIPHERTEXT BIT';
        this.targetZoom = Math.min(availW / 780, availH / 360);
        this.targetPanX = this.width / 2 - 780 * this.targetZoom;
        this.targetPanY = this.height / 2 - 240 * this.targetZoom;
        this.sceneLaser = { active: true, x1: this.mallory.x, y1: this.mallory.y, x2: 845, y2: 80, color: '#ff0055', alpha: 1 };
        this.triggerPacket({ seq: 2, isAttack: true, attack: 'tamper', rc: -2, verdict: 'AUTH FAILED' });
        break;

      case 11: // Replay Attack
        this.mallory.active = true;
        this.mallory.action = 'REPLAYING ACCEPTED PACKET';
        this.targetZoom = Math.min(availW / 780, availH / 360);
        this.targetPanX = this.width / 2 - 820 * this.targetZoom;
        this.targetPanY = this.height / 2 - 230 * this.targetZoom;
        this.triggerPacket({ seq: 1, isAttack: true, attack: 'replay', rc: -3, verdict: 'REPLAY DETECTED' });
        break;

      case 12: // AAD Attack
        this.mallory.active = true;
        this.mallory.action = 'MODIFYING CLEAR SEQUENCE (AAD)';
        this.targetZoom = Math.min(availW / 780, availH / 360);
        this.targetPanX = this.width / 2 - 820 * this.targetZoom;
        this.targetPanY = this.height / 2 - 250 * this.targetZoom;
        this.triggerPacket({ seq: 1001, isAttack: true, attack: 'aad', rc: -2, verdict: 'AAD TAG MISMATCH' });
        break;

      case 13: // Sequence Attack
        this.mallory.active = true;
        this.mallory.action = 'FORGING 2^64-1 POISON SEQ';
        this.targetZoom = Math.min(availW / 780, availH / 360);
        this.targetPanX = this.width / 2 - 820 * this.targetZoom;
        this.targetPanY = this.height / 2 - 250 * this.targetZoom;
        this.triggerPacket({ seq: '18446744073709551615', isAttack: true, attack: 'forged', rc: -2, verdict: 'TAG FAILED (UNPOISONED)' });
        break;

      case 14: // Wrong Key
        this.targetZoom = Math.min(availW / 780, availH / 360);
        this.targetPanX = this.width / 2 - 820 * this.targetZoom;
        this.targetPanY = this.height / 2 - 280 * this.targetZoom;
        this.spawnRejectionExplosion(845, 350, -2, 'TAG MISMATCH · ZEROED');
        break;

      case 15: // Key Wrapping
        this.targetZoom = Math.min(availW / 720, availH / 350);
        this.targetPanX = this.width / 2 - 1000 * this.targetZoom;
        this.targetPanY = this.height / 2 - 250 * this.targetZoom;
        this.spawnRadar('argon2_wrap', '#39ff14');
        this.spawnRadar('key_vault', '#39ff14');
        break;

      case 16: // Wrong Passphrase
        this.targetZoom = Math.min(availW / 720, availH / 350);
        this.targetPanX = this.width / 2 - 1000 * this.targetZoom;
        this.targetPanY = this.height / 2 - 250 * this.targetZoom;
        this.spawnRejectionExplosion(1030, 330, -1, 'MAC FAILED · ZEROED');
        break;

      case 17: // MITM Plain
        this.mallory.active = true;
        this.mallory.action = 'SWAPPING PUBLIC KEYS (PLAIN DH)';
        this.targetZoom = Math.min(availW / 1000, availH / 400);
        this.targetPanX = (this.width - 1000 * this.targetZoom) / 2;
        this.targetPanY = (this.height - 400 * this.targetZoom) / 2;
        this.spawnRadar('kx_exchange', '#ff0055');
        break;

      case 18: // MITM Defense
        this.mallory.active = true;
        this.mallory.action = 'SUBSTITUTIONS BLOCKED BY ED25519 PIN';
        this.targetZoom = Math.min(availW / 900, availH / 380);
        this.targetPanX = this.width / 2 - 400 * this.targetZoom;
        this.targetPanY = this.height / 2 - 220 * this.targetZoom;
        this.spawnRejectionExplosion(290, 350, -1, 'KEY SWAP REJECTED');
        break;

      case 19: // Re-Keying
        this.targetZoom = Math.min(availW / 880, availH / 380);
        this.targetPanX = this.width / 2 - 480 * this.targetZoom;
        this.targetPanY = this.height / 2 - 190 * this.targetZoom;
        this.rekeyWave = { active: true, x: 475, y: 190, radius: 10, maxRadius: 550, alpha: 1 };
        this.spawnRadar('key_split', '#b8a6ff');
        this.spawnRadar('key_wipe', '#b8a6ff');
        break;

      case 20: // Test Suites
        this.targetZoom = Math.min(availW / 1140, availH / 430);
        this.targetPanX = (this.width - 1140 * this.targetZoom) / 2;
        this.targetPanY = (this.height - 430 * this.targetZoom) / 2;
        for (const n of this.nodes) {
          setTimeout(() => this.spawnRadar(n.id, '#39ff14'), Math.random() * 350);
        }
        break;

      case 21: // Final Verdict
        this.targetZoom = Math.min(availW / 1140, availH / 430);
        this.targetPanX = (this.width - 1140 * this.targetZoom) / 2;
        this.targetPanY = (this.height - 430 * this.targetZoom) / 2;
        for (const n of this.nodes) {
          this.spawnRadar(n.id, '#00f0ff');
        }
        break;

      default:
        this.autoFit();
        break;
    }
  }
}
