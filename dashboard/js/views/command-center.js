// command-center.js — Page B: Command Center (The Flagship Interactive Laboratory)
// Centerpiece application with full-screen HTML5 Canvas network visualization,
// top status telemetry strip, quick action bar, live entropy confidence waveform,
// real-time security event feed, and deep node inspector.

import { store, engine, run, subscribe } from '../store.js';
import { esc, time, chip, icons, toast, busy } from '../ui.js';
import { NetworkEngine } from '../network-engine.js';

let canvasEngine = null;
let waveRaf = null;

export default {
  id: 'command_center',
  label: 'Live Lab',
  icon: 'channel',

  mount(root, ctx) {
    root.classList.add('view-flush');
    root.innerHTML = `
      <div class="command-center-layout">
        <!-- Top High-Density Status Strip (Inspired by Video Header) -->
        <header class="cc-header">
          <div class="cc-header-left">
            <div class="cc-sys-pill">
              <span class="live-indicator"></span>
              <span class="cc-sys-name">SECURE CHANNEL // CRYPTOGRAPHIC COMMAND CENTER</span>
              <span class="cc-sys-sub">FASTEN v09 1.12 · C11 / LIBSODIUM</span>
            </div>
            <div class="cc-state-badge">
              <span class="eyebrow-mini">PROTOCOL STATE</span>
              <span id="cc-protocol-state" class="state-pill state-${store.session.state.toLowerCase()}">
                ${store.session.state}
              </span>
            </div>
          </div>

          <div class="cc-header-metrics">
            <div class="metric-card">
              <div class="m-val text-cyan" id="cc-packets-total">
                ${(store.channel?.sent || 0) + (store.channel?.received || 0)}
              </div>
              <div class="m-lbl">PACKETS PROCESSED</div>
            </div>

            <div class="metric-card">
              <div class="m-val text-lime" id="cc-verify-ratio">
                ${store.attacks.executed > 0 ? (store.attacks.blocked / store.attacks.executed).toFixed(2) : '1.00'}
              </div>
              <div class="m-lbl">VERIFY RATIO</div>
            </div>

            <div class="metric-card">
              <div class="m-val text-magenta" id="cc-attacks-blocked">
                ${store.attacks.blocked} / ${store.attacks.executed}
              </div>
              <div class="m-lbl">ATTACKS BLOCKED</div>
            </div>

            <div class="metric-card">
              <div class="m-val text-violet" id="cc-epoch">
                EPOCH ${store.session.epoch || 1}
              </div>
              <div class="m-lbl">KEY GENERATION</div>
            </div>

            <div class="metric-card">
              <div class="m-val text-amber" id="cc-latency">
                ~1.3 µs
              </div>
              <div class="m-lbl">AEAD LATENCY</div>
            </div>
          </div>

          <!-- Quick Action Triggers -->
          <div class="cc-header-actions">
            <button id="cc-btn-cinema" class="btn btn-sm" style="background: linear-gradient(135deg, #00f0ff, #0088cc); color: #020c14; font-weight: 700; border: 1px solid #00f0ff; box-shadow: 0 0 12px rgba(0,240,255,0.4);" title="Launch the full 21-scene cinematic cybersecurity lab">
              🎬 Cinematic Lab
            </button>
            <button id="cc-btn-send" class="btn btn-sm btn-cyan" title="Send a sealed ChaCha20-Poly1305 packet">
              ${icons.send || ''} Send Packet
            </button>
            <button id="cc-btn-attack" class="btn btn-sm btn-magenta" title="Launch a live attack simulation">
              ${icons.attacks || ''} Test Attack
            </button>
            <button id="cc-btn-rekey" class="btn btn-sm btn-violet" title="Derive fresh session keys in-place">
              ${icons.rekey || ''} Re-Key
            </button>
            <button id="cc-btn-handshake" class="btn btn-sm btn-ghost" title="Re-negotiate X25519 session keys">
              Handshake
            </button>
          </div>
        </header>

        <!-- Main Workspace: Large Canvas + Floating Inspection Drawer -->
        <div class="cc-canvas-container">
          <canvas id="cc-network-canvas" class="cc-canvas"></canvas>

          <!-- Floating View Controls (HUD) -->
          <div class="cc-canvas-hud">
            <button id="cc-cam-reset" class="btn-hud" title="Reset View">⤢ Reset</button>
            <button id="cc-cam-zoom-in" class="btn-hud" title="Zoom In">+</button>
            <button id="cc-cam-zoom-out" class="btn-hud" title="Zoom Out">−</button>
            <button id="cc-cam-speed" class="btn-hud" title="Toggle Speed">1.0x</button>
            <button id="cc-cam-pause" class="btn-hud" title="Pause / Resume Motion">⏸ Pause</button>
          </div>

          <!-- Interactive Node Inspector Drawer -->
          <aside id="cc-node-drawer" class="cc-drawer" hidden>
            <div class="drawer-head">
              <div class="drawer-title" id="drawer-node-label">NODE DETAILS</div>
              <button id="drawer-close" class="btn-close" aria-label="Close">✕</button>
            </div>
            <div class="drawer-body">
              <div class="drawer-sub" id="drawer-node-sub">—</div>
              <div class="drawer-desc" id="drawer-node-desc">—</div>
              <div class="drawer-field">
                <span class="field-k">CODE REFERENCE</span>
                <code class="field-v" id="drawer-node-code">—</code>
              </div>
              <div class="drawer-field">
                <span class="field-k">CURRENT STATUS</span>
                <span class="field-v" id="drawer-node-status">—</span>
              </div>
              <div class="drawer-actions">
                <button id="drawer-btn-pulse" class="btn btn-sm btn-cyan">Pulse Node</button>
              </div>
            </div>
          </aside>
        </div>

        <!-- Bottom Telemetry Panels (Lower Third matching video) -->
        <footer class="cc-footer">
          <!-- Waveform / Entropy Stream -->
          <div class="telemetry-panel telemetry-wave">
            <div class="panel-tag">
              <span>CONFIDENCE WAVEFORM</span>
              <span class="tag-status text-lime">SYNC 99.8%</span>
            </div>
            <canvas id="cc-waveform-canvas" class="waveform-canvas" width="280" height="52"></canvas>
          </div>

          <!-- Real-Time Packet Breakdown -->
          <div class="telemetry-panel telemetry-packet">
            <div class="panel-tag">
              <span>LATEST PACKET INSPECTION</span>
              <span id="cc-pkt-verdict" class="tag-status text-cyan">AWAITING TRANSMISSION</span>
            </div>
            <div class="pkt-hex-strip">
              <div class="hex-item hex-seq" title="Sequence Number (8 Bytes, BE)">
                <span class="hex-k">SEQ (8B)</span>
                <code class="hex-v" id="cc-hex-seq">00000000 00000001</code>
              </div>
              <div class="hex-item hex-nonce" title="Nonce (12 Bytes, CSPRNG)">
                <span class="hex-k">NONCE (12B)</span>
                <code class="hex-v" id="cc-hex-nonce">e1 4f 2b 88 c9 a0 ...</code>
              </div>
              <div class="hex-item hex-ct" title="Ciphertext (ChaCha20)">
                <span class="hex-k">CT</span>
                <code class="hex-v" id="cc-hex-ct">38 d9 f4 10 9b ...</code>
              </div>
              <div class="hex-item hex-tag" title="Poly1305 MAC Tag (16 Bytes)">
                <span class="hex-k">TAG (16B)</span>
                <code class="hex-v" id="cc-hex-tag">a4 1b 88 5f c2 ...</code>
              </div>
            </div>
          </div>

          <!-- Security Event Feed -->
          <div class="telemetry-panel telemetry-events">
            <div class="panel-tag">
              <span>SECURITY TELEMETRY LOG</span>
              <span class="tag-status text-violet">${store.events.length} EVENTS</span>
            </div>
            <div class="mini-event-feed" id="cc-mini-events">
              <!-- Rendered dynamically -->
            </div>
          </div>
        </footer>
      </div>
    `;

    // 1. Mount Canvas Network Engine
    const canvas = root.querySelector('#cc-network-canvas');
    if (canvas) {
      canvasEngine = new NetworkEngine(canvas, {
        interactive: true,
        showControls: true,
        ambientParticles: true,
        onNodeSelect: (node) => this.showNodeDrawer(root, node),
      });
      canvasEngine.start();
    }

    // 2. Mount Live Waveform Canvas
    this.initWaveform(root);

    // 3. Render event logs
    this.updateMiniEvents(root);

    // 4. Attach Event Listeners
    this.bindActionHandlers(root, ctx);

    // 5. Subscribe to store changes
    this.unsub = subscribe(() => {
      this.updateStatus(root);
      this.updateMiniEvents(root);
    });

    this.cleanup = () => {
      root.classList.remove('view-flush');
      if (canvasEngine) {
        canvasEngine.stop();
        canvasEngine = null;
      }
      if (waveRaf) {
        cancelAnimationFrame(waveRaf);
        waveRaf = null;
      }
      if (this.unsub) {
        this.unsub();
        this.unsub = null;
      }
    };
  },

  unmount() {
    if (this.cleanup) {
      this.cleanup();
      this.cleanup = null;
    }
  },

  /* ---- UI Updaters ------------------------------------------------------- */
  updateStatus(root) {
    const s = store.session;
    const ch = store.channel || {};
    const atks = store.attacks;

    const stateEl = root.querySelector('#cc-protocol-state');
    if (stateEl) {
      stateEl.textContent = s.state;
      stateEl.className = `state-pill state-${s.state.toLowerCase()}`;
    }

    const pktsEl = root.querySelector('#cc-packets-total');
    if (pktsEl) pktsEl.textContent = (ch.sent || 0) + (ch.received || 0);

    const ratioEl = root.querySelector('#cc-verify-ratio');
    if (ratioEl) {
      ratioEl.textContent = atks.executed > 0
        ? ((atks.blocked) / atks.executed).toFixed(2)
        : '1.00';
    }

    const atksEl = root.querySelector('#cc-attacks-blocked');
    if (atksEl) atksEl.textContent = `${atks.blocked} / ${atks.executed}`;

    const epochEl = root.querySelector('#cc-epoch');
    if (epochEl) epochEl.textContent = `EPOCH ${s.epoch || 1}`;

    // Update latest packet hex if present
    const latestPkt = store.packets[0];
    if (latestPkt) {
      const vEl = root.querySelector('#cc-pkt-verdict');
      if (vEl) {
        vEl.textContent = `${latestPkt.verdict || 'DELIVERED'} (rc ${latestPkt.rc ?? 0})`;
        vEl.className = latestPkt.rc === 0 ? 'tag-status text-lime' : 'tag-status text-magenta';
      }
      const seqEl = root.querySelector('#cc-hex-seq');
      if (seqEl && latestPkt.seq_hex) seqEl.textContent = latestPkt.seq_hex;
      const nonceEl = root.querySelector('#cc-hex-nonce');
      if (nonceEl && latestPkt.nonce_hex) nonceEl.textContent = latestPkt.nonce_hex.slice(0, 18) + '...';
      const ctEl = root.querySelector('#cc-hex-ct');
      if (ctEl && latestPkt.ct_hex) ctEl.textContent = latestPkt.ct_hex.slice(0, 18) + '...';
      const tagEl = root.querySelector('#cc-hex-tag');
      if (tagEl && latestPkt.tag_hex) tagEl.textContent = latestPkt.tag_hex.slice(0, 18) + '...';
    }
  },

  updateMiniEvents(root) {
    const list = root.querySelector('#cc-mini-events');
    if (!list) return;

    const events = store.events.slice(-6).reverse();
    if (!events.length) {
      list.innerHTML = '<div class="mini-empty">No security events recorded yet</div>';
      return;
    }

    list.innerHTML = events.map((e) => {
      let tagClass = 'tag-info';
      if (e.level === 'BLOCK' || e.level === 'ALERT' || e.level === 'ERROR') tagClass = 'tag-block';
      if (e.level === 'WIPE') tagClass = 'tag-wipe';
      if (e.level === 'AUTH' || e.level === 'SECURE') tagClass = 'tag-secure';

      return `
        <div class="mini-event-row">
          <span class="m-time">${time(e.ts)}</span>
          <span class="m-badge ${tagClass}">[${e.level}]</span>
          <span class="m-text">${esc(e.msg)}</span>
        </div>
      `;
    }).join('');
  },

  showNodeDrawer(root, node) {
    const drawer = root.querySelector('#cc-node-drawer');
    if (!drawer) return;

    drawer.hidden = false;
    root.querySelector('#drawer-node-label').textContent = node.label;
    root.querySelector('#drawer-node-sub').textContent = node.sub;
    root.querySelector('#drawer-node-desc').textContent = node.details;
    root.querySelector('#drawer-node-code').textContent = node.codeRef;
    root.querySelector('#drawer-node-status').textContent = node.status.toUpperCase();

    root.querySelector('#drawer-btn-pulse').onclick = () => {
      canvasEngine?.spawnRadar(node.id, '#00f0ff');
    };
  },

  initWaveform(root) {
    const canvas = root.querySelector('#cc-waveform-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let phase = 0;

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.7)';
      ctx.lineWidth = 1.5;
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 6;

      ctx.beginPath();
      const mid = canvas.height / 2;
      for (let x = 0; x < canvas.width; x += 2) {
        const y = mid + Math.sin(x * 0.04 + phase) * 16 + Math.cos(x * 0.08 - phase * 0.6) * 8;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      // Faint secondary harmonic
      ctx.strokeStyle = 'rgba(184, 166, 255, 0.4)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let x = 0; x < canvas.width; x += 2) {
        const y = mid + Math.cos(x * 0.05 - phase * 0.8) * 12;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      phase += 0.04;
      waveRaf = requestAnimationFrame(draw);
    };
    draw();
  },

  bindActionHandlers(root, ctx) {
    // Canvas HUD
    root.querySelector('#cc-cam-reset')?.addEventListener('click', () => {
      canvasEngine?.resetView();
    });
    root.querySelector('#cc-cam-zoom-in')?.addEventListener('click', () => {
      canvasEngine?.zoomBy(1.15);
    });
    root.querySelector('#cc-cam-zoom-out')?.addEventListener('click', () => {
      canvasEngine?.zoomBy(0.85);
    });
    root.querySelector('#cc-cam-speed')?.addEventListener('click', (e) => {
      if (!canvasEngine) return;
      if (canvasEngine.speed === 1.0) {
        canvasEngine.setSpeed(2.0);
        e.target.textContent = '2.0x';
      } else if (canvasEngine.speed === 2.0) {
        canvasEngine.setSpeed(0.5);
        e.target.textContent = '0.5x';
      } else {
        canvasEngine.setSpeed(1.0);
        e.target.textContent = '1.0x';
      }
    });
    root.querySelector('#cc-cam-pause')?.addEventListener('click', (e) => {
      if (!canvasEngine) return;
      const isPaused = canvasEngine.togglePause();
      e.target.textContent = isPaused ? '▶ Play' : '⏸ Pause';
    });

    // Close drawer
    root.querySelector('#drawer-close')?.addEventListener('click', () => {
      const drawer = root.querySelector('#cc-node-drawer');
      if (drawer) drawer.hidden = true;
    });

    // Launch Cinematic Lab Action
    root.querySelector('#cc-btn-cinema')?.addEventListener('click', () => {
      if (window.cinemaLab) window.cinemaLab.goTo(0, { runIt: true });
      else document.querySelector('#btn-open-cinema')?.click();
    });

    // Send Encrypted Packet Action
    root.querySelector('#cc-btn-send')?.addEventListener('click', async (e) => {
      if (store.session.state !== 'SECURE') {
        toast('Cannot send: Channel is in ' + store.session.state + ', not SECURE. Run Handshake first!', true);
        return;
      }
      const msg = 'Secure command transmission at ' + new Date().toLocaleTimeString();
      await busy(e.target, async () => {
        const resp = await engine('send', msg);
        if (resp.ok && resp.steps?.[0]?.packet) {
          const pkt = resp.steps[0].packet;
          canvasEngine?.triggerPacket({
            seq: pkt.seq,
            nonceHex: pkt.nonce_hex,
            ctHex: pkt.ct_hex,
            tagHex: pkt.tag_hex,
            rc: resp.steps[0].rc,
            verdict: resp.steps[0].verdict,
          });
          toast(`Packet delivered: "${resp.delivered_text}" (rc 0)`);
        } else {
          toast(resp.error || 'Send failed', true);
        }
      });
    });

    // Test Attack Action (triggers modal or cycles attack)
    root.querySelector('#cc-btn-attack')?.addEventListener('click', async (e) => {
      if (store.session.state !== 'SECURE') {
        toast('Cannot test attacks outside SECURE state. Establish handshake first!', true);
        return;
      }
      const attacks = ['tamper', 'aad', 'replay', 'reorder', 'wrongkey', 'short', 'forged'];
      const chosen = attacks[Math.floor(Math.random() * attacks.length)];
      await busy(e.target, async () => {
        const resp = await engine('attack', chosen);
        if (resp.ok && resp.attack) {
          const atk = resp.attack;
          canvasEngine?.triggerPacket({
            seq: atk.seq || 'ATK',
            rc: atk.rc,
            verdict: atk.result,
            attack: chosen,
          });
          toast(`Attack simulation [${chosen.toUpperCase()}]: ${atk.result} (rc ${atk.rc})`);
        } else {
          toast(resp.error || 'Attack failed', true);
        }
      });
    });

    // Re-Key Action
    root.querySelector('#cc-btn-rekey')?.addEventListener('click', async (e) => {
      if (store.session.state !== 'SECURE') {
        toast('Cannot re-key: channel must be in SECURE state.', true);
        return;
      }
      await busy(e.target, async () => {
        const resp = await engine('rekey');
        if (resp.ok) {
          canvasEngine?.spawnRadar('key_split', '#b8a6ff');
          canvasEngine?.spawnRadar('key_wipe', '#ff0055');
          toast(`Session re-keyed: advanced to Epoch ${resp.session.epoch}`);
        } else {
          toast(resp.error || 'Re-key failed', true);
        }
      });
    });

    // Handshake Action
    root.querySelector('#cc-btn-handshake')?.addEventListener('click', async (e) => {
      await busy(e.target, async () => {
        const resp = await engine('handshake', 'signed');
        if (resp.ok) {
          canvasEngine?.triggerHandshake({ mode: 'signed', ok: true, authenticated: true });
          toast('Signed Handshake established: state is now SECURE');
        } else {
          toast(resp.error || 'Handshake failed', true);
        }
      });
    });
  },
};
