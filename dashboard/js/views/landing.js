// landing.js — Page A: Immersive Landing Page ("Inside the Secure Channel")
// Striking university presentation opening screen with live interactive network
// visual, core guarantees, architecture breakdown, verified test scorecards, and
// quick triggers to the Command Center and Guided Demo.

import { store } from '../store.js';
import { esc, chip, icons } from '../ui.js';
import { NetworkEngine } from '../network-engine.js';

let heroEngine = null;

export default {
  id: 'landing',
  label: 'Overview',
  icon: 'overview',

  mount(root, ctx) {
    root.innerHTML = `
      <div class="landing-page">
        <!-- Hero Section with Live Animated Canvas -->
        <section class="hero-section">
          <div class="hero-canvas-wrap">
            <canvas id="hero-network-canvas" class="hero-canvas"></canvas>
            <div class="hero-gradient-overlay"></div>
          </div>

          <div class="hero-content">
            <div class="hero-badge">
              <span class="live-dot"></span>
              <span>APPLIED CRYPTOGRAPHIC DESIGN · WORKSHOP 2 · C11 / LIBSODIUM / OPENSSL</span>
            </div>

            <h1 class="hero-title">SECURE CHANNEL</h1>

            <div class="hero-subtitle">THE CRYPTOGRAPHIC CINEMATIC LAB</div>

            <p class="hero-tagline">
              "Every Packet Tells a Story. Every Attack Has a Consequence."
            </p>

            <p class="hero-desc">
              Experience cryptographic security as a live, interactive network journey.
              Observe the cryptographic handshake, follow authenticated AEAD packets through the wire,
              trigger adversarial attacks, and verify empirical defenses backed by real C binaries.
            </p>

            <div class="hero-actions">
              <button id="hero-watch-demo" class="btn btn-hero-primary" style="background: linear-gradient(135deg, #00f0ff, #0088cc); color: #020c14; font-weight: 700; border-color: #00f0ff; box-shadow: 0 0 18px rgba(0,240,255,0.45);">
                🎬 <span>START CINEMATIC JOURNEY</span>
              </button>
              <button id="hero-enter-lab" class="btn btn-hero-secondary">
                ${icons.channel || ''} <span>ENTER COMMAND CENTER</span>
              </button>
              <button id="hero-inspect-attacks" class="btn btn-hero-ghost">
                ${icons.attacks || ''} <span>ATTACK LABORATORY</span>
              </button>
            </div>

            <!-- Mini Live Stat Bar -->
            <div class="hero-metrics">
              <div class="metric-item">
                <span class="metric-label">PROTOCOL STATE</span>
                <span class="metric-val text-cyan" id="hero-state">${store.session.state || 'INIT'}</span>
              </div>
              <div class="metric-item">
                <span class="metric-label">CRYPTOGRAPHIC CORE</span>
                <span class="metric-val text-lime">libsodium 1.0.18</span>
              </div>
              <div class="metric-item">
                <span class="metric-label">SECURITY VERIFICATION</span>
                <span class="metric-val text-violet">8/8 Attacks Blocked</span>
              </div>
              <div class="metric-item">
                <span class="metric-label">TRUST BOUNDARY</span>
                <span class="metric-val text-amber">Zero Secrets Leaked</span>
              </div>
            </div>
          </div>
        </section>

        <!-- Project Objectives & Identity -->
        <section class="landing-section">
          <div class="section-tag">// 01 · FOUNDATIONS</div>
          <h2 class="section-heading">Core Cryptographic Guarantees</h2>
          <p class="section-desc">
            A secure channel must defend against an active attacker who controls the network wire.
            Every design choice in this implementation directly enforces one of three fundamental security pillars.
          </p>

          <div class="pillars-grid">
            <div class="pillar-card pillar-cyan">
              <div class="pillar-header">
                <span class="pillar-icon">🔒</span>
                <h3>CONFIDENTIALITY</h3>
              </div>
              <div class="pillar-meta">ChaCha20 Stream Cipher · 256-Bit Ephemeral Key</div>
              <p>
                Eavesdroppers on the wire cannot read message content. Session keys are negotiated
                via ephemeral X25519 Elliptic Curve Diffie-Hellman and wiped with <code>sodium_memzero</code>
                immediately after termination for forward secrecy.
              </p>
              <div class="pillar-footer">
                <span class="badge badge-cyan">RFC 8439</span>
                <span class="badge badge-lime">Constant-Time</span>
              </div>
            </div>

            <div class="pillar-card pillar-lime">
              <div class="pillar-header">
                <span class="pillar-icon">🛡️</span>
                <h3>INTEGRITY & AUTHENTICITY</h3>
              </div>
              <div class="pillar-meta">Poly1305 MAC · 16-Byte Tag covering Ciphertext + AAD</div>
              <p>
                Unauthorized bit modifications are caught before plaintext is released. If even a single
                ciphertext or sequence bit is flipped, Poly1305 verification fails, memory is wiped,
                and <code>unseal()</code> returns return code <code>-2</code>.
              </p>
              <div class="pillar-footer">
                <span class="badge badge-lime">AEAD Construction</span>
                <span class="badge badge-cyan">Zeroed Memory</span>
              </div>
            </div>

            <div class="pillar-card pillar-violet">
              <div class="pillar-header">
                <span class="pillar-icon">⏱️</span>
                <h3>FRESHNESS & REPLAY GUARD</h3>
              </div>
              <div class="pillar-meta">64-Bit Monotonic Sequence Number · Strict Window</div>
              <p>
                Packets cannot be replayed or reordered. The sequence number is authenticated as Additional
                Authenticated Data (AAD). <strong>Critical invariant:</strong> <code>last_seq</code> is updated
                <em>only after</em> the Poly1305 tag verifies, defeating denial-of-service sequence forgery.
              </p>
              <div class="pillar-footer">
                <span class="badge badge-violet">Replay Window</span>
                <span class="badge badge-lime">State Invariant</span>
              </div>
            </div>
          </div>
        </section>

        <!-- System Architecture & Trust Boundary -->
        <section class="landing-section">
          <div class="section-tag">// 02 · ARCHITECTURE</div>
          <h2 class="section-heading">Multi-Tier Security Architecture</h2>
          <p class="section-desc">
            The project enforces a strict separation of concerns across Windows and WSL Ubuntu:
            cryptography executes exclusively in native C processes, while the browser acts purely as a visualization monitor.
          </p>

          <div class="arch-container">
            <div class="arch-box arch-browser">
              <div class="arch-title">BROWSER FRONTEND</div>
              <div class="arch-sub">HTML5 / Canvas / Vanilla JS</div>
              <ul>
                <li>High-performance Canvas network engine</li>
                <li>Real-time packet inspection & telemetry</li>
                <li>Zero cryptographic secret material in DOM/JS</li>
                <li>Strict CSP: script-src 'self'</li>
              </ul>
            </div>

            <div class="arch-arrow">
              <span>HTTP / SSE</span>
              <div class="arrow-line"></div>
              <span>X-SC-Client</span>
            </div>

            <div class="arch-box arch-bridge">
              <div class="arch-title">LOCAL NODE BRIDGE</div>
              <div class="arch-sub">127.0.0.1:8787 · Zero Dependencies</div>
              <ul>
                <li>Strict command whitelist & input validation</li>
                <li>Host header DNS-rebinding guard (421)</li>
                <li>Spawns C executables in WSL Ubuntu</li>
                <li>Never passes secrets in CLI arguments</li>
              </ul>
            </div>

            <div class="arch-arrow">
              <span>STDIN / STDOUT</span>
              <div class="arrow-line"></div>
              <span>JSON Protocol</span>
            </div>

            <div class="arch-box arch-c">
              <div class="arch-title">C CRYPTOGRAPHIC ENGINE</div>
              <div class="arch-sub">sc_engine · libsodium 1.0.18</div>
              <ul>
                <li>Session keys locked in sodium_malloc()</li>
                <li>Exact-size key file I/O with 0600 modes</li>
                <li>Emits only public bytes & return codes</li>
                <li>sodium_memzero() prevents dead-store removal</li>
              </ul>
            </div>
          </div>
        </section>

        <!-- The Wire Packet Format -->
        <section class="landing-section">
          <div class="section-tag">// 03 · PROTOCOL SPECIFICATION</div>
          <h2 class="section-heading">The AEAD Wire Packet Dissection</h2>
          <p class="section-desc">
            Every message crossing the simulated network follows the RFC 8439 ChaCha20-Poly1305 packet layout.
            Header fields are visible to eavesdroppers but cryptographically tamper-proof.
          </p>

          <div class="packet-dissection">
            <div class="pkt-block pkt-seq">
              <div class="pkt-field">SEQUENCE NUMBER</div>
              <div class="pkt-len">8 BYTES (Big-Endian)</div>
              <div class="pkt-role">Freshness & Anti-Replay Guard · Bound as AAD</div>
            </div>
            <div class="pkt-block pkt-nonce">
              <div class="pkt-field">NONCE</div>
              <div class="pkt-len">12 BYTES (96 BITS)</div>
              <div class="pkt-role">CSPRNG Random · Uniqueness guarantee per key</div>
            </div>
            <div class="pkt-block pkt-ct">
              <div class="pkt-field">CIPHERTEXT</div>
              <div class="pkt-len">N BYTES (1..64 KiB)</div>
              <div class="pkt-role">ChaCha20 Stream Ciphertext · Confidentiality</div>
            </div>
            <div class="pkt-block pkt-tag">
              <div class="pkt-field">POLY1305 MAC TAG</div>
              <div class="pkt-len">16 BYTES (128 BITS)</div>
              <div class="pkt-role">One-Time Authenticator · Integrity & Authenticity</div>
            </div>
          </div>

          <div class="packet-formula">
            Total Wire Packet Length = 20 Bytes Header + N Bytes Ciphertext + 16 Bytes Tag = <b>(36 + N) Bytes</b>
          </div>
        </section>

        <!-- Attack Lab Overview -->
        <section class="landing-section">
          <div class="section-tag">// 04 · EMPIRICAL VERIFICATION</div>
          <h2 class="section-heading">The 8 Attack Scenarios Matrix</h2>
          <p class="section-desc">
            The project implements 8 automated attack simulations testing all adversary capabilities in the threat model.
            All return codes originate from the actual C implementation.
          </p>

          <div class="attacks-table-wrap">
            <table class="landing-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>ATTACK SCENARIO</th>
                  <th>ADVERSARY ACTION</th>
                  <th>VERIFIER DEFENSE</th>
                  <th>EXPECTED RC</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>1</td>
                  <td><b>Normal Message</b></td>
                  <td>Legitimate sealed packet</td>
                  <td>Length OK, seq fresh, Poly1305 tag verified</td>
                  <td><code class="code-lime">rc 0</code></td>
                  <td><span class="badge badge-lime">ACCEPTED</span></td>
                </tr>
                <tr>
                  <td>2</td>
                  <td><b>Ciphertext Bit-Flip</b></td>
                  <td>XOR bit 0 of first ciphertext byte</td>
                  <td>Poly1305 tag mismatch, plaintext zeroed</td>
                  <td><code class="code-magenta">rc -2</code></td>
                  <td><span class="badge badge-magenta">BLOCKED</span></td>
                </tr>
                <tr>
                  <td>3</td>
                  <td><b>Sequence / AAD Tamper</b></td>
                  <td>Modify cleartext sequence counter</td>
                  <td>AAD mismatch under Poly1305 MAC tag</td>
                  <td><code class="code-magenta">rc -2</code></td>
                  <td><span class="badge badge-magenta">BLOCKED</span></td>
                </tr>
                <tr>
                  <td>4</td>
                  <td><b>Replay Attack</b></td>
                  <td>Re-inject previously captured packet</td>
                  <td>Replay window check: seq ≤ last_seq</td>
                  <td><code class="code-magenta">rc -3</code></td>
                  <td><span class="badge badge-magenta">BLOCKED</span></td>
                </tr>
                <tr>
                  <td>5</td>
                  <td><b>Packet Reordering</b></td>
                  <td>Deliver seq 3 before seq 2</td>
                  <td>Second packet rejected: seq 2 ≤ last_seq (3)</td>
                  <td><code class="code-magenta">rc -3</code></td>
                  <td><span class="badge badge-magenta">BLOCKED</span></td>
                </tr>
                <tr>
                  <td>6</td>
                  <td><b>Wrong-Key Decryption</b></td>
                  <td>Seal packet with attacker key</td>
                  <td>Tag cannot verify under recipient's session key</td>
                  <td><code class="code-magenta">rc -2</code></td>
                  <td><span class="badge badge-magenta">BLOCKED</span></td>
                </tr>
                <tr>
                  <td>7</td>
                  <td><b>Short / Malformed Packet</b></td>
                  <td>Truncate packet to 10 bytes</td>
                  <td>Length guard rejects before any crypto execution</td>
                  <td><code class="code-magenta">rc -1</code></td>
                  <td><span class="badge badge-magenta">BLOCKED</span></td>
                </tr>
                <tr>
                  <td>8</td>
                  <td><b>Forged Large Sequence</b></td>
                  <td>Set seq = 2⁶⁴-1 on tampered packet</td>
                  <td>Tag fails: last_seq UNCHANGED; valid seq 5 accepted!</td>
                  <td><code class="code-magenta">rc -2</code></td>
                  <td><span class="badge badge-magenta">BLOCKED</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- Test Suite Summary & Limitations -->
        <section class="landing-section">
          <div class="two-col-grid">
            <div class="info-card">
              <div class="section-tag">// 05 · AUDIT RESULTS</div>
              <h3 class="card-heading">Automated Test Verification</h3>
              <p>All test suites pass cleanly with zero compiler warnings:</p>
              <ul class="test-bullets">
                <li><b>Required Attack Suite:</b> 8 passed, 0 failed (make test)</li>
                <li><b>Extended Suite:</b> 35 passed, 0 failed (./test_extended)</li>
                <li><b>UI Integration Suite:</b> 46 passed, 0 failed (test_integration.js)</li>
                <li><b>OpenSSL Comparison:</b> CBC tamper undetected vs AEAD rejection</li>
                <li><b>Memory Hygiene:</b> 0 private key bytes leaked in API responses</li>
              </ul>
            </div>

            <div class="info-card info-card-warn">
              <div class="section-tag">// 06 · HONEST SECURITY GAPS</div>
              <h3 class="card-heading">Known Limitations & Boundaries</h3>
              <p>Transparent cybersecurity reporting requires documenting limitations:</p>
              <ul class="limit-bullets">
                <li><b>Plain crypto_kx is Unauthenticated:</b> Vulnerable to active MITM without the Ed25519-signed handshake extension.</li>
                <li><b>Strict Replay Window:</b> Single last_seq counter drops out-of-order packets (ideal for TCP; UDP requires a sliding bitmap).</li>
                <li><b>Nonce Birthday Bound:</b> Random 96-bit nonces should be re-keyed before 2³² packets to prevent collision risk.</li>
                <li><b>Educational Implementation:</b> Not a replacement for TLS 1.3 or Noise Protocol.</li>
              </ul>
            </div>
          </div>
        </section>
      </div>
    `;

    // Initialize Hero Network Canvas
    const canvas = root.querySelector('#hero-network-canvas');
    if (canvas) {
      heroEngine = new NetworkEngine(canvas, {
        interactive: false,
        showControls: false,
        ambientParticles: true,
      });
      heroEngine.start();

      // Trigger periodic ambient packets across hero
      const ambientInterval = setInterval(() => {
        if (!heroEngine) return;
        const seq = Math.floor(Math.random() * 99) + 1;
        heroEngine.triggerPacket({ seq, rc: 0 });
      }, 3500);

      this.cleanup = () => {
        clearInterval(ambientInterval);
        if (heroEngine) {
          heroEngine.stop();
          heroEngine = null;
        }
      };
    }

    // Attach button event listeners
    root.querySelector('#hero-enter-lab')?.addEventListener('click', () => {
      ctx.navigate('command_center', { focus: true });
    });

    root.querySelector('#hero-watch-demo')?.addEventListener('click', () => {
      if (window.cinemaLab) window.cinemaLab.goTo(0, { runIt: true });
      else document.querySelector('#btn-open-cinema')?.click();
    });

    root.querySelector('#hero-inspect-attacks')?.addEventListener('click', () => {
      ctx.navigate('attacks', { focus: true });
    });
  },

  unmount() {
    if (this.cleanup) {
      this.cleanup();
      this.cleanup = null;
    }
  },
};
