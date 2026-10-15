// boot.js — Cinematic Boot-Up Sequence ("The Dark Network Wakes Up")
// Atmospheric opening scene: begins in near-total darkness, constellation points of light
// emerge, cryptographic telemetry connects the grid, and the lab awakens.

import { store } from './store.js';

let bootCanvas = null;
let bootCtx = null;
let animId = null;
let points = [];
let connections = [];
let phase = 0; // 0: dark/points, 1: lines connecting, 2: telemetry active, 3: title reveal
let bootStartTime = 0;

export function initBootSequence({ onEnterLab, onEnterCinema, onSkip }) {
  // If already dismissed in this session, provide instant access unless explicitly triggered
  const overlay = document.createElement('div');
  overlay.id = 'boot-sequence-overlay';
  overlay.className = 'boot-overlay';
  overlay.innerHTML = `
    <canvas id="boot-canvas" class="boot-canvas"></canvas>
    <div class="boot-vignette"></div>

    <div class="boot-telemetry" id="boot-telemetry" aria-live="polite">
      <div class="boot-term-line text-cyan">> [SYS_INIT] PREPARING CRYPTOGRAPHIC ENVIRONMENT...</div>
    </div>

    <div class="boot-center" id="boot-center">
      <div class="boot-brand-mark">
        <svg viewBox="0 0 48 48" class="boot-svg-icon" aria-hidden="true">
          <rect x="2" y="2" width="44" height="44" rx="12" fill="none" stroke="#00f0ff" stroke-width="2"/>
          <circle cx="14" cy="24" r="5" fill="#00f0ff" class="pulse-point"/>
          <circle cx="34" cy="24" r="5" fill="#39ff14" class="pulse-point"/>
          <path d="M19 24h10" stroke="#00f0ff" stroke-width="2" stroke-dasharray="3 3"/>
          <rect x="21" y="20" width="6" height="8" rx="2" fill="#b8a6ff"/>
        </svg>
      </div>

      <div class="boot-eyebrow">APPLIED CRYPTOGRAPHIC DESIGN · C11 / LIBSODIUM / OPENSSL</div>
      <h1 class="boot-title">SECURE CHANNEL</h1>
      <div class="boot-sub">THE CRYPTOGRAPHIC CINEMATIC LAB</div>
      <p class="boot-tagline">“Every Packet Tells a Story. Every Attack Has a Consequence.”</p>
      <p class="boot-desc">Experience cryptographic security as a live, interactive network journey.</p>

      <div class="boot-actions">
        <button id="boot-btn-cinema" class="btn-boot btn-boot-primary">
          <span class="btn-glow"></span>
          <span class="btn-icon">🎬</span>
          <span>START CINEMATIC JOURNEY</span>
        </button>
        <button id="boot-btn-lab" class="btn-boot btn-boot-secondary">
          <span class="btn-icon">⚡</span>
          <span>ENTER COMMAND CENTER</span>
        </button>
        <button id="boot-btn-skip" class="btn-boot btn-boot-ghost">
          <span>SKIP INTRO</span>
        </button>
      </div>

      <div class="boot-footer-meta">
        <span>STRICT INTEGRITY (INT-CTXT)</span>
        <span>•</span>
        <span>STATE-MACHINE FAIL-CLOSED</span>
        <span>•</span>
        <span>ZERO SECRETS EXPORTED</span>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  bootCanvas = document.getElementById('boot-canvas');
  if (bootCanvas) {
    bootCtx = bootCanvas.getContext('2d');
    resizeBootCanvas();
    window.addEventListener('resize', resizeBootCanvas);
    initPoints();
    bootStartTime = performance.now();
    startAnimation();
  }

  // Typewriter telemetry lines
  const telemetryLines = [
    { t: 400, text: '> [SODIUM] Initializing libsodium 1.0.18 secure heap...' },
    { t: 900, text: '> [CSPRNG] Seeding cryptographic pseudo-random generator with randombytes_buf...' },
    { t: 1400, text: '> [KEYIO] Atomic 0600 file permission guard verified for private keys...' },
    { t: 1900, text: '> [RECORD] ChaCha20-Poly1305 AEAD record pipeline ready (RFC 8439)...' },
    { t: 2400, text: '> [REPLAY] 64-bit anti-replay window armed (fail-closed state invariant)...' },
    { t: 2900, text: '> [BRIDGE] Local integration channel connected to sc_engine...' },
    { t: 3400, text: '> [SUCCESS] CRYPTOGRAPHIC COMMAND GRID ONLINE.' },
  ];

  const termEl = document.getElementById('boot-telemetry');
  telemetryLines.forEach(({ t, text }) => {
    setTimeout(() => {
      if (!overlay.parentNode) return;
      const line = document.createElement('div');
      line.className = 'boot-term-line';
      if (text.includes('SUCCESS')) line.classList.add('text-lime');
      else if (text.includes('SODIUM') || text.includes('RECORD')) line.classList.add('text-cyan');
      else if (text.includes('KEYIO')) line.classList.add('text-violet');
      line.textContent = text;
      termEl.appendChild(line);
      termEl.scrollTop = termEl.scrollHeight;
    }, t);
  });

  // Reveal center title after initial points gather
  setTimeout(() => {
    const centerEl = document.getElementById('boot-center');
    if (centerEl) centerEl.classList.add('boot-center-visible');
  }, 1600);

  function dismiss(callback) {
    overlay.classList.add('boot-overlay-exit');
    if (animId) cancelAnimationFrame(animId);
    window.removeEventListener('resize', resizeBootCanvas);
    setTimeout(() => {
      overlay.remove();
      sessionStorage.setItem('sc_boot_shown', 'true');
      if (typeof callback === 'function') callback();
    }, 600);
  }

  document.getElementById('boot-btn-cinema')?.addEventListener('click', () => {
    dismiss(onEnterCinema);
  });

  document.getElementById('boot-btn-lab')?.addEventListener('click', () => {
    dismiss(onEnterLab);
  });

  document.getElementById('boot-btn-skip')?.addEventListener('click', () => {
    dismiss(onSkip);
  });
}

function resizeBootCanvas() {
  if (!bootCanvas) return;
  bootCanvas.width = window.innerWidth;
  bootCanvas.height = window.innerHeight;
}

function initPoints() {
  const w = window.innerWidth;
  const h = window.innerHeight;
  points = [];
  const count = Math.min(80, Math.floor((w * h) / 18000));
  for (let i = 0; i < count; i++) {
    points.push({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 2 + 1,
      color: i % 5 === 0 ? '#b8a6ff' : i % 3 === 0 ? '#39ff14' : '#00f0ff',
      alpha: Math.random() * 0.7 + 0.3,
    });
  }
}

function startAnimation() {
  function draw() {
    if (!bootCtx || !bootCanvas) return;
    const w = bootCanvas.width;
    const h = bootCanvas.height;

    bootCtx.fillStyle = 'rgba(5, 7, 11, 0.25)';
    bootCtx.fillRect(0, 0, w, h);

    // Update and draw points
    for (let i = 0; i < points.length; i++) {
      const p = points[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = w;
      if (p.x > w) p.x = 0;
      if (p.y < 0) p.y = h;
      if (p.y > h) p.y = 0;

      bootCtx.beginPath();
      bootCtx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      bootCtx.fillStyle = p.color;
      bootCtx.globalAlpha = p.alpha;
      bootCtx.shadowColor = p.color;
      bootCtx.shadowBlur = 8;
      bootCtx.fill();
      bootCtx.shadowBlur = 0;

      // Draw connections
      for (let j = i + 1; j < points.length; j++) {
        const p2 = points[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 140) {
          bootCtx.beginPath();
          bootCtx.moveTo(p.x, p.y);
          bootCtx.lineTo(p2.x, p2.y);
          const lineAlpha = (1 - dist / 140) * 0.22;
          bootCtx.strokeStyle = p.color;
          bootCtx.globalAlpha = lineAlpha;
          bootCtx.lineWidth = 1;
          bootCtx.stroke();
        }
      }
    }
    bootCtx.globalAlpha = 1;

    animId = requestAnimationFrame(draw);
  }

  animId = requestAnimationFrame(draw);
}
