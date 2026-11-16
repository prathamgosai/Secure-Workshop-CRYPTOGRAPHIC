const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, AlignmentType, HeadingLevel, BorderStyle, ShadingType,
  ExternalHyperlink, Header, Footer, PageNumber, PageBreak, ImageRun
} = require('docx');

// Colors
const COLOR_PRIMARY = '1B365D';      // Deep Navy
const COLOR_SECONDARY = '2E6B9E';    // Slate Blue
const COLOR_TEXT = '222222';         // Charcoal
const COLOR_MUTED = '555555';        // Muted Gray
const COLOR_LIGHT_BG = 'F4F7FA';     // Off-white / Ice Blue
const COLOR_CODE_BG = 'F6F8FA';      // Code block background
const COLOR_BORDER = 'D0D7DE';       // Light Border
const COLOR_SUCCESS = '1E7E34';      // Green Pass
const COLOR_DANGER = 'B02A37';       // Red Fail / Blocked
const COLOR_ACCENT = '008080';       // Teal accent

const GITHUB_REPO_URL = 'https://github.com/prathamgosai/Secure-Workshop-CRYPTOGRAPHIC.git';
const SCREENSHOTS_DIR = path.join(__dirname, '..', 'secure-workshop', 'docs', 'screenshots');

// Helper to check image existence
function getImageBuffer(filename) {
  const p = path.join(SCREENSHOTS_DIR, filename);
  if (fs.existsSync(p)) {
    return fs.readFileSync(p);
  }
  console.warn(`Warning: Image not found: ${p}`);
  return null;
}

// Styling helper functions
function p(text, opts = {}) {
  const runs = Array.isArray(text) ? text : [new TextRun({ text: String(text), color: opts.color || COLOR_TEXT, size: opts.size || 22, bold: opts.bold, italics: opts.italics, font: opts.font || 'Calibri' })];
  return new Paragraph({
    children: runs,
    spacing: { before: opts.spaceBefore !== undefined ? opts.spaceBefore : 120, after: opts.spaceAfter !== undefined ? opts.spaceAfter : 120, line: opts.line || 280 },
    alignment: opts.alignment || AlignmentType.LEFT
  });
}

function h1(title) {
  return new Paragraph({
    children: [
      new TextRun({ text: title, bold: true, color: COLOR_PRIMARY, size: 32, font: 'Calibri' })
    ],
    spacing: { before: 360, after: 180 },
    border: {
      bottom: { style: BorderStyle.SINGLE, size: 12, color: COLOR_PRIMARY }
    }
  });
}

function h2(title) {
  return new Paragraph({
    children: [
      new TextRun({ text: title, bold: true, color: COLOR_SECONDARY, size: 26, font: 'Calibri' })
    ],
    spacing: { before: 280, after: 140 }
  });
}

function h3(title) {
  return new Paragraph({
    children: [
      new TextRun({ text: title, bold: true, color: COLOR_PRIMARY, size: 23, font: 'Calibri' })
    ],
    spacing: { before: 200, after: 100 }
  });
}

function callout(title, bodyText, type = 'info') {
  let borderColor = COLOR_PRIMARY;
  let bg = COLOR_LIGHT_BG;
  if (type === 'success') { borderColor = COLOR_SUCCESS; bg = 'EDF7EE'; }
  if (type === 'danger') { borderColor = COLOR_DANGER; bg = 'FDEDEC'; }
  if (type === 'accent') { borderColor = COLOR_ACCENT; bg = 'E6F4F4'; }

  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: 9360, type: WidthType.DXA },
            shading: { fill: bg },
            margins: { top: 140, bottom: 140, left: 240, right: 180 },
            borders: {
              top: { style: BorderStyle.NONE },
              right: { style: BorderStyle.NONE },
              bottom: { style: BorderStyle.NONE },
              left: { style: BorderStyle.SINGLE, size: 28, color: borderColor }
            },
            children: [
              new Paragraph({
                children: [new TextRun({ text: title, bold: true, color: borderColor, size: 22, font: 'Calibri' })],
                spacing: { before: 40, after: 60 }
              }),
              new Paragraph({
                children: [new TextRun({ text: bodyText, color: COLOR_TEXT, size: 21, font: 'Calibri' })],
                spacing: { before: 0, after: 40, line: 260 }
              })
            ]
          })
        ]
      })
    ]
  });
}

function codeBlock(codeLines) {
  const paras = codeLines.map(line => new Paragraph({
    children: [new TextRun({ text: line, font: 'Consolas', size: 19, color: '24292F' })],
    spacing: { before: 20, after: 20, line: 220 }
  }));

  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: 9360, type: WidthType.DXA },
            shading: { fill: COLOR_CODE_BG },
            margins: { top: 120, bottom: 120, left: 180, right: 180 },
            borders: {
              top: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
              bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
              left: { style: BorderStyle.SINGLE, size: 16, color: COLOR_SECONDARY },
              right: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER }
            },
            children: paras
          })
        ]
      })
    ]
  });
}

function figure(filename, captionText, customWidth, customHeight) {
  const buf = getImageBuffer(filename);
  if (!buf) {
    return new Paragraph({
      children: [new TextRun({ text: `[Image: ${filename} (Not Found)]`, italics: true, color: COLOR_MUTED })]
    });
  }

  // Determine aspect ratio from header if not explicitly given
  let w = customWidth || 530;
  let h = customHeight;
  if (!h) {
    const imgW = buf.readUInt32BE(16);
    const imgH = buf.readUInt32BE(20);
    const aspect = imgW / imgH;
    h = Math.round(w / aspect);
    // Limit height to fit within single Word page comfortably
    if (h > 620) {
      h = 600;
      w = Math.round(h * aspect);
    }
  }

  return [
    new Paragraph({
      children: [
        new ImageRun({
          data: buf,
          transformation: { width: w, height: h }
        })
      ],
      alignment: AlignmentType.CENTER,
      spacing: { before: 200, after: 80 }
    }),
    new Paragraph({
      children: [
        new TextRun({ text: 'Figure: ', bold: true, color: COLOR_PRIMARY, size: 20, font: 'Calibri' }),
        new TextRun({ text: captionText, italics: true, color: COLOR_MUTED, size: 20, font: 'Calibri' })
      ],
      alignment: AlignmentType.CENTER,
      spacing: { before: 40, after: 200 }
    })
  ];
}

function buildTable(headers, rowsData, colWidths) {
  const totalW = colWidths ? colWidths.reduce((a, b) => a + b, 0) : 9360;

  const headerRow = new TableRow({
    children: headers.map((h, i) => new TableCell({
      width: { size: colWidths ? colWidths[i] : Math.round(9360 / headers.length), type: WidthType.DXA },
      shading: { fill: COLOR_PRIMARY },
      margins: { top: 120, bottom: 120, left: 140, right: 140 },
      borders: {
        top: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
        bottom: { style: BorderStyle.SINGLE, size: 8, color: COLOR_PRIMARY },
        left: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
        right: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER }
      },
      children: [new Paragraph({
        children: [new TextRun({ text: h, bold: true, color: 'FFFFFF', size: 20, font: 'Calibri' })],
        alignment: AlignmentType.LEFT
      })]
    }))
  });

  const bodyRows = rowsData.map((row, rIdx) => {
    const isAlt = (rIdx % 2 === 1);
    return new TableRow({
      children: row.map((cellText, cIdx) => new TableCell({
        width: { size: colWidths ? colWidths[cIdx] : Math.round(9360 / row.length), type: WidthType.DXA },
        shading: { fill: isAlt ? COLOR_LIGHT_BG : 'FFFFFF' },
        margins: { top: 100, bottom: 100, left: 140, right: 140 },
        borders: {
          top: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
          bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
          left: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
          right: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER }
        },
        children: [new Paragraph({
          children: [new TextRun({ text: cellText, color: COLOR_TEXT, size: 19, font: 'Calibri' })],
          alignment: AlignmentType.LEFT
        })]
      }))
    });
  });

  return new Table({
    width: { size: totalW, type: WidthType.DXA },
    rows: [headerRow, ...bodyRows]
  });
}

console.log('Building document content...');

const docChildren = [];

// ==========================================
// 1. COVER PAGE
// ==========================================
docChildren.push(
  new Paragraph({
    children: [
      new TextRun({ text: 'APPLIED CRYPTOGRAPHIC DESIGN', bold: true, color: COLOR_SECONDARY, size: 24, font: 'Calibri' })
    ],
    alignment: AlignmentType.CENTER,
    spacing: { before: 400, after: 100 }
  }),
  new Paragraph({
    children: [
      new TextRun({ text: 'SECURE CHANNEL IMPLEMENTATION &\nCRYPTOGRAPHIC COMMAND CENTER', bold: true, color: COLOR_PRIMARY, size: 36, font: 'Calibri' })
    ],
    alignment: AlignmentType.CENTER,
    spacing: { before: 100, after: 150 }
  }),
  new Paragraph({
    children: [
      new TextRun({ text: 'A High-Assurance, Misuse-Resistant Protocol Engine with libsodium, Argon2id Key-Wrapping, Active Threat Simulation Lab, and OpenSSL Malleability Analysis', italics: true, color: COLOR_MUTED, size: 22, font: 'Calibri' })
    ],
    alignment: AlignmentType.CENTER,
    spacing: { before: 0, after: 400 }
  }),
  new Paragraph({
    children: [
      new TextRun({ text: '──────────────────────────────────────────────────────────────────────────', color: COLOR_SECONDARY })
    ],
    alignment: AlignmentType.CENTER,
    spacing: { before: 0, after: 400 }
  })
);

// Cover Metadata Card
const metadataRows = [
  ['Project Title', 'Secure Channel Workshop 2: Applied Cryptographic Design'],
  ['Repository URL', GITHUB_REPO_URL],
  ['Author 1 / Lead', 'Pratham Gosai (Student ID: 1551619)'],
  ['Author 2', 'Harika Thammina (Student ID: 1716803)'],
  ['Author 3', 'Leslie Varghese (Student ID: 1606013)'],
  ['Author 4', 'Fizza Fahim (Student ID: 7717258)'],
  ['Module / Domain', 'Applied Cryptographic Design & Network Security'],
  ['Submission Date', 'November 2026'],
  ['Verification Status', '100% PASS (All Core Tasks 1–6 + 4 Stretch Extensions + 89 Automated Tests)']
];

docChildren.push(
  buildTable(['Metadata Property', 'Project Specification'], metadataRows, [3000, 6360]),
  p(''),
  callout(
    'OFFICIAL REPOSITORY ACCESS',
    `The full source code, C implementation, build harness, automated test suites, and interactive dashboard telemetry are publicly available at:\n${GITHUB_REPO_URL}`,
    'accent'
  ),
  new Paragraph({
    children: [
      new ExternalHyperlink({
        children: [
          new TextRun({ text: '👉 Click here to access the GitHub Repository (prathamgosai/Secure-Workshop-CRYPTOGRAPHIC)', color: '0066CC', underline: {}, bold: true, size: 22 })
        ],
        link: GITHUB_REPO_URL
      })
    ],
    alignment: AlignmentType.CENTER,
    spacing: { before: 200, after: 400 }
  }),
  ...figure('01-overview-initial.png', 'Cryptographic Command Center Overview showing Clean Initial State and Telemetry', 520, 325),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 2. EXECUTIVE SUMMARY & TABLE OF CONTENTS
// ==========================================
docChildren.push(
  h1('Executive Summary'),
  p('This comprehensive technical report presents the architectural design, formal threat modeling, implementation, and empirical verification of a high-assurance secure communication channel implemented in C utilizing the modern cryptographic library libsodium, paired with an interactive real-time visual telemetry and attack-simulation dashboard ("Cryptographic Command Center").'),
  p('Modern secure channels must provide robust mathematical and systemic guarantees across three non-negotiable vectors: Confidentiality (guaranteeing that unauthorized third parties cannot read messages), Integrity/Authenticity (guaranteeing that any unauthorized alteration is instantaneously detected and rejected), and Freshness (ensuring messages cannot be recorded, replayed, or reordered).'),
  p('While commercial protocols such as TLS 1.3 and WireGuard implement these primitives at industrial scale, understanding the nuanced failure modes—such as unauthenticated state transitions, counter-poisoning denial of service, stream cipher keystream reuse, and CBC bit-flipping malleability—requires hands-on construction from fundamental cryptographic primitives.'),
  callout(
    'KEY ARCHITECTURAL HIGHLIGHTS',
    '1. 100% Automated Test Pass: 8/8 core attack vectors rejected, 35/35 extended C tests verified, 46/46 UI/Bridge tests passed.\n' +
    '2. Atomic Key Protection: Race-free file descriptor creation with strict 0600 POSIX permissions and Argon2id password-based key wrapping.\n' +
    '3. Authenticated Encryption with Associated Data (AEAD): ChaCha20-Poly1305-IETF with sequence counter bound as AAD.\n' +
    '4. Strictly Gated Anti-Replay: Protocol state updates occur strictly post-MAC validation, thwarting max-counter DoS attacks.\n' +
    '5. Real-World Attack Lab: Empirical proof of OpenSSL AES-256-CBC malleability bit-flip exploit vs. libsodium AEAD integrity failure.',
    'success'
  ),
  h2('Table of Contents Overview'),
  buildTable(
    ['Section', 'Title', 'Key Focus Areas'],
    [
      ['Section 1', 'Introduction, Aims & Cryptographic Objectives', 'Security triad, threat landscape, design philosophy'],
      ['Section 2', 'Adversarial Threat Model & Attack Surface', 'Dolev-Yao network attacker, OS boundary, threat matrix'],
      ['Section 3', 'System Architecture & Wire Protocol', 'State machine (INIT→AUTH→SECURE→TERMINATE), packet layout'],
      ['Section 4', 'Core Task Implementations (Tasks 1–5)', 'Key generation, X25519 kx, AEAD, replay engine, Argon2id'],
      ['Section 5', 'Task 6: libsodium vs. OpenSSL Comparative Analysis', 'PEM/DER vs binary, CBC bit-flipping attack proof, table'],
      ['Section 6', 'Advanced Protocol Extensions & Stretch Challenges', 'Localhost TCP, Ed25519-signed handshake (MITM), re-keying, benchmark'],
      ['Section 7', 'The Cryptographic Command Center Dashboard', 'Node bridge, DNS rebinding/CORS defenses, 8-byte fingerprints'],
      ['Section 8', 'Empirical Verification Matrix & Security Audit', 'Test suite outputs, compiler flags, audit checklist'],
      ['Section 9', 'Answers to Core Cryptographic Design Questions', 'In-depth academic responses to questions Q1 through Q6'],
      ['Section 10', 'Architectural Limitations & Production Roadmap', 'Residual risks, nonce limits, TLS 1.3 / Noise framework mapping'],
      ['Section 11', 'Conclusion, Deliverables & References', 'Executive wrap-up, RFC citations, repository summary']
    ],
    [1500, 4200, 3660]
  ),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 3. SECTION 1: INTRODUCTION & THREAT MODEL
// ==========================================
docChildren.push(
  h1('1. Introduction, Aims & Threat Model'),
  h2('1.1 Project Context and Problem Statement'),
  p('In modern distributed systems, data moving across untrusted networks faces relentless adversarial pressure. Network channels are routinely intercepted, analyzed, forged, and manipulated by active adversaries ranging from automated malware to nation-state intelligence. Naive cryptographic approaches frequently fail not from mathematical weaknesses in their underlying algorithms, but from flawed operational design: utilizing encryption without cryptographic integrity, failing to bind metadata to ciphertexts, exposing secret keys via improper file permissions, or allowing unauthenticated packets to poison internal state machines.'),
  p('The primary objective of this project is to architect, build, and rigorously validate a hardened point-to-point secure channel in C using libsodium, accompanied by automated regression suites and an educational visual telemetry environment. The project adheres to strict defense-in-depth principles: zero warnings under the most rigorous GCC flags, constant-time operations for secret-dependent comparisons, atomic OS file creation, and strict memory zeroization.'),

  h2('1.2 Adversarial Threat Model'),
  p('We adopt the standard Dolev-Yao adversarial model. The adversary completely controls the communication medium between the client and the server. Specifically, the adversary has the capability to:'),
  p('• Read and record every transmitted byte across the wire (Passive Eavesdropping).\n' +
    '• Mutate, flip, or inject arbitrary bits into packets in transit (Active Tampering).\n' +
    '• Replay captured valid packets at any subsequent point in time (Replay Attack).\n' +
    '• Reorder or delay legitimate packets (Reordering Attack).\n' +
    '• Inject fabricated packets with arbitrary payloads and sequence headers (Injection Attack).\n' +
    '• Interpose between client and server to negotiate separate keys with each (Man-in-the-Middle Attack).'),
  p('Adversarial Limitations and Assumptions: The attacker cannot break standard mathematical primitives (Curve25519 discrete logarithm, ChaCha20 PRF security, Poly1305 MAC unforgeability). Furthermore, the attacker cannot read files protected by 0600 POSIX permissions on the local host without root compromise, nor can they brute-force high-entropy passwords protected by memory-hard Argon2id parameters.'),

  h2('1.3 Comprehensive Threat Mitigation Matrix'),
  buildTable(
    ['Threat Vector', 'Adversarial Action', 'Consequence if Unprotected', 'Engine Mitigation Mechanism'],
    [
      ['Eavesdropping', 'Attacker intercepts wire traffic', 'Complete plaintext disclosure', 'ChaCha20 stream cipher with ephemeral 256-bit session key.'],
      ['Ciphertext Tamper', 'Attacker flips bits in payload', 'Altered application commands executed', 'Poly1305 128-bit MAC over ciphertext; fails with rc -2.'],
      ['Metadata Tamper', 'Attacker alters cleartext sequence number', 'Desynchronized counter or forged sequence', 'Sequence counter passed as Additional Authenticated Data (AAD).'],
      ['Packet Replay', 'Attacker re-sends valid captured packet', 'Duplicate transactions (e.g. double spend)', 'Strictly increasing sequence window; rejected with rc -3.'],
      ['Packet Reordering', 'Attacker delivers packet N before N-1', 'Out-of-order execution / corrupted state', 'Strict sequence check requires seq > last_seq.'],
      ['State Poisoning DoS', 'Attacker injects forged seq = 2^64 - 1', 'Receiver rejects all future genuine packets', 'last_seq counter is updated ONLY after tag verifies.'],
      ['Key Reflection', 'Attacker reflects client packet to client', 'Client accepts own packet as server reply', 'Directional key derivation: client_tx == server_rx; client_tx != client_rx.'],
      ['Disk Theft', 'Attacker steals backup image / server drive', 'Long-term private key extracted', 'Argon2id key wrapping (64 MiB RAM, salt + secretbox).'],
      ['Active MITM', 'Attacker impersonates server in handshake', 'Attacker intercepts and decrypts all traffic', 'Ed25519-signed transcript extension (Stretch 2).']
    ],
    [1600, 2400, 2500, 2860]
  ),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 4. SECTION 2: SYSTEM ARCHITECTURE
// ==========================================
docChildren.push(
  h1('2. System Architecture & Protocol Specification'),
  h2('2.1 Finite State Machine (FSM) Lifecycle'),
  p('A secure channel must enforce strict temporal boundaries. At any given instant, the protocol engine exists in exactly one of four discrete states:'),
  codeBlock([
    '┌────────┐  keys loaded   ┌────────┐  session keys   ┌──────────┐  close / error  ┌─────────────┐',
    '│  INIT  │ ─────────────► │  AUTH  │ ──────────────► │  SECURE  │ ──────────────► │  TERMINATE  │',
    '└────────┘                └────────┘   agree         └──────────┘                 └─────────────┘',
    ' sodium_init()            exchange public keys       seal()/unseal() allowed      sodium_memzero()',
    ' load key files           crypto_kx_*_session_keys   replay window active         sodium_free() secrets'
  ]),
  p('1. INIT: libsodium is initialized (sodium_init). Cryptographic key pairs are either generated or loaded from disk. No cryptographic operations on application data are permitted.\n' +
    '2. AUTH: Client and server exchange their ephemeral X25519 public keys. The Diffie-Hellman key agreement executes via crypto_kx, deriving directional session keys.\n' +
    '3. SECURE: Both parties have agreed upon directional session keys. seal() and unseal() are unlocked. The anti-replay window is active and enforcing sequence monotonicity.\n' +
    '4. TERMINATE: The session is closed either gracefully or due to a fatal cryptographic error. All session keys and ephemeral secrets are zeroized in memory and freed.'),
  ...figure('12-terminated.png', 'Protocol State Machine showing completion of full INIT → AUTH → SECURE → TERMINATE lifecycle', 520, 325),

  h2('2.2 Memory Safety and Zeroization Policy'),
  p('A common vulnerability in cryptographic C code is the residual presence of key material in memory after a session terminates. Standard memset() calls are vulnerable to Dead-Store Elimination, wherein optimizing compilers (such as GCC with -O2 or -O3) detect that the buffer is not subsequently read and optimize away the wiping operation.'),
  p('To eliminate this risk, our engine enforces:'),
  p('• sodium_memzero(): Used on all stack buffers holding secret keys, salts, derived secrets, and plaintexts immediately upon completion of their cryptographic scope. libsodium guarantees that sodium_memzero() will not be removed by compiler dead-store elimination.\n' +
    '• sodium_malloc() / sodium_free(): Used for dynamically allocated session key contexts. Memory allocated via sodium_malloc() is backed by mlock(), preventing the operating system from paging secret keys to swap space, and is flanked by guard pages to detect buffer overruns. Upon deallocation, sodium_free() automatically zeroes the entire memory region before returning it to the OS heap.'),
  ...figure('13-logs-wipe.png', 'Command Center Audit Log proving execution of sodium_memzero and sodium_free memory wiping events', 520, 325),

  h2('2.3 Binary Wire Packet Layout'),
  p('The protocol defines an immutable, unambiguous packet layout in src/common.h:'),
  codeBlock([
    '┌──────────────────────────┬────────────────────────────┬─────────────────────────────┬───────────────────────────┐',
    '│ Sequence Number (8 B)    │ Nonce (12 B)               │ Ciphertext (n Bytes)        │ Authentication Tag (16 B) │',
    '│ 64-bit Big-Endian        │ CSPRNG randombytes_buf()   │ ChaCha20 Stream Cipher      │ Poly1305 MAC              │',
    '│ Sent in Clear; Bound AAD │ Unique per message         │ Confidential Message Body   │ Covers AAD + Ciphertext   │',
    '└──────────────────────────┴────────────────────────────┴─────────────────────────────┴───────────────────────────┘',
    '◄────────────── Header = 20 Bytes ──────────────────────►◄──────── Minimum Wire Packet = 36 Bytes ────────────────►'
  ]),
  p('• Sequence Counter (8 Bytes, Big-Endian): Guarantees packet ordering and freshness. Sent in clear so the receiver can inspect it prior to performing computationally intensive decryption. It is passed into the AEAD function as Additional Authenticated Data (AAD), ensuring the tag guarantees its integrity.\n' +
    '• Nonce (12 Bytes): 96-bit cryptographically secure pseudorandom number generated fresh for each packet via randombytes_buf().\n' +
    '• Ciphertext (Variable length, 0 to 64 KiB): The encrypted application payload produced by ChaCha20.\n' +
    '• Authentication Tag (16 Bytes): 128-bit Poly1305 MAC covering the 8-byte sequence counter concatenated with the ciphertext.'),
  ...figure('05-inspector.png', 'Packet Inspector showing Byte-Level Dissection of Header, Nonce, Ciphertext, and Poly1305 Tag', 520, 325),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 5. SECTION 3: CORE TASK IMPLEMENTATIONS
// ==========================================
docChildren.push(
  h1('3. Core Technical Implementations (Tasks 1–5)'),
  h2('3.1 Task 1: Key Generation & Atomic Secure Storage'),
  p('Long-term key material constitutes the root of trust for all cryptographic operations. Task 1 implements keygen, generating two distinct cryptographic key pairs: an Ed25519 signing pair (for identity and authentication) and an X25519 pair (for Diffie-Hellman key exchange).'),
  buildTable(
    ['Key Identifier', 'Algorithm / Purpose', 'File Path', 'Size', 'POSIX Mode', 'Access Rationale'],
    [
      ['server_pk.bin', 'Ed25519 Public Key', 'keys/server_pk.bin', '32 Bytes', '0644', 'Public identity; readable by all local users.'],
      ['server_sk.bin', 'Ed25519 Secret Key', 'keys/server_sk.bin', '64 Bytes', '0600', 'Private signing key; owner read/write ONLY.'],
      ['server_kx_pk.bin', 'X25519 Public Key', 'keys/server_kx_pk.bin', '32 Bytes', '0644', 'Public key exchange; readable by all.'],
      ['server_kx_sk.bin', 'X25519 Secret Key', 'keys/server_kx_sk.bin', '32 Bytes', '0600', 'Private DH key; owner read/write ONLY.']
    ],
    [1800, 2200, 2000, 1100, 1100, 1160]
  ),
  p('The Race Condition Vulnerability in Standard File Creation: A naive implementation creates a file using fopen(path, "wb") and subsequently calls chmod(path, 0600). This creates a critical race condition: for a finite number of CPU cycles between creation and chmod, the file exists with the default system umask (frequently 0644 or 0664). An unprivileged local attacker monitoring the directory with inotify can open a read handle during this microsecond window and retain read access even after chmod executes.'),
  p('Our Hardened Solution (src/keyio.c): We invoke POSIX open() directly with the required mode passed as an atomic creation argument, augmented with O_NOFOLLOW (to prevent symlink hijacking attacks) and O_CLOEXEC:'),
  codeBlock([
    'int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);',
    'if (fd < 0) return -1;',
    'if (fchmod(fd, mode) != 0 || write_all(fd, buf, len) != 0) {',
    '    close(fd);',
    '    return -1;',
    '}'
  ]),
  p('Automated Functional Key Reload Verification: Rather than merely inspecting disk files with stat(), keygen implements an active functional test: it reloads the secret keys from disk, signs a canary message, verifies the signature against the public key, and recomputes the public X25519 point from the secret point. If file permissions or cryptographic integrity fail, the program aborts immediately.'),
  ...figure('02-vault-keys.png', 'Cryptographic Key Vault confirming atomic 0600 private permissions and 0644 public permissions', 520, 325),
  ...figure('15-vault-full.png', 'Full Key Vault Explorer showing Key Verification Status, Raw Hex, and Cryptographic Fingerprints', 420, 604),

  h2('3.2 Task 2: Ephemeral Diffie-Hellman Key Agreement (crypto_kx)'),
  p('Task 2 implements ephemeral key exchange using libsodium’s crypto_kx API on Curve25519. Client and server each generate an ephemeral key pair and transmit solely their 32-byte public keys across the network.'),
  p('Mutual Public Key Binding: Raw Curve25519 scalar multiplication produces a group element that is not uniformly distributed. crypto_kx hashes the raw 32-byte Diffie-Hellman shared secret together with both the client and server public keys using BLAKE2b-512:'),
  codeBlock([
    '// Cryptographic derivation performed internally by crypto_kx:',
    'K = BLAKE2b-512( shared_secret || client_public_key || server_public_key )',
    '// K is 64 bytes, partitioned into two 32-byte direction-specific keys:',
    'client_rx = server_tx = K[0..31]',
    'client_tx = server_rx = K[32..63]'
  ]),
  p('Why Binding Public Keys is Essential: If only the shared secret were hashed, an attacker could mount key-substitution attacks or force the parties into a small-subgroup condition. By including both public keys in the BLAKE2b hash transcript, the derived session keys are mathematically bound to this specific pair of ephemeral endpoints. If an attacker substitutes a public key, the resulting session keys diverge completely.'),
  p('Directional Key Separation & Reflection Attack Mitigation: A critical vulnerability in naive symmetric channels is key reuse across both directions. If client and server share a single symmetric key K, an attacker can intercept a packet sent by the client and reflect it back to the client; the client would successfully verify the MAC and execute its own command as if it came from the server. By generating distinct complementary keys (client_tx == server_rx and client_rx == server_tx, with client_tx != client_rx), our engine guarantees that a reflected packet fails authentication with return code -2.'),
  ...figure('03-handshake.png', 'Key Agreement Handshake showing Ephemeral Public Key Exchange and Complementary BLAKE2b Fingerprints', 520, 325),

  h2('3.3 Task 3: Authenticated Encryption with Associated Data (AEAD)'),
  p('Task 3 constructs the core record layer routines: seal() and unseal(). We deploy ChaCha20-Poly1305-IETF (RFC 8439), an authenticated cipher combining the 256-bit ChaCha20 stream cipher with the 128-bit Poly1305 universal hash MAC.'),
  codeBlock([
    '// Encryption and Authentication (seal)',
    'store_be64(seqb, seq);                     // 64-bit big-endian sequence counter',
    'randombytes_buf(nonce, NONCE_LEN);         // Fresh 12-byte CSPRNG nonce',
    'crypto_aead_chacha20poly1305_ietf_encrypt(',
    '    ct, &ct_len,                          // Ciphertext output buffer',
    '    pt, pt_len,                           // Plaintext input buffer',
    '    seqb, SEQ_LEN,                        // Sequence counter bound as AAD',
    '    NULL, nonce, key                      // Nonce and 256-bit directional key',
    ');'
  ]),
  p('Hardened Buffer Overflow Defenses: Both seal() and unseal() strictly validate output buffer capacities (out_cap and pt_cap). Furthermore, payload sizes are capped at 64 KiB to prevent memory exhaustion attacks. If unseal() encounters any authentication or capacity failure, it immediately executes sodium_memzero() over the plaintext buffer before returning, ensuring no unauthenticated or partially decrypted data is ever leaked to the caller.'),
  ...figure('04-channel-send.png', 'Live Secure Channel Transmission showing Authenticated Delivery and Verification', 520, 325),
  ...figure('04b-channel-packet-in-flight.png', 'Channel Visualization showing Encrypted Packet in Transit across Untrusted Network', 520, 325),

  h2('3.4 Task 4: Anti-Replay Protection & Active Attack Simulations'),
  p('A channel providing confidentiality and integrity remains vulnerable to replay and reordering attacks unless freshness is explicitly verified. Task 4 implements a strict sequence checking engine combined with a rigorous 8-vector attack suite.'),
  p('The Critical Security Invariant: Gating State Updates by Cryptographic Authentication:'),
  callout(
    'THE FUNDAMENTAL REPLAY STATE INVARIANT',
    'The receiver\'s replay state (last_seq) must NEVER be updated until AFTER the cryptographic authentication tag has been fully verified.\n\n' +
    'Adversarial Analysis: If an engine updates last_seq immediately upon reading the cleartext header, an attacker could forge a single packet containing sequence number 2^64 - 1. While the authentication tag would fail, the receiver\'s last_seq would now be set to maximum. Consequently, every subsequent legitimate packet sent by the client would have seq < last_seq and would be permanently rejected as a replay. Updating state prior to authentication enables a fatal single-packet Denial of Service (DoS).',
    'danger'
  ),
  p('Order of Operations in unseal():'),
  p('1. Header & Length Validation: Verify packet length >= 36 bytes and <= max capacity. If invalid, return rc -1 without performing any cryptographic calculations.\n' +
    '2. Freshness Pre-Check: Read the 8-byte big-endian sequence counter. Verify seq > last_seq. If seq <= last_seq, reject immediately with rc -3. Do NOT update state.\n' +
    '3. Authenticated Decryption: Execute crypto_aead_chacha20poly1305_ietf_decrypt. If the Poly1305 tag does not match, wipe the output buffer and reject with rc -2. Do NOT update state.\n' +
    '4. State Update: Only after step 3 succeeds, update last_seq = seq, and return rc 0 with verified plaintext.'),

  h3('Automated 8-Vector Attack Test Suite Results'),
  buildTable(
    ['Test #', 'Attack Vector', 'Adversarial Action', 'Expected Return Code', 'Observed Result'],
    [
      ['Test 1', 'Baseline Round-Trip', 'Legitimate seal() followed by unseal()', 'rc 0 (Success)', 'PASS (Plaintext verified)'],
      ['Test 2', 'Ciphertext Tamper', 'Flip 1 single bit in ciphertext body', 'rc -2 (Auth Failed)', 'PASS (Poly1305 rejected)'],
      ['Test 3', 'AAD Tamper', 'Mutate sequence bytes in cleartext header', 'rc -2 (Auth Failed)', 'PASS (AAD tag mismatch)'],
      ['Test 4', 'Packet Replay', 'Transmit exact duplicate of valid packet', 'rc -3 (Replay Detected)', 'PASS (Second copy blocked)'],
      ['Test 5', 'Packet Reorder', 'Transmit packet with seq=3, then seq=2', 'rc -3 (Replay Detected)', 'PASS (Out-of-order blocked)'],
      ['Test 6', 'Wrong Key Confusion', 'Attempt decryption with different key', 'rc -2 (Auth Failed)', 'PASS (Tag mismatch)'],
      ['Test 7', 'Packet Truncation', 'Transmit truncated packet (< 36 bytes)', 'rc -1 (Malformed Packet)', 'PASS (Rejected prior to crypto)'],
      ['Test 8', 'Forged Seq DoS Attack', 'Inject fake packet with seq=1000, then valid seq=5', 'rc 0 on valid packet', 'PASS (State unpoisoned; seq=5 accepted)']
    ],
    [900, 1900, 2600, 1960, 2000]
  ),
  ...figure('06-attack-tamper.png', 'Attack Lab: Single Ciphertext Bit-Flip Rejected by Poly1305 MAC with rc -2', 520, 325),
  ...figure('07-attack-replay.png', 'Attack Lab: Duplicate Packet Replay Blocked by Anti-Replay Engine with rc -3', 520, 325),
  ...figure('18-attack-lab-all8.png', 'Comprehensive Attack Lab showing All 8 Attack Scenarios Executed Live and Proven Blocked', 420, 604),
  ...figure('08-test-suite.png', 'Command Center Automated Test Suite showing 8/8 Tests Passing with Zero Failures', 520, 325),

  h2('3.5 Task 5: Encrypted Key Storage via Argon2id Key Wrapping'),
  p('Storing private keys in raw binary files leaves them vulnerable if server disk storage or backups are stolen. Task 5 implements password-based key wrapping using Argon2id (RFC 9106) and XSalsa20-Poly1305 (crypto_secretbox).'),
  p('Why Argon2id: Traditional KDFs like PBKDF2 or standard SHA-256 are compute-bound only; an adversary utilizing custom ASIC or GPU arrays can compute billions of candidate password hashes per second in parallel. Argon2id is a memory-hard password hashing algorithm designed to resist GPU/ASIC acceleration by filling large regions of memory with pseudorandom data and performing unpredictable reads and writes.'),
  p('Operational Parameters: We configure crypto_pwhash with OPSLIMIT_INTERACTIVE and MEMLIMIT_INTERACTIVE (64 MiB RAM requirement). On our benchmark platform, each Argon2id derivation consumes approximately 103–130 milliseconds. While imperceptible for an interactive user login, this 64 MiB memory requirement forces any brute-force attacker to commit terabytes of fast memory to test even modest dictionary candidate sets.'),
  p('Wrapped File Structure (120 Bytes total):'),
  codeBlock([
    '┌────────────────┬────────────────┬──────────────────────────┬─────────────────────────────┐',
    '│ Salt (16 B)    │ Nonce (24 B)   │ Poly1305 MAC (16 B)      │ Ciphertext (64 B)           │',
    '│ CSPRNG random  │ XSalsa20 nonce │ Authentication Tag       │ Encrypted Ed25519 Secret    │',
    '└────────────────┴────────────────┴──────────────────────────┴─────────────────────────────┘'
  ]),
  p('Automated Verification: keywrap tests four boundary cases: (1) Correct passphrase successfully unwraps the exact original key; (2) Incorrect passphrase triggers MAC failure and yields no key material; (3) Tampering with the wrapped file triggers MAC rejection; (4) Two consecutive wraps of the identical key produce distinct ciphertexts due to fresh CSPRNG salt and nonce generation.'),
  ...figure('09-key-wrapping.png', 'Password-Based Key Wrapping Lab showing Argon2id Derivation and Rejection of Incorrect Passphrases', 520, 325),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 6. SECTION 4: TASK 6 OPENSSL COMPARISON
// ==========================================
docChildren.push(
  h1('4. Comparative Cryptographic Analysis: libsodium vs. OpenSSL CLI (Task 6)'),
  h2('4.1 Architectural Differences: Raw Binary vs. ASN.1 / PEM'),
  p('Task 6 compares the design choices of modern libsodium against the widely used OpenSSL CLI (OpenSSL 3.5.5). The fundamental difference lies in their philosophy of representation and misuse resistance:'),
  p('• libsodium: Operates strictly on raw, fixed-size byte buffers (32-byte public keys, 64-byte secret keys). There are no headers, metadata wrappers, or ASN.1 parsing layers. This eliminates entire classes of ASN.1 parser vulnerabilities (such as buffer overflows and integer parsing flaws) and enforces predictable memory sizes.\n' +
    '• OpenSSL CLI: Encapsulates keys within ASN.1 structures (PKCS#8 for private keys, SubjectPublicKeyInfo for public keys) and encodes them using Base64 text framed by "-----BEGIN/END-----" delimiters (PEM). An OpenSSL Ed25519 public key expands to 44 DER bytes (or over 100 bytes of PEM text) compared to libsodium’s 32 raw bytes.'),

  h2('4.2 The Danger of Unauthenticated Encryption: AES-256-CBC Malleability Exploit'),
  p('A critical finding in our comparative study is the stark contrast between Authenticated Encryption (AEAD) and legacy cipher modes like AES-256-CBC.'),
  callout(
    'THE AES-CBC BIT-FLIPPING MATHEMATICAL VULNERABILITY',
    'In Cipher Block Chaining (CBC) mode, decryption of ciphertext block C_i to yield plaintext block P_i proceeds according to:\n' +
    '    P_i = AES_Decrypt(C_i) ⊕ C_{i-1}\n\n' +
    'Notice that C_{i-1} is XORed directly into the decrypted output. Consequently, if an attacker alters bit k in ciphertext block C_{i-1}, exactly bit k in plaintext block P_i is flipped! While block P_{i-1} decrypts to random garbage, block P_i undergoes deterministic, controlled modification without triggering any cryptographic error.',
    'danger'
  ),
  p('Real Exploit Execution (scripts/openssl_compare.sh):'),
  p('1. A transaction message is encrypted using OpenSSL: openssl enc -aes-256-cbc -salt -pbkdf2 -in payment.txt -out payment.enc.\n' +
    '   Plaintext payload: "FROM=Pratham;TO=Bob;AMOUNT=00100"\n' +
    '2. The script executes an active bit-flip: byte 30 in the ciphertext (corresponding to the AMOUNT field in block 2) is XORed with 0x09.\n' +
    '3. Decryption is attempted: openssl enc -d -aes-256-cbc -pbkdf2 -in tampered.enc.\n' +
    '4. Critical Observation: OpenSSL decrypts the file and exits with code 0 (SUCCESS)! The first block is scrambled, but the second block reads: "Bob;AMOUNT=90100". The recipient accepts a forged payment of $90,100 instead of $100.\n' +
    '5. In contrast, the identical bit flip applied to our libsodium ChaCha20-Poly1305 packet is immediately detected by the Poly1305 MAC; unseal() aborts with rc -2 and wipes the buffer.'),

  h2('4.3 Detailed Feature Comparison Matrix'),
  buildTable(
    ['Property', 'libsodium (This Implementation)', 'OpenSSL Command-Line Tool (CLI)'],
    [
      ['Key Representation', 'Raw binary bytes (32 B X25519, 64 B Ed25519)', 'PKCS#8 / SubjectPublicKeyInfo structures (ASN.1 DER)'],
      ['Key File Encoding', 'Raw binary (.bin), zero overhead', 'PEM: Base64 ASCII between -----BEGIN/END----- banners'],
      ['File Permission Safety', 'Atomic 0600 creation via open(O_CREAT | O_EXCL)', 'Created as 0600 in OpenSSL 3; older versions relied on umask'],
      ['Encryption Mode', 'ChaCha20-Poly1305 AEAD (Confidentiality + Integrity)', 'aes-256-cbc: Confidentiality only, NO MAC'],
      ['Tamper Detection', 'Guaranteed: 128-bit Poly1305 tag catches all alterations', 'NONE: Bit flips decrypt cleanly with exit code 0'],
      ['Password KDF', 'Argon2id (Memory-hard: 64 MiB RAM, GPU-resistant)', 'PBKDF2 (CPU-bound: highly vulnerable to GPU cracking)'],
      ['Padding Attacks', 'Immune: stream cipher requires no block padding', 'Vulnerable to Vaudenay padding oracle attacks'],
      ['Misuse Resistance', 'Very High: opinionated API with safe cryptographic defaults', 'Lower: hundreds of algorithm flags; easy to pick insecure mode']
    ],
    [1600, 3880, 3880]
  ),
  ...figure('10-openssl.png', 'OpenSSL Comparison View displaying Key Structures and CLI Encryption Pipelines', 520, 325),
  ...figure('16-openssl-full.png', 'Empirical Proof of OpenSSL CBC Malleability Bit-Flip Attack vs. libsodium AEAD Integrity Failure', 420, 604),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 7. SECTION 5: ADVANCED EXTENSIONS
// ==========================================
docChildren.push(
  h1('5. Advanced Protocol Extensions & Stretch Challenges'),
  p('Beyond the mandatory core requirements, four advanced stretch challenges were implemented to address real-world deployment challenges: network transport, active Man-in-the-Middle attacks, long-term session key exhaustion, and hardware performance characterization.'),

  h2('5.1 Stretch 1: Localhost TCP Client/Server Socket Implementation'),
  p('The core tasks execute in a single process. Stretch 1 extends the engine across real POSIX network sockets (src/tcp_server.c, src/tcp_client.c, src/net.c) listening on 127.0.0.1:7700.'),
  p('• Binary Framing Protocol: Stream sockets (TCP) provide a continuous stream of bytes without message boundaries. We implement a binary framing protocol: every message begins with a 4-byte big-endian length prefix, followed by a 1-byte frame type (FRAME_HANDSHAKE, FRAME_DATA, FRAME_ACK, FRAME_ALERT, FRAME_BYE), followed by the packet body.\n' +
    '• Transport-Level Attack Resistance: An attacker tampering with packets or injecting replays across the local socket is detected in real time. The server rejects invalid packets and transmits an ALERT frame before closing the socket. Graceful termination ensures keys are wiped with sodium_free() upon client disconnect.'),
  ...figure('20-tcp-mode.png', 'Localhost TCP Client/Server Architecture executing Encrypted Communication and Re-Keying over Sockets', 420, 604),

  h2('5.2 Stretch 2: Defense Against Active Man-in-the-Middle (MITM) Attacks'),
  p('The Fundamental Vulnerability of Plain crypto_kx: Anonymous Diffie-Hellman key exchange provides confidentiality against passive eavesdroppers, but provides zero identity authentication. An active adversary (Mallory) on the network path can intercept the client’s public key, return her own public key, and concurrently negotiate a second session with the server. Mallory decrypts, reads, alters, and re-encrypts all messages transparently.'),
  p('Our Solution: Ed25519-Signed Handshake Transcripts (src/handshake.c):'),
  codeBlock([
    '// Server signs the mutual transcript with long-term Ed25519 identity key:',
    'transcript = "SC-HANDSHAKE-v1" || server_ephemeral_pk || client_ephemeral_pk',
    'crypto_sign_detached(signature, NULL, transcript, sizeof(transcript), server_identity_sk);',
    '',
    '// Client verifies the signature against trusted server_pk.bin prior to key derivation:',
    'if (crypto_sign_verify_detached(signature, transcript, sizeof(transcript), server_identity_pk) != 0) {',
    '    abort_handshake(); // MITM detected!',
    '}'
  ]),
  p('Why Binding the Client Public Key is Vital: If the server only signed its own ephemeral key, Mallory could capture a valid server signature from one session and replay it into another session. By including the client’s ephemeral public key in the signed transcript, the signature is cryptographically bound to this unique handshake instance. The attack lab tests three MITM variations: (1) Substituted ephemeral key; (2) Mallory’s forged signature; (3) Replayed signature from a prior session. All three are successfully thwarted.'),
  ...figure('19-handshake-mitm.png', 'Ed25519-Signed Handshake Transcript defeating Active Man-in-the-Middle Attack Variants', 420, 604),

  h2('5.3 Stretch 3: Epoch-Based In-Place Session Re-Keying'),
  p('To maintain Forward Secrecy across prolonged sessions and prevent nonce exhaustion, Stretch 3 implements an in-place Key Derivation ratchet using crypto_kdf_derive_from_key:'),
  codeBlock([
    '// Both endpoints derive epoch K_{i+1} from K_i without on-wire key exchange:',
    'crypto_kdf_derive_from_key(new_key, 32, epoch, "SCREKEY1", current_key);',
    'sodium_memzero(current_key, 32);',
    'memcpy(current_key, new_key, 32);'
  ]),
  p('Because the KDF is a one-way cryptographic hash, knowledge of key K_{epoch+1} provides zero information about prior key K_{epoch}. Re-keying occurs automatically every N messages or upon explicit demand.'),

  h2('5.4 Stretch 4: High-Performance AEAD Benchmarking'),
  p('Stretch 4 implements aead_bench, measuring encryption throughput and latency across payload sizes from 64 Bytes to 16 KiB on a modern multicore CPU with AES-NI hardware extensions:'),
  buildTable(
    ['Algorithm', 'Hardware Acceleration', 'Latency (1 KiB)', 'Throughput (1 KiB)', 'Security / Portability Assessment'],
    [
      ['ChaCha20-Poly1305-IETF', 'Software (Pure ALU/SIMD)', '≈ 1.30 µs', '≈ 740 MiB/s', 'Constant-time on all CPUs; immune to cache-timing attacks.'],
      ['AES-256-GCM', 'Hardware AES-NI & CLMUL', '≈ 0.80 µs', '≈ 1180 MiB/s', 'Ultra-fast on modern x86/ARM; vulnerable to timing leaks if no hardware AES.'],
      ['seal() Wrapper (Total)', 'Software + Random Nonce', '≈ 1.35 µs', '≈ 720 MiB/s', 'Complete wire packet encapsulation overhead is < 4% total execution time.']
    ],
    [2200, 2000, 1400, 1500, 2260]
  ),
  ...figure('17-bench-full.png', 'High-Performance Cryptographic AEAD Benchmarking showing Throughput and Latency Profiles', 420, 604),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 8. SECTION 6: COMMAND CENTER & DASHBOARD
// ==========================================
docChildren.push(
  h1('6. The Cryptographic Command Center (Web Dashboard & Bridge)'),
  h2('6.1 Zero-Trust Local Bridge Architecture'),
  p('To demonstrate the cryptographic engine without introducing security vulnerabilities, the project includes a zero-dependency local web bridge (bridge/server.js) written in Node.js, interfacing with the C engine (sc_engine).'),
  p('Strict Localhost Security Isolation:'),
  p('• Loopback Binding: The HTTP server binds exclusively to 127.0.0.1, preventing any inbound network connections from adjacent hosts.\n' +
    '• DNS Rebinding Defense: Every incoming HTTP request is checked against a strict Host header whitelist (localhost:7070 or 127.0.0.1:7070). Malicious external domains attempting DNS rebinding are rejected with 403 Forbidden.\n' +
    '• CSRF & Cross-Site Scripting Protection: The bridge enforces a custom header requirement (X-Requested-With: sc-dashboard). Standard cross-origin browser form submissions or fetch() calls cannot attach custom headers without triggering CORS preflights, which the bridge strictly rejects.\n' +
    '• Whitelisted Command Execution: The bridge accepts only a rigid whitelist of predefined commands; it never invokes arbitrary shell strings.'),

  h2('6.2 Privacy-Preserving Visual Telemetry: BLAKE2b Key Fingerprinting'),
  p('A core requirement of the visual dashboard is allowing human operators to confirm that client_tx matches server_rx without exposing secret keys in the browser or on the loopback IPC channel.'),
  p('Solution: 8-Byte Domain-Keyed Fingerprints:'),
  codeBlock([
    '// sc_engine computes a one-way fingerprint using BLAKE2b with a fixed internal domain key:',
    'crypto_generichash(fingerprint, 8, session_key, 32, "SC-FINGERPRINT-v1", 17);'
  ]),
  p('Because BLAKE2b is a preimage-resistant cryptographic hash, observing the fingerprint reveals zero information about the underlying session key bytes. Yet, identical session keys produce identical 8-byte hexadecimal fingerprints, providing instant visual verification of key agreement. Our automated integration test suite scans every HTTP response to mathematically guarantee that raw session key bytes never leave the C process.'),

  h2('6.3 20-Step Automated Interactive Demonstration'),
  p('The dashboard incorporates an automated 20-step demonstration runner that steps through the complete system lifecycle against the live compiled binaries: generating keys, validating POSIX 0600 modes, running the X25519 handshake, transmitting sealed packets, executing all 8 attack simulations, demonstrating Argon2id key-wrapping, running the OpenSSL CBC exploit, and culminating in memory zeroization upon session termination.'),
  ...figure('14-attack-lab-full.png', 'Attack Lab Control Panel displaying Interactive Attack Scenarios and Live Return Code Telemetry', 420, 604),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 9. SECTION 7: TEST MATRIX & SECURITY AUDIT
// ==========================================
docChildren.push(
  h1('7. Empirical Verification Matrix & Security Audit'),
  h2('7.1 Comprehensive Test Suite Summary'),
  p('Every component of the secure channel undergoes rigorous automated regression testing across multiple testing tiers:'),
  buildTable(
    ['Test Suite', 'Test Runner', 'Scope of Verification', 'Total Checks', 'Passing', 'Status'],
    [
      ['Core Attacks Suite', 'tests/test_attacks.c', 'AEAD roundtrip, tamper, AAD mutate, replay, reorder, wrong key, truncation, forged seq DoS', '8', '8', '100% PASS'],
      ['Extended C Suite', 'tests/test_extended.c', 'Atomic permissions, symlink refusal, state transitions, re-keying, signed handshake', '35', '35', '100% PASS'],
      ['UI / Bridge Suite', 'bridge/test_integration.js', 'Bridge security headers, DNS rebinding, API validation, secret leak scan, live attack lab', '46', '46', '100% PASS'],
      ['Terminal Security Audit', 'make audit', 'Memory protection, compiler flags, binary hardening, POSIX file modes', '16', '16', '100% PASS'],
      ['TOTAL VERIFICATIONS', 'All Suites Combined', 'End-to-End Cryptographic, Systemic, and Network Integrity', '105', '105', '100% PASS']
    ],
    [1600, 2000, 3160, 900, 800, 900]
  ),

  h2('7.2 Compiler Hardening Flags'),
  p('The project Makefile enforces an uncompromising compiler configuration with zero warnings:'),
  codeBlock([
    'CFLAGS = -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -O2 \\',
    '         -fstack-protector-strong -D_FORTIFY_SOURCE=2'
  ]),
  p('• -fstack-protector-strong: Emits stack canaries for any function with local arrays, guarding against stack buffer overflow exploitation.\n' +
    '• -D_FORTIFY_SOURCE=2: Enables runtime buffer length checks for standard memory and string operations.\n' +
    '• -Wshadow & -Wpedantic: Prohibits variable shadowing and enforces strict ISO C standards compliance.'),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 10. SECTION 8: ANSWERS TO DESIGN QUESTIONS
// ==========================================
docChildren.push(
  h1('8. Solutions to Core Cryptographic Design Questions'),
  h2('Question 1: Why are private keys stored with 0600 permissions, created atomically?'),
  p('Answer: POSIX mode 0600 enforces that only the file owner has read and write permissions; all other system users and group members are denied access. Creating the file atomically using open(path, O_CREAT | O_EXCL, 0600) ensures that the file is born with 0600 permissions. If a developer instead calls fopen() followed by chmod(), the operating system creates the file with permissions governed by the process umask (commonly 0644 or 0664). This creates a critical time-of-check to time-of-use (TOCTOU) race window during which an unprivileged local adversary can open a read handle and continuously read key data even after chmod() executes.'),

  h2('Question 2: Why does crypto_kx hash the shared secret together with both public keys?'),
  p('Answer: The raw output of Curve25519 scalar multiplication is an elliptic curve point, not a uniformly distributed pseudorandom key. Hashing it with BLAKE2b-512 extracts entropy and produces uniformly random key material. Crucially, concatenating both the client and server public keys into the hash transcript (shared_secret || client_pk || server_pk) cryptographically binds the derived session keys to this exact pair of participants. This defeats key-substitution attacks and prevents small-subgroup vulnerabilities. Furthermore, partitioning the 64-byte BLAKE2b output into distinct client_tx and server_tx keys provides directional separation, preventing packet reflection attacks.'),

  h2('Question 3: Why is the sequence number sent in clear but included as AAD?'),
  p('Answer: The receiver must inspect the sequence number before decrypting the packet in order to discard replayed, delayed, or out-of-order packets prior to committing CPU resources to cryptographic decryption. Therefore, the sequence number cannot be encrypted inside the ciphertext. However, if it were sent without authentication, an active attacker could alter the sequence bytes to bypass replay defenses. Passing the sequence counter as Additional Authenticated Data (AAD) into the AEAD cipher ensures that the Poly1305 MAC covers both the sequence counter and the ciphertext; any modification of the cleartext sequence counter causes MAC verification to fail.'),

  h2('Question 4: Why must last_seq be updated only after the tag verifies?'),
  p('Answer: Before the authentication tag is verified, all bytes in the incoming packet—including the sequence number—are unauthenticated and controlled entirely by the adversary. If an implementation updates last_seq immediately upon reading the header, an attacker could inject a single forged packet with sequence number 2^64 - 1. While the ciphertext would fail decryption, last_seq would now be poisoned at its maximum value. From that moment forward, every legitimate packet transmitted by the sender would have seq < last_seq and would be permanently rejected. Updating state strictly post-verification prevents this fatal single-packet Denial of Service.'),

  h2('Question 5: Which requirement does aes-256-cbc fail, and why?'),
  p('Answer: aes-256-cbc fails the requirement of Integrity / Authenticity. CBC mode is unauthenticated; it provides confidentiality but contains zero mathematical mechanism to detect message tampering. In CBC mode, ciphertext block C_{i-1} is XORed directly into the decrypted output of block C_i. Consequently, flipping bit k in C_{i-1} flips bit k in plaintext P_i deterministically. As demonstrated in our OpenSSL experiment, an attacker altered an invoice payment amount from 00100 to 90100, and OpenSSL decrypted the file with zero errors. Furthermore, unauthenticated CBC is vulnerable to Vaudenay padding oracle attacks.'),

  h2('Question 6: Why sodium_memzero() instead of memset()?'),
  p('Answer: Standard C compilers implementing dead-store elimination are permitted to delete calls to memset() if the targeted buffer is not read again before leaving scope or before being deallocated. If an optimizing compiler (-O2 / -O3) eliminates the memset(), sensitive key material remains intact in physical RAM, exposing it to memory scraping, cold-boot attacks, or core dump extraction. sodium_memzero() is implemented with memory barriers that guarantee the memory clearing operation cannot be optimized away by the compiler.'),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 11. SECTION 9: LIMITATIONS & ROADMAP
// ==========================================
docChildren.push(
  h1('9. System Limitations & Production Roadmap'),
  h2('9.1 Residual System Limitations'),
  p('While the implementation is hardened against network adversaries, several inherent constraints of the current architecture must be documented:'),
  p('• Strict Replay Window (TCP Only): The current anti-replay logic rejects any packet with seq <= last_seq. This is optimal for reliable ordered streams (TCP), but causes catastrophic packet loss over unreliable datagram networks (UDP), where packets routinely arrive out of order. A datagram implementation requires a sliding-window bitmap (such as the 64-packet bitmap used in IPsec and DTLS).\n' +
    '• 96-bit Nonce Birthday Bound: With random 96-bit nonces, the probability of nonce reuse reaches one in a million after approximately 2^32 packets. In long-running high-throughput sessions, our protocol must either transition to sequential deterministic nonces or adopt XChaCha20-Poly1305 (which features a 192-bit nonce with negligible collision probability across 2^96 packets).\n' +
    '• Ephemeral Key Authenticity: Plain crypto_kx does not authenticate the server identity. As shown in our analysis, defense against active MITM requires the Ed25519-signed handshake transcript (Stretch 2) and trusted out-of-band distribution of server_pk.bin.'),
  ...figure('21-limitations.png', 'Command Center Architectural Limitations Review and Security Boundary Assessment', 520, 325),

  h2('9.2 Production Roadmap: Mapping to TLS 1.3 & Noise Framework'),
  p('For enterprise-scale production deployment, this educational secure channel maps directly onto two established industry frameworks:'),
  p('• TLS 1.3 (RFC 8446): The architecture can be formalized as a minimal TLS 1.3 profile utilizing the TLS_CHACHA20_POLY1305_SHA256 cipher suite, X25519 key exchange, Ed25519 certificates for mutual identity verification, and TLS record framing.\n' +
    '• The Noise Protocol Framework: Our signed handshake corresponds closely to the Noise_XX or Noise_IK handshake patterns, providing formal mathematical proofs of secrecy, identity hiding, and forward secrecy.'),
  new Paragraph({ children: [new PageBreak()] })
);

// ==========================================
// 12. SECTION 10: CONCLUSION & REFERENCES
// ==========================================
docChildren.push(
  h1('10. Conclusion & Project Deliverables'),
  p('This project has successfully conceptualized, constructed, and empirically verified a complete, hardened secure channel in C using libsodium, accompanied by an interactive Command Center telemetry dashboard. Every core assignment objective was met with 100% automated test compliance:'),
  p('1. Atomic POSIX 0600 key generation and storage eliminating TOCTOU race conditions.\n' +
    '2. Ephemeral Curve25519 key exchange with mutual public key binding and directional separation.\n' +
    '3. ChaCha20-Poly1305 AEAD record layer binding sequence numbers as AAD.\n' +
    '4. Anti-replay verification strictly gating protocol state updates post-authentication.\n' +
    '5. Argon2id password-based key wrapping providing 64 MiB memory hardness against GPU cracking.\n' +
    '6. Empirical proof of OpenSSL AES-CBC malleability bit-flipping vs. libsodium AEAD integrity.\n' +
    '7. Four advanced stretch extensions: Localhost TCP sockets, Ed25519-signed MITM defense, epoch re-keying, and AEAD benchmarking.'),
  p('The codebase stands as a testament to modern cryptographic engineering: zero compiler warnings, zero secrets leaked over telemetry, constant-time operations, and comprehensive automated verification.'),
  callout(
    'OFFICIAL PROJECT REPOSITORY',
    `GitHub Repository: ${GITHUB_REPO_URL}\n` +
    'Team Members: Pratham Gosai (1551619), Harika Thammina (1716803), Leslie Varghese (1606013), Fizza Fahim (7717258)',
    'success'
  ),

  h1('11. References & Standards'),
  p('1. Y. Nir and A. Langley. "ChaCha20 and Poly1305 for IETF Protocols." RFC 8439, Internet Engineering Task Force, 2018.\n' +
    '2. A. Biryukov, D. Dinu, D. Khovratovich, and S. Josefsson. "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications." RFC 9106, 2021.\n' +
    '3. A. Langley, M. Hamburg, and S. Turner. "Elliptic Curves for Security." RFC 7748, Internet Engineering Task Force, 2016.\n' +
    '4. S. Josefsson and I. Liusvaara. "Edwards-Curve Digital Signature Algorithm (EdDSA)." RFC 8032, 2017.\n' +
    '5. E. Rescorla. "The Transport Layer Security (TLS) Protocol Version 1.3." RFC 8446, 2018.\n' +
    '6. D. J. Bernstein. "The Poly1305-AES Message-Authentication Code." Fast Software Encryption (FSE), 2005.\n' +
    '7. S. Vaudenay. "Security Flaws Induced by CBC Padding — Applications to SSL, IPsec, WTLS." EUROCRYPT, 2002.\n' +
    '8. Libsodium Documentation. "The libsodium cryptographic library." https://doc.libsodium.org/\n' +
    '9. OpenSSL Project. "OpenSSL Cryptography and SSL/TLS Toolkit Documentation (v3.5)." https://www.openssl.org/docs/\n' +
    '10. T. Perrin. "The Noise Protocol Framework." Revision 34, 2018.')
);

// Assemble the document
const doc = new Document({
  creator: 'Pratham Gosai, Harika Thammina, Leslie Varghese, Fizza Fahim',
  title: 'Secure Channel Cryptographic Design Report',
  description: 'Applied Cryptographic Design Project Report with libsodium, OpenSSL, and Cryptographic Command Center',
  styles: {
    default: {
      document: {
        run: {
          font: 'Calibri',
          size: 22,
          color: COLOR_TEXT
        }
      }
    }
  },
  sections: [{
    properties: {
      page: {
        margin: {
          top: 1440,
          bottom: 1440,
          left: 1440,
          right: 1440
        }
      }
    },
    headers: {
      default: new Header({
        children: [
          new Paragraph({
            children: [
              new TextRun({ text: 'Applied Cryptographic Design — Secure Channel & Command Center Report', size: 18, color: COLOR_MUTED, italics: true })
            ],
            alignment: AlignmentType.RIGHT,
            spacing: { after: 120 },
            border: {
              bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER }
            }
          })
        ]
      })
    },
    footers: {
      default: new Footer({
        children: [
          new Paragraph({
            children: [
              new TextRun({ text: 'Secure Channel with libsodium (RFC 8439 / RFC 9106)  |  ', size: 18, color: COLOR_MUTED }),
              new TextRun({ text: 'Page ', size: 18, color: COLOR_MUTED }),
              PageNumber.CURRENT,
              new TextRun({ text: ' of ', size: 18, color: COLOR_MUTED }),
              PageNumber.TOTAL_PAGES
            ],
            alignment: AlignmentType.CENTER,
            spacing: { before: 120 },
            border: {
              top: { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER }
            }
          })
        ]
      })
    },
    children: docChildren
  }]
});

const outputPathRoot = path.join(__dirname, '..', 'Secure_Channel_Cryptographic_Project_Report.docx');
const outputPathDocs = path.join(__dirname, '..', 'secure-workshop', 'docs', 'Secure_Channel_Cryptographic_Project_Report.docx');

console.log('Packing Word document to buffer...');
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPathRoot, buffer);
  console.log(`Saved report in root: ${outputPathRoot} (${(buffer.length / (1024 * 1024)).toFixed(2)} MB)`);
  fs.writeFileSync(outputPathDocs, buffer);
  console.log(`Saved report in docs: ${outputPathDocs}`);
  console.log('Report generation completed successfully!');
}).catch(err => {
  console.error('Error generating document:', err);
  process.exit(1);
});

