// patterns.js — Threat pattern library (loaded before content.js)
// Each entry: { type, group, freeTier?, basic?, regex, validate? }
// basic: IP/API “Basic Protection” (always gated by basicProtection toggle, Free + Pro).
// group: "devsec" | "fintech" | "corporate" | "civic" — Pro toggle gating (MAC = devsec; FinTech PII = fintech; Corporate / Civic = respective toggles).
// freeTier: when true, pattern may run on Free tier (still requires basicProtection for basic patterns).

'use strict';

function isPureHex(s) {
  return /^[a-f0-9]+$/i.test(s);
}

function isFalsePositiveApiMatch(match) {
  const lower = String(match).toLowerCase();
  if (lower.startsWith('bearer ')) {
    const t = lower.slice(7).trim();
    return t.length >= 16 && isPureHex(t);
  }
  if (/^sk-|^pk-/i.test(match)) {
    const t = lower.replace(/^(sk|pk)-/, '').trim();
    return t.length >= 16 && isPureHex(t);
  }
  return false;
}

function luhnValid(digitsOnly) {
  if (digitsOnly.length !== 15 && digitsOnly.length !== 16) return false;
  let sum = 0;
  let alt = false;
  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let n = parseInt(digitsOnly[i], 10);
    if (Number.isNaN(n)) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function validIpv4(match) {
  const octets = match.split('.').map(Number);
  if (octets[0] === 127 || octets[0] === 255) return false;
  return octets.every((o) => o >= 0 && o <= 255);
}

function validCreditCard(match) {
  const d = match.replace(/\D/g, '');
  return (d.length === 15 || d.length === 16) && luhnValid(d);
}

// v3.5 — Named API key regexes (each provider gets its own label)
const RE_OPENAI_KEY    = /\bsk-proj-[a-zA-Z0-9_-]{20,}\b/gi;
const RE_OPENAI_LEGACY = /\bsk-(?!proj-|ant-)[a-zA-Z0-9_-]{16,}\b/gi;
const RE_ANTHROPIC_KEY = /\bsk-ant-[a-zA-Z0-9_-]{10,}\b/gi;
const RE_AWS_KEY       = /\bAKIA[0-9A-Z]{16}\b/g;
const RE_AWS_STS       = /\bASIA[0-9A-Z]{16}\b/g;
const RE_AWS_SECRET    = /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)\s*[=:"'\s]+["']?([A-Za-z0-9\/+=]{40})["']?/g;
const RE_AWS_SECRET_RAW = /(?<![A-Za-z0-9\/+])[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9\/+=])/g;
const RE_GITHUB_PAT    = /\bghp_[a-zA-Z0-9]{20,}\b/g;
const RE_GITHUB_PAT_FG = /\bgithub_pat_[a-zA-Z0-9_]{20,}\b/g;
const RE_GITHUB_OAUTH  = /\bgh[osux]_[a-zA-Z0-9]{20,}\b/g;
const RE_SLACK_KEY     = /\bxox[bap]-[a-zA-Z0-9-]{10,}\b/gi;
const RE_STRIPE_KEY    = /\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b/g;
const RE_STRIPE_PK     = /\bpk_(?:live|test)_[a-zA-Z0-9]{24,}\b/g;
const RE_BEARER        = /\bbearer\s+[a-zA-Z0-9._~+/=-]{16,}\b/gi;
const RE_API_KEY_CATCH  = /\bpk-[a-zA-Z0-9_-]{16,}\b/gi;
const RE_DOCKER_KEY    = /\bdckr_pat_[a-zA-Z0-9_-]{20,}\b/g;
const RE_NPM_TOKEN     = /\bnpm_[a-zA-Z0-9]{36,}\b/g;
const RE_TWILIO_KEY    = /\bSK[a-f0-9]{32}\b/g;
const RE_SENDGRID_KEY  = /\bSG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}\b/g;

const THREAT_PATTERNS = Object.freeze([
  {
    type: 'IP',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    validate: validIpv4,
  },
  // ── v3.5 Named API Key Labels ──────────────────────────────────────────────
  { type: 'OPENAI_KEY',    group: 'devsec', freeTier: true, basic: true,  regex: RE_OPENAI_KEY },
  { type: 'OPENAI_KEY',    group: 'devsec', freeTier: true, basic: true,  regex: RE_OPENAI_LEGACY, validate: (m) => !isFalsePositiveApiMatch(m) },
  { type: 'ANTHROPIC_KEY', group: 'devsec', freeTier: true, basic: true,  regex: RE_ANTHROPIC_KEY },
  { type: 'AWS_KEY',       group: 'devsec', freeTier: true, basic: true,  regex: RE_AWS_KEY },
  { type: 'AWS_KEY',       group: 'devsec', freeTier: true, basic: true,  regex: RE_AWS_STS },
  { type: 'AWS_SECRET',    group: 'devsec', freeTier: true, basic: true,  regex: RE_AWS_SECRET, validate: (m) => !/^[0-9a-f]{40}$/.test(m) },
  { type: 'AWS_SECRET',    group: 'devsec', freeTier: true, basic: true,  regex: RE_AWS_SECRET_RAW, validate: (m) => !/^[0-9a-fA-F]{40}$/.test(m) },
  { type: 'GITHUB_PAT',    group: 'devsec', freeTier: true, basic: true,  regex: RE_GITHUB_PAT },
  { type: 'GITHUB_PAT_FG', group: 'devsec', freeTier: true, basic: true,  regex: RE_GITHUB_PAT_FG },
  { type: 'GITHUB_OAUTH',  group: 'devsec', freeTier: true, basic: true,  regex: RE_GITHUB_OAUTH },
  { type: 'SLACK_KEY',     group: 'devsec', freeTier: true, basic: true,  regex: RE_SLACK_KEY },
  { type: 'STRIPE_KEY',    group: 'devsec', freeTier: true, basic: true,  regex: RE_STRIPE_KEY },
  { type: 'STRIPE_PK',     group: 'devsec', freeTier: true, basic: true,  regex: RE_STRIPE_PK },
  { type: 'BEARER',        group: 'devsec', freeTier: true, basic: true,  regex: RE_BEARER, validate: (m) => !isFalsePositiveApiMatch(m) },
  { type: 'DOCKER_KEY',     group: 'devsec', freeTier: true, basic: true,  regex: RE_DOCKER_KEY },
  { type: 'NPM_TOKEN',      group: 'devsec', freeTier: true, basic: true,  regex: RE_NPM_TOKEN },
  { type: 'TWILIO_KEY',     group: 'devsec', freeTier: true, basic: true,  regex: RE_TWILIO_KEY },
  { type: 'SENDGRID_KEY',   group: 'devsec', freeTier: true, basic: true,  regex: RE_SENDGRID_KEY },
  { type: 'API_KEY',       group: 'devsec', freeTier: true, basic: true,  regex: RE_API_KEY_CATCH, validate: (m) => !isFalsePositiveApiMatch(m) },
  {
    type: 'MAC_ADDRESS',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
  },
  {
    type: 'CREDIT_CARD',
    group: 'fintech',
    freeTier: false,
    regex: /\b(?:\d{4}[-\s]?){3}\d{3,4}\b/g,
    validate: validCreditCard,
  },
  {
    type: 'US_SSN',
    group: 'fintech',
    freeTier: false,
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    type: 'EU_IBAN',
    group: 'fintech',
    freeTier: false,
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi,
  },
  {
    type: 'UK_NINO',
    group: 'fintech',
    freeTier: false,
    regex: /\b[A-Z]{2}\d{6}[A-Z]\b/g,
  },
  {
    type: 'NG_BANK',
    group: 'fintech',
    freeTier: false,
    regex: /\b\d{10}\b/g,
  },
  {
    type: 'NG_PHONE',
    group: 'fintech',
    freeTier: false,
    regex: /\b0[789][01]\d{8}\b/g,
  },
  {
    type: 'NG_NIN',
    group: 'fintech',
    freeTier: false,
    regex: /\b(?!0[789][01]\d{8})\d{11}\b/g,
  },

  // ── Canada ──────────────────────────────────────────────────
  {
    type: 'CA_SIN',
    group: 'fintech',
    freeTier: false,
    // Social Insurance Number: 123-456-789 (first digit never 0 or 8)
    regex: /\b[1-79]\d{2}-\d{3}-\d{3}\b/g,
  },

  // ── India ────────────────────────────────────────────────────
  {
    type: 'IN_AADHAAR',
    group: 'fintech',
    freeTier: false,
    // Aadhaar: 12 digits, optionally space-separated in groups of 4
    // First digit never 0 or 1
    regex: /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    validate(m) {
      const d = m.replace(/[\s-]/g, '');
      return d.length === 12;
    },
  },
  {
    type: 'IN_PAN',
    group: 'fintech',
    freeTier: false,
    // PAN Card: ABCDE1234F — 5 alpha, 4 numeric, 1 alpha
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  },

  // ── South Africa ─────────────────────────────────────────────
  {
    type: 'ZA_ID',
    group: 'fintech',
    freeTier: false,
    // SA ID: 13 digits YYMMDD GGGG C A Z
    // First 6 digits are a valid date (YYMMDD)
    regex: /\b\d{13}\b/g,
    validate(m) {
      const month = parseInt(m.slice(2, 4), 10);
      const day   = parseInt(m.slice(4, 6), 10);
      return month >= 1 && month <= 12 && day >= 1 && day <= 31;
    },
  },

  // ── Australia ────────────────────────────────────────────────
  {
    type: 'AU_TFN',
    group: 'fintech',
    freeTier: false,
    // Tax File Number: 8-9 digits, optionally space-separated
    regex: /\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b/g,
    validate(m) {
      const d = m.replace(/[\s-]/g, '');
      return d.length === 8 || d.length === 9;
    },
  },

  // ── Brazil ───────────────────────────────────────────────────
  {
    type: 'BR_CPF',
    group: 'fintech',
    freeTier: false,
    // CPF: 123.456.789-09
    regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,
  },

  // ── Singapore ────────────────────────────────────────────────
  {
    type: 'SG_NRIC',
    group: 'fintech',
    freeTier: false,
    // NRIC/FIN: S/T/F/G + 7 digits + 1 alpha
    regex: /\b[STFG]\d{7}[A-Z]\b/g,
  },

  // ── Germany ──────────────────────────────────────────────────
  {
    type: 'DE_TAX_ID',
    group: 'fintech',
    freeTier: false,
    // Steueridentifikationsnummer: 11 digits, first digit 1-9
    regex: /\b[1-9]\d{10}\b/g,
  },

  // ── United States ─────────────────────────────────────────────
  {
    type: 'US_GREEN_CARD',
    group: 'fintech',
    freeTier: false,
    // Permanent Resident Card (Form I-551)
    // Format: 3 alpha + 10 digits  e.g. ABC1234567890
    // Or older format: 2 alpha + 9 digits  e.g. AB123456789
    regex: /\b[A-Z]{2,3}\d{9,10}\b/g,
    validate(m) {
      // Must start with known USCIS prefixes
      // Common prefixes: A (Alien Registration), LIN, EAC, WAC, SRC, MSC, IOE
      const prefixes = ['LIN','EAC','WAC','SRC','MSC','IOE'];
      const upper = m.toUpperCase();
      // 3-letter prefix format
      if (prefixes.some(p => upper.startsWith(p))) return true;
      // A-number format: A + 8-9 digits
      if (/^A\d{8,9}$/.test(upper)) return true;
      // I-551 card number: 3 alpha + 10 digits
      if (/^[A-Z]{3}\d{10}$/.test(upper)) return true;
      return false;
    },
  },

  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bbc1[a-z0-9]{6,87}\b/gi,
  },
  {
    type: 'ETH_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b0x[a-fA-F0-9]{40}\b/g,
  },
  {
    type: 'CRYPTO_KEY',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b[a-fA-F0-9]{64}\b/g,
    validate: (match, _unused, fullText) => {
      // Do not redact SHA-256 checksums — they are public by design
      const surrounding = typeof fullText === 'string'
        ? fullText.slice(Math.max(0, fullText.indexOf(match) - 60), fullText.indexOf(match) + 70).toLowerCase()
        : '';
      const hashContext    = /sha[-_]?256|sha[-_]?512|checksum|hash|digest|file.?hash|image.?hash|verif/.test(surrounding);
      const secretContext  = /private.?key|secret|wallet|eth.?private|ethereum.?private|seed|mnemonic|crypto.?key/.test(surrounding);
      if (hashContext && !secretContext) return false;
      return true;
    },
  },
  {
    type: 'CRYPTO_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g,
  },
  {
    type: 'GEMINI_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    type: 'SOL_ADDRESS',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b[1-9A-HJ-NP-Za-km-z]{44}\b/g,
  },

  {
    type: 'SEED_PHRASE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b([a-z]+\s){11}[a-z]+\b/g,
    validate(m) {
      const words = m.trim().split(/\s+/)
      return words.length === 12
    }
  },
  {
    type: 'SEED_PHRASE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b([a-z]+\s){23}[a-z]+\b/g,
    validate(m) {
      const words = m.trim().split(/\s+/)
      return words.length === 24
    }
  },
  {
    type: 'ETH_PRIVATE_KEY',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b0x[a-fA-F0-9]{64}\b/g,
  },
  {
    type: 'PEM_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE KEY-----/g,
  },

  // ── v3.4.1 NEW PATTERNS ──────────────────────────────────────────

  // Corporate ID Shield
  {
    type: 'DUNS',
    group: 'corporate',
    freeTier: false,
    regex:
      /(?:D[-\s]?U[-\s]?N[-\s]?S|D&B|Dun\s*&\s*Bradstreet)[^0-9]{0,50}(\d{2}-\d{3}-\d{4}|\d{9})/gi,
  },
  {
    type: 'EIN',
    group: 'corporate',
    freeTier: false,
    regex: /\b(?:EIN|Tax\s*ID|Federal\s*Tax\s*ID)[^0-9]{0,20}(\d{2}-\d{7})\b/gi,
  },
  {
    type: 'VAT_EU',
    group: 'corporate',
    freeTier: false,
    regex:
      /\b(ATU\d{8}|BE0\d{9}|BG\d{9,10}|CY\d{8}L|CZ\d{8,10}|DE\d{9}|DK\d{8}|EE\d{9}|EL\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]|FI\d{8}|FR[A-Z0-9]{2}\d{9}|HR\d{11}|HU\d{8}|IE\d{7}[A-Z]{1,2}|IT\d{11}|LT\d{9,12}|LU\d{8}|LV\d{11}|MT\d{8}|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|RO\d{2,10}|SE\d{12}|SI\d{8}|SK\d{10})\b/g,
  },

  // Mission & Civic Shield
  {
    type: 'GPS_COORDS',
    group: 'civic',
    freeTier: false,
    regex:
      /\b(-?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)),\s*(-?(?:1[0-7]\d(?:\.\d+)?|(?:[1-9]?\d(?:\.\d+)?)|180(?:\.0+)?))\b/g,
  },
  {
    type: 'UNHCR_ID',
    group: 'civic',
    freeTier: false,
    regex: /\b(?:UNHCR[-\s]?(?:ID|Reg(?:istration)?)?[-\s#:]*)?([A-Z]{3}-\d{2}-\d{6,8}C?\d?)\b/gi,
  },
  {
    type: 'DONOR_ID',
    group: 'civic',
    freeTier: false,
    regex:
      /\b(?:Donor|Beneficiary|Bene|Case|Client|Member|Ref)[-\s]?(?:ID|No|#|Number|Code)[-\s:]*([A-Z0-9]{4,16})\b/gi,
  },
  {
    type: 'ENV_VALUE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /(?<=^[A-Z][A-Z0-9_]*=)(?!sk-proj-|sk-ant-|AKIA|ASIA|ghp_|github_pat_|gh[osux]_|xox[bap]-|AIza|sk_live_|sk_test_|pk_live_|pk_test_|dckr_pat_|npm_|SG\.|SK[0-9a-f]).+$/gm,
    validate: (match) => {
      const v = match.trim();
      // Skip if value matches a named key pattern — let named pattern win
      if (/^sk-proj-[a-zA-Z0-9_-]{20,}$/i.test(v)) return false;
      if (/^sk-ant-[a-zA-Z0-9_-]{10,}$/i.test(v)) return false;
      if (/^AKIA[0-9A-Z]{16}$/.test(v)) return false;
      if (/^ASIA[0-9A-Z]{16}$/.test(v)) return false;
      if (/^ghp_[a-zA-Z0-9]{20,}$/.test(v)) return false;
      if (/^github_pat_[a-zA-Z0-9_]{20,}$/.test(v)) return false;
      if (/^gh[osux]_[a-zA-Z0-9]{20,}$/.test(v)) return false;
      if (/^xox[bap]-[a-zA-Z0-9-]{10,}$/i.test(v)) return false;
      if (/^AIza[0-9A-Za-z\-_]{35}$/.test(v)) return false;
      if (/^sk_(?:live|test)_[a-zA-Z0-9]{24,}$/.test(v)) return false;
      if (/^pk_(?:live|test)_[a-zA-Z0-9]{24,}$/.test(v)) return false;
      if (/^dckr_pat_[a-zA-Z0-9_-]{20,}$/.test(v)) return false;
      if (/^npm_[a-zA-Z0-9]{36,}$/.test(v)) return false;
      if (/^SK[a-f0-9]{32}$/.test(v)) return false;
      if (/^bearer\s+/i.test(v)) return false;
      return true;
    },
  },
]);