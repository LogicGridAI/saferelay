// vault.js
// ─────────────────────────────────────────────────────────────
// Zero-trust RAM vault.
// NEVER attached to window. Closure-only access.
// Cleared automatically when the content script context is destroyed (tab close / navigation).
// Placeholders: [TYPE_n] with per-type sequential ids; same (type, value) reuses existing key.
// ─────────────────────────────────────────────────────────────

const _store = new Map();
/** @type {Map<string, number>} next index per threat type (1-based counter state) */
const _counters = new Map();
/** @type {Map<string, string>} `${type}\0${value}` → full placeholder key `[TYPE_n]` */
const _valueToKey = new Map();

const _dedupeKey = (type, value) => `${type}\0${value}`;

const SafeVault = Object.freeze({
  /**
   * Store a real value and return its placeholder key.
   * Reuses the same placeholder if the same (type, value) was stored before.
   * @param {string} threatType  - e.g. "US_SSN", "DEVSEC", "NDA"
   * @param {string} realValue   - the actual sensitive string
   * @returns {string}           - e.g. [US_SSN_1], [DEVSEC_2]
   */
  store(threatType, realValue) {
    const dk = _dedupeKey(threatType, realValue);
    const existing = _valueToKey.get(dk);
    if (existing !== undefined) {
      return existing;
    }
    const next = (_counters.get(threatType) || 0) + 1;
    _counters.set(threatType, next);
    const key = `[${threatType}_${next}]`;
    _store.set(key, realValue);
    _valueToKey.set(dk, key);
    return key;
  },

  /**
   * Resolve a placeholder back to the real value.
   * Returns null if key not found — never throws, never substitutes wrong value.
   * @param {string} placeholder
   * @returns {string|null}
   */
  resolve(placeholder) {
    return _store.get(placeholder) ?? null;
  },

  /** All current placeholder keys */
  keys() {
    return [..._store.keys()];
  },

  size() {
    return _store.size;
  },

  /** Wipe placeholders, per-type counters, and value dedupe map */
  clear() {
    _store.clear();
    _counters.clear();
    _valueToKey.clear();
  },
});

// Export to module scope only — not window
// Other files loaded by the same content script world can reference SafeVault directly.
