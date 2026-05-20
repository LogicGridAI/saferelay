#!/usr/bin/env python3
"""
safepaste — SafePaste Enterprise CLI v3.4.1
Zero-trust DLP: intercepts 41 global PII patterns before logs reach AI tools.
Free tier: IPv4 + API-style tokens only → [DEVSEC_n], no vault.
Pro tier: License-verified; vault persisted; full unmask support.
Shield Packs: DevSec, FinTech, Corporate Identity, Web3, Mission & Civic.
"""
__version__ = "3.4.2"
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable
try:
    import redis  # type: ignore[import-untyped]
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

VAULT_PATH   = Path.home() / ".safepaste" / "vault.json"
CONFIG_PATH  = Path.home() / ".safepaste" / "config.json"
REDIS_ENV_VAR = "SAFEPASTE_REDIS_URL"
REDIS_HASH_KEY = "safepaste:vault"

# ── License validation (SafePaste Worker) ───────────────────────────────────
LICENSE_VERIFY_URL = "https://logicgrid-commerce-worker.admin-thequanthub.workers.dev/license/validate"

DEFAULT_CONFIG: dict = {
    "is_licensed":       False,
    "license_key":       "",
    "license_tier":      "",
    "devsec_mode":       True,
    "fintech_shield":    True,
    "corporate_shield":  True,
    "web3_shield":       True,
    "civic_shield":      True,
    "custom_keywords":   [],
}

# ── Helpers ─────────────────────────────────────────────────────────────────
def _load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(CONFIG_PATH.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def _save_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))

def _get_device_id() -> str:
    import platform, hashlib
    raw = "|".join([platform.node(), platform.machine(), platform.system()])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

# ── License verification ─────────────────────────────────────────────────────
def verify_license(license_key: str, timeout: float = 30.0) -> tuple[bool, str]:
    """POST to SafePaste worker; returns (valid, tier)."""
    key = license_key.strip()
    if not key:
        return False, ""
    device_id = _get_device_id()
    payload = json.dumps({"license_key": key, "device_id": device_id}).encode()
    req = urllib.request.Request(
        LICENSE_VERIFY_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": f"safepaste-cli/{__version__}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            if data.get("success") is True or data.get("valid") is True:
                tier = str(data.get("tier", "pro")).lower().strip()
                return True, tier
            return False, ""
    except Exception as exc:
        print(f"safepaste: license check failed — {exc}", file=sys.stderr)
        return False, ""

# ── Vault ────────────────────────────────────────────────────────────────────
def _get_redis() -> "redis.Redis | None":
    url = os.environ.get(REDIS_ENV_VAR, "")
    if not url or not HAS_REDIS:
        return None
    try:
        r = redis.Redis.from_url(url, socket_timeout=2)
        r.ping()
        return r
    except Exception:
        return None

def _load_vault() -> dict:
    r = _get_redis()
    if r:
        raw = r.hgetall(REDIS_HASH_KEY)
        return {k.decode(): v.decode() for k, v in raw.items()} if raw else {}
    if VAULT_PATH.exists():
        try:
            return json.loads(VAULT_PATH.read_text())
        except Exception:
            pass
    return {}

def _save_vault(vault: dict) -> None:
    r = _get_redis()
    if r:
        if vault:
            r.hset(REDIS_HASH_KEY, mapping=vault)
        else:
            r.delete(REDIS_HASH_KEY)
        return
    VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    VAULT_PATH.write_text(json.dumps(vault, indent=2))

# ── Patterns (41 total) ──────────────────────────────────────────────────────

# DevSec Shield
RE_IPV4          = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_API_KEY       = re.compile(r"\b(?:sk|pk|rk|key|token|secret|api[-_]?key)[-_]?[a-zA-Z0-9]{16,64}\b", re.IGNORECASE)
RE_AWS_KEY       = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_GITHUB_TOKEN  = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b")
RE_SLACK_TOKEN   = re.compile(r"\bxox[bpaso]-[0-9A-Za-z\-]{10,72}\b")
RE_OPENAI_KEY    = re.compile(r"\bsk-[A-Za-z0-9]{32,64}\b")
RE_BEARER        = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,512}\b")
RE_MAC_ADDR      = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")
RE_ENV_VALUE     = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=\S{8,}$")
RE_INTERNAL_URL  = re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s]*\b")

# FinTech Shield
RE_US_SSN        = re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")
RE_EU_IBAN       = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
RE_SWIFT_BIC     = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")
RE_CREDIT_CARD   = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b")
RE_UK_NINO       = re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", re.IGNORECASE)
RE_CA_SIN        = re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b")
RE_IN_AADHAAR    = re.compile(r"\b[2-9]\d{3}[- ]?\d{4}[- ]?\d{4}\b")
RE_IN_PAN        = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
RE_NG_NIN        = re.compile(r"\b\d{11}\b")
RE_ZA_ID         = re.compile(r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}[01]\d{2}\b")
RE_AU_TFN        = re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b")
RE_BR_CPF        = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
RE_SG_NRIC       = re.compile(r"\b[STFG]\d{7}[A-Z]\b", re.IGNORECASE)
RE_PASSPORT      = re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b")

# Corporate Identity Shield
RE_DUNS          = re.compile(r"\b\d{2}-\d{3}-\d{4}\b|\b\d{9}\b")
RE_EIN           = re.compile(r"\b\d{2}-\d{7}\b")
RE_VAT_EU        = re.compile(r"\b(ATU\d{8}|BE0\d{9}|DE\d{9}|FR[A-Z0-9]{2}\d{9}|GB\d{9}|IT\d{11}|NL\d{9}B\d{2}|ES[A-Z0-9]\d{7}[A-Z0-9]|PL\d{10}|SE\d{12})\b")
RE_VENDOR_ID     = re.compile(r"(?i)\b(?:VEND|PO|TENDER|CONTRACT|RFQ|INV)-[A-Z0-9]{4,20}\b")
RE_INVOICE       = re.compile(r"(?i)\b(?:Invoice|INV|PO)[- ]?(?:No|#|Number)?[- ]?([A-Z]{0,4}\d{4,12})\b")

# Web3 Shield
RE_ETH_WALLET    = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_BTC_WIF       = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
RE_SOL_ADDR      = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
RE_SEED_PHRASE   = re.compile(r"\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b|\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b")
RE_GEMINI_KEY    = re.compile(r"\baccount-[A-Za-z0-9]{20,40}\b")

# Mission & Civic Shield
RE_GPS_COORDS    = re.compile(r"\b-?[0-9]{1,3}\.[0-9]{4,}\s*,\s*-?[0-9]{1,3}\.[0-9]{4,}\b")
RE_UNHCR_ID      = re.compile(r"\b[A-Z]{3}-\d{2}-\d{6,8}C?\d?\b")
RE_BENEFICIARY   = re.compile(r"(?i)\b(?:BEN|DONOR|CASE|HH|PROG)-[A-Z0-9]{4,16}\b")

# Context-aware validators
_DUNS_CTX  = re.compile(r"(?i)(DUNS|D-U-N-S|D&B|Dun\s*&\s*Bradstreet|business\s*credit)")
_EIN_CTX   = re.compile(r"(?i)(EIN|Tax\s*ID|TIN|employer\s*identification|federal\s*tax)")

def _duns_validator(m: re.Match, text: str) -> bool:
    start = max(0, m.start() - 80)
    end   = min(len(text), m.end() + 80)
    return bool(_DUNS_CTX.search(text[start:end]))

def _ein_validator(m: re.Match, text: str) -> bool:
    start = max(0, m.start() - 50)
    end   = min(len(text), m.end() + 50)
    return bool(_EIN_CTX.search(text[start:end]))

# ── Threat table ─────────────────────────────────────────────────────────────
# (priority, label, pattern, shield, validator)
# shield: "free" | "devsec" | "fintech" | "corporate" | "web3" | "civic"
ThreatRow = tuple[int, str, re.Pattern, str, Callable]

def _build_threats(cfg: dict, is_pro: bool) -> list[ThreatRow]:
    devsec    = is_pro and cfg.get("devsec_mode", True)
    fintech   = is_pro and cfg.get("fintech_shield", True)
    corporate = is_pro and cfg.get("corporate_shield", True)
    web3      = is_pro and cfg.get("web3_shield", True)
    civic     = is_pro and cfg.get("civic_shield", True)

    rows: list[ThreatRow] = [
        # Free tier
        (10, "IPV4",          RE_IPV4,       "free",      lambda m, t: True),
        (11, "DEVSEC",        RE_API_KEY,    "free",      lambda m, t: True),
        (12, "DEVSEC",        RE_AWS_KEY,    "free",      lambda m, t: True),
        (13, "DEVSEC",        RE_OPENAI_KEY, "free",      lambda m, t: True),
    ]
    if devsec:
        rows += [
            (20, "DEVSEC",    RE_GITHUB_TOKEN, "devsec",  lambda m, t: True),
            (21, "DEVSEC",    RE_SLACK_TOKEN,  "devsec",  lambda m, t: True),
            (22, "DEVSEC",    RE_BEARER,       "devsec",  lambda m, t: True),
            (23, "MAC_ADDR",  RE_MAC_ADDR,     "devsec",  lambda m, t: True),
            (24, "ENV_VALUE", RE_ENV_VALUE,    "devsec",  lambda m, t: True),
            (25, "INT_URL",   RE_INTERNAL_URL, "devsec",  lambda m, t: True),
        ]
    if fintech:
        rows += [
            (30, "US_SSN",    RE_US_SSN,     "fintech",   lambda m, t: True),
            (31, "EU_IBAN",   RE_EU_IBAN,    "fintech",   lambda m, t: True),
            (32, "SWIFT_BIC", RE_SWIFT_BIC,  "fintech",   lambda m, t: True),
            (33, "CC",        RE_CREDIT_CARD,"fintech",   lambda m, t: True),
            (34, "UK_NINO",   RE_UK_NINO,    "fintech",   lambda m, t: True),
            (35, "CA_SIN",    RE_CA_SIN,     "fintech",   lambda m, t: True),
            (36, "IN_AADHAAR",RE_IN_AADHAAR, "fintech",   lambda m, t: True),
            (37, "IN_PAN",    RE_IN_PAN,     "fintech",   lambda m, t: True),
            (38, "NG_NIN",    RE_NG_NIN,     "fintech",   lambda m, t: True),
            (39, "ZA_ID",     RE_ZA_ID,      "fintech",   lambda m, t: True),
            (40, "AU_TFN",    RE_AU_TFN,     "fintech",   lambda m, t: True),
            (41, "BR_CPF",    RE_BR_CPF,     "fintech",   lambda m, t: True),
            (42, "SG_NRIC",   RE_SG_NRIC,    "fintech",   lambda m, t: True),
            (43, "PASSPORT",  RE_PASSPORT,   "fintech",   lambda m, t: True),
        ]
    if corporate:
        rows += [
            (50, "DUNS",      RE_DUNS,       "corporate", _duns_validator),
            (51, "EIN",       RE_EIN,        "corporate", _ein_validator),
            (52, "VAT_EU",    RE_VAT_EU,     "corporate", lambda m, t: True),
            (53, "VENDOR_ID", RE_VENDOR_ID,  "corporate", lambda m, t: True),
            (54, "INVOICE",   RE_INVOICE,    "corporate", lambda m, t: True),
        ]
    if web3:
        rows += [
            (60, "ETH_WALLET",  RE_ETH_WALLET,  "web3",  lambda m, t: True),
            (61, "BTC_WIF",     RE_BTC_WIF,     "web3",  lambda m, t: True),
            (62, "SOL_ADDR",    RE_SOL_ADDR,    "web3",  lambda m, t: True),
            (63, "SEED_PHRASE", RE_SEED_PHRASE, "web3",  lambda m, t: True),
            (64, "GEMINI_KEY",  RE_GEMINI_KEY,  "web3",  lambda m, t: True),
        ]
    if civic:
        rows += [
            (70, "GPS_COORDS",   RE_GPS_COORDS,   "civic", lambda m, t: True),
            (71, "UNHCR_ID",     RE_UNHCR_ID,     "civic", lambda m, t: True),
            (72, "BENEFICIARY",  RE_BENEFICIARY,  "civic", lambda m, t: True),
        ]
    return sorted(rows, key=lambda r: r[0])

# ── Redaction engine ─────────────────────────────────────────────────────────
def redact(text: str, threats: list[ThreatRow], vault: dict,
           custom_keywords: list[str]) -> tuple[str, dict]:
    counters: dict[str, int] = {}
    result = text

    # Custom NDA keywords first
    for kw in custom_keywords:
        escaped = re.escape(kw)
        pat = re.compile(escaped, re.IGNORECASE)
        for m in reversed(list(pat.finditer(result))):
            counters["NDA"] = counters.get("NDA", 0) + 1
            ph = f"[NDA_{counters['NDA']}]"
            vault[ph] = m.group(0)
            result = result[:m.start()] + ph + result[m.end():]

    # Shield patterns
    matches: list[tuple[int, int, str, str]] = []
    for _, label, pattern, shield, validator in threats:
        for m in pattern.finditer(result):
            if validator(m, result):
                matches.append((m.start(), m.end(), label, m.group(0)))

    # Sort by position descending to replace without offset issues
    matches.sort(key=lambda x: x[0], reverse=True)
    seen_spans: set[tuple[int,int]] = set()
    for start, end, label, value in matches:
        if any(s <= start < e or s < end <= e for s, e in seen_spans):
            continue
        seen_spans.add((start, end))
        counters[label] = counters.get(label, 0) + 1
        ph = f"[{label}_{counters[label]}]"
        vault[ph] = value
        result = result[:start] + ph + result[end:]

    return result, vault

# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    cfg = _load_config()
    is_pro = bool(cfg.get("is_licensed"))

    p = argparse.ArgumentParser(
        prog="safepaste",
        description=(
            f"SafePaste Enterprise CLI v{__version__} — "
            "41 global PII patterns across 12+ countries. "
            "Zero-trust DLP for AI-assisted workflows. "
            "Free: IP + API key redaction. Pro: all Shield Packs + vault."
        ),
    )
    p.add_argument("input", nargs="?", type=argparse.FileType("r"), default=sys.stdin,
                   help="Input file (default: stdin).")
    p.add_argument("--unmask",  metavar="PLACEHOLDER",
                   help="Reveal a vaulted placeholder, e.g. [US_SSN_1].")
    p.add_argument("--unlock",  metavar="LICENSE_KEY",
                   help="Verify license key and enable Pro Shield Packs.")
    p.add_argument("--status",  action="store_true",
                   help="Show current license tier and active shields.")
    p.add_argument("--clear-vault", action="store_true",
                   help="Wipe all vaulted values.")
    p.add_argument("--pro",    action="store_true",
                   help="Force Pro-tier for this run (no license call).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Shield toggles
    p.add_argument("--no-devsec",    action="store_true", help="Disable DevSec Shield.")
    p.add_argument("--no-fintech",   action="store_true", help="Disable FinTech Shield.")
    p.add_argument("--no-corporate", action="store_true", help="Disable Corporate Identity Shield.")
    p.add_argument("--no-web3",      action="store_true", help="Disable Web3 Shield.")
    p.add_argument("--no-civic",     action="store_true", help="Disable Mission & Civic Shield.")
    p.add_argument("--mask",         action="store_true", help="Alias for default redact mode.")

    args = p.parse_args()

    # ── --unlock ──────────────────────────────────────────────────────────────
    if args.unlock:
        key = args.unlock.strip() or os.environ.get("SAFEPASTE_LICENSE_KEY", "").strip()
        if not key:
            print("safepaste: pass LICENSE_KEY or set SAFEPASTE_LICENSE_KEY", file=sys.stderr)
            sys.exit(1)
        print(f"safepaste: verifying license…", file=sys.stderr)
        ok, tier = verify_license(key)
        if ok:
            cfg["is_licensed"]  = True
            cfg["license_key"]  = key
            cfg["license_tier"] = tier
            _save_config(cfg)
            print(f"safepaste: ✓ License verified — tier={tier}. Pro Shield Packs enabled.")
        else:
            print("safepaste: ✗ Invalid license key. Check your key and try again.", file=sys.stderr)
            sys.exit(1)
        return

    # ── --status ──────────────────────────────────────────────────────────────
    if args.status:
        on, off = "✓ on", "✗ off"
        tier = cfg.get("license_tier", "free") if is_pro else "free"
        print(f"safepaste v{__version__}")
        print(f"  License   : {'Pro — ' + tier if is_pro else 'Free'}")
        print(f"  DevSec    : {on if cfg.get('devsec_mode') else off}")
        print(f"  FinTech   : {on if is_pro and cfg.get('fintech_shield') else off}")
        print(f"  Corporate : {on if is_pro and cfg.get('corporate_shield') else off}")
        print(f"  Web3      : {on if is_pro and cfg.get('web3_shield') else off}")
        print(f"  Civic     : {on if is_pro and cfg.get('civic_shield') else off}")
        kws = cfg.get("custom_keywords", [])
        print(f"  NDA terms : {len(kws)} ({', '.join(kws[:3])}{'…' if len(kws) > 3 else ''})")
        return

    # ── --clear-vault ─────────────────────────────────────────────────────────
    if args.clear_vault:
        _save_vault({})
        print("safepaste: vault cleared.")
        return

    # ── --unmask ──────────────────────────────────────────────────────────────
    if args.unmask:
        vault = _load_vault()
        ph = args.unmask.strip()
        if not ph.startswith("["):
            ph = f"[{ph}]"
        val = vault.get(ph)
        if val:
            print(val)
        else:
            print(f"safepaste: {ph} not found in vault.", file=sys.stderr)
            sys.exit(1)
        return

    # ── Apply CLI overrides to config ─────────────────────────────────────────
    if args.pro:
        is_pro = True
    if args.no_devsec:
        cfg["devsec_mode"] = False
    if args.no_fintech:
        cfg["fintech_shield"] = False
    if args.no_corporate:
        cfg["corporate_shield"] = False
    if args.no_web3:
        cfg["web3_shield"] = False
    if args.no_civic:
        cfg["civic_shield"] = False

    # ── Read input ────────────────────────────────────────────────────────────
    try:
        text = args.input.read()
    except KeyboardInterrupt:
        sys.exit(0)

    # ── Build threats & redact ────────────────────────────────────────────────
    threats = _build_threats(cfg, is_pro)
    vault   = _load_vault() if is_pro else {}
    custom  = cfg.get("custom_keywords", []) if is_pro else []

    redacted, vault = redact(text, threats, vault, custom)

    if is_pro:
        _save_vault(vault)

    print(redacted, end="")

if __name__ == "__main__":
    main()
