#!/usr/bin/env python3
"""
saferelay — SafeRelay CLI
Zero-trust local DLP for AI-era workflows.
8 shields incl. Gov/CUI + exfiltration, 50+ canonical threat patterns.

This CLI shares ONE pattern engine with the SafeRelay SDK (client.py):
patterns, validators, labels, and the engine semantics (definition-order
precedence, claimed-span suppression, NFKC normalisation, exfiltration
bulk-block, fail-closed) are imported from .client so the `saferelay`
command, the SafeRelayClient class, and the Docker image all redact
identically to the Browser Relay / Desktop engine. No drift.
"""
from __future__ import annotations
__version__ = "3.7.1"

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import redis  # type: ignore[import-untyped]
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

# ── Canonical pattern engine (single source of truth) ───────────────────────
# _PATTERNS entries: (type_id, group, compiled_regex, validator|None, strategy|ctx)
# groups: "devsec" | "fintech" | "corporate" | "civic" | "gov_cui"
# protect_relay_text mirrors dlp.js protectRelayText (precedence, claimed-span
# suppression, NFKC normalisation, exfiltration bulk-block, fail-closed).
from .client import (  # noqa: E402
    _PATTERNS,
    PATTERN_TYPES,
    protect_relay_text,
    check_exfiltration,
)

_LEGACY_DIR = Path.home() / ".safepaste"
_CONFIG_DIR = Path.home() / ".saferelay"
if _LEGACY_DIR.exists() and not _CONFIG_DIR.exists():
    try:
        _LEGACY_DIR.rename(_CONFIG_DIR)
    except OSError:
        _CONFIG_DIR = _LEGACY_DIR
VAULT_PATH = _CONFIG_DIR / "vault.json"
CONFIG_PATH = _CONFIG_DIR / "config.json"
REDIS_ENV_VAR = "SAFEPASTE_REDIS_URL"
REDIS_HASH_KEY = "saferelay:vault"

LICENSE_VERIFY_URL = "https://logicgrid-commerce-worker.admin-thequanthub.workers.dev/license/validate"

# Which groups are free vs Pro. devsec = free; everything else = Pro.
FREE_GROUPS = {"devsec"}

DEFAULT_CONFIG: dict = {
    "is_licensed":      False,
    "license_key":      "",
    "license_tier":     "",
    "devsec_mode":      True,
    "fintech_shield":   True,
    "corporate_shield": True,
    "civic_shield":     True,
    "gov_cui_shield":   True,
    "exfil_shield":     True,
    "custom_keywords":  [],
}


# ── Config ───────────────────────────────────────────────────────────────────
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
    key = license_key.strip()
    if not key:
        return False, ""
    device_id = _get_device_id()
    payload = json.dumps({"license_key": key, "device_id": device_id}).encode()
    req = urllib.request.Request(
        LICENSE_VERIFY_URL,
        data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": f"saferelay-cli/{__version__}"},
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
        print(f"saferelay: license check failed — {exc}", file=sys.stderr)
        return False, ""


# ── Vault ────────────────────────────────────────────────────────────────────
def _get_redis():
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


# ── Shields (consumes client.py protect_relay_text) ──────────────────────────
# Map the CLI config/flags onto the canonical shields dict understood by the
# engine. devsec/basicProtection are the free tier (always on). Everything
# else is Pro and toggled off when not licensed or disabled via a flag.
def _build_shields(cfg: dict, is_pro: bool) -> dict:
    return {
        "basicProtection":    True,
        "devsec":             True,
        "fintech":            bool(is_pro and cfg.get("fintech_shield", True)),
        "corporate":          bool(is_pro and cfg.get("corporate_shield", True)),
        "civic":              bool(is_pro and cfg.get("civic_shield", True)),
        "gov_cui":            bool(is_pro and cfg.get("gov_cui_shield", True)),
        "exfiltrationShield": bool(is_pro and cfg.get("exfil_shield", True)),
        "customTerms":        False,
    }


class _BulkBlocked(Exception):
    """CLI-local: raised to the main() handler when the exfiltration shield
    (or a fail-closed engine error) blocks the relay."""

    def __init__(self, block: dict):
        self.block = block
        super().__init__(block.get("errorCode", "BLOCKED"))


def redact(text: str, shields: dict, vault: dict,
           custom_keywords: list[str], emoji: bool = True) -> tuple[str, dict]:
    """Redact using the canonical engine in client.py.

    Delegates to protect_relay_text so ordering, claimed-span suppression,
    NFKC normalisation, the exfiltration bulk-block and fail-closed behaviour
    all match the Browser Relay / Desktop engine exactly. Custom NDA keywords
    are fed to the engine as CUSTOM_TERM patterns (word-boundary, verbatim).
    The CLI vault is populated by the engine for reversible --unmask.

    Returns (redacted_text, vault). Raises _BulkBlocked when the relay is
    blocked, so main() can emit a hard error instead of raw text.
    """
    terms = [k for k in (custom_keywords or []) if k and k.strip()]
    engine_shields = dict(shields)
    if terms:
        engine_shields["customTerms"] = True

    result = protect_relay_text(
        text, engine_shields, emoji=emoji, vault=vault, custom_terms=terms,
    )
    if result.get("blocked"):
        raise _BulkBlocked(result)
    return result["text"], vault


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    cfg = _load_config()
    is_pro = bool(cfg.get("is_licensed"))

    p = argparse.ArgumentParser(
        prog="saferelay",
        description=(
            f"SafeRelay CLI v{__version__} — "
            f"8 shields, {len(PATTERN_TYPES)} canonical threat patterns. "
            "Zero-trust DLP for AI-assisted workflows. "
            "Free: DevSec Shield (API keys, cloud keys, IPs, crypto, env values). "
            "Pro: FinTech / Corporate / Civic / Gov-CUI shields, bulk "
            "exfiltration block, + reversible vault."
        ),
    )
    p.add_argument("input", nargs="?", type=argparse.FileType("r"), default=sys.stdin,
                   help="Input file (default: stdin).")
    p.add_argument("--unmask", metavar="PLACEHOLDER",
                   help="Reveal a vaulted placeholder, e.g. [US_SSN_1].")
    p.add_argument("--unlock", metavar="LICENSE_KEY",
                   help="Verify license key and enable Pro Shield Packs.")
    p.add_argument("--status", action="store_true",
                   help="Show current license tier and active shields.")
    p.add_argument("--clear-vault", action="store_true",
                   help="Wipe all vaulted values.")
    p.add_argument("--add-term", metavar="TERM",
                   help="Add a Custom Protected Term (server/client/project name) to always redact. Pro.")
    p.add_argument("--remove-term", metavar="TERM",
                   help="Remove a Custom Protected Term.")
    p.add_argument("--list-terms", action="store_true",
                   help="List all Custom Protected Terms.")
    p.add_argument("--pro", action="store_true",
                   help="Force Pro-tier for this run (no license call).")
    p.add_argument("--no-emoji", action="store_true",
                   help="Plain placeholders like [AWS_KEY_1] (no lock prefix).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Shield toggles
    p.add_argument("--no-fintech", action="store_true", help="Disable FinTech Shield.")
    p.add_argument("--no-corporate", action="store_true", help="Disable Corporate Shield.")
    p.add_argument("--no-civic", action="store_true", help="Disable Mission & Civic Shield.")
    p.add_argument("--no-gov-cui", action="store_true", help="Disable Gov / CUI Shield.")
    p.add_argument("--no-exfil", action="store_true",
                   help="Disable the Exfiltration Shield bulk-relay block.")
    p.add_argument("--mask", action="store_true", help="Alias for default redact mode.")

    args = p.parse_args()

    # Apply the --pro override BEFORE command dispatch so Pro-gated commands
    # (e.g. --add-term) honour it, not just the redact path.
    if args.pro:
        is_pro = True

    # ── --unlock ──────────────────────────────────────────────────────────────
    if args.unlock:
        key = (args.unlock.strip()
               or os.environ.get("SAFERELAY_LICENSE_KEY", "").strip()
               or os.environ.get("SAFEPASTE_LICENSE_KEY", "").strip())
        if not key:
            print("saferelay: pass LICENSE_KEY or set SAFERELAY_LICENSE_KEY", file=sys.stderr)
            sys.exit(1)
        print("saferelay: verifying license…", file=sys.stderr)
        ok, tier = verify_license(key)
        if ok:
            cfg["is_licensed"] = True
            cfg["license_key"] = key
            cfg["license_tier"] = tier
            _save_config(cfg)
            print(f"saferelay: ✓ License verified — tier={tier}. Pro Shield Packs enabled.")
        else:
            print("saferelay: ✗ Invalid license key. Check your key and try again.", file=sys.stderr)
            sys.exit(1)
        return

    # ── --status ──────────────────────────────────────────────────────────────
    if args.status:
        on, off = "✓ on", "✗ off"
        tier = cfg.get("license_tier", "free") if is_pro else "free"
        print(f"saferelay v{__version__}")
        print(f"  License   : {'Pro — ' + tier if is_pro else 'Free'}")
        print(f"  DevSec    : ✓ on (free)")
        print(f"  FinTech   : {on if is_pro and cfg.get('fintech_shield') else off}")
        print(f"  Corporate : {on if is_pro and cfg.get('corporate_shield') else off}")
        print(f"  Civic     : {on if is_pro and cfg.get('civic_shield') else off}")
        print(f"  Gov / CUI : {on if is_pro and cfg.get('gov_cui_shield') else off}")
        print(f"  Exfil     : {on if is_pro and cfg.get('exfil_shield') else off}")
        kws = cfg.get("custom_keywords", [])
        print(f"  NDA terms : {len(kws)} ({', '.join(kws[:3])}{'…' if len(kws) > 3 else ''})")
        print(f"  Patterns  : {len(PATTERN_TYPES)} canonical types, 8 shields")
        return

    # ── --clear-vault ─────────────────────────────────────────────────────────
    if args.clear_vault:
        _save_vault({})
        print("saferelay: vault cleared.")
        return

    # ── Custom Protected Terms (Pro) ──────────────────────────────────────────
    if args.add_term:
        if not is_pro:
            print("saferelay: Custom Protected Terms require Pro. Run --unlock <key>.", file=sys.stderr)
            sys.exit(1)
        term = args.add_term.strip()
        terms = cfg.get("custom_keywords", [])
        if term and term.lower() not in [t.lower() for t in terms]:
            terms.append(term)
            cfg["custom_keywords"] = terms
            _save_config(cfg)
            print(f"saferelay: added protected term '{term}' ({len(terms)} total).")
        else:
            print(f"saferelay: '{term}' already protected or empty.")
        return

    if args.remove_term:
        term = args.remove_term.strip()
        terms = cfg.get("custom_keywords", [])
        new_terms = [t for t in terms if t.lower() != term.lower()]
        cfg["custom_keywords"] = new_terms
        _save_config(cfg)
        print(f"saferelay: removed '{term}' ({len(new_terms)} remaining).")
        return

    if args.list_terms:
        terms = cfg.get("custom_keywords", [])
        if not terms:
            print("saferelay: no Custom Protected Terms set.")
        else:
            print(f"saferelay: {len(terms)} Custom Protected Term(s):")
            for t in terms:
                print(f"  • {t}")
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
            print(f"saferelay: {ph} not found in vault.", file=sys.stderr)
            sys.exit(1)
        return

    # ── Apply CLI overrides ─────────────────────────────────────────────────────
    if args.pro:
        is_pro = True
    if args.no_fintech:
        cfg["fintech_shield"] = False
    if args.no_corporate:
        cfg["corporate_shield"] = False
    if args.no_civic:
        cfg["civic_shield"] = False
    if args.no_gov_cui:
        cfg["gov_cui_shield"] = False
    if args.no_exfil:
        cfg["exfil_shield"] = False

    # ── Read input ────────────────────────────────────────────────────────────
    try:
        text = args.input.read()
    except KeyboardInterrupt:
        sys.exit(0)

    # ── Redact ──────────────────────────────────────────────────────────────────
    shields = _build_shields(cfg, is_pro)
    vault = _load_vault() if is_pro else {}
    custom = cfg.get("custom_keywords", []) if is_pro else []
    emoji = not args.no_emoji

    try:
        redacted, vault = redact(text, shields, vault, custom, emoji=emoji)
    except _BulkBlocked as blocked:
        b = blocked.block
        if b.get("errorCode") == "BULK_EXFILTRATION_RISK":
            cats = ", ".join(b.get("categories", [])) or "bulk export"
            print(
                f"saferelay: ✗ BLOCKED — bulk exfiltration risk "
                f"({cats}; {b.get('matchCount')} matches). "
                f"Relay refused; no text emitted. Use --no-exfil to override.",
                file=sys.stderr,
            )
        else:
            print(
                f"saferelay: ✗ BLOCKED — protection engine error "
                f"({b.get('errorCode')}). Relay refused (fail-closed).",
                file=sys.stderr,
            )
        sys.exit(2)

    if is_pro:
        _save_vault(vault)

    print(redacted, end="")


if __name__ == "__main__":
    main()
