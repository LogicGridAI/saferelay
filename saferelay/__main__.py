#!/usr/bin/env python3
"""
saferelay — SafeRelay CLI
Zero-trust local DLP for AI-era workflows.
53 canonical threat patterns across 10+ countries.

This CLI shares ONE pattern engine with the SafeRelay SDK (client.py):
patterns, validators, and labels are imported from .client so the
`saferelay` command, the SafeRelayClient class, and the Docker image
all redact identically. No drift.
"""
from __future__ import annotations
__version__ = "3.6.1"

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
# _PATTERNS entries: (label, group, compiled_regex, validator|None, context_fn|None)
# groups: "devsec" | "fintech" | "corporate" | "civic"
from .client import _PATTERNS, PATTERN_TYPES  # noqa: E402

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


# ── Redaction engine (consumes client.py _PATTERNS) ──────────────────────────
def _enabled_groups(cfg: dict, is_pro: bool) -> set[str]:
    groups = set(FREE_GROUPS)  # devsec always available
    if is_pro:
        if cfg.get("fintech_shield", True):
            groups.add("fintech")
        if cfg.get("corporate_shield", True):
            groups.add("corporate")
        if cfg.get("civic_shield", True):
            groups.add("civic")
    return groups


def redact(text: str, enabled_groups: set[str], vault: dict,
           custom_keywords: list[str], emoji: bool = True) -> tuple[str, dict]:
    """Redact using the canonical _PATTERNS from client.py.

    Mirrors client.SafeRelayClient.redact ordering and the preserve-group-1
    strategy for ENV_VALUE / NG_BVN / NG_NIN, while adding CLI vault + NDA.
    """
    counters: dict[str, int] = {}
    prefix = "🔒" if emoji else ""
    source = text
    result = text

    # Custom NDA keywords first (Pro only — caller passes [] if free)
    for kw in custom_keywords:
        if not kw:
            continue
        pat = re.compile(re.escape(kw), re.IGNORECASE)

        def _nda_sub(m):
            counters["NDA"] = counters.get("NDA", 0) + 1
            ph = f"{prefix}[NDA_{counters['NDA']}]"
            vault[f"[NDA_{counters['NDA']}]"] = m.group(0)
            return ph

        result = pat.sub(_nda_sub, result)

    # Canonical patterns, in order
    for entry in _PATTERNS:
        label, group, pattern, validator, context_fn = entry
        if group not in enabled_groups:
            continue
        counter = [counters.get(label, 0)]

        def _sub(m, l=label, v=validator, cf=context_fn, c=counter):
            if cf == "preserve_group1":
                value = m.group(2)
                if v and not v(value):
                    return m.group(0)
                c[0] += 1
                counters[l] = c[0]
                vault[f"[{l}_{c[0]}]"] = value
                return f"{m.group(1)}{prefix}[{l}_{c[0]}]"
            match_str = m.group(0)
            if v and not v(match_str):
                return match_str
            if callable(cf) and not cf(m, source):
                return match_str
            c[0] += 1
            counters[l] = c[0]
            vault[f"[{l}_{c[0]}]"] = match_str
            return f"{prefix}[{l}_{c[0]}]"

        result = pattern.sub(_sub, result)

    return result, vault


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    cfg = _load_config()
    is_pro = bool(cfg.get("is_licensed"))

    p = argparse.ArgumentParser(
        prog="saferelay",
        description=(
            f"SafeRelay CLI v{__version__} — "
            "53 canonical threat patterns across 10+ countries. "
            "Zero-trust DLP for AI-assisted workflows. "
            "Free: DevSec Shield (API keys, cloud keys, IPs, crypto, env values). "
            "Pro: FinTech / Corporate / Civic shields + reversible vault."
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
    p.add_argument("--pro", action="store_true",
                   help="Force Pro-tier for this run (no license call).")
    p.add_argument("--no-emoji", action="store_true",
                   help="Plain placeholders like [AWS_KEY_1] (no lock prefix).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Shield toggles
    p.add_argument("--no-fintech", action="store_true", help="Disable FinTech Shield.")
    p.add_argument("--no-corporate", action="store_true", help="Disable Corporate Shield.")
    p.add_argument("--no-civic", action="store_true", help="Disable Mission & Civic Shield.")
    p.add_argument("--mask", action="store_true", help="Alias for default redact mode.")

    args = p.parse_args()

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
        kws = cfg.get("custom_keywords", [])
        print(f"  NDA terms : {len(kws)} ({', '.join(kws[:3])}{'…' if len(kws) > 3 else ''})")
        print(f"  Patterns  : {len(PATTERN_TYPES)} canonical types")
        return

    # ── --clear-vault ─────────────────────────────────────────────────────────
    if args.clear_vault:
        _save_vault({})
        print("saferelay: vault cleared.")
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

    # ── Read input ────────────────────────────────────────────────────────────
    try:
        text = args.input.read()
    except KeyboardInterrupt:
        sys.exit(0)

    # ── Redact ──────────────────────────────────────────────────────────────────
    enabled = _enabled_groups(cfg, is_pro)
    vault = _load_vault() if is_pro else {}
    custom = cfg.get("custom_keywords", []) if is_pro else []
    emoji = not args.no_emoji

    redacted, vault = redact(text, enabled, vault, custom, emoji=emoji)

    if is_pro:
        _save_vault(vault)

    print(redacted, end="")


if __name__ == "__main__":
    main()
