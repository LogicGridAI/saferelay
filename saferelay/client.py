"""
SafeRelay Python SDK — SafeRelayClient
pip install saferelay

Usage:
    from saferelay import SafeRelayClient
    client = SafeRelayClient(mode="zero-trust")
    safe = client.redact("token AKIAIOSFODNN7EXAMPLE at 10.1.2.3")
    print(safe)        # "token 🔒[AWS_KEY_1] at 🔒[IP_1]"
    print(client.last_detections)  # {"AWS_KEY": 1, "IP": 1}

Pattern parity:
    This module mirrors the canonical SafeRelay pattern registry shared by the
    browser extension (patterns.js) and the desktop agent (boomerang_snip.py).
    50 unique detection types. Type names and regexes are kept identical across
    all SafeRelay products so placeholder labels (e.g. [US_SSN_1]) are uniform.
"""

from __future__ import annotations
import re
from typing import Callable, Literal, Optional

# ---------------------------------------------------------------------------
# Helper validators (ported verbatim from boomerang_snip.py / patterns.js)
# ---------------------------------------------------------------------------

_CONTEXT_WINDOW = 100  # chars to scan around a bare 64-hex match

_SHA256_SAFE_CONTEXT = re.compile(
    r"(?:sha[\s\-_]?256|sha256sum|sha256\s*:|sha256\s*=|"
    r"checksum|digest|file[\s_\-]?hash|image[\s_\-]?hash|"
    r"\bhash\b|hash:)",
    re.IGNORECASE,
)


def _is_pure_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]+", s, re.IGNORECASE))


def _is_false_positive_api_match(match: str) -> bool:
    """Filter hex-only Bearer / sk- / pk- tokens (git SHAs, digests, examples)."""
    lower = match.lower()
    if lower.startswith("bearer "):
        t = lower[7:].strip()
        return len(t) >= 16 and _is_pure_hex(t)
    if re.match(r"^(sk|pk)-", match, re.IGNORECASE):
        t = re.sub(r"^(sk|pk)-", "", lower).strip()
        return len(t) >= 16 and _is_pure_hex(t)
    if len(match) == 40 and _is_pure_hex(match):
        return True
    return False


def _luhn_valid(digits_only: str) -> bool:
    if len(digits_only) not in (15, 16):
        return False
    total = 0
    alt = False
    for ch in reversed(digits_only):
        if not ch.isdigit():
            return False
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _v_openai_legacy(m: str) -> bool:
    return not _is_false_positive_api_match(m)


def _v_aws_secret_named(m: str) -> bool:
    return not bool(re.fullmatch(r"[0-9a-f]{40}", m, re.IGNORECASE))


def _v_aws_secret_raw(m: str) -> bool:
    return not bool(re.fullmatch(r"[0-9a-fA-F]{40}", m))


def _v_bearer(m: str) -> bool:
    return not _is_false_positive_api_match(m)


def _v_api_key_catch(m: str) -> bool:
    return not _is_false_positive_api_match(m)


def _v_seed_12(m: str) -> bool:
    return len(m.strip().split()) == 12


def _v_seed_24(m: str) -> bool:
    return len(m.strip().split()) == 24


def _v_ipv4(m: str) -> bool:
    octets = m.split(".")
    if len(octets) != 4:
        return False
    try:
        ints = [int(o) for o in octets]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in ints):
        return False
    if ints[0] == 127 or ints[0] == 255:
        return False
    return True


def _v_env_value(value: str) -> bool:
    """Receives the VALUE (group 2) of a KEY=value line. Skip if it's already
    tokenised or starts with a named-key prefix (let the named pattern win)."""
    v = value.strip()
    if re.match(r"^\[[A-Z_]+_\d+\]", v):
        return False
    _named_prefixes = (
        "sk-proj-", "sk-ant-", "sk-", "AKIA", "ASIA",
        "ghp_", "github_pat_", "gho_", "ghs_", "ghu_", "ghx_",
        "xoxb-", "xoxa-", "xoxp-",
        "sk_live_", "sk_test_", "pk_live_", "pk_test_",
        "dckr_pat_", "npm_", "SG.", "bearer ", "AIza", "SK",
    )
    lower_v = v.lower()
    return not any(lower_v.startswith(p.lower()) for p in _named_prefixes)


def _v_credit_card(m: str) -> bool:
    digits = re.sub(r"\D", "", m)
    return len(digits) in (15, 16) and _luhn_valid(digits)


def _v_aadhaar(m: str) -> bool:
    return len(re.sub(r"[\s-]", "", m)) == 12


def _v_za_id(m: str) -> bool:
    try:
        month = int(m[2:4]); day = int(m[4:6])
    except (ValueError, IndexError):
        return False
    return 1 <= month <= 12 and 1 <= day <= 31


def _v_au_tfn(m: str) -> bool:
    return len(re.sub(r"[\s-]", "", m)) in (8, 9)


def _v_us_green_card(m: str) -> bool:
    upper = m.upper()
    if any(upper.startswith(p) for p in ("LIN", "EAC", "WAC", "SRC", "MSC", "IOE")):
        return True
    if re.fullmatch(r"A\d{8,9}", upper):
        return True
    if re.fullmatch(r"[A-Z]{3}\d{10}", upper):
        return True
    return False


def _v_email(m: str) -> bool:
    return not re.search(r"\.(png|jpg|jpeg|gif|svg|webp|css|js|json|html?)$", m, re.IGNORECASE)


def _ctx_64_hex(m: re.Match, source: str) -> bool:
    """64-hex: redact unless surrounded by sha256/checksum/hash context."""
    start = max(0, m.start() - _CONTEXT_WINDOW)
    end = min(len(source), m.end() + _CONTEXT_WINDOW)
    context = source[start:end]
    if _SHA256_SAFE_CONTEXT.search(context):
        return False
    return True


# ---------------------------------------------------------------------------
# Canonical pattern registry — 50 types, mirrors patterns.js + boomerang_snip.py
# Tuple: (TYPE, group, compiled_regex, validator|None, context_fn|None)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, str, re.Pattern, Optional[Callable], Optional[Callable]]] = [
    # ── Connection-string credentials (scheme://user:PASSWORD@host) ────────
    # Redacts only the password; keeps scheme/user/host visible so the log
    # stays debuggable. Runs first so the password is gone before any other
    # rule sees it. preserve_group1 keeps g1 (scheme://user:), g3 (@host).
    ("CONN_STRING",   "devsec", re.compile(
        r"\b([a-z][a-z0-9+.\-]*://[^:/\s@]+:)([^\s]+?)(@[a-zA-Z0-9.\-]+(?::\d+)?(?:[/\s]|$))",
        re.I), None, "preserve_conn"),
    # ── DevSec / API keys — named (most specific first) ────────────────────
    ("OPENAI_KEY",    "devsec", re.compile(r"\bsk-proj-[a-zA-Z0-9_-]{20,}\b", re.I), None, None),
    ("OPENAI_KEY",    "devsec", re.compile(r"\bsk-(?!proj-|ant-)[a-zA-Z0-9_-]{16,}\b", re.I), _v_openai_legacy, None),
    ("ANTHROPIC_KEY", "devsec", re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{10,}\b", re.I), None, None),
    ("AWS_KEY",       "devsec", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None, None),
    ("AWS_KEY",       "devsec", re.compile(r"\bASIA[0-9A-Z]{16}\b"), None, None),
    ("AWS_SECRET",    "devsec", re.compile(
        r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)"
        r"\s*[=:\"'\s]+[\"']?([A-Za-z0-9/+=]{40})[\"']?"), _v_aws_secret_named, None),
    ("AWS_SECRET",    "devsec", re.compile(
        r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), _v_aws_secret_raw, None),
    ("GITHUB_PAT",    "devsec", re.compile(r"\bghp_[a-zA-Z0-9]{20,}\b"), None, None),
    ("GITHUB_PAT_FG", "devsec", re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{20,}\b"), None, None),
    ("GITHUB_OAUTH",  "devsec", re.compile(r"\bgh[osux]_[a-zA-Z0-9]{20,}\b"), None, None),
    ("SLACK_KEY",     "devsec", re.compile(r"\bxox[bap]-[a-zA-Z0-9-]{10,}\b", re.I), None, None),
    ("SLACK_WEBHOOK", "devsec", re.compile(
        r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+"), None, None),
    ("STRIPE_KEY",    "devsec", re.compile(r"\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b"), None, None),
    ("STRIPE_PK",     "devsec", re.compile(r"\bpk_(?:live|test)_[a-zA-Z0-9]{24,}\b"), None, None),
    ("BEARER",        "devsec", re.compile(r"\bbearer\s+[a-zA-Z0-9._~+/=-]{16,}\b", re.I), _v_bearer, None),
    ("DOCKER_KEY",    "devsec", re.compile(r"\bdckr_pat_[a-zA-Z0-9_-]{20,}\b"), None, None),
    ("NPM_TOKEN",     "devsec", re.compile(r"\bnpm_[a-zA-Z0-9]{36,}\b"), None, None),
    ("TWILIO_KEY",    "devsec", re.compile(r"\bSK[a-f0-9]{32}\b"), None, None),
    ("SENDGRID_KEY",  "devsec", re.compile(r"\bSG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}\b"), None, None),
    ("GEMINI_KEY",    "devsec", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), None, None),
    # Google OAuth (client id / secret / refresh token)
    ("GOOGLE_OAUTH",  "devsec", re.compile(r"\b\d{6,}-[a-z0-9]+\.apps\.googleusercontent\.com\b", re.I), None, None),
    ("GOOGLE_OAUTH",  "devsec", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"), None, None),
    ("GOOGLE_OAUTH",  "devsec", re.compile(r"\b1//[A-Za-z0-9_\-]{10,}\b"), None, None),
    ("API_KEY",       "devsec", re.compile(r"\bpk-[a-zA-Z0-9_-]{16,}\b", re.I), _v_api_key_catch, None),
    ("PEM_KEY",       "devsec", re.compile(r"-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE KEY-----"), None, None),

    # ── Crypto ─────────────────────────────────────────────────────────────
    ("BTC_ADDRESS",   "devsec", re.compile(r"\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b"), None, None),
    ("BTC_ADDRESS",   "devsec", re.compile(r"\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b"), None, None),
    ("BTC_ADDRESS",   "devsec", re.compile(r"\bbc1[a-z0-9]{6,87}\b", re.I), None, None),
    # ETH_PRIVATE_KEY before ETH_ADDRESS/CRYPTO_KEY so 64-hex wins
    ("ETH_PRIVATE_KEY", "devsec", re.compile(r"\b0x[a-fA-F0-9]{64}\b"), None, None),
    ("ETH_ADDRESS",   "devsec", re.compile(r"\b0x[a-fA-F0-9]{40}\b"), None, None),
    ("CRYPTO_KEY",    "devsec", re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"), None, None),
    ("CRYPTO_KEY",    "devsec", re.compile(r"\b[a-fA-F0-9]{64}\b"), None, _ctx_64_hex),
    ("SOL_ADDRESS",   "devsec", re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{44}\b"), None, None),
    ("SEED_PHRASE",   "devsec", re.compile(r"\b([a-z]+\s){11}[a-z]+\b"), _v_seed_12, None),
    ("SEED_PHRASE",   "devsec", re.compile(r"\b([a-z]+\s){23}[a-z]+\b"), _v_seed_24, None),
    ("MAC_ADDRESS",   "devsec", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), None, None),
    ("IP",            "devsec", re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), _v_ipv4, None),
    # ENV_VALUE matches KEY=value but only redacts the value (group 2);
    # the key prefix is preserved via the preserve_group strategy below.
    ("ENV_VALUE",     "devsec", re.compile(r"(?m)(^[A-Z][A-Z0-9_]*=)(.+)$"), _v_env_value, "preserve_group1"),

    # ── FinTech / national-ID PII ──────────────────────────────────────────
    ("CREDIT_CARD",   "fintech", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{3,4}\b"), _v_credit_card, None),
    ("US_SSN",        "fintech", re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None, None),
    ("EU_IBAN",       "fintech", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.I), None, None),
    ("EMAIL",         "fintech", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), _v_email, None),
    ("UK_NINO",       "fintech", re.compile(r"\b[A-Z]{2}\d{6}[A-Z]\b"), None, None),
    ("CA_SIN",        "fintech", re.compile(r"\b[1-79]\d{2}-\d{3}-\d{3}\b"), None, None),
    ("IN_AADHAAR",    "fintech", re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"), _v_aadhaar, None),
    ("IN_PAN",        "fintech", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), None, None),
    ("ZA_ID",         "fintech", re.compile(r"\b\d{13}\b"), _v_za_id, None),
    ("AU_TFN",        "fintech", re.compile(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b"), _v_au_tfn, None),
    ("BR_CPF",        "fintech", re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), None, None),
    ("SG_NRIC",       "fintech", re.compile(r"\b[STFG]\d{7}[A-Z]\b"), None, None),
    ("US_GREEN_CARD", "fintech", re.compile(r"\b[A-Z]{2,3}\d{9,10}\b"), _v_us_green_card, None),
    # ── Nigeria — context-aware (labeled) identifiers ───────────────────────
    # Python re has no variable-width lookbehind, so we capture (label)(number)
    # and use the preserve_group1 strategy to keep the label, redact only the
    # 11-digit value: "BVN: 12345678901" -> "BVN: [NG_BVN_1]". These MUST
    # precede the bare NG_NIN + DE_TAX_ID patterns so labeled numbers win.
    ("NG_BVN",        "fintech", re.compile(
        r"(\b(?:BVN|Bank[\s-]?Verification(?:[\s-]?(?:Number|No|#))?)\s*[:#-]?\s*)(\d{11})\b", re.I), None, "preserve_group1"),
    ("NG_NIN",        "fintech", re.compile(
        r"(\b(?:NIN|National[\s-]?(?:Identification|Identity|ID)(?:[\s-]?(?:Number|No|#))?)\s*[:#-]?\s*)(\d{11})\b", re.I), None, "preserve_group1"),
    # ── Nigeria — bare-digit fallbacks ──────────────────────────────────────
    ("NG_PHONE",      "fintech", re.compile(r"\b0[789][01]\d{8}\b"), None, None),
    ("NG_BANK",       "fintech", re.compile(r"\b\d{10}\b"), None, None),
    ("NG_NIN",        "fintech", re.compile(r"\b(?!0[789][01]\d{8})\d{11}\b"), None, None),
    # DE_TAX_ID after the NG block so a bare 11-digit NIN is labeled NG_NIN.
    ("DE_TAX_ID",     "fintech", re.compile(r"\b[1-9]\d{10}\b"), None, None),

    # ── Corporate ID Shield ────────────────────────────────────────────────
    ("DUNS",          "corporate", re.compile(
        r"(?:D[-\s]?U[-\s]?N[-\s]?S|D&B|Dun\s*&\s*Bradstreet)"
        r"[^0-9]{0,50}(\d{2}-\d{3}-\d{4}|\d{9})", re.I), None, None),
    ("EIN",           "corporate", re.compile(
        r"\b(?:EIN|Tax\s*ID|Federal\s*Tax\s*ID)[^0-9]{0,20}(\d{2}-\d{7})\b", re.I), None, None),
    ("VAT_EU",        "corporate", re.compile(
        r"\b(ATU\d{8}|BE0\d{9}|BG\d{9,10}|CY\d{8}L|CZ\d{8,10}"
        r"|DE\d{9}|DK\d{8}|EE\d{9}|EL\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]"
        r"|FI\d{8}|FR[A-Z0-9]{2}\d{9}|HR\d{11}|HU\d{8}"
        r"|IE\d{7}[A-Z]{1,2}|IT\d{11}|LT\d{9,12}|LU\d{8}|LV\d{11}"
        r"|MT\d{8}|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|RO\d{2,10}"
        r"|SE\d{12}|SI\d{8}|SK\d{10})\b"), None, None),

    # ── Mission & Civic Shield ─────────────────────────────────────────────
    ("GPS_COORDS",    "civic", re.compile(
        r"\b(-?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)),"
        r"\s*(-?(?:1[0-7]\d(?:\.\d+)?|(?:[1-9]?\d(?:\.\d+)?)|180(?:\.0+)?))\b"), None, None),
    ("UNHCR_ID",      "civic", re.compile(
        r"\b(?:UNHCR[-\s]?(?:ID|Reg(?:istration)?)?[-\s#:]*)?"
        r"([A-Z]{3}-\d{2}-\d{6,8}C?\d?)\b", re.I), None, None),
    ("DONOR_ID",      "civic", re.compile(
        r"\b(?:Donor|Beneficiary|Bene|Case|Client|Member|Ref)"
        r"[-\s]?(?:ID|No|#|Number|Code)[-\s:]*([A-Z0-9]{4,16})\b", re.I), None, None),
]


class SafeRelayClient:
    """
    Local, zero-trust DLP client for Python (CI/CD, serverless, CLI).

    Modes:
        zero-trust  — redacts in place, nothing leaves the process (default)
        audit       — redacts and records detections for logging/reporting
    """

    def __init__(self, mode: Literal["zero-trust", "audit"] = "zero-trust"):
        self.mode = mode
        self._detections: dict[str, int] = {}

    def redact(self, text: str, emoji: bool = True) -> str:
        """Redact all detected secrets and PII from *text*.

        Args:
            text:  The raw string to scan.
            emoji: If True (default) prefix tokens with 🔒. Set False for
                   plain tokens like [AWS_KEY_1].
        """
        if not text:
            return text

        source = text  # immutable reference for context validators
        result = text
        self._detections = {}
        prefix = "🔒" if emoji else ""

        for label, _group, pattern, validator, context_fn in _PATTERNS:
            counter = [self._detections.get(label, 0)]

            def _replace(m, l=label, v=validator, cf=context_fn, c=counter):
                # ENV_VALUE special case: redact only the value (group 2),
                # validate against the value, keep the KEY= prefix.
                if cf == "preserve_group1":
                    prefix_grp = m.group(1)
                    value = m.group(2)
                    if v and not v(value):
                        return m.group(0)
                    c[0] += 1
                    self._detections[l] = c[0]
                    return f"{prefix_grp}{prefix}[{l}_{c[0]}]"

                # CONN_STRING: redact only the password (group 2), keep
                # group 1 (scheme://user:) and group 3 (@host) visible.
                if cf == "preserve_conn":
                    c[0] += 1
                    self._detections[l] = c[0]
                    return f"{m.group(1)}{prefix}[{l}_{c[0]}]{m.group(3)}"

                match_str = m.group(0)
                if v and not v(match_str):
                    return match_str
                if callable(cf) and not cf(m, source):
                    return match_str
                c[0] += 1
                self._detections[l] = c[0]
                return f"{prefix}[{l}_{c[0]}]"

            result = pattern.sub(_replace, result)

        return result

    def is_safe(self, text: str) -> bool:
        """Return True if no secrets are detected in *text*."""
        return self.redact(text, emoji=False) == text

    @property
    def last_detections(self) -> dict[str, int]:
        """Dict of {PATTERN_TYPE: count} from the last redact() call."""
        return dict(self._detections)

    @property
    def last_detection_count(self) -> int:
        """Total number of secrets found in the last redact() call."""
        return sum(self._detections.values())


# Introspection helpers (mirror SDK exports)
PATTERN_TYPES = sorted({p[0] for p in _PATTERNS})
