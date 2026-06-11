"""
SafeRelay Python SDK — SafeRelayClient
pip install saferelay-enterprise

Usage:
    from saferelay import SafeRelayClient
    client = SafeRelayClient(mode="zero-trust")
    safe = client.redact("token AKIAIOSFODNN7EXAMPLE at 10.1.2.3")
    print(safe)        # "token 🔒[AWS_KEY_1] at 🔒[INTERNAL_IP_1]"
    print(client.last_detections)  # {"AWS_KEY": 1, "INTERNAL_IP": 1}
"""

from __future__ import annotations
import re
from typing import Literal

# ---------------------------------------------------------------------------
# Pattern definitions — mirrors patterns.js and boomerang_snip.py
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern, callable | None]] = [
    # ── Network ────────────────────────────────────────────────────────────
    ("INTERNAL_IP", re.compile(
        r'\b(?!127\.|255\.|0\.0\.0\.0)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b'
    ), lambda m: all(0 <= int(x) <= 255 for x in m.split('.'))),

    # ── AWS ────────────────────────────────────────────────────────────────
    ("AWS_KEY", re.compile(r'\bAKIA[0-9A-Z]{16}\b'), None),
    ("AWS_KEY", re.compile(r'\bASIA[0-9A-Z]{16}\b'), None),
    ("AWS_SECRET", re.compile(
        r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)'
        r'\s*[=:"\'\s]+["\']?([A-Za-z0-9/+=]{40})["\']?'
    ), None),
    ("AWS_SECRET", re.compile(
        r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'
    ), lambda m: not re.fullmatch(r'[0-9a-fA-F]{40}', m)),

    # ── API Keys ───────────────────────────────────────────────────────────
    ("OPENAI_KEY",    re.compile(r'\bsk-proj-[a-zA-Z0-9_-]{20,}\b', re.I), None),
    ("OPENAI_KEY",    re.compile(r'\bsk-(?!proj-|ant-)[a-zA-Z0-9_-]{16,}\b', re.I), None),
    ("ANTHROPIC_KEY", re.compile(r'\bsk-ant-[a-zA-Z0-9_-]{10,}\b', re.I), None),
    ("GITHUB_TOKEN",  re.compile(r'\bghp_[a-zA-Z0-9]{20,}\b'), None),
    ("GITHUB_TOKEN",  re.compile(r'\bgithub_pat_[a-zA-Z0-9_]{20,}\b'), None),
    ("GITHUB_TOKEN",  re.compile(r'\bgh[osux]_[a-zA-Z0-9]{20,}\b'), None),
    ("SLACK_TOKEN",   re.compile(r'\bxox[bap]-[a-zA-Z0-9-]{10,}\b', re.I), None),
    ("SLACK_WEBHOOK", re.compile(
        r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+'
    ), None),
    ("STRIPE_KEY",    re.compile(r'\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b'), None),
    ("DOCKER_TOKEN",  re.compile(r'\bdckr_pat_[a-zA-Z0-9_-]{20,}\b'), None),
    ("NPM_TOKEN",     re.compile(r'\bnpm_[a-zA-Z0-9]{36,}\b'), None),
    ("TWILIO_KEY",    re.compile(r'\bSK[a-f0-9]{32}\b'), None),
    ("SENDGRID_KEY",  re.compile(r'\bSG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}\b'), None),
    ("GEMINI_KEY",    re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), None),

    # ── Google OAuth ──────────────────────────────────────────────────────
    ("GOOGLE_OAUTH",  re.compile(r'\b\d{6,}-[a-z0-9]+\.apps\.googleusercontent\.com\b', re.I), None),
    ("GOOGLE_OAUTH",  re.compile(r'\bGOCSPX-[A-Za-z0-9_-]{20,}\b'), None),
    ("GOOGLE_OAUTH",  re.compile(r'\b1//[A-Za-z0-9_\-]{10,}\b'), None),

    # ── Crypto ─────────────────────────────────────────────────────────────
    ("BTC_ADDRESS",   re.compile(r'\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b'), None),
    ("BTC_ADDRESS",   re.compile(r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b'), None),
    ("BTC_ADDRESS",   re.compile(r'\bbc1[a-z0-9]{6,87}\b', re.I), None),
    ("ETH_ADDRESS",   re.compile(r'\b0x[a-fA-F0-9]{40}\b'), None),
    ("SEED_PHRASE",   re.compile(r'\b([a-z]+\s){11}[a-z]+\b'), lambda m: len(m.strip().split()) == 12),
    ("SEED_PHRASE",   re.compile(r'\b([a-z]+\s){23}[a-z]+\b'), lambda m: len(m.strip().split()) == 24),
    ("PEM_KEY",       re.compile(r'-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE KEY-----'), None),

    # ── PII ────────────────────────────────────────────────────────────────
    ("US_SSN",        re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), None),
    ("CREDIT_CARD",   re.compile(r'\b(?:\d{4}[-\s]?){3}\d{3,4}\b'), None),
]


class SafeRelayClient:
    """
    Local, zero-trust DLP client for Python.

    Modes:
        zero-trust  — redacts in place, nothing leaves the process (default)
        audit       — redacts and records detections for logging/reporting

    Example:
        client = SafeRelayClient(mode="zero-trust")
        safe = client.redact(raw_log)
        print(client.last_detections)
    """

    def __init__(self, mode: Literal["zero-trust", "audit"] = "zero-trust"):
        self.mode = mode
        self._detections: dict[str, int] = {}

    def redact(self, text: str, emoji: bool = True) -> str:
        """Redact all detected secrets and PII from *text*.

        Args:
            text:  The raw string to scan.
            emoji: If True (default) prefix tokens with 🔒. Set False for
                   plain tokens like [AWS_KEY_1] instead of 🔒[AWS_KEY_1].

        Returns:
            Sanitised string with secrets replaced by labelled tokens.
        """
        if not text:
            return text

        result = text
        self._detections = {}
        prefix = "🔒" if emoji else ""

        for label, pattern, validator in _PATTERNS:
            counter = self._detections.get(label, 0)

            def _replace(m, l=label, v=validator, c=[counter]):
                match_str = m.group(0)
                if v and not v(match_str):
                    return match_str
                c[0] += 1
                self._detections[l] = c[0]
                return f"{prefix}[{l}_{c[0]}]"

            result = pattern.sub(_replace, result)

        return result

    def is_safe(self, text: str) -> bool:
        """Return True if no secrets are detected in *text*."""
        probe = self.redact(text, emoji=False)
        return probe == text

    @property
    def last_detections(self) -> dict[str, int]:
        """Dict of {PATTERN_TYPE: count} from the last redact() call."""
        return dict(self._detections)

    @property
    def last_detection_count(self) -> int:
        """Total number of secrets found in the last redact() call."""
        return sum(self._detections.values())
