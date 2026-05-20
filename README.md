# SafePaste Enterprise CLI

> Zero-trust DLP for Linux pipelines — 35+ threat patterns across 8+ countries.

[![PyPI](https://img.shields.io/pypi/v/safepaste-enterprise)](https://pypi.org/project/safepaste-enterprise/)
[![Docker Hub](https://img.shields.io/badge/Docker-logicgridai%2Fsafepaste-blue)](https://hub.docker.com/r/logicgridai/safepaste)
[![Chrome Web Store](https://img.shields.io/badge/Chrome-Web%20Store-blue)](https://safepaste.app)

SafePaste redacts sensitive data in your Linux pipelines before it reaches AI tools, log aggregators, or external services.
BEFORE                                    AFTER (SafePaste)
─────────────────────────────────         ─────────────────────────────────
OPENAI_API_KEY=sk-proj-abc...xyz
AWS_ACCESS_KEY_ID=AKIA1234ABCD
Authorization: Bearer eyJhb...            Authorization: Bearer [BEARER_1]
Server: [IP_1]                      Server: [DEVSEC_1]
SSN: [US_SSN_1]                          SSN: [US_SSN_1]

## Installation

```bash
pip install safepaste-enterprise

# With Redis support (enterprise distributed vault)
pip install safepaste-enterprise[redis]
```

Requires Python 3.9+. No external dependencies for the base install.

## Usage

```bash
# Free tier — mask IPs and API keys
cat /var/log/app.log | safepaste --mask

# Pro tier — full vault with unmask
docker logs my-app | safepaste --mask > clean.log
cat ai_response.txt | safepaste --unmask

# Activate Pro
safepaste --unlock "YOUR-LICENSE-KEY"

# Status
safepaste --status
```

## What gets redacted

| Pattern | Free | Pro |
|---------|------|-----|
| IPv4 addresses | ✓ | ✓ |
| API keys (OpenAI, Anthropic, AWS, GitHub, Slack, Gemini) | ✓ | ✓ |
| Bitcoin / Ethereum addresses | ✓ | ✓ |
| PEM private keys | ✓ | ✓ |
| .env file values | ✓ | ✓ |
| MAC addresses | — | ✓ |
| Credit cards (Luhn-validated) | — | ✓ |
| US SSN | — | ✓ |
| EU IBAN | — | ✓ |
| UK NINO | — | ✓ |
| Nigeria NIN / Bank / Phone | — | ✓ |
| Canada SIN | — | ✓ |
| India Aadhaar / PAN | — | ✓ |
| South Africa ID | — | ✓ |
| Australia TFN | — | ✓ |
| Brazil CPF | — | ✓ |
| Singapore NRIC | — | ✓ |
| Germany Tax ID | — | ✓ |
| Seed phrases (12/24 word) | — | ✓ |
| ETH private keys | — | ✓ |
| Custom NDA keywords | — | ✓ |

## Docker

```bash
docker pull logicgridai/safepaste:latest

cat /var/log/app.log | docker run --rm -i logicgridai/safepaste --mask
```

## Kubernetes sidecar

```yaml
containers:
  - name: safepaste
    image: logicgridai/safepaste:3.4.1
    env:
      - name: SAFEPASTE_LICENSE_KEY
        valueFrom:
          secretKeyRef:
            name: safepaste-secret
            key: license-key
```

## Pricing

| Tier | Price | Features |
|------|-------|---------|
| Free | $0 | IP + API key redaction |
| Pro | $7.99/month or $59/year | 35+ patterns, full vault |
| SafeRelay Suite | $99 one-time | SafePaste + SpeakPaste + Boomerang Snip |

→ [Get a license at safepaste.app](https://safepaste.app)

## Privacy

Clipboard and log content never leaves your machine. License activation sends only a hashed device fingerprint to `api.safepaste.app` — no log data, ever.

Full privacy policy: [safepaste.app/privacy](https://safepaste.app/privacy)

**Built by [LogicGrid AI, LLC](https://logicgrid.ai)** — support@logicgrid.ai
