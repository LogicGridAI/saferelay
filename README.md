# SafePaste Enterprise CLI

> Zero-trust DLP for Linux pipelines — 35+ threat patterns across 8+ countries.

[![PyPI](https://img.shields.io/pypi/v/saferelay-enterprise)](https://pypi.org/project/saferelay-enterprise/)
[![Docker Hub](https://img.shields.io/badge/Docker-logicgridai%2Fsafepaste-blue)](https://hub.docker.com/r/logicgridai/saferelay)
[![Chrome Web Store](https://img.shields.io/badge/Chrome-Web%20Store-blue)](https://saferelay.ai)

SafePaste redacts sensitive data in your Linux pipelines before it reaches AI tools, log aggregators, or external services.
BEFORE                                    AFTER (SafePaste)
─────────────────────────────────         ─────────────────────────────────
OPENAI_API_KEY=sk-proj-abc...xyz
AWS_ACCESS_KEY_ID=AKIA1234ABCD
Authorization: Bearer eyJhb...            Authorization: Bearer [BEARER_1]
Server: [IP_1]                      Server: [DEVSEC_1]
SSN: [US_SSN_1]                          SSN: [US_SSN_1]

## Get a License

| Tier | Price | Get it |
|------|-------|--------|
| Free | $0 | [Chrome Web Store](https://chromewebstore.google.com/detail/saferelay-enterprise/odeoilooelkodahbbdokbollgahdcaag) |
| Pro | $7.99/mo or $59/yr | [saferelay.ai/#pricing](https://saferelay.ai/#pricing) |
| SafeRelay Suite | $99 one-time | [saferelay.ai/saferelay](https://saferelay.ai/saferelay) |

## Installation

```bash
pip install saferelay-enterprise

# With Redis support (enterprise distributed vault)
pip install saferelay-enterprise[redis]
```

Requires Python 3.9+. No external dependencies for the base install.

## Usage

```bash
# Free tier — mask IPs and API keys
cat /var/log/app.log | saferelay --mask

# Pro tier — full vault with unmask
docker logs my-app | saferelay --mask > clean.log
cat ai_response.txt | saferelay --unmask

# Activate Pro
saferelay --unlock "YOUR-LICENSE-KEY"

# Status
saferelay --status
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
docker pull logicgridai/saferelay:latest

cat /var/log/app.log | docker run --rm -i logicgridai/saferelay --mask
```

## Kubernetes sidecar

```yaml
containers:
  - name: saferelay
    image: logicgridai/saferelay:latest
    env:
      - name: SAFEPASTE_LICENSE_KEY
        valueFrom:
          secretKeyRef:
            name: saferelay-secret
            key: license-key
```

## Pricing

| Tier | Price | Features |
|------|-------|---------|
| Free | $0 | IP + API key redaction |
| Pro | $7.99/month or $59/year | 35+ patterns, full vault |
| SafeRelay Suite | $99 one-time | SafePaste + SpeakPaste + Boomerang Snip |

→ [Get a license at saferelay.ai](https://saferelay.ai)

## Privacy

Clipboard and log content never leaves your machine. License activation sends only a hashed device fingerprint to `api.saferelay.ai` — no log data, ever.

Full privacy policy: [saferelay.ai/privacy](https://saferelay.ai/privacy)

**Built by [LogicGrid AI, LLC](https://logicgrid.ai)** — support@logicgrid.ai
