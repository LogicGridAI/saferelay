# SafeRelay CLI

**Zero-trust local DLP for AI-era workflows — 40+ threat patterns across 8+ countries.**

[![PyPI](https://img.shields.io/pypi/v/saferelay)](https://pypi.org/project/saferelay/)
[![Docker](https://img.shields.io/docker/v/logicgridai/saferelay?label=docker)](https://hub.docker.com/r/logicgridai/saferelay)

SafeRelay redacts sensitive data in your pipelines before it reaches AI tools, log aggregators, or external services. Everything runs locally — your data never leaves your machine.

```text
BEFORE                                      AFTER (SafeRelay)
─────────────────────────────────────────  ─────────────────────────────────────────
OPENAI_API_KEY=sk-proj-abc...xyz            OPENAI_API_KEY=[OPENAI_KEY_1]
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE       AWS_ACCESS_KEY_ID=[AWS_KEY_1]
Authorization: Bearer eyJhbGciOiJIUzI1...   Authorization: Bearer [BEARER_1]
Server: 10.45.2.115                         Server: [IP_1]
SSN: 234-56-7890                            SSN: [US_SSN_1]
```

## Installation

```bash
pip install saferelay

# With Redis support (distributed vault)
pip install saferelay[redis]
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
      - name: SAFERELAY_LICENSE_KEY
        valueFrom:
          secretKeyRef:
            name: saferelay-secret
            key: license-key
```

## What gets redacted

Free tier covers core patterns (IPv4 addresses, cloud access keys). Pro unlocks all 40+ patterns below.

| Pattern |
|---|
| IPv4 addresses |
| API keys (OpenAI, Anthropic, AWS, GitHub, Slack, Gemini) |
| AWS Secret Access Keys (YAML + bare) |
| Docker / npm tokens, Slack webhooks, Google OAuth |
| Bitcoin / Ethereum addresses |
| PEM private keys |
| .env file values |
| MAC addresses |
| Credit cards (Luhn-validated) |
| US SSN |
| EU IBAN |
| UK NINO |
| Nigeria NIN / BVN |
| Canada SIN |
| India Aadhaar / PAN |
| South Africa ID |
| Australia TFN |
| Brazil CPF |
| Singapore NRIC |
| Germany Tax ID |
| Seed phrases (12/24 word) |
| ETH private keys |
| Custom NDA keywords |

## Browser extensions

| Browser | Link |
|---|---|
| Chrome | [Chrome Web Store](https://chromewebstore.google.com/detail/saferelay-%E2%80%94-local-ai-dlp/odeoilooelkodahbbdokbollgahdcaag) |
| Firefox | [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/saferelay-dlp/) |

## Pricing

| Tier | Price | Features |
|---|---|---|
| Free | \$0 | Core patterns — IPv4, cloud access keys |
| Pro | \$7.99/mo or \$59/yr | 40+ patterns, full vault |
| SafeRelay Suite | \$99 one-time | CLI Pro + Browser Pro + Desktop Agent (waitlist) |

→ Get a license at [saferelay.ai](https://saferelay.ai/#pricing)

## Privacy

Clipboard and log content **never leaves your machine**. License activation sends only a hashed device fingerprint to the license server — no log data, ever.

Full privacy policy: [saferelay.ai/privacy](https://saferelay.ai/privacy)

---

Built by **LogicGrid AI, LLC** — support@logicgrid.ai
