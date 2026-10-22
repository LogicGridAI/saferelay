# SafeRelay CLI

**Local DLP for AI-era workflows — 8 shields, 69 pattern types incl. Gov/CUI + exfiltration.**

[![PyPI](https://img.shields.io/pypi/v/saferelay)](https://pypi.org/project/saferelay/)
[![Docker](https://img.shields.io/docker/v/logicgridai/saferelay?label=docker)](https://hub.docker.com/r/logicgridai/saferelay)

SafeRelay redacts sensitive data in your pipelines before it reaches AI tools, log aggregators, or external services. Redaction runs locally — your content is never sent to SafeRelay servers. Same engine as SafeRelay Browser Relay and Desktop.

```text
BEFORE                                      AFTER (SafeRelay)
─────────────────────────────────────────  ─────────────────────────────────────────
OPENAI_API_KEY=sk-proj-abc...xyz            OPENAI_API_KEY=[OPENAI_KEY_1]
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE       AWS_ACCESS_KEY_ID=[AWS_KEY_1]
Authorization: Bearer eyJhbGciOiJIUzI1...   Authorization: Bearer [BEARER_1]
Server: 10.45.2.115                         Server: [IP_1]
SSN: 234-56-7890                            SSN: [US_SSN_1]
CONTRACT: W912DR-24-C-0001                  CONTRACT: [DOD_CONTRACT_1]
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

# Pro tier — full engine
docker logs my-app | saferelay --pro --mask > clean.log
cat ai_response.txt | saferelay --unmask

# Toggle individual shields off
cat data.txt | saferelay --pro --no-gov-cui --no-exfil

# Activate Pro
saferelay --unlock "YOUR-LICENSE-KEY"

# Status — shows active shields
saferelay --status --pro
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

## Exfiltration Shield (bulk-export protection)

Beyond per-value redaction, SafeRelay blocks **bulk exports** — a sign of a dataset dump
rather than a snippet. Thresholds: **≥3 SSNs, ≥5 Luhn-valid credit cards, or ≥20 email
addresses** in one input. When tripped, the CLI exits with a hard block (exit code 2) and
relays nothing. Disable with `--no-exfil`.

## What gets redacted (8 shields, 69 types)

Free tier covers core developer secrets (devsec). Pro unlocks all 8 shields. National-ID
patterns are checksum-validated (Luhn, mod-97 IBAN, Verhoeff Aadhaar, CPF, TFN, UK VAT)
to minimize false positives.

| Shield | Covers | Free | Pro |
|---|---|---|---|
| **DevSec** | IPv4, API keys (OpenAI/Anthropic/AWS/GitHub/Slack/Google/Stripe/Docker/npm/Twilio/SendGrid/Gemini), bearer tokens, connection strings, .env values, crypto (BTC/ETH/SOL/WIF/seed phrases), PEM keys, MAC addresses | ✓ | ✓ |
| **FinTech & PII** | Credit cards (Luhn), US SSN, email, EU IBAN, UK NINO, Nigeria NIN/BVN/bank/phone, Canada SIN, India Aadhaar/PAN, South Africa ID, Australia TFN, Brazil CPF, Singapore NRIC, Germany Tax ID, US Green Card | — | ✓ |
| **Corporate** | EIN, DUNS, EU VAT, GB VAT | — | ✓ |
| **Mission / Civic** | GPS coordinates, UNHCR IDs, donor/beneficiary case IDs | — | ✓ |
| **Gov / CUI** | CUI markings & banners, DoD contract numbers (PIID), CAGE codes, SAM.gov UEI, DoD ID/EDIPI, FOUO/NOFORN/REL TO/DIST statements, ITAR/EAR99/ECCN export controls, .gov/.mil emails, FedRAMP IDs | — | ✓ |
| **Exfiltration** | Bulk-export threshold block (≥3 SSN / ≥5 CC / ≥20 email) | — | ✓ |
| **Custom Terms** | Your own codenames, hostnames, project IDs (`--add-term`) | — | ✓ |

## Browser extension & apps

| Surface | Link |
|---|---|
| Chrome | [Chrome Web Store](https://chromewebstore.google.com/detail/saferelay-%E2%80%94-local-ai-dlp/emoeabddnlcaodeelgdfdfpjlcldjhng) |
| Firefox | Pending Mozilla review |
| Desktop (Windows) | [saferelay.ai](https://saferelay.ai) |

## Pricing

Browser extension is free (Chrome; Firefox pending). Desktop app is free to download; Pro unlocks the heavier shields. See [saferelay.ai](https://saferelay.ai/#pricing) for current plans.

| Plan | Price |
|---|---|
| Free | \$0 — browser & desktop |
| Browser Relay Pro | \$6.99/mo or \$69/yr |
| Desktop Pro | \$9.99/mo or \$99/yr |
| SafeRelay Suite (both) | \$12.99/mo or \$129/yr |
| Founder Lifetime (Browser + Desktop) | \$99 one-time — first 100 founders |

## Privacy

Redaction runs locally — your clipboard and log content is never sent to SafeRelay servers.
License activation sends only a license key and an anonymous install ID to the license
server — no log or clipboard data, ever. Pro license verification is fully offline (Ed25519),
so it works air-gapped.

Full privacy policy: [saferelay.ai/privacy](https://saferelay.ai/privacy)

---

Built by **LogicGrid AI, LLC** — support@logicgrid.ai
