# SafeRelay.ai

**Local-first DLP for AI workflows, developer logs, tickets, and enterprise apps.**

SafeRelay redacts secrets, PII, API keys, tokens, and internal IPs before they reach ChatGPT, Claude, Gemini, Copilot, or browser-based enterprise tools. Server names, client names, and proprietary company terms are protected by adding them to your Custom Protected Terms list.

It works locally first: sensitive paste content is detected and replaced with labeled placeholders before it leaves your workflow. Detection and redaction run entirely in your browser — no clipboard content, pasted text, or detected values are ever sent to external servers.

```text
BEFORE                                  AFTER
──────────────────────────────          ──────────────────────────────
OPENAI_API_KEY=sk-proj-abc...xyz        OPENAI_API_KEY=[OPENAI_KEY_1]
AWS_ACCESS_KEY_ID=AKIA1234ABCD          AWS_ACCESS_KEY_ID=[AWS_KEY_1]
Authorization: Bearer eyJhb...          Authorization: Bearer [BEARER_TOKEN_1]
Contact: jane.doe@acme.com              Contact: [EMAIL_1]
Server: prod-db-01 / 10.50.22.18        Server: [ORG_SERVER_1] / [INTERNAL_IP_1]
Customer: Acme Health Partners          Customer: [CLIENT_NAME_1]
```

## How it works

SafeRelay intercepts paste events in the browser. Before the text reaches the page, 35+ built-in threat patterns scan for sensitive data and replace it with labeled placeholders. Internal IPs and structured secrets (API keys, tokens, credentials) are detected automatically; org-specific values like server names, client names, and project codenames are caught once you add them as Custom Protected Terms.

## Core features

- **Zero-trust local processing** — all pattern matching and redaction happens 100% in your browser.
- **35+ threat patterns** across 8+ countries — cloud keys, bearer tokens, credentials, financial identifiers, and PII.
- **Custom Protected Terms** — add your own server names, client names, internal IPs, or proprietary terms to the shield list.
- **RAM-only vault** — redacted values are held in temporary memory for local un-redaction if needed, and destroyed when the tab closes.
- **Exfiltration shield** — get warned before pasting large blocks of operational data.
- **Privacy first** — the only outbound request is a hashed license-validation ping. No clipboard content, browsing history, or detected values leave your machine.

## Fair use

SafeRelay is a supplementary DLP layer, not a guarantee against all data exposure. Pattern-based detection may not catch non-standard formats. Fair-use limits apply.