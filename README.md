# SCAMCHECK example backend

A rule-based (no AI, no external services) implementation of the extension's
`/v1/check` and `/v1/health` contract, meant only for testing the extension
end-to-end while you build the real backend. See
`../scamcheck-extension/README.md` for the full API contract.

## Run it

```bash
npm install
npm start
```

Then in the extension's settings (gear icon in the popup), set:

- **API base URL**: `http://localhost:8787`
- **API key**: leave blank (this example doesn't check one)

## What it actually detects

- **Text**: a small set of regex rules for urgency, threats, prize lures,
  credential/payment requests, brand impersonation phrases, job/romance/
  investment scam patterns.
- **URLs**: non-HTTPS, suspicious TLDs, long subdomain chains, lookalike
  domains for a short list of well-known brands, raw IP hosts, and
  homograph-style non-Latin characters in the hostname.
- **Full-check page context**: flags pages whose forms include a password
  or payment field.

This is intentionally simple — good enough to see every part of the
extension light up (badge colors, warning signs, evidence, recommended
actions), not a substitute for the AI + reputation-database + threat-intel
layers described in the full product spec.
