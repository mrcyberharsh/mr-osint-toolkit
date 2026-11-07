# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Current `main` branch (development build) | :white_check_mark: |
| Most recent tagged release | :white_check_mark: |
| Older releases | :x: |

> MR OSINT Toolkit is under active development. Only the latest `main` branch and the most recent tagged release receive security fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in **MR OSINT Toolkit itself** (not an OSINT finding on a target), report it privately:

- **Maintainer / Developer:** Harsh Saini — cyber.h4rsh@zohomail.in
- **Manager:** Prachi Sharma — manager.prachi@zohomail.in
- **Organization:** MR Cyber Pulse

Please include:

- Type of issue (e.g., command injection, path traversal, unsafe file write, dependency flaw, telemetry leak, bypass of the candidate-permission gate)
- Full paths of the source file(s) related to the issue
- Step-by-step reproduction instructions
- Impact assessment — does it break local-only processing, the consent gate, or the passive-only design?
- Suggested fix, if available

You can expect an acknowledgement within **7 days**. We will keep you informed of progress and coordinate disclosure timing with you.

## Out of Scope

The following are **not** considered vulnerabilities in MR OSINT Toolkit:

- Inaccurate, incomplete, or stale OSINT results from third-party public services (documented limitation)
- Rate-limiting, blocking, or API changes by upstream providers (GitHub API, IP geolocation, MX lookups, etc.)
- Missing optional dependencies (`phonenumbers`, `dnspython`) on the operator's system
- A username, email, or phone number appearing on a public platform — this is a data-source result, not a security flaw in the tool
- Local export files (`.txt`, HTML, JSON, CSV) being readable by the local user — exports are opt-in and stored locally by design
- Refusal to perform non-consensual, private-individual, or doxxing-related lookups — this is intentional ethical scope enforcement, not a bypass target

## Safe Harbor

We support safe harbor for security researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service interruption
- Only test the tool itself and public services they are permitted to query
- Do not use the tool to target private individuals, attempt unauthorized access, or scrape beyond publicly available data
- Report findings privately and give us reasonable time to fix before disclosure

## Security-Relevant Design Guarantees

MR OSINT Toolkit is built around the following invariants. Reports that break any of these are treated as security issues, not feature requests:

1. **Passive-only** — the toolkit queries public APIs and public web pages only. It must never authenticate against target platforms, bypass access controls, or scrape private data.
2. **Local-only processing** — no telemetry, no remote logging, no upload of scan results. Exports are opt-in and written to the local filesystem only.
3. **Consent gate for candidate reports** — the candidate workflow must require the operator to confirm that links and information were voluntarily supplied by the candidate for that purpose, before any report is generated.
4. **No private-individual targeting** — the tool must not add features for doxxing, tracking private individuals, facial recognition, or collecting private personal information.
5. **Provider-respectful behaviour** — requests must remain within reasonable bounds, respect provider terms, and avoid excessive or abusive request patterns.
6. **No secrets in outputs** — the tool must not write API keys, credentials, or tokens into any export or log file.
