# Support

Thanks for using **MR OSINT Toolkit**! Here's how to get help.

## Documentation

Start with:

- [README.md](README.md) — installation, CLI usage, GUI workflow, ethical boundaries, limitations, and exports
- [GUI.md](GUI.md) — desktop GUI-specific guidance *(if present)*
- [SECURITY.md](SECURITY.md) — responsible-disclosure policy for vulnerabilities in the tool itself
- `CONTRIBUTING.md` — contribution workflow *(if present in the repository)*

## Questions and Discussions

For usage questions, ideas, and general discussion, please use [GitHub Discussions](https://github.com/mrcyberharsh/mr-osint-toolkit/discussions) (if enabled) or open a GitHub issue using the appropriate template.

## Bug Reports

Open an issue using the **Bug report** template and include:

- OS and Python version (3.8+ required)
- MR OSINT Toolkit version/commit
- The command used (`username`, `ip`, `email`, `phone`, `scamcheck`, `candidate`, `health`) or the GUI tab
- Expected behavior vs actual behavior
- Sanitized error output or logs
- Whether optional dependencies (`phonenumbers`, `dnspython`, `tkinter`) are installed
- Whether the issue involves the CLI or the desktop GUI

Please sanitize everything before posting — remove real usernames, emails, phone numbers, IP addresses, candidate profiles, and exported file contents. Never include passwords, API keys, or private personal data.

## Feature Requests

Open an issue using the **Feature request** template and describe:

- The passive, consent-based OSINT use case
- Why existing checks are insufficient
- Whether the feature stays passive-only and local-only
- Safety and ethical implications (does it involve private individuals, authentication, or private data?)
- Proposed test plan

> Requests for doxxing, tracking private individuals, facial recognition, authentication bypass, private-data scraping, or telemetry will be closed.

## Security Issues

Do **not** open a public issue for vulnerabilities in MR OSINT Toolkit itself. Report privately:

- **Maintainer / Developer:** Harsh Saini — cyber.h4rsh@zohomail.in
- **Manager:** Prachi Sharma — manager.prachi@zohomail.in

See [SECURITY.md](SECURITY.md) for the full responsible-disclosure policy, supported versions, out-of-scope items, and the tool's passive-only / local-only / consent-gate design guarantees.

## Third-Party Provider Issues

MR OSINT Toolkit relies on public services and APIs. If a check returns incomplete or stale data:

- Confirm the provider is reachable via the `health` command
- Check whether the provider has changed its API or terms
- Re-run after a short wait — providers may rate-limit
- Do **not** file a security issue for provider-side inaccuracies or rate limits; these are documented limitations

## Project and Collaboration Queries

For partnership, collaboration, or organizational queries:

- **Manager:** Prachi Sharma — manager.prachi@zohomail.in
- **Organization:** MR Cyber Pulse
- **GitHub:** [https://github.com/mrcyberharsh](https://github.com/mrcyberharsh)

## Response Expectations

This is a community-maintained project. Response times vary, but security reports and privacy-impacting bugs are prioritized. Please be patient and avoid pinging maintainers on multiple channels for the same issue.
