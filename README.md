# MR OSINT Toolkit

A single command-line toolkit for legitimate, passive OSINT tasks — username presence checks, IP/email/phone metadata lookups, scam-website red-flag checks, and candidate profile verification for hiring.

No hosting required. Runs entirely on your own machine.

Built by **Harsh Saini** — [MR Cyber Pulse](https://mrcyberharsh.github.io/mrcyber/)

---

## What's inside

| Command      | What it does                                                          |
|--------------|------------------------------------------------------------------------|
| `username`   | Checks if a username exists across 20 major platforms                  |
| `ip`         | Geolocation, ISP, and ASN info for an IP address                       |
| `email`      | Syntax validation, domain check, disposable-domain flag, MX records    |
| `phone`      | Format validation, country, carrier, and number type                  |
| `scamcheck`  | Checks a website against public scam red flags (WHOIS age, SSL, patterns) |
| `candidate`  | Generates an HTML report verifying a job candidate's self-provided GitHub/portfolio/certificate links |

## Why this exists

Most tools that do pieces of this are either scattered across ten different scripts, technical and ugly (looking at you, bare WHOIS output), or quietly cross ethical lines. This toolkit is built around one rule: **every check reports technical/public metadata only — never who a real person is.** See the "Ethical boundaries" section below; it's not just a disclaimer, it's baked into what the code will and won't do.

## Installation

```bash
git clone https://github.com/<your-username>/mr-osint-toolkit.git
cd mr-osint-toolkit
pip install -r requirements.txt
```

`requests` is required for most commands. `phonenumbers` and `dnspython` are optional — without them, `phone` and `email` fall back to basic checks and tell you what you're missing.

## Usage

```bash
# Check a username across platforms
python mr_osint_toolkit.py username torvalds

# IP geolocation / ISP info
python mr_osint_toolkit.py ip 8.8.8.8

# Email validation + domain/MX check
python mr_osint_toolkit.py email someone@example.com

# Phone number validation + carrier/type
python mr_osint_toolkit.py phone +14155552671

# Website scam red-flag check
python mr_osint_toolkit.py scamcheck suspicious-site.xyz

# Candidate verification report (saves an HTML file)
python mr_osint_toolkit.py candidate \
    --name "Candidate Name" \
    --github their-github-username \
    --portfolio https://theirportfolio.com \
    --cert https://credly.com/badges/xxxx
```

Run `python mr_osint_toolkit.py <command> --help` for options on any subcommand.

## Ethical boundaries — read before using

This toolkit is built for:
- Checking your own digital footprint
- Security research with consent
- Verifying scam/phishing red flags on suspicious sites
- Verifying job-candidate claims **they volunteered themselves** during a hiring process

It is **not** built for, and will not be extended to do:
- Identifying who owns a given username, email, phone number, or IP address
- Facial recognition or photo-based person identification
- Investigating people who haven't consented or applied for something
- Any form of stalking, harassment, or doxxing

If a request would cross these lines, the answer is no — regardless of how the request is framed.

## Requirements

- Python 3.8+
- See [`requirements.txt`](requirements.txt)

## License

All rights reserved — see [`LICENSE`](LICENSE). Free to use and modify for personal and educational purposes; don't redistribute as your own work without credit.

## Contact

- Email: manager.prachi@zohomail.in
- Website: https://mrcyberharsh.github.io/mrcyber/

---

*"Complex ko simple. Simple ko powerful."* — MR Cyber Pulse
