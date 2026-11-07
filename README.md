# MR OSINT Toolkit

A local command-line toolkit for **passive, consent-based OSINT checks**. It brings common public-data and technical-metadata checks together in one Python interface.

Built by **Harsh Saini · MR Cyber Pulse**.

## What it includes

| Command | Purpose |
|---|---|
| `username` | Checks public account presence across supported platforms |
| `ip` | Displays technical IP metadata such as geolocation, ISP, and ASN |
| `email` | Checks syntax, domain information, disposable-domain status, and MX records |
| `phone` | Validates number format and displays available numbering metadata |
| `scamcheck` | Reviews public website signals that may indicate risk |
| `candidate` | Creates a report from public profile and certificate links voluntarily supplied by a candidate |
| `health` | Checks optional dependencies and public provider connectivity |

Results depend on third-party public services and may be incomplete or inaccurate. They are not identity verification or proof of wrongdoing.

## Requirements

- Python 3.8+
- `requests` for most commands
- Optional: `phonenumbers` and `dnspython` for enhanced phone and email checks

See [requirements.txt](requirements.txt) for the project dependency list.

## Installation

```bash
git clone https://github.com/mrcyberharsh/mr-osint-toolkit.git
cd mr-osint-toolkit
python -m pip install -r requirements.txt
```

Run the toolkit's help screen:

```bash
python mr_osint_toolkit.py --help
```

## Usage examples

Check optional dependencies and the public GitHub API connection:

```bash
python mr_osint_toolkit.py health
```

```bash
# Public username presence
python mr_osint_toolkit.py username torvalds

# Technical IP metadata
python mr_osint_toolkit.py ip 8.8.8.8

# Email syntax and domain checks
python mr_osint_toolkit.py email someone@example.com

# Phone-number format and numbering metadata
python mr_osint_toolkit.py phone +14155552671

# Public website risk signals
python mr_osint_toolkit.py scamcheck example.org
```

For candidate reports, use only links and information the person has voluntarily provided for that purpose:

```bash
python mr_osint_toolkit.py candidate --help

# Optional JSON and CSV exports
python mr_osint_toolkit.py candidate --name "Example" --github example --json-output candidate.json --csv-output candidate.csv
```

Run `python mr_osint_toolkit.py <command> --help` to see the options supported by your installed version.

## Exports and provider health

The candidate command always creates a local HTML report. JSON and CSV exports are opt-in through `--json-output` and `--csv-output`; they contain only the candidate name and public profile/link metadata supplied for that report. The toolkit does not maintain background history.

The `health` command checks optional Python dependencies and whether the public GitHub API is reachable. It does not scan targets.

## Ethical boundaries

This project is intended for:
- Reviewing your own public digital footprint
- Authorized security research and education
- Checking technical/public signals from websites
- Reviewing professional links voluntarily supplied by a candidate

This project is **not** for identifying or tracking private individuals, doxxing, harassment, facial recognition, or collecting private personal information. A username, email address, phone number, or IP address must not be treated as proof of a person's identity or location.

Use public services responsibly, follow their terms, and avoid excessive requests.

## Limitations

- Third-party APIs and websites can change, rate-limit, or block requests.
- Geolocation and reputation data are approximate and can be stale.
- A positive or negative signal is not a definitive security verdict.
- Optional dependencies may be required for some enriched checks.

## Contributing

Bug reports and focused pull requests are welcome. Include the command used, expected result, actual result, and sanitized error output. Never include passwords, API keys, or private personal data.

## License

See [LICENSE](LICENSE) for the project's usage and redistribution terms. Please retain attribution when sharing or modifying the project.

## Contact

- GitHub: https://github.com/mrcyberharsh
- Website: https://mrcyberharsh.github.io/mrcyber/

*Complex ko simple. Simple ko powerful.* — MR Cyber Pulse
