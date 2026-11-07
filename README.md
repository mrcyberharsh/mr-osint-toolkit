# MR OSINT Toolkit

A local toolkit for passive, consent-based OSINT checks. It brings common public-data and technical-metadata checks together in one Python interface, and now also includes a cross-platform desktop GUI for Windows, macOS, and Linux.

Built by Harsh Saini · MR Cyber Pulse.

## What it includes

### Command-line tools

| Command | Purpose |
|---|---|
| `username` | Checks public account presence across supported platforms |
| `ip` | Displays technical IP metadata such as geolocation, ISP, and ASN |
| `email` | Checks syntax, domain information, disposable-domain status, and MX records |
| `phone` | Validates number format and displays available numbering metadata |
| `scamcheck` | Reviews public website signals that may indicate risk |
| `candidate` | Creates a report from public profile and certificate links voluntarily supplied by a candidate |
| `health` | Checks optional dependencies and public provider connectivity |

### Desktop GUI

The project now includes a native desktop app powered by Python's built-in Tkinter. It runs the same toolkit checks locally without needing a server or an external backend.

Features:
- Cross-platform desktop interface for Windows, macOS, and Linux
- Tabs for username, IP, email, phone, scamcheck, candidate report, and health checks
- Background execution so the interface stays responsive
- Save output for each check as a local `.txt` file
- Candidate-report permission check before verifying links

Results depend on third-party public services and may be incomplete or inaccurate. They are not identity verification or proof of wrongdoing.

## Requirements

- Python 3.8+
- `requests` for most commands
- Optional: `phonenumbers` and `dnspython` for enhanced phone and email checks
- Tkinter for the desktop GUI (usually included with Python installers; on some Linux systems it may require a separate package like `python3-tk`)

See [requirements.txt](requirements.txt) for the project dependency list.

## Installation

```bash
git clone https://github.com/mrcyberharsh/mr-osint-toolkit.git
cd mr-osint-toolkit
python -m pip install -r requirements.txt
```

Run the CLI help screen:

```bash
python mr_osint_toolkit.py --help
```

Run the desktop GUI:

```bash
python gui.py
```

## Usage examples

CLI examples:

```bash
# Health and dependency check
python mr_osint_toolkit.py health

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

GUI usage:

```bash
python gui.py
```

Open the desktop app and use the tabs for each check. After a command finishes, use the "Save output..." button to export the output to a local text file.

## New feature: GUI + output export

The toolkit now includes a desktop interface and a built-in output export action.

### GUI
- Works on Windows, macOS, and Linux
- Runs existing CLI checks locally
- Provides a simple tab-based workflow
- Keeps the project usable without a web service

### Save output
- After a check completes, select "Save output..."
- The GUI saves the visible command output to a local `.txt` file
- Export is opt-in and does not upload content anywhere

## Exports and provider health

The candidate command always creates a local HTML report. JSON and CSV exports are opt-in through `--json-output` and `--csv-output`; they contain only the candidate name and public profile/link metadata.

The `health` command checks optional Python dependencies and whether the public GitHub API is reachable. It does not scan targets.

The GUI also supports saving each check's output locally for later review.

## Ethical boundaries

This project is intended for:
- Reviewing your own public digital footprint
- Authorized security research and education
- Checking technical/public signals from websites
- Reviewing professional links voluntarily supplied by a candidate

This project is not for identifying or tracking private individuals, doxxing, harassment, facial recognition, or collecting private personal information. A username, email address, phone number, or domain is not proof of identity or wrongdoing.

Use public services responsibly, follow their terms, and avoid excessive requests.

## Limitations

- Third-party APIs and websites can change, rate-limit, or block requests.
- Geolocation and reputation data are approximate and can be stale.
- A positive or negative signal is not a definitive security verdict.
- Optional dependencies may be required for some enriched checks.
- GUI checks still rely on the same public services the CLI uses; they cannot guarantee correctness or availability.

## Contributing

Bug reports and focused pull requests are welcome. Include the command used, expected result, actual result, and sanitized error output. Never include passwords, API keys, or private personal data in reports or issue descriptions.

## License

See [LICENSE](LICENSE) for the project's usage and redistribution terms. Please retain attribution when sharing or modifying the project.

## Contact

- GitHub: https://github.com/mrcyberharsh
- Website: https://mrcyberharsh.github.io/mrcyber/

*Complex ko simple. Simple ko powerful.* — MR Cyber Pulse
