# AGENTS.md

## Project

<PROJECT_NAME> — <one-line description>.

## Setup

```bash
git clone https://github.com/mrcyberharsh/<REPO>.git
cd <REPO>
python -m venv .venv
source .venv/bin/activate   # or .\.venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
```

## Build / Test

```bash
python -m unittest discover -s tests -v
```

## Code Style

- Python 3.10+ (or 3.11+ for pulse-infragraph)
- PEP 8
- Use existing `logging` patterns, not `print()`
- New config keys go to `config.yaml` with safe defaults

## Safety Rules

- <Project-specific safety rule 1>
- <Project-specific safety rule 2>
- Never add <forbidden feature: e.g., credential guessing / authentication / write operations>

## Key Files

| File | Purpose |
|------|---------|
| `main.py` / `cli.py` | Entry point |
| `core/` / `modules/` | Business logic |
| `tests/` | Unit tests |
| `config.yaml` | Configuration |
