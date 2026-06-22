# Contributing

Thanks for helping improve S4W.

## Ground Rules

- Keep the project passive and consent-first.
- Do not add brute force, exploit delivery, bypass, stealth or destructive behavior.
- Prefer clear remediation guidance over offensive payload examples.
- Keep output useful for defenders, auditors and application owners.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Run a quick syntax check:

```bash
python -m compileall s4w
```

Run the CLI:

```bash
s4w -help
```

## Pull Requests

Please include:

- a short explanation of the change;
- the security/defensive use case;
- manual test notes;
- screenshots or sample output when the terminal UI changes.
