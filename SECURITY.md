# Security Policy

The LLM Red Team Lab is security tooling, so its own security posture matters.

## Reporting a vulnerability

Do **not** open a public issue for a suspected security problem. Report it
privately to the maintainers (check the GitHub repo for a
`SECURITY.md`-linked contact or use the private vulnerability-reporting
workflow). Include:

- Type of issue (injection into our tooling, report XSS, credential leak, …)
- Affected files/commands and version
- Reproduction steps and impact
- Any suggested remediation

You should receive an acknowledgement within 5 business days.

## What we care about

- **Report injection** — findings/responses rendered into HTML are auto-escaped
  (Jinja2 autoescape). If you find a way to break execution context, report it.
- **Secret handling** — reports redact known environment-variable values; a
  bypass in `rtl/utils/secrets.py` is a vulnerability.
- **Prompt-library integrity** — authorized-use boundary must never be
  silently weakened.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | :white_check_mark: active |