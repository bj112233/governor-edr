# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send details to the repository owner via GitHub's private
   vulnerability reporting feature (Security tab → "Report a vulnerability").
   If unavailable, open a private security advisory.

2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce (proof of concept)
   - Affected files/components
   - Potential impact
   - Suggested fix (if any)

3. **Response time**: This is a personal research project with no SLA.
   Reports will be reviewed on a best-effort basis.

### Scope

| In scope | Out of scope |
|----------|-------------|
| Code in this repository | Vulnerabilities in dependencies (report upstream) |
| Security logic (HITL, auth, rate limiting) | The LLM model itself (Qwen — report to upstream) |
| Config handling (secret leakage) | KoboldCpp runtime (report upstream) |
| YARA rules, detection logic | Telegram bot API (report to Telegram) |

### What to Expect

- Acknowledgment within 7 days (best effort).
- Public disclosure after a fix is released, or after 90 days if no fix
  is forthcoming (coordinated disclosure).
- Credit in the fix commit unless you request anonymity.

## Security Architecture Notes

- **HITL (Human-in-the-Loop)**: All critical OS remediation actions
  (firewall changes, process kill, shell execution) require explicit
  Telegram approval from the admin chat_id.
- **Zero-Trust Temp File Bridge**: Skill outputs are sandboxed before
  injection into the agent context.
- **Secret Scan Gate**: gitleaks runs as a pre-commit hook and CI gate.
  Personal PII rules (MACs, chat_id) run locally via
  `.gitleaks-local.toml` (gitignored).
- **No hardcoded secrets**: All API keys load from environment variables.
  Example config files contain only placeholders.

## Disclaimer

This project is a research/portfolio artifact, not a supported security
product. The security measures above are engineering demonstrations, not
production-grade controls. See [README.md](README.md#what-this-is-not).
