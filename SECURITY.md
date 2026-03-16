# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**j.d.a.jewell@open.ac.uk**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Policy

We follow the principle of [Coordinated Vulnerability Disclosure](https://vuls.cert.org/confluence/display/CVD/Executive+Summary).

## Security Measures

panic-attacker implements several security measures:

1. **No unsafe code** in the core library (only in specific performance-critical sections with documented justification)
2. **Dependency auditing** via cargo-audit in CI
3. **OpenSSF Scorecard** for supply chain security
4. **CodeQL analysis** for vulnerability detection
5. **Secret scanning** with TruffleHog
6. **SBOM generation** for dependency transparency

## Self-Testing

panic-attacker is tested against itself ("eating our own dogfood") to verify its own robustness and identify potential security issues in its implementation.

## Security Advisories

Security advisories will be published via:
- GitHub Security Advisories
- The CHANGELOG.md file
- Release notes for security-related releases

## Attribution

We appreciate responsible disclosure and will acknowledge security researchers in our release notes and CHANGELOG (unless you prefer to remain anonymous).

## Learn More

For more information about security in the hyperpolymath ecosystem:
- RSR Security Standards: https://github.com/hyperpolymath/rsr-template-repo
- Hypatia Security Analysis: https://github.com/hyperpolymath/hypatia
