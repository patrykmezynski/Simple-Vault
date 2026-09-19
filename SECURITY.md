# Security Policy

## Supported Versions

Security updates are provided for the latest released version of Simple-Vault.

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older versions | ❌ |

Development builds and unreleased code from the `main` branch are not considered stable releases.

## Reporting a Vulnerability

If you discover a security vulnerability in Simple-Vault, please **do not open a public issue or discussion**.

Instead, report it privately using GitHub's **Private Vulnerability Reporting** / Security Advisory feature.

When reporting a vulnerability, please include:

- A description of the vulnerability
- Steps required to reproduce it
- The affected Simple-Vault version
- Your operating system and environment
- The potential security impact
- Any proof-of-concept code, logs, or additional information that may help investigate the issue

Please do **not** include real passwords, encryption keys, recovery data, vault contents, or other sensitive information.

## Response

Security reports will be reviewed as soon as reasonably possible.

If the vulnerability is confirmed, a fix will be prepared and released before technical details are publicly disclosed whenever possible.

## Scope

Security issues may include, but are not limited to:

- Encryption or cryptographic implementation flaws
- Authentication bypasses
- Unauthorized vault access
- Sensitive data exposure
- Password or key leakage
- Unsafe import or export handling
- Path traversal or arbitrary file access
- Integrity verification bypasses
- Dependency vulnerabilities affecting Simple-Vault
