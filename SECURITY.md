# Security Policy

## Scope

Security reports concerning OpenForge components are welcome.

Please do not publicly disclose a serious vulnerability before there is an
opportunity to investigate and address it.

## Important

OpenForge, including SecureChat, is experimental software.

Cryptographic and security-sensitive components should not be considered
production-ready merely because automated tests pass.

## Credentials

Never commit:

- private keys
- API tokens
- passwords
- GitHub credentials
- SSH credentials
- GPG private keys
- model credentials
- production configuration secrets

If a secret is accidentally committed, assume it is compromised and rotate it.
