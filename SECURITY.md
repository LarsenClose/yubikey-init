# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model

yubikey-init is designed with security as a core principle:

### What Is Protected

- **Passphrases**: Never stored, always prompted fresh
- **PINs**: Never stored, passed directly to GPG/ykman
- **Private Keys**: Never leave the user's control or their YubiKey
- **Backup Files**: Created by user in location of their choice

### Secure By Design

- **No Shell Injection**: Uses subprocess with argument lists, not shell strings
- **Minimal Dependencies**: Only `pexpect` and `rich` as runtime dependencies
- **Type Safety**: Strict mypy checking catches potential issues
- **Explicit Confirmation**: Destructive operations require explicit user consent
- **SecureString Wrapper**: Masks sensitive data in logs and error messages

### What Users Control

- Passphrase strength and storage
- PIN selection and complexity
- Backup storage location and encryption
- Whether to remove master key from local storage

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. **Email** the maintainer directly at [security contact to be added]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: ASAP (target 24-48 hours)
  - High: Within 1 week
  - Medium: Within 2 weeks
  - Low: Next release

### Disclosure Policy

- We follow responsible disclosure practices
- Security fixes are released as soon as possible
- CVE IDs will be requested for significant vulnerabilities
- Credit will be given to reporters (unless anonymity is requested)

## Security Considerations for Users

### Best Practices

1. **Verify Downloads**: Check signatures when available
2. **Secure Backups**: Store encrypted backups in a secure, offline location
3. **Strong Passphrases**: Use strong, unique passphrases for GPG keys
4. **PIN Security**: Use PINs that are not easily guessable
5. **Physical Security**: Keep YubiKeys physically secure
6. **Regular Updates**: Keep yubikey-init, GPG, and ykman updated

### Known Limitations

- **Python Memory**: Python doesn't guarantee secure memory wiping
- **Terminal History**: Commands may appear in terminal history
- **Process Memory**: Passphrases exist in process memory briefly
- **Logging**: Debug output may contain sensitive paths

### Threat Model

yubikey-init assumes:

- The local machine is trusted during key generation
- The user can securely enter passphrases
- GPG and ykman binaries are authentic and uncompromised
- The YubiKey hardware is genuine (attestation can verify this)

yubikey-init does NOT protect against:

- Compromised local machine
- Physical access to the machine during operation
- Shoulder surfing during passphrase entry
- Compromised dependencies (GPG, ykman)
