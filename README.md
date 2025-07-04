# Vaultfile

A secure shared secret manager written in Go that enables multiple users to securely share secrets using asymmetric cryptography, without requiring a server.

[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

Vaultfile solves the common problem of securely sharing secrets (API keys, passwords, credentials) among team members. Unlike tools that require a server or use simple symmetric encryption, vaultfile uses a hybrid cryptographic approach:

- **RSA-2048** for asymmetric encryption of AES keys
- **AES-256-GCM** for symmetric encryption of actual secrets
- **Individual access control** through public key cryptography
- **File-based storage** that can be safely committed to version control

## Key Features

- 🔐 **Strong cryptography**: RSA-2048 with OAEP padding, AES-256-GCM
- 👥 **Multi-user support**: Each user has their own key pair for access control
- 📁 **File-based**: No server required, vault files can be versioned with your code
- 🔑 **Key revocation**: Remove user access by deregistering keys and rotating secrets
- 🛡️ **Memory safe**: Written in Go with no unsafe code
- ✅ **Well tested**: Comprehensive test suite for all cryptographic operations

## Installation

### From Source

```bash
git clone https://github.com/jemmic/vaultfile-go.git
cd vaultfile-go
go build -o vaultfile ./cmd/vaultfile
```

### Using Go Install

```bash
go install jemmic.com/vaultfile-go/cmd/vaultfile@latest
```

## Quick Start

### 1. Generate Your Key Pair

First, generate your RSA key pair:

```bash
vaultfile generate-key
```

This creates:
- `~/.config/vaultfile/$USER.key` (private key - keep this secure!)
- `~/.config/vaultfile/$USER.key.pub` (public key)

### 2. Create a Vaultfile and Register Your Key

```bash
vaultfile new
```

This creates a `Vaultfile` in the current directory and registers your public key.

### 3. Add a Secret

```bash
vaultfile add-secret --name api_key --value "your-secret-api-key"
```

### 4. Read a Secret

```bash
vaultfile read-secret --name api_key
```

### 5. Share with Team Members

To give a team member access:

1. They generate their key pair: `vaultfile generate-key`
2. They share their public key file with you
3. You register their key: `vaultfile register-key --key-name alice --key-file alice.key.pub`
4. Both of you can now access all secrets in the vault

## Usage

### Key Management

```bash
# Generate a new key pair
vaultfile generate-key

# Create new vaultfile with your key
vaultfile new

# Register another user's key
vaultfile register-key --key-name alice --key-file alice.key.pub

# List all registered keys
vaultfile list-keys

# Show a specific public key (for sharing)
vaultfile show-key --key-name alice

# Remove a user's access (revoke key)
vaultfile deregister-key --key-name alice
```

### Secret Management

```bash
# Add a text secret
vaultfile add-secret --name database_url --value "postgres://user:pass@host/db"

# Add a binary secret (base64 encoded)
vaultfile add-secret --name ssl_cert --base64-value "$(base64 < cert.pem)"

# List all secrets
vaultfile list-secrets

# Read a secret
vaultfile read-secret --name database_url

# Read a secret without trailing newline (useful for scripts)
vaultfile read-secret --name api_key --no-eol

# Delete a secret
vaultfile delete-secret --name old_api_key
```

### Working with Different Vaultfiles

By default, commands operate on a file named `Vaultfile` in the current directory. You can specify a different file:

```bash
vaultfile add-secret --file production.vault --name api_key --value "prod-key"
vaultfile read-secret --file production.vault --name api_key
```

## Security Model

### Cryptographic Details

1. **Key Generation**: RSA-2048 keys generated using `crypto/rand` for cryptographically secure randomness
2. **Secret Encryption**: Each secret is encrypted with a random AES-256 key using GCM mode
3. **Key Encryption**: The AES key is encrypted with each user's RSA public key using OAEP padding with SHA-256
4. **No Key Reuse**: Each secret gets its own random AES key

### Security Guarantees

- **Confidentiality**: Secrets are protected by strong encryption
- **Access Control**: Only users with registered private keys can decrypt secrets
- **Forward Secrecy**: Removing a key and rotating secrets ensures past access doesn't compromise future secrets
- **Integrity**: AES-GCM provides authenticated encryption preventing tampering

### Security Best Practices

1. **Protect Private Keys**: Store private keys with restrictive permissions (`chmod 600` or `chmod 400`)
2. **Rotate Secrets**: When removing user access, change the secret values (key revocation alone isn't sufficient)
3. **Audit Access**: Regularly review registered keys with `vaultfile list-keys`
4. **Backup Keys**: Securely backup your private key - losing it means losing access to secrets

## File Locations

- **Private keys**: `~/.config/vaultfile/$USER.key`
- **Public keys**: `~/.config/vaultfile/$USER.key.pub`
- **Vaultfiles**: `./Vaultfile` (or specified with `--file`)

On Windows, `~` refers to `%USERPROFILE%` and `$USER` refers to `%USERNAME%`.

## Vaultfile Format

Vaultfiles are JSON documents that can be safely committed to version control:

```json
{
  "keys": {
    "alice": {"N": "...", "E": 65537},
    "bob": {"N": "...", "E": 65537}
  },
  "secrets": {
    "api_key": {
      "secret": "base64-encrypted-data...",
      "encrypted_key": {
        "alice": "base64-rsa-encrypted-aes-key...",
        "bob": "base64-rsa-encrypted-aes-key..."
      }
    }
  }
}
```

## CLI Reference

### Global Flags

- `--file`, `-f`: Specify vaultfile path (default: `Vaultfile`)

### Commands

| Command | Description |
|---------|-------------|
| `generate-key` | Generate a new RSA key pair |
| `register-key` (alias: `new`) | Register a public key in a vaultfile |
| `list-keys` | List all registered keys |
| `show-key` | Display a public key as JSON |
| `deregister-key` | Remove a key from the vaultfile |
| `add-secret` | Add an encrypted secret |
| `read-secret` | Decrypt and read a secret |
| `list-secrets` | List all secret names |
| `delete-secret` | Remove a secret |

Use `vaultfile [command] --help` for detailed usage of each command.

## Development

### Building from Source

```bash
git clone https://github.com/jemmic/vaultfile-go.git
cd vaultfile-go
go build ./cmd/vaultfile
```

### Running Tests

```bash
go test ./...
```

### Code Quality

```bash
go vet ./...
gofmt -s -w .
```

## Migration from Rust Version

This Go implementation is a faithful port of the original Rust vaultfile tool. Vaultfiles created with either version are fully compatible.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `go test ./...`
2. Code is formatted: `gofmt -s -w .`
3. No issues from vet: `go vet ./...`
4. Security-sensitive changes are carefully reviewed

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/jemmic/vaultfile-go).