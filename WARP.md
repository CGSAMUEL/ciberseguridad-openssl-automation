# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Repository Overview

This is a cybersecurity practice project (Práctica 2) focused on automated OpenSSL cryptography challenges and privilege escalation techniques. The project contains bash scripts that automate the resolution of various cryptographic challenges on a target system (10.42.2.1).

## Common Commands

### Development and Testing

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Test system prerequisites and connectivity
./scripts/automate_service.sh test

# Test OpenSSL installation and basic functionality
./scripts/crypto_utils.sh test_openssl

# Test privilege escalation verification tools
./scripts/privilege_escalation.sh test
```

### Main Workflow Commands

```bash
# Phase 1: Automated cryptographic challenge resolution
./scripts/automate_service.sh auto

# Phase 2: SSH connection using obtained credentials
./scripts/automate_service.sh ssh

# Phase 3: Privilege escalation automation
./scripts/privilege_escalation.sh auto

# Manual connection for debugging/testing
./scripts/automate_service.sh manual
```

### Utility Commands

```bash
# Quick cryptographic operations
./scripts/crypto_utils.sh base64_decode <base64_text>
./scripts/crypto_utils.sh hash md5 <input_text>
./scripts/crypto_utils.sh symmetric_decrypt aes-192-ecb <hex_key> <base64_encrypted>

# Interactive crypto examples (useful for learning/testing)
./scripts/crypto_utils.sh interactive

# Manual signature verification
./scripts/privilege_escalation.sh manual <file> <signature> <public_key> <hash_algorithm>

# Test all signature combinations
./scripts/privilege_escalation.sh test
```

## Architecture Overview

### Core Components

**`automate_service.sh`** - Main automation engine that connects to target port 54471 and solves cryptographic challenges sequentially:
- Base64 decoding challenges
- Hash calculation (MD5, SHA256, SHA512, etc.)  
- Symmetric cipher decryption (AES, DES variants)
- Asymmetric cipher decryption (RSA)
- Hybrid encryption schemes (RSA + AES)
- Uses `expect` for terminal interaction automation
- Outputs either SSH credentials (if completed quickly) or user flags

**`privilege_escalation.sh`** - Handles privilege escalation through digital signature verification:
- Automatically captures public/private key pairs, files, and signatures from escalation program
- Performs signature verification using OpenSSL
- Tests different key combinations to find correct signature matches
- Outputs root credentials or flags upon successful verification

**`crypto_utils.sh`** - Utility library providing individual cryptographic operations:
- Base64 encoding/decoding functions
- Hash calculation utilities
- Symmetric encryption/decryption helpers
- Key generation and signature verification tools
- Interactive examples for testing and learning

### Data Flow Architecture

1. **Connection Phase**: Scripts connect to target service on 10.42.2.1:54471
2. **Challenge Resolution**: Expect-based automation parses challenge formats and applies appropriate cryptographic operations
3. **Credential Extraction**: Successful completion yields SSH credentials or user flags
4. **Privilege Escalation**: Secondary program verifies digital signatures to obtain root access
5. **Output Management**: Results stored in temporary files (ssh_credentials.txt, user_flag.txt, root_flag.txt)

### Directory Structure

```
├── scripts/              # Main automation scripts
├── temp/                 # Temporary files and logs (created at runtime)
├── keys/                 # Cryptographic keys (created at runtime)  
└── README.md            # Detailed project documentation
```

### Expected Challenge Patterns

The automation handles these cryptographic challenge types:
- **Encoding**: Base64 decode operations
- **Hashing**: MD5, SHA1, SHA256, SHA512 calculations
- **Symmetric**: AES/DES variants with ECB/CBC modes  
- **Asymmetric**: RSA encryption/decryption
- **Hybrid**: RSA-encrypted symmetric keys + AES-encrypted data
- **Digital Signatures**: RSA signature verification with various hash algorithms

## Prerequisites

Required tools (auto-installed on target systems):
- `netcat-traditional` - Network connectivity testing and raw socket communication
- `openssl` - All cryptographic operations
- `expect` - Terminal automation and interaction scripting
- `sshpass` - Automated SSH authentication
- `xxd` - Hexadecimal conversion utilities

## Configuration

### Network Configuration
- Target host: `10.42.2.1`
- Service port: `54471` 
- SSH port: `22`
- Timeout: 30 seconds for challenge completion

### Runtime Directories
Scripts automatically create required directories:
- `temp/` - Session logs and temporary processing files
- `keys/` - Cryptographic key storage during script execution

## Common Issues and Debugging

### Connectivity Problems
```bash
# Test network connectivity
nc -z 10.42.2.1 54471
nc -z 10.42.2.1 22

# Verify tools are available
which nc openssl expect sshpass
```

### Cryptographic Errors
- Scripts include comprehensive error handling for malformed inputs
- Check `temp/session.log` for detailed execution traces
- Use manual mode first to understand challenge patterns
- Verify OpenSSL algorithms with `openssl enc -list`

### Privilege Escalation Issues  
- Ensure signature files are properly base64 decoded
- Check hash algorithm matches (usually sha512)
- Verify key format compatibility (PEM format expected)
- Review `temp/verification_results.txt` for detailed verification outcomes

## Output Files

- `ssh_credentials.txt` - SSH access credentials (if challenges completed in time)
- `user_flag.txt` - User-level flag (if timeout occurs)  
- `root_credentials.txt` - Root access credentials (from privilege escalation)
- `root_flag.txt` - Root-level flag (final objective)
- `temp/session.log` - Detailed execution log
- `temp/escalation.log` - Privilege escalation process log
- `temp/verification_results.txt` - Signature verification results

## Testing and Development

For script development and testing:
```bash
# Test individual crypto operations
./scripts/crypto_utils.sh help

# Generate test keys
./scripts/crypto_utils.sh generate_keys

# Manual signature verification  
./scripts/crypto_utils.sh verify_sig <file> <signature> <public_key> <hash_algorithm>

# Interactive testing mode
./scripts/crypto_utils.sh interactive
```

Scripts include comprehensive logging and error handling. All temporary files are automatically cleaned up after execution to maintain security.