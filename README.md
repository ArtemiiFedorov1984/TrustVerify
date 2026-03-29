# TrustVerify - CLI Tool for File Integrity

This project is a Python-based CLI tool designed to ensure file integrity and authenticity using SHA-256 hashing and RSA digital signatures.

## Features
- **Hashing**: SHA-256 for file integrity.
- **Manifest**: metadata.json tracking.
- **Signing**: RSA-based digital signatures for authenticity.
- **Verification**: Detection of data tampering/poisoning.

## How to run
1. Install dependencies: `pip install cryptography`
2. Run `python main.py`
3. Follow the CLI menu to generate keys, sign files, and verify integrity.
