# Python Vault

Python Vault is an educational encrypted file vault written in Python.

It stores files individually in encrypted form, keeps file metadata inside an encrypted manifest, and supports modifying the vault without rebuilding all stored data.

> [!IMPORTANT]
> This project is under active development and has not undergone a professional cryptographic security audit. Do not use it as a replacement for mature, audited tools when protecting critical data.

## Features

- AES-256-GCM authenticated encryption
- Scrypt-based password key derivation
- Random 256-bit master key
- HKDF-SHA256 for deriving separate keys
- Per-vault `vault_id`
- Per-file `file_id`
- Chunked encryption for large files
- SHA-256 verification of decrypted files
- Encrypted manifest containing original file metadata
- Random encrypted storage names
- Add files without rebuilding the entire vault
- Remove individual files
- Rename files by updating the encrypted manifest
- Extract a single file
- Change the password without re-encrypting stored files
- Full-vault integrity verification
- Vault names are not stored as predictable directory names

## Current Commands

```text
create
open
list
add
remove
rename
extract
change-password
verify
```

Run the CLI through:

```powershell
py main.py --help
```

For full command documentation and examples, see:

**[Usage.md](Usage.md)**

## Project Structure

```text
python_vault/
├── src/
│   ├── cli.py
│   ├── crypto.py
│   ├── manifest.py
│   ├── vault.py
│   └── vault_config.py
├── vaults/
├── test.py
├── main.py
├── README.md
└── Usage.md
```

A vault is stored approximately as:

```text
vaults/
└── <random_vault_id>/
    ├── key.enc
    ├── manifest.enc
    └── data/
        ├── random_name.enc
        ├── random_name.enc
        └── random_name.enc
```

The original vault name and original file paths are stored only inside encrypted metadata.

## Security Model

The current implementation uses:

- AES-256-GCM for authenticated encryption
- Scrypt for deriving a password-based wrapping key
- a random master key for the vault
- HKDF-SHA256 for deriving separate keys
- authenticated additional data (AAD) to bind encrypted chunks to the correct vault, file, and chunk position
- SHA-256 to verify the complete decrypted file
- chunked processing to avoid loading large files entirely into memory
- versioned binary formats
- validation of chunk order, size, identifiers, and integrity

Changing the password re-encrypts only the protected master key in `key.enc`. Stored file data does not need to be encrypted again.

The `verify` command checks the vault without permanently writing decrypted files to disk.

## AI-Assisted Development

This project is partially developed with the assistance of AI tools.

AI may be used to:

- propose implementations and refactors,
- identify possible bugs and security issues,
- generate or update tests,
- improve documentation,
- review architecture and cryptographic handling.

AI-generated or AI-modified changes are not accepted blindly. Changes introduced with AI assistance are reviewed and verified after implementation, including syntax checks, functional tests, integrity tests, and targeted failure/corruption tests where applicable.

AI assistance does not replace independent security review or a professional cryptographic audit.

## Testing

Run the project tests with:

```powershell
py test.py
```

Current tests cover core operations such as:

- source scanning,
- vault creation,
- vault opening,
- adding files,
- renaming files,
- removing files,
- extracting files,
- vault verification,
- password changes,
- vault listing,
- corruption detection.

## Installation

Python 3.12+ is recommended.

Install dependencies:

```powershell
py -m pip install cryptography click
```

Optional virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\activate
py -m pip install cryptography click
```

## Status

The project is currently in active development.

The core vault format and basic file operations are implemented, but the project should still be treated as experimental until the format stabilizes and receives broader testing and external review.

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for details.
