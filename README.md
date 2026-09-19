# Python Vault

Python Vault is an experimental encrypted file vault written in Python.

Files are encrypted independently, sensitive metadata is stored in an encrypted manifest, and common operations can modify a vault without rebuilding all stored data. The current `0.0.2-alpha` development cycle adds a versioned and validated import/export format.

> [!IMPORTANT]
> This project is under active development and has not undergone a professional cryptographic security audit. Do not use it as a replacement for mature, audited tools when protecting critical or irreplaceable data.

## Features

- AES-256-GCM authenticated encryption
- Scrypt-based password key derivation
- Random 256-bit vault master key
- HKDF-SHA256 for deriving independent manifest and file keys
- Random per-vault `vault_id`
- Random per-file `file_id`
- Chunked encryption and verification for large files
- SHA-256 verification of complete plaintext files
- Encrypted manifest containing original names, paths, hashes and metadata
- Random encrypted storage names
- Add files without rebuilding the complete vault
- Remove individual files
- Rename or move files by changing authenticated metadata only
- Extract individual files
- Change a password without re-encrypting stored file data
- Full-vault integrity verification without permanently extracting plaintext
- Versioned TAR export format with `export.json`
- SHA-256 sidecar for export transfer/corruption checks
- Safe staged import with archive-structure validation
- Import protection against path traversal, links and unsupported TAR entries
- Full cryptographic verification before an imported vault is published
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
export
import
```

Run the CLI through:

```powershell
py main.py --help
```

For complete command documentation and examples, see:

**[docs/USAGE.md](docs/USAGE.md)**

## Project Structure

```text
python_vault/
├── docs/
│   ├── CHANGELOG.md
│   └── USAGE.md
├── src/
│   ├── cli.py
│   ├── crypto.py
│   ├── manifest.py
│   ├── vault.py
│   └── vault_config.py
├── test/
├── test.py
├── main.py
├── requirements.txt
├── README.md
└── LICENSE
```

Runtime vaults are stored approximately as:

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

The original vault name, original file names and logical paths are stored only inside encrypted metadata.

## Export Format

A current export consists of two files:

```text
<random_vault_id>.tar
<random_vault_id>.tar.sha256
```

The TAR archive contains:

```text
export.json
<random_vault_id>/
├── key.enc
├── manifest.enc
└── data/
    └── *.enc
```

`export.json` contains only public technical metadata required by the importer:

- export format identifier,
- export format version,
- encrypted vault format version,
- random `vault_id`,
- export creation timestamp.

It intentionally does **not** contain the original vault name or original file paths.

The `.sha256` sidecar is used to detect accidental corruption or incomplete transfer of the TAR archive. It is not a substitute for authenticated encryption because an attacker able to replace both files could also replace the checksum. During import, the encrypted key, manifest and every encrypted file are therefore verified independently using the vault cryptographic integrity checks.

## Import Safety

Import follows a fail-closed staged process:

1. validate the TAR path and checksum sidecar,
2. verify the complete TAR SHA-256,
3. parse and validate `export.json`,
4. validate supported export and vault format versions,
5. inspect every TAR member before extraction,
6. reject absolute paths, `..` traversal, links, device entries and unexpected files,
7. extract only validated regular files/directories into a temporary directory,
8. authenticate `key.enc` and `manifest.enc`,
9. verify `vault_id` consistency,
10. cryptographically verify every encrypted file,
11. detect missing or orphan encrypted blobs,
12. atomically publish the imported vault only after all checks succeed.

An existing vault directory is never silently overwritten.

## Security Model

The current implementation uses:

- AES-256-GCM for authenticated encryption,
- Scrypt for deriving a password-based key-encryption key,
- a random master key for each vault,
- HKDF-SHA256 for key separation,
- authenticated additional data (AAD) to bind encrypted chunks to their vault, file and chunk index,
- SHA-256 for complete plaintext-file verification,
- chunked processing to avoid loading large files entirely into memory,
- versioned binary formats,
- validation of chunk order, sizes, identifiers and trailing data,
- atomic manifest replacement,
- temporary staging before imported data becomes visible as a vault.

Changing the password only re-wraps the existing master key inside `key.enc`; encrypted file blobs and `manifest.enc` are not re-encrypted.

## Testing

Run the complete regression suite with:

```powershell
py test.py
```

The current suite contains 25 isolated regression tests covering:

- source scanning,
- creation, opening and listing,
- full-vault verification,
- add / rename / remove / extract operations,
- password rotation,
- encrypted-blob corruption detection,
- export metadata and checksum generation,
- export overwrite protection,
- complete export → delete → import → verify round-trip,
- wrong-password import rejection,
- missing and corrupted checksum rejection,
- missing and malformed `export.json`,
- unsupported export and vault format versions,
- TAR path traversal attempts,
- symbolic-link TAR entries,
- tampered encrypted blobs even when the outer checksum is recomputed,
- duplicate vault import protection,
- public CLI exposure of `export` and `import`.

Tests use temporary directories and do not operate on normal project vault storage.

## AI-Assisted Development

This project is partially developed with the assistance of AI tools.

AI may be used to:

- propose implementations and refactors,
- identify possible bugs and security issues,
- generate or update tests,
- write, update and improve project documentation,
- prepare README files, usage guides, changelogs and code documentation,
- review architecture and cryptographic handling.

AI-generated or AI-modified changes are not accepted blindly. Changes introduced with AI assistance are reviewed and verified after implementation using syntax checks, functional tests, integrity tests and targeted failure/corruption tests where applicable.

AI assistance does not replace independent security review or a professional cryptographic audit.

## Installation

Python 3.12+ is recommended.

Install project dependencies from `requirements.txt`:

```powershell
py -m pip install -r requirements.txt
```

Optional virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

## Development Status

- `0.0.1-alpha`: core encrypted vault operations implemented.
- `0.0.2-alpha`: import/export and format-versioning work is currently being completed and hardened.

The vault and export formats should still be treated as experimental until compatibility policy, migrations and broader security testing are established.

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for details.
