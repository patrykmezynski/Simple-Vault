# Python Vault Usage

This document describes the current Python Vault CLI and Python API.

The CLI entry point is `main.py`.

## Help

Show all available commands:

```powershell
py main.py --help
```

Show help for a specific command:

```powershell
py main.py create --help
py main.py open --help
py main.py list --help
py main.py add --help
py main.py remove --help
py main.py rename --help
py main.py extract --help
py main.py change-password --help
py main.py verify --help
py main.py export --help
py main.py import --help
```

Passwords are prompted with hidden input unless they are explicitly supplied as CLI arguments.

## Create a Vault

Create a new encrypted vault from a source directory:

```powershell
py main.py create
```

The program asks for:

```text
Vault name:
Password:
Repeat for confirmation:
Source folder:
```

You can also provide non-secret arguments directly:

```powershell
py main.py create --name MyVault --source "G:\Documents"
```

A newly created vault is stored inside:

```text
vaults/<random_vault_id>/
```

The original vault name is kept only inside encrypted metadata.

## Open a Vault

Open the authenticated encrypted manifest and display stored files:

```powershell
py main.py open
```

Or:

```powershell
py main.py open --name MyVault
```

Example output:

```text
Vault: MyVault

     7.73 MB  image.png
         10 B  test.txt
         10 B  folder/test.txt
```

Opening a vault does not decrypt every stored file. Only the master key and encrypted manifest required to display metadata are opened.

## List Vaults

List physical vault containers without revealing encrypted names:

```powershell
py main.py list
```

To attempt to unlock names using a password:

```powershell
py main.py list --unlock
```

Only vaults that can be successfully authenticated with the supplied password reveal their original names.

## Add a File

Add one file without rebuilding the complete vault:

```powershell
py main.py add
```

Example:

```powershell
py main.py add --name MyVault --source "G:\file.txt" --path "docs/file.txt"
```

The new file receives an independent random file identifier and encrypted storage name. Existing encrypted blobs remain unchanged.

## Remove a File

Remove one logical file:

```powershell
py main.py remove
```

Example:

```powershell
py main.py remove --name MyVault --file "docs/file.txt"
```

The selected encrypted blob is removed only after the updated authenticated manifest is safely written.

## Rename or Move a File

Rename or move one logical file:

```powershell
py main.py rename
```

Example:

```powershell
py main.py rename --name MyVault --file "docs/file.txt" --new-path "archive/file.txt"
```

File contents are not decrypted or re-encrypted. Only authenticated manifest metadata changes.

## Extract One File

Extract one selected file:

```powershell
py main.py extract
```

Example:

```powershell
py main.py extract --name MyVault --file "folder/test.txt" --destination output
```

The logical vault path is recreated under the selected destination:

```text
output/folder/test.txt
```

Plaintext is published only after authenticated decryption, size checks and SHA-256 verification succeed.

## Change the Password

Change the password protecting an existing vault:

```powershell
py main.py change-password
```

The operation:

1. authenticates the current password,
2. unlocks the existing random master key,
3. derives a fresh wrapping key from the new password and a fresh Scrypt salt,
4. writes and verifies a replacement `key.enc`,
5. atomically replaces the old wrapped key.

`manifest.enc` and encrypted files do not need to be re-encrypted.

## Verify a Vault

Verify the complete vault without permanently extracting plaintext:

```powershell
py main.py verify
```

Verification checks:

- `key.enc` authentication,
- `manifest.enc` authentication,
- vault and file identifiers,
- duplicate manifest entries,
- encrypted storage names,
- AES-GCM authentication for every file chunk,
- chunk order and sizes,
- complete plaintext size,
- SHA-256 values,
- missing encrypted blobs,
- unexpected/orphan encrypted blobs,
- logical directory size metadata.

## Export a Vault

Export an encrypted vault as a versioned TAR archive:

```powershell
py main.py export
```

Or provide the destination directly:

```powershell
py main.py export --name MyVault --destination exports
```

`--dest` is accepted as a shorter alias for `--destination`.

The command creates:

```text
exports/<random_vault_id>.tar
exports/<random_vault_id>.tar.sha256
```

The TAR contains:

```text
export.json
<random_vault_id>/
├── key.enc
├── manifest.enc
└── data/
    └── *.enc
```

`export.json` contains only public technical metadata required for compatibility checks. It does not expose the original vault name or original file paths.

The `.sha256` file detects accidental archive corruption or incomplete transfer. It is not an attacker-authenticated signature because anyone able to replace both the TAR and sidecar could recompute the checksum. The importer therefore performs full authenticated verification of the encrypted vault before publishing it.

Existing export files are never silently overwritten.

## Import a Vault

Import an export created by Python Vault:

```powershell
py main.py import
```

Or:

```powershell
py main.py import --archive "exports\<vault_id>.tar"
```

The matching `<vault_id>.tar.sha256` file must be present next to the archive.

Import performs the following checks before the vault becomes available:

1. archive and checksum files exist,
2. the complete TAR SHA-256 matches the sidecar,
3. `export.json` exists and contains valid JSON,
4. export format and vault format versions are supported,
5. `vault_id` is valid,
6. TAR entries are unique and follow the expected layout,
7. absolute paths and `..` path traversal are rejected,
8. symbolic links, hard links, device nodes, FIFOs and unsupported TAR entries are rejected,
9. extraction occurs only inside a temporary staging directory,
10. `key.enc` and `manifest.enc` authenticate with the supplied password,
11. encrypted metadata uses the same `vault_id` as the export,
12. every encrypted file is cryptographically verified,
13. missing and unexpected encrypted blobs are rejected,
14. an existing vault is never overwritten,
15. the fully verified staged directory is atomically moved into `vaults/`.

A wrong password or any integrity failure leaves no partially imported vault behind.

## Use from Python

### Create

```python
from src import vault as v

created = v.create_vault(
    "MyVault",
    "password123",
    "test"
)
```

### Open

```python
from src import vault as v

manifest = v.open_vault(
    "MyVault",
    "password123"
)

for file in manifest.files:
    print(file.path, file.size)
```

### Extract

```python
from src import vault as v

output_path = v.extract_file(
    "MyVault",
    "password123",
    "folder/test.txt",
    "output"
)
```

### Export

```python
from src import vault as v

archive_path = v.export_vault(
    "MyVault",
    "password123",
    "exports"
)
```

### Import

```python
from src import vault as v

vault_path = v.import_vault(
    "exports/<vault_id>.tar",
    "password123"
)
```

## Internal Vault Layout

```text
vaults/
└── <random_vault_id>/
    ├── key.enc
    ├── manifest.enc
    └── data/
        ├── random_name.enc
        └── ...
```

### `key.enc`

Contains the random vault master key protected using a password-derived wrapping key.

### `manifest.enc`

Contains authenticated encrypted metadata including:

- vault name,
- logical file paths,
- encrypted storage names,
- file identifiers,
- sizes,
- timestamps,
- SHA-256 hashes.

### `data/`

Contains independently encrypted file blobs. Original file names are not used as physical storage names.

## Tests

Run the regression suite:

```powershell
py test.py
```

The tests are isolated in temporary directories and cover successful operations plus import/export corruption and hostile TAR scenarios. `src/vault.py` contains production vault logic only; the test runner lives entirely in `test.py`.

## Security Notice

Python Vault is an educational and experimental project under active development.

Although it uses established cryptographic primitives, the complete architecture and implementation have not undergone a professional independent security audit. Do not rely on it as the only protection for critical data.
