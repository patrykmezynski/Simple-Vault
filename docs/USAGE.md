# Python Vault Usage

This document contains command usage and examples for Python Vault.

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
```

## Create a Vault

Create a new vault from a source directory:

```powershell
py main.py create
```

The program will ask for:

```text
Vault name:
Password:
Repeat for confirmation:
Source folder:
```

You can also provide some arguments directly:

```powershell
py main.py create --name MyVault --source "G:\Documents"
```

The password is still requested through hidden input.

A newly created vault is stored inside:

```text
vaults/<random_vault_id>/
```

The original vault name is stored only inside encrypted metadata.

## Open a Vault

Open the encrypted manifest and display the file list:

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

Opening a vault does not decrypt all stored files. Only the encrypted metadata required to display the vault contents is opened.

## List Vaults

List available vault containers:

```powershell
py main.py list
```

Because vault names are encrypted, locked vaults cannot expose their original names without being unlocked.

If the CLI supports unlocked listing, use:

```powershell
py main.py list --unlock
```

The command may request a password and display names only for vaults that can be successfully unlocked with that password.

## Add a File

Add a single file without rebuilding the entire vault:

```powershell
py main.py add
```

Example:

```powershell
py main.py add --name MyVault --source "G:\file.txt" --path "docs/file.txt"
```

The source file is encrypted separately and added to the vault data directory. The encrypted manifest is then updated.

## Remove a File

Remove a single file from the vault:

```powershell
py main.py remove
```

Example:

```powershell
py main.py remove --name MyVault --file "docs/file.txt"
```

The encrypted blob belonging to the selected file is removed and the manifest is updated.

## Rename a File

Rename or move a file inside the logical vault structure:

```powershell
py main.py rename
```

Example:

```powershell
py main.py rename --name MyVault --file "docs/file.txt" --new-path "archive/file.txt"
```

The encrypted file data does not need to be rewritten. Only the encrypted manifest is updated.

## Extract One File

Extract a selected file:

```powershell
py main.py extract
```

Example:

```powershell
py main.py extract --name MyVault --file "folder/test.txt" --destination output
```

The extracted file will be written as:

```text
output/folder/test.txt
```

Before the final file is published, the implementation verifies authenticated encryption data and the expected SHA-256 hash.

## Change the Password

Change the vault password:

```powershell
py main.py change-password
```

The operation:

1. unlocks the vault using the current password,
2. keeps the existing random master key,
3. derives a new wrapping key from the new password,
4. creates a new encrypted `key.enc`.

Stored files and `manifest.enc` do not need to be re-encrypted.

This means password changes remain fast even for very large vaults.

## Verify a Vault

Verify the complete vault:

```powershell
py main.py verify
```

Verification checks the encrypted structure and stored files, including:

- `key.enc`,
- `manifest.enc`,
- vault identifiers,
- file identifiers,
- AES-GCM authentication,
- chunk ordering,
- chunk sizes,
- complete file sizes,
- SHA-256 values,
- missing encrypted blobs,
- unexpected/orphan encrypted blobs.

The verifier processes file data in chunks and does not need to permanently extract every file.

## Use from Python

### Create a Vault

```python
from src import vault as v

result = v.create_vault(
    "MyVault",
    "password123",
    "test"
)

print(result)
```

### Open a Vault

```python
from src import vault as v

manifest = v.open_vault(
    "MyVault",
    "password123"
)

for file in manifest.files:
    print(file.path, file.size)
```

### Extract a File

```python
from src import vault as v

output_path = v.extract_file(
    "MyVault",
    "password123",
    "folder/test.txt",
    "output"
)

print(output_path)
```

## Internal Vault Layout

A vault currently uses a layout similar to:

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

### `key.enc`

Contains the vault master key protected with a password-derived wrapping key.

### `manifest.enc`

Contains encrypted metadata such as:

- vault name,
- original file paths,
- encrypted storage names,
- file identifiers,
- sizes,
- timestamps,
- SHA-256 hashes.

### `data/`

Contains separately encrypted file blobs.

Original file names are not used as physical file names in this directory.

## Tests

Run:

```powershell
py test.py
```

The project tests currently cover the primary vault operations and selected security failure cases.

## Security Notice

Python Vault is an educational project under active development.

Although it uses established cryptographic primitives, the complete design and implementation have not undergone a professional independent security audit.

Do not rely on it as the only protection for critical or irreplaceable data.
