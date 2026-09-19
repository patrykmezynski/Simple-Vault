from dataclasses import dataclass


@dataclass
class FileEntry:
    """Metadata describing one file stored inside the vault."""

    # Original relative path visible to the user.
    path: str

    # Random identifier cryptographically bound to encrypted file chunks.
    file_id: str

    # Random encrypted file name used inside the vault data directory.
    storage_name: str

    # SHA-256 of the original plaintext file stored inside encrypted manifest.
    sha256: str

    # Original file size in bytes.
    size: int

    # Original filesystem timestamps.
    date_created: str
    date_modified: str


@dataclass
class DirectoryEntry:
    """Metadata describing one directory stored inside the vault."""

    # Original relative path visible to the user.
    path: str

    # Total size of files stored inside this directory.
    size: int

    # Original filesystem timestamps.
    date_created: str
    date_modified: str


@dataclass
class VaultManifest:
    """Complete metadata describing the contents of one encrypted vault."""

    # Version of the logical vault manifest format.
    format_version: int

    # Random identifier used to bind the key, manifest and encrypted files.
    vault_id: str

    # Original vault name entered by the user.
    vault_name: str

    # Stored file and directory metadata.
    files: list[FileEntry]
    directories: list[DirectoryEntry]

    # Number of files and directories stored in the vault.
    file_count: int
    directory_count: int

    # Total size of all files in bytes.
    size: int

    # Vault creation and last modification timestamps.
    date_created: str
    date_modified: str

@dataclass
class VaultListEntry:
    """Metadata used to display one stored vault without exposing its name by default."""

    # Random vault identifier used as the physical directory name.
    vault_id: str

    # Decrypted vault name. None means the vault was not unlocked.
    vault_name: str | None

    # True only when the provided password successfully unlocked the vault.
    unlocked: bool



@dataclass
class VaultVerifyResult:
    """Summary returned after complete vault verification."""

    # Decrypted vault name that was successfully verified.
    vault_name: str

    # Number of encrypted files verified against the manifest.
    file_count: int

    # Number of logical directories stored in the manifest.
    directory_count: int

    # Total plaintext size of all verified files in bytes.
    total_size: int
