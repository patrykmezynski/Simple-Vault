import json
import secrets

from datetime import datetime
from dataclasses import asdict
from pathlib import Path

from src import vault_config
from src import crypto


def create_manifest(
    vault_name: str,
    vault_path: Path,
    master_key: bytes,
    vault_id: bytes,
    files: list[vault_config.FileEntry],
    directories: list[vault_config.DirectoryEntry]
) -> None:
    """
    Create and save the encrypted manifest for a new vault.

    The manifest stores original paths, file identifiers, storage names,
    plaintext SHA-256 values and filesystem metadata. It is encrypted with
    a manifest-specific key derived from the random vault master key.

    Args:
        vault_name (str): Original vault name entered by the user.
        vault_path (Path): Path to the vault directory.
        master_key (bytes): Random master key belonging to this vault.
        vault_id (bytes): Random identifier belonging to this vault.
        files (list): FileEntry objects created while scanning and encrypting.
        directories (list): DirectoryEntry objects created while scanning.
    """

    # Use the same creation and modification date for a new manifest.
    current_date = datetime.now().isoformat(timespec="seconds")

    # Build complete manifest object from scanned source metadata.
    manifest = vault_config.VaultManifest(
        format_version=crypto.FORMAT_VERSION,
        vault_id=vault_id.hex(),
        vault_name=vault_name,
        files=files,
        directories=directories,
        file_count=len(files),
        directory_count=len(directories),

        # Total size of the vault.
        size=sum(file.size for file in files),

        date_created=current_date,
        date_modified=current_date
    )

    # Save the manifest to a file.
    _save_manifest(
        manifest,
        vault_path,
        master_key,
        vault_id
    )



def save_manifest(
    manifest: vault_config.VaultManifest,
    vault_path: Path,
    master_key: bytes,
    vault_id: bytes
) -> None:
    """
    Update and save an existing encrypted vault manifest.

    This function is used after add, remove and rename operations. Counts,
    total size and modification time are recalculated before the manifest
    is encrypted and atomically replaced on disk.

    Args:
        manifest (vault_config.VaultManifest): Decrypted manifest to update.
        vault_path (Path): Path to the vault directory.
        master_key (bytes): Vault master key.
        vault_id (bytes): Random identifier belonging to this vault.

    Raises:
        ValueError: If the manifest contains duplicate or inconsistent entries.
    """

    # Keep logical format and vault identity synchronized with encrypted files.
    manifest.format_version = crypto.FORMAT_VERSION
    manifest.vault_id = vault_id.hex()

    # Recalculate values that can change after file operations.
    manifest.file_count = len(manifest.files)
    manifest.directory_count = len(manifest.directories)
    manifest.size = sum(file.size for file in manifest.files)
    manifest.date_modified = datetime.now().isoformat(timespec="seconds")

    # File paths must stay unique inside one logical vault.
    file_paths = [file.path for file in manifest.files]
    if len(file_paths) != len(set(file_paths)):
        raise ValueError("Manifest contains duplicate file paths.")

    # Physical encrypted blob names must also stay unique.
    storage_names = [file.storage_name for file in manifest.files]
    if len(storage_names) != len(set(storage_names)):
        raise ValueError("Manifest contains duplicate storage names.")

    # Cryptographic file identifiers may never be reused.
    file_ids = [file.file_id for file in manifest.files]
    if len(file_ids) != len(set(file_ids)):
        raise ValueError("Manifest contains duplicate file identifiers.")

    # Save the updated authenticated manifest.
    _save_manifest(
        manifest,
        vault_path,
        master_key,
        vault_id
    )

def _save_manifest(
    manifest: vault_config.VaultManifest,
    vault_path: Path,
    master_key: bytes,
    vault_id: bytes
) -> None:
    """
    Serialize, encrypt and save a VaultManifest object.

    The manifest is converted to JSON and encrypted with AES-GCM using a
    key derived from the vault master key. Format header and vault_id are
    authenticated so the manifest cannot be moved between different vaults.

    Args:
        manifest (vault_config.VaultManifest): Manifest to save.
        vault_path (Path): Path to the vault directory.
        master_key (bytes): Vault master key.
        vault_id (bytes): Random identifier belonging to this vault.
    """

    # Convert dataclass to dictionary, then encode JSON as bytes.
    manifest_bytes = json.dumps(
        asdict(manifest),
        separators=(",", ":")
    ).encode("utf-8")

    # Encrypt manifest using a key derived from the vault master key.
    encrypted_manifest = crypto.encrypt_manifest(
        manifest_bytes,
        master_key,
        vault_id
    )

    # Write to a temporary file so an interrupted update does not
    # destroy the last valid manifest.
    manifest_path = vault_path / "manifest.enc"
    temp_path = manifest_path.with_name(
        f".{manifest_path.name}.{secrets.token_hex(8)}.tmp"
    )

    try:
        temp_path.write_bytes(encrypted_manifest)
        temp_path.replace(manifest_path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def load_manifest(
    vault_path: Path,
    master_key: bytes,
    vault_id: bytes
) -> vault_config.VaultManifest:
    """
    Read, decrypt and rebuild the vault manifest.

    The function validates the manifest binary header and vault identifier,
    decrypts authenticated JSON and recreates FileEntry, DirectoryEntry and
    VaultManifest objects.

    Args:
        vault_path (Path): Path to the vault directory.
        master_key (bytes): Decrypted vault master key.
        vault_id (bytes): Vault identifier read from key.enc.

    Returns:
        vault_config.VaultManifest: Decrypted manifest object.

    Raises:
        FileNotFoundError: If manifest.enc does not exist.
        ValueError: If the manifest is invalid, corrupted or inconsistent.
    """

    # Build path to the encrypted manifest file.
    manifest_path = vault_path / "manifest.enc"

    # Check if the manifest file exists.
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Manifest file does not exist in vault '{vault_path}'."
        )

    # Read the whole manifest because it contains only metadata.
    data = manifest_path.read_bytes()

    # Validate and decrypt manifest using the vault master key.
    decrypted_manifest = crypto.decrypt_manifest(
        data,
        master_key,
        vault_id
    )

    try:
        # Convert decrypted JSON bytes back to a Python dictionary.
        manifest_data = json.loads(
            decrypted_manifest.decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(
            "Decrypted manifest contains invalid JSON."
        ) from e

    # Validate logical manifest version before rebuilding objects.
    if manifest_data.get("format_version") != crypto.FORMAT_VERSION:
        raise ValueError(
            "Unsupported logical manifest format version."
        )

    # Check that the encrypted manifest belongs to the expected vault.
    if manifest_data.get("vault_id") != vault_id.hex():
        raise ValueError(
            "Manifest vault_id does not match vault key."
        )

    try:
        # Rebuild FileEntry objects from dictionaries stored in JSON.
        files = [
            vault_config.FileEntry(**file)
            for file in manifest_data["files"]
        ]

        # Rebuild DirectoryEntry objects from dictionaries stored in JSON.
        directories = [
            vault_config.DirectoryEntry(**directory)
            for directory in manifest_data["directories"]
        ]

        # Rebuild complete VaultManifest object.
        manifest = vault_config.VaultManifest(
            format_version=manifest_data["format_version"],
            vault_id=manifest_data["vault_id"],
            vault_name=manifest_data["vault_name"],
            files=files,
            directories=directories,
            file_count=manifest_data["file_count"],
            directory_count=manifest_data["directory_count"],
            size=manifest_data["size"],
            date_created=manifest_data["date_created"],
            date_modified=manifest_data["date_modified"]
        )
    except (KeyError, TypeError) as e:
        raise ValueError(
            "Manifest structure is invalid or incomplete."
        ) from e

    # Verify calculated metadata against values stored in the manifest.
    if manifest.file_count != len(manifest.files):
        raise ValueError("Manifest file_count is invalid.")

    if manifest.directory_count != len(manifest.directories):
        raise ValueError("Manifest directory_count is invalid.")

    if manifest.size != sum(file.size for file in manifest.files):
        raise ValueError("Manifest total size is invalid.")

    return manifest
